/**
 * Guarded outbound fetch for URLs that come from the caller rather than from
 * the operator (currently the client JWKS URL in the launch options).
 *
 * Every request is restricted to http and https, and every address the
 * request is about to connect to must be public. The address check runs in
 * the `lookup` function of the http/https agent, so it applies to the address
 * actually used for the connection (no gap between a pre-check and the fetch
 * for DNS rebinding to exploit). IP literals skip `lookup` in Node, so they are
 * checked before each request. Redirects are followed manually and every hop
 * goes through the same checks.
 *
 * Operator-configured upstreams (FHIR_SERVER_*, FHIR_SERVER_*_INTERNAL) do not
 * use this module: pointing those at internal servers is supported.
 */
import dns, { LookupAddress, LookupOptions } from "dns"
import http  from "http"
import https from "https"
import net   from "net"
import fetch from "cross-fetch"
import config from "./config"


/**
 * Thrown when a URL or a resolved address is not allowed. The message never
 * contains the resolved address.
 */
export class BlockedUrlError extends Error {
    code = "ERR_BLOCKED_URL"

    constructor(message: string) {
        super(message)
        Object.setPrototypeOf(this, new.target.prototype)
    }
}


// Address classification ------------------------------------------------------

const blockedIPv4 = new net.BlockList();
[
    ["0.0.0.0"     ,  8], // "this network", includes the unspecified address
    ["10.0.0.0"    ,  8], // private
    ["100.64.0.0"  , 10], // carrier-grade NAT
    ["127.0.0.0"   ,  8], // loopback
    ["169.254.0.0" , 16], // link-local, includes the cloud metadata address
    ["172.16.0.0"  , 12], // private
    ["192.0.0.0"   , 24], // IETF protocol assignments
    ["192.0.2.0"   , 24], // documentation
    ["192.88.99.0" , 24], // 6to4 relay anycast
    ["192.168.0.0" , 16], // private
    ["198.18.0.0"  , 15], // benchmarking
    ["198.51.100.0", 24], // documentation
    ["203.0.113.0" , 24], // documentation
    ["224.0.0.0"   ,  4], // multicast
    ["240.0.0.0"   ,  4], // reserved, includes the broadcast address
].forEach(([net, prefix]) => blockedIPv4.addSubnet(net as string, prefix as number, "ipv4"));

const blockedIPv6 = new net.BlockList();
[
    ["::"       , 128], // unspecified
    ["::1"      , 128], // loopback
    ["100::"    ,  64], // discard-only
    ["2001:db8::", 32], // documentation
    ["fc00::"   ,   7], // unique local
    ["fe80::"   ,  10], // link-local
    ["fec0::"   ,  10], // site-local (deprecated)
    ["ff00::"   ,   8], // multicast
].forEach(([net, prefix]) => blockedIPv6.addSubnet(net as string, prefix as number, "ipv6"));

/**
 * Parses an IPv6 address (without brackets or zone id) into 8 hextets.
 * Returns null if the input is not a valid IPv6 address.
 */
function parseIPv6(address: string): number[] | null {
    if (net.isIPv6(address) === false) {
        return null
    }

    let head = address, tail: number[] = []

    // Trailing dotted quad (e.g. ::ffff:127.0.0.1)
    const dotted = address.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/)
    if (dotted) {
        const octets = dotted[2].split(".").map(Number)
        tail = [(octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]]
        head = dotted[1].endsWith("::") ? dotted[1] : dotted[1].slice(0, -1)
    }

    const toHextets = (s: string) => s ? s.split(":").map(h => parseInt(h, 16)) : []

    let hextets: number[]
    const gap = head.indexOf("::")
    if (gap === -1) {
        hextets = [...toHextets(head), ...tail]
    } else {
        const left  = toHextets(head.slice(0, gap))
        const right = [...toHextets(head.slice(gap + 2)), ...tail]
        hextets = [...left, ...new Array(8 - left.length - right.length).fill(0), ...right]
    }

    return hextets.length === 8 ? hextets : null
}

/**
 * If an IPv6 address embeds an IPv4 address that a host could end up
 * connecting to (IPv4-mapped, IPv4-compatible, IPv4-translated, NAT64
 * well-known prefix, 6to4), returns that IPv4 address.
 */
function embeddedIPv4(h: number[]): string | null {
    const v4 = (hi: number, lo: number) => [hi >> 8, hi & 255, lo >> 8, lo & 255].join(".")
    const zeros = (from: number, to: number) => h.slice(from, to).every(x => x === 0)

    // ::ffff:a.b.c.d (mapped) and ::a.b.c.d (compatible)
    if (zeros(0, 5) && (h[5] === 0xffff || h[5] === 0)) {
        return v4(h[6], h[7])
    }
    // ::ffff:0:a.b.c.d (translated)
    if (zeros(0, 4) && h[4] === 0xffff && h[5] === 0) {
        return v4(h[6], h[7])
    }
    // 64:ff9b::a.b.c.d (NAT64 well-known prefix)
    if (h[0] === 0x64 && h[1] === 0xff9b && zeros(2, 6)) {
        return v4(h[6], h[7])
    }
    // 2002:aabb:ccdd::/48 (6to4)
    if (h[0] === 0x2002) {
        return v4(h[1], h[2])
    }
    return null
}

/**
 * Returns true if the given IP address is loopback, unspecified, private,
 * link-local, unique-local, CGNAT, multicast, broadcast, reserved, or an IPv6
 * form that embeds any of those. Anything that is not a valid IP address is
 * also treated as blocked.
 */
export function isBlockedAddress(address: string): boolean {
    let ip = String(address || "").trim()

    // Accept bracketed IPv6 and strip any zone id (fe80::1%eth0)
    if (ip.startsWith("[") && ip.endsWith("]")) {
        ip = ip.slice(1, -1)
    }
    ip = ip.replace(/%.*$/, "")

    if (net.isIPv4(ip)) {
        return blockedIPv4.check(ip, "ipv4")
    }

    const hextets = parseIPv6(ip)
    if (!hextets) {
        return true
    }

    if (blockedIPv6.check(ip, "ipv6")) {
        return true
    }

    const v4 = embeddedIPv4(hextets)
    if (v4 !== null) {
        return blockedIPv4.check(v4, "ipv4")
    }

    return false
}


// URL and connection checks ---------------------------------------------------

export type IsBlocked = (address: string) => boolean

export type Resolver = (
    hostname: string,
    options: LookupOptions & { all: true },
    callback: (err: NodeJS.ErrnoException | null, addresses: LookupAddress[]) => void
) => void

/**
 * Validates a URL before a request is made to it: the protocol must be http or
 * https and, if the host is an IP literal, the address must not be blocked.
 * Host names are checked at connection time by the guarded lookup.
 */
export function assertAllowedUrl(input: string | URL, isBlocked: IsBlocked = isBlockedAddress): URL {
    let url: URL
    try {
        url = new URL(String(input))
    } catch {
        throw new BlockedUrlError("Invalid URL")
    }

    if (url.protocol !== "http:" && url.protocol !== "https:") {
        throw new BlockedUrlError("Only http and https URLs are allowed")
    }

    // The WHATWG URL parser normalises decimal, hex and octal IPv4 forms to
    // dotted decimal and keeps IPv6 literals in brackets
    const host = url.hostname.replace(/^\[(.*)\]$/, "$1")
    if (net.isIP(host) && isBlocked(host)) {
        throw new BlockedUrlError("The URL host is not allowed")
    }

    return url
}

/**
 * Creates a `lookup` function for http/https agents that resolves every
 * address for the host name and fails if any of them is blocked. Supports both
 * the single-address and the `all: true` calling conventions (Node uses the
 * latter when `autoSelectFamily` is on).
 */
export function createGuardedLookup(isBlocked: IsBlocked = isBlockedAddress, resolve: Resolver = dns.lookup as unknown as Resolver) {
    return function guardedLookup(hostname: string, options: any, callback: (...args: any[]) => void) {
        if (typeof options === "function") {
            callback = options
            options  = {}
        } else if (typeof options === "number") {
            options = { family: options }
        }
        options = options || {}

        resolve(hostname, { ...options, all: true }, (err, addresses) => {
            if (err) {
                return callback(err)
            }
            if (!addresses || !addresses.length) {
                return callback(Object.assign(new Error("No addresses found"), { code: "ENOTFOUND" }))
            }
            if (addresses.some(a => isBlocked(a.address))) {
                return callback(new BlockedUrlError("The URL host is not allowed"))
            }
            if (options.all) {
                return callback(null, addresses)
            }
            return callback(null, addresses[0].address, addresses[0].family)
        })
    }
}


// Fetch -----------------------------------------------------------------------

const REDIRECT_CODES = [301, 302, 303, 307, 308]

export interface GuardedFetchOptions {
    /**
     * Skip the address checks (protocol is still checked). Defaults to the
     * ALLOW_PRIVATE_JWKS_URLS setting.
     */
    allowPrivate?: boolean

    /** Address classifier (tests only) */
    isBlocked?: IsBlocked

    /** DNS resolver (tests only) */
    resolve?: Resolver

    /** Maximum number of redirects to follow. Defaults to 5 */
    maxRedirects?: number

    /** Request timeout in ms. Defaults to 10 seconds */
    timeout?: number

    /** Maximum response body size in bytes. Defaults to 1 MiB */
    size?: number
}

/**
 * Fetches a caller-supplied URL, refusing non-http(s) URLs and any connection
 * to a non-public address, including after redirects.
 */
export async function guardedFetch(
    input: string,
    init: { headers?: Record<string, string> } = {},
    options: GuardedFetchOptions = {}
): Promise<Response> {
    const {
        allowPrivate = config.allowPrivateJwksUrls,
        isBlocked    = isBlockedAddress,
        resolve      = dns.lookup as unknown as Resolver,
        maxRedirects = 5,
        timeout      = 10_000,
        size         = 1024 * 1024
    } = options

    const policy: IsBlocked = allowPrivate ? () => false : isBlocked

    let agent: ((url: URL) => http.Agent) | undefined
    if (!allowPrivate) {
        const lookup    = createGuardedLookup(policy, resolve) as any
        const httpAgent  = new http.Agent({ lookup })
        const httpsAgent = new https.Agent({ lookup })
        agent = (url: URL) => url.protocol === "https:" ? httpsAgent : httpAgent
    }

    let url = assertAllowedUrl(input, policy)

    for (let hop = 0; ; hop++) {
        // node-fetch specific options (agent, timeout, size) are not part of
        // the DOM RequestInit type that cross-fetch declares
        const res = await fetch(url.href, {
            ...init,
            redirect: "manual",
            agent,
            timeout,
            size
        } as RequestInit)

        const location = res.headers.get("location")
        if (!REDIRECT_CODES.includes(res.status) || !location) {
            return res
        }

        // Discard the redirect body
        await res.arrayBuffer().catch(() => {})

        if (hop >= maxRedirects) {
            throw new Error("Too many redirects")
        }

        url = assertAllowedUrl(new URL(location, url), policy)
    }
}
