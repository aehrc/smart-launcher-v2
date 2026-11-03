import http, { Server } from "http"
import { AddressInfo }  from "net"
import { expect }       from "chai"
import config           from "../../backend/config"
import {
    assertAllowedUrl,
    BlockedUrlError,
    createGuardedLookup,
    guardedFetch,
    isBlockedAddress,
    Resolver
} from "../../backend/outboundFetch"


describe("outboundFetch", () => {

    describe("isBlockedAddress()", () => {

        const blocked: [string, string][] = [
            ["0.0.0.0"           , "unspecified IPv4"],
            ["0.1.2.3"           , "this network (0.0.0.0/8)"],
            ["127.0.0.1"         , "loopback"],
            ["127.255.255.254"   , "loopback (end of 127/8)"],
            ["10.0.0.1"          , "private 10/8"],
            ["10.255.255.255"    , "private 10/8 (end)"],
            ["172.16.0.1"        , "private 172.16/12"],
            ["172.31.255.255"    , "private 172.16/12 (end)"],
            ["192.168.1.1"       , "private 192.168/16"],
            ["169.254.169.254"   , "link-local cloud metadata"],
            ["169.254.0.1"       , "link-local"],
            ["100.64.0.1"        , "CGNAT"],
            ["100.127.255.255"   , "CGNAT (end)"],
            ["224.0.0.1"         , "multicast"],
            ["239.255.255.250"   , "multicast (end)"],
            ["255.255.255.255"   , "broadcast"],
            ["240.0.0.1"         , "reserved"],
            ["192.0.0.8"         , "IETF protocol assignments"],
            ["198.18.0.1"        , "benchmarking"],
            ["::"                , "unspecified IPv6"],
            ["::1"               , "IPv6 loopback"],
            ["[::1]"             , "bracketed IPv6 loopback"],
            ["fe80::1"           , "IPv6 link-local"],
            ["fe80::1%eth0"      , "IPv6 link-local with zone id"],
            ["febf:ffff::1"      , "IPv6 link-local (end of fe80::/10)"],
            ["fc00::1"           , "unique local fc00::/7"],
            ["fd12:3456:789a::1" , "unique local fd00::/8"],
            ["ff02::1"           , "IPv6 multicast"],
            ["::ffff:127.0.0.1"  , "IPv4-mapped loopback (dotted)"],
            ["::ffff:7f00:1"     , "IPv4-mapped loopback (hex)"],
            ["[::ffff:7f00:1]"   , "bracketed IPv4-mapped loopback"],
            ["::ffff:10.0.0.1"   , "IPv4-mapped private"],
            ["::ffff:a9fe:a9fe"  , "IPv4-mapped cloud metadata"],
            ["::ffff:0.0.0.0"    , "IPv4-mapped unspecified"],
            ["0:0:0:0:0:ffff:c0a8:0101", "IPv4-mapped private (uncompressed)"],
            ["::127.0.0.1"       , "IPv4-compatible loopback"],
            ["::ffff:0:10.0.0.1" , "IPv4-translated private"],
            ["64:ff9b::a9fe:a9fe", "NAT64 cloud metadata"],
            ["2002:7f00:1::"     , "6to4 loopback"],
            ["not-an-ip"         , "not an IP address"],
            [""                  , "empty string"],
        ]

        const allowed: [string, string][] = [
            ["8.8.8.8"                , "public IPv4"],
            ["1.1.1.1"                , "public IPv4"],
            ["93.184.216.34"          , "public IPv4"],
            ["172.15.255.255"         , "just below 172.16/12"],
            ["172.32.0.0"             , "just above 172.16/12"],
            ["100.63.255.255"         , "just below CGNAT"],
            ["100.128.0.0"            , "just above CGNAT"],
            ["169.253.255.255"        , "just below link-local"],
            ["2606:4700:4700::1111"   , "public IPv6"],
            ["[2001:4860:4860::8888]" , "bracketed public IPv6"],
            ["::ffff:8.8.8.8"         , "IPv4-mapped public"],
            ["::ffff:808:808"         , "IPv4-mapped public (hex)"],
            ["64:ff9b::808:808"       , "NAT64 public"],
            ["2002:808:808::"         , "6to4 public"],
        ]

        blocked.forEach(([ip, label]) => {
            it(`blocks ${label} (${JSON.stringify(ip)})`, () => {
                expect(isBlockedAddress(ip)).to.equal(true)
            })
        })

        allowed.forEach(([ip, label]) => {
            it(`allows ${label} (${ip})`, () => {
                expect(isBlockedAddress(ip)).to.equal(false)
            })
        })
    })

    describe("assertAllowedUrl()", () => {

        const refused = [
            "ftp://example.com/jwks.json",
            "file:///etc/passwd",
            "data:application/json,{}",
            "javascript:alert(1)",
            "gopher://example.com/",
            "not a url",
            "http://127.0.0.1/",
            "http://127.0.0.1:8080/jwks.json",
            "https://10.1.2.3/jwks.json",
            "http://169.254.169.254/latest/meta-data/",
            "http://0.0.0.0:80/",
            "http://[::1]/",
            "http://[::]/",
            "http://[fe80::1]/",
            "http://[fd00::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:169.254.169.254]/",
            "http://[0:0:0:0:0:ffff:7f00:1]/",
            "http://2130706433/",          // decimal 127.0.0.1
            "http://0x7f000001/",          // hex 127.0.0.1
            "http://0x7f.0.0.1/",          // hex first octet
            "http://017700000001/",        // octal 127.0.0.1
            "http://0177.0.0.1/",          // octal first octet
            "http://127.1/",               // short form
            "http://0xa9fea9fe/",          // hex 169.254.169.254
            "http://2852039166/",          // decimal 169.254.169.254
            "http://192.168.0.1./",        // trailing dot
        ]

        refused.forEach(url => {
            it(`refuses ${url}`, () => {
                expect(() => assertAllowedUrl(url)).to.throw(BlockedUrlError)
            })
        })

        const accepted = [
            "http://8.8.8.8/jwks.json",
            "https://[2606:4700:4700::1111]/jwks.json",
            "https://example.com/.well-known/jwks.json",
            "http://localhost/", // host names are checked at connection time
        ]

        accepted.forEach(url => {
            it(`accepts ${url}`, () => {
                expect(assertAllowedUrl(url)).to.be.instanceOf(URL)
            })
        })

        it("checks IP literals with the given classifier", () => {
            expect(() => assertAllowedUrl("http://127.0.0.1/", () => false)).not.to.throw()
            expect(() => assertAllowedUrl("ftp://127.0.0.1/", () => false)).to.throw(BlockedUrlError)
        })
    })

    describe("createGuardedLookup()", () => {

        function fakeResolver(addresses: string[]): Resolver {
            return (_hostname, _options, cb) => cb(null, addresses.map(address => ({
                address,
                family: address.includes(":") ? 6 : 4
            })))
        }

        function run(addresses: string[], options: any): Promise<any[]> {
            return new Promise(resolve => {
                createGuardedLookup(undefined, fakeResolver(addresses))(
                    "jwks.example.com",
                    options,
                    (...args: any[]) => resolve(args)
                )
            })
        }

        it("refuses when any resolved address is private", async () => {
            const [err] = await run(["93.184.216.34", "10.0.0.1"], { all: true })
            expect(err).to.be.instanceOf(BlockedUrlError)
            expect(err.message).not.to.contain("10.0.0.1")
        })

        it("refuses an IPv4-mapped private address", async () => {
            const [err] = await run(["::ffff:192.168.1.1"], {})
            expect(err).to.be.instanceOf(BlockedUrlError)
        })

        it("returns all addresses when called with all: true", async () => {
            const [err, addresses] = await run(["93.184.216.34", "2606:2800:220:1::1"], { all: true })
            expect(err).to.equal(null)
            expect(addresses).to.have.length(2)
        })

        it("returns a single address otherwise", async () => {
            const [err, address, family] = await run(["93.184.216.34"], { family: 0 })
            expect(err).to.equal(null)
            expect(address).to.equal("93.184.216.34")
            expect(family).to.equal(4)
        })

        it("supports the (hostname, family, callback) form", async () => {
            const [err, address] = await run(["93.184.216.34"], 4)
            expect(err).to.equal(null)
            expect(address).to.equal("93.184.216.34")
        })

        it("refuses localhost with the real resolver", async () => {
            const err = await new Promise(resolve => {
                createGuardedLookup()("localhost", { all: true }, resolve)
            })
            expect(err).to.be.instanceOf(BlockedUrlError)
        })
    })

    describe("guardedFetch()", () => {

        let server: Server
        let port: number
        let hits: string[] = []
        let redirectTo = ""

        before(done => {
            server = http.createServer((req, res) => {
                hits.push(req.url!)
                if (req.url === "/redirect") {
                    res.writeHead(302, { location: redirectTo })
                    return res.end()
                }
                if (req.url === "/loop") {
                    res.writeHead(302, { location: "/loop" })
                    return res.end()
                }
                res.writeHead(200, { "content-type": "application/json" })
                res.end(JSON.stringify({ keys: [] }))
            })
            server.listen(0, "127.0.0.1", () => {
                port = (server.address() as AddressInfo).port
                done()
            })
        })

        after(done => {
            server.close(() => done())
        })

        beforeEach(() => {
            hits = []
        })

        afterEach(() => {
            config.allowPrivateJwksUrls = false
        })

        async function expectBlocked(promise: Promise<any>) {
            let error: any
            try {
                await promise
            } catch (ex) {
                error = ex
            }
            expect(error, "expected the request to be refused").to.exist
            expect(error.code).to.equal("ERR_BLOCKED_URL")
        }

        it("refuses an IP literal loopback URL and makes no request", async () => {
            await expectBlocked(guardedFetch(`http://127.0.0.1:${port}/jwks.json`))
            expect(hits).to.deep.equal([])
        })

        it("refuses a host name that resolves to loopback and makes no request", async () => {
            await expectBlocked(guardedFetch(`http://localhost:${port}/jwks.json`))
            expect(hits).to.deep.equal([])
        })

        it("checks the address at connection time (DNS answer is private)", async () => {
            const resolve: Resolver = (_h, _o, cb) => cb(null, [{ address: "127.0.0.1", family: 4 }])
            await expectBlocked(guardedFetch(`http://jwks.example.com:${port}/jwks.json`, {}, { resolve }))
            expect(hits).to.deep.equal([])
        })

        it("checks the address at connection time for https as well", async () => {
            const resolve: Resolver = (_h, _o, cb) => cb(null, [{ address: "127.0.0.1", family: 4 }])
            await expectBlocked(guardedFetch(`https://jwks.example.com:${port}/jwks.json`, {}, { resolve }))
            expect(hits).to.deep.equal([])
        })

        it("connects when the classifier allows the resolved address", async () => {
            const resolve: Resolver = (_h, _o, cb) => cb(null, [{ address: "127.0.0.1", family: 4 }])
            const res = await guardedFetch(`http://jwks.example.com:${port}/jwks.json`, {}, {
                resolve,
                isBlocked: ip => ip !== "127.0.0.1"
            })
            expect(await res.json()).to.deep.equal({ keys: [] })
            expect(hits).to.deep.equal(["/jwks.json"])
        })

        it("allows private addresses when ALLOW_PRIVATE_JWKS_URLS is on", async () => {
            config.allowPrivateJwksUrls = true
            const res = await guardedFetch(`http://localhost:${port}/jwks.json`)
            expect(await res.json()).to.deep.equal({ keys: [] })
            expect(hits).to.deep.equal(["/jwks.json"])
        })

        it("still refuses non-http(s) URLs when ALLOW_PRIVATE_JWKS_URLS is on", async () => {
            config.allowPrivateJwksUrls = true
            await expectBlocked(guardedFetch("file:///etc/passwd"))
        })

        describe("redirects", () => {

            // Treat only 127.0.0.1 as public so the local server can play the
            // role of a public JWKS host that redirects elsewhere
            const isBlocked = (ip: string) => ip !== "127.0.0.1"

            it("follows a redirect to an allowed address", async () => {
                redirectTo = `http://127.0.0.1:${port}/jwks.json`
                const res = await guardedFetch(`http://127.0.0.1:${port}/redirect`, {}, { isBlocked })
                expect(res.status).to.equal(200)
                expect(hits).to.deep.equal(["/redirect", "/jwks.json"])
            })

            it("refuses a redirect to a blocked IP literal", async () => {
                redirectTo = "http://169.254.169.254/latest/meta-data/"
                await expectBlocked(guardedFetch(`http://127.0.0.1:${port}/redirect`, {}, { isBlocked }))
                expect(hits).to.deep.equal(["/redirect"])
            })

            it("refuses a redirect to an IPv4-mapped IPv6 literal", async () => {
                redirectTo = `http://[::ffff:127.0.0.2]:${port}/jwks.json`
                await expectBlocked(guardedFetch(`http://127.0.0.1:${port}/redirect`, {}, { isBlocked }))
                expect(hits).to.deep.equal(["/redirect"])
            })

            it("refuses a redirect to a host name that resolves to a blocked address", async () => {
                redirectTo = `http://internal.example.com:${port}/jwks.json`
                const resolve: Resolver = (_h, _o, cb) => cb(null, [{ address: "10.0.0.1", family: 4 }])
                await expectBlocked(guardedFetch(`http://127.0.0.1:${port}/redirect`, {}, { isBlocked, resolve }))
                expect(hits).to.deep.equal(["/redirect"])
            })

            it("refuses a redirect to a non-http(s) URL", async () => {
                redirectTo = "file:///etc/passwd"
                await expectBlocked(guardedFetch(`http://127.0.0.1:${port}/redirect`, {}, { isBlocked }))
            })

            it("stops after too many redirects", async () => {
                let error: any
                try {
                    await guardedFetch(`http://127.0.0.1:${port}/loop`, {}, { isBlocked, maxRedirects: 3 })
                } catch (ex) {
                    error = ex
                }
                expect(error?.message).to.equal("Too many redirects")
                expect(hits).to.have.length(4)
            })
        })
    })
})
