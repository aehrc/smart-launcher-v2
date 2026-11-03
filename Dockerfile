# Install the production dependencies only. The backend runs from TypeScript
# source with ts-node and does not use the React build output, so no frontend
# tooling is installed or built.
FROM node:24-alpine AS deps

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --legacy-peer-deps --no-audit --no-fund \
    && npm cache clean --force


FROM node:24-alpine

# The runtime starts node directly; remove the package managers that ship with
# the base image so they are not part of the attack surface
RUN rm -rf /usr/local/lib/node_modules \
           /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
           /usr/local/bin/yarn /usr/local/bin/yarnpkg /opt/yarn-*

WORKDIR /app

ENV NODE_ENV="production"
ENV PORT="80"

COPY --from=deps /app/node_modules ./node_modules
COPY package.json private-key.pem public-key.pem ./
COPY backend ./backend
COPY src/isomorphic ./src/isomorphic

EXPOSE 80

CMD ["/app/node_modules/.bin/ts-node", "--skipProject", "--transpile-only", "./backend/index.ts"]
