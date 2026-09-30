FROM node:24-alpine

WORKDIR /app

# Copy workspace lib dists into node_modules
COPY libs/sdk/dist/ /app/node_modules/@frontmcp/sdk/
COPY libs/adapters/dist/ /app/node_modules/@frontmcp/adapters/
COPY libs/lazy-zod/dist/ /app/node_modules/@frontmcp/lazy-zod/
COPY libs/utils/dist/ /app/node_modules/@frontmcp/utils/
COPY libs/di/dist/ /app/node_modules/@frontmcp/di/
COPY libs/protocol/dist/ /app/node_modules/@frontmcp/protocol/
COPY libs/guard/dist/ /app/node_modules/@frontmcp/guard/
COPY libs/auth/dist/ /app/node_modules/@frontmcp/auth/
COPY libs/storage-sqlite/dist/ /app/node_modules/@frontmcp/storage-sqlite/
COPY libs/uipack/dist/ /app/node_modules/@frontmcp/uipack/

# Copy package.json with only required deps and install
COPY docker-package.json /app/package.json
COPY yarn.lock /app/yarn.lock
COPY .yarnrc.yml /app/.yarnrc.yml
COPY .yarn/ /app/.yarn/

RUN corepack enable && yarn install --no-immutable

# Copy the built e2e app
COPY dist/apps/e2e/demo-e2e-openapi/ /app/

EXPOSE 3114

ENV PORT=3114
ENV NODE_ENV=production

CMD [node, main.js]
