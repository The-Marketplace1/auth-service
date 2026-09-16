FROM node:24-alpine AS build

WORKDIR /app
RUN corepack enable

COPY package.json pnpm-lock.yaml ./
COPY tsconfig.json build.mjs ./
COPY src ./src
COPY docs ./docs
COPY scripts ./scripts

RUN pnpm install --frozen-lockfile
RUN pnpm run codegen
RUN pnpm run build

FROM node:24-alpine AS runtime

WORKDIR /app
ENV NODE_ENV=production

COPY --from=build /app/dist ./dist

EXPOSE 8080
USER node

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --spider --quiet http://127.0.0.1:${PORT:-8080}/api/healthz || exit 1

CMD ["node", "--enable-source-maps", "dist/index.mjs"]
