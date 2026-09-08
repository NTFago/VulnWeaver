FROM node:24-alpine AS build

ARG NPM_CONFIG_REGISTRY=https://registry.npmmirror.com
ENV NPM_CONFIG_REGISTRY=${NPM_CONFIG_REGISTRY}

WORKDIR /workspace
RUN corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/contracts ./packages/contracts
COPY apps/web ./apps/web

RUN pnpm install --frozen-lockfile --filter @vulnweaver/web... \
    && pnpm --filter @vulnweaver/web build

FROM nginxinc/nginx-unprivileged:1.29-alpine

COPY apps/web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /workspace/apps/web/dist /usr/share/nginx/html

EXPOSE 8080
