ARG UV_VERSION=0.10.0

FROM node:24-bookworm-slim AS node-runtime

FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv-runtime

FROM python:3.12-slim-bookworm

ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=1000
ARG PNPM_VERSION=11.10.0
ARG DEBIAN_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/debian
ARG DEBIAN_SECURITY_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/debian-security
ARG NPM_REGISTRY=https://registry.npmmirror.com

COPY --from=node-runtime /usr/local/ /usr/local/
COPY --from=uv-runtime /uv /uvx /usr/local/bin/

RUN sed -i \
        -e "s|http://deb.debian.org/debian-security|${DEBIAN_SECURITY_MIRROR}|g" \
        -e "s|http://deb.debian.org/debian|${DEBIAN_MIRROR}|g" \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        libpq-dev \
        libffi-dev \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        shared-mime-info \
        fonts-dejavu \
        openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && npm install --global "pnpm@${PNPM_VERSION}" --registry="${NPM_REGISTRY}" \
    && groupadd --gid "${USER_GID}" "${USERNAME}" \
    && useradd --uid "${USER_UID}" --gid "${USER_GID}" --create-home --shell /bin/bash "${USERNAME}"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    NPM_CONFIG_REGISTRY=https://registry.npmmirror.com \
    UV_DEFAULT_INDEX=https://pypi.tuna.tsinghua.edu.cn/simple \
    UV_LINK_MODE=copy

WORKDIR /workspace/vulnweaver
USER ${USERNAME}

CMD ["sleep", "infinity"]
