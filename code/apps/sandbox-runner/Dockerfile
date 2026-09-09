FROM python:3.12-slim

ARG UV_DEFAULT_INDEX=https://pypi.tuna.tsinghua.edu.cn/simple
ARG DEBIAN_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/debian
ARG DEBIAN_SECURITY_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/debian-security
ENV PYTHONUNBUFFERED=1 UV_DEFAULT_INDEX=${UV_DEFAULT_INDEX} UV_LINK_MODE=copy PATH=/app/.venv/bin:$PATH

RUN sed -i \
      -e "s|http://deb.debian.org/debian|${DEBIAN_MIRROR}|g" \
      -e "s|https://deb.debian.org/debian|${DEBIAN_MIRROR}|g" \
      -e "s|http://deb.debian.org/debian-security|${DEBIAN_SECURITY_MIRROR}|g" \
      -e "s|https://deb.debian.org/debian-security|${DEBIAN_SECURITY_MIRROR}|g" \
      /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install --no-install-recommends -y docker.io docker-cli ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN python -m pip install --no-cache-dir --index-url "${UV_DEFAULT_INDEX}" "uv>=0.10,<0.11"

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY packages ./packages
COPY apps/sandbox-runner ./apps/sandbox-runner
COPY deploy/tool-specs ./deploy/tool-specs
RUN uv sync --frozen --no-dev --no-editable --package vulnweaver-sandbox-runner-service

CMD ["python", "-m", "vulnweaver_sandbox_runner_service.main"]
