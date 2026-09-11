FROM python:3.12-slim

ARG UV_DEFAULT_INDEX=https://pypi.tuna.tsinghua.edu.cn/simple
ARG DEBIAN_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/debian
ARG DEBIAN_SECURITY_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/debian-security
ENV PYTHONUNBUFFERED=1 \
    UV_DEFAULT_INDEX=${UV_DEFAULT_INDEX} \
    UV_LINK_MODE=copy \
    PATH=/app/.venv/bin:$PATH \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0

RUN sed -i \
      -e "s|http://deb.debian.org/debian|${DEBIAN_MIRROR}|g" \
      -e "s|https://deb.debian.org/debian|${DEBIAN_MIRROR}|g" \
      -e "s|http://deb.debian.org/debian-security|${DEBIAN_SECURITY_MIRROR}|g" \
      -e "s|https://deb.debian.org/debian-security|${DEBIAN_SECURITY_MIRROR}|g" \
      /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install --no-install-recommends -y binutils cppcheck ca-certificates upx-ucl \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-dejavu-core fonts-noto-cjk \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir \
    --index-url "${UV_DEFAULT_INDEX}" \
    "semgrep==1.130.0" \
    "setuptools<81" \
    "uv>=0.10,<0.11"

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY packages ./packages
COPY apps/analysis-worker ./apps/analysis-worker
COPY deploy/ghidra /opt/vulnweaver/ghidra
RUN uv sync --frozen --no-dev --no-editable --package vulnweaver-analysis-worker \
    && useradd --create-home --uid 10001 vulnweaver
USER vulnweaver
CMD ["vulnweaver-analysis-worker"]
