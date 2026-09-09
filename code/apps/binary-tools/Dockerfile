FROM python:3.12-slim

ARG DEBIAN_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/debian
ARG DEBIAN_SECURITY_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/debian-security
ARG DIE_VERSION=3.21
ARG GHIDRA_VERSION=12.1.3
ARG GHIDRA_BUILD_DATE=20260817
ENV PYTHONUNBUFFERED=1 UV_LINK_MODE=copy PATH=/app/.venv/bin:$PATH UV_DEFAULT_INDEX=${UV_DEFAULT_INDEX:-https://pypi.tuna.tsinghua.edu.cn/simple}

RUN sed -i \
      -e "s|http://deb.debian.org/debian|${DEBIAN_MIRROR}|g" \
      -e "s|https://deb.debian.org/debian|${DEBIAN_MIRROR}|g" \
      -e "s|http://deb.debian.org/debian-security|${DEBIAN_SECURITY_MIRROR}|g" \
      -e "s|https://deb.debian.org/debian-security|${DEBIAN_SECURITY_MIRROR}|g" \
      /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install --no-install-recommends -y \
      binutils upx-ucl openjdk-21-jdk-headless ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://github.com/horsicq/DIE-engine/releases/download/${DIE_VERSION}/die_${DIE_VERSION}_Debian_13_amd64.deb" \
      -o /tmp/die.deb \
    && dpkg -i /tmp/die.deb || (apt-get update && apt-get -f install -y && dpkg -i /tmp/die.deb) \
    && rm -f /tmp/die.deb

RUN curl -fsSL "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD_DATE}.zip" \
      -o /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt/ghidra-zip \
    && mv /opt/ghidra-zip/ghidra_* /opt/ghidra \
    && rm -rf /opt/ghidra-zip /tmp/ghidra.zip \
    && chmod +x /opt/ghidra/support/analyzeHeadless

RUN python -m pip install --no-cache-dir --index-url "${UV_DEFAULT_INDEX}" "uv>=0.10,<0.11"

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY packages ./packages
RUN uv sync --frozen --no-editable --package vulnweaver-binary-analysis

COPY deploy/ghidra/ExportVulnWeaver.java /opt/vulnweaver/ghidra-scripts/ExportVulnWeaver.java
COPY apps/binary-tools/vulnweaver-binary-entrypoint /usr/local/bin/vulnweaver-binary-entrypoint
RUN chmod 0555 /usr/local/bin/vulnweaver-binary-entrypoint \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin vulnweaver \
    && rm -rf /home/vulnweaver && ln -s /work/home /home/vulnweaver

USER 10001:10001
ENV GHIDRA_HEADLESS_EXECUTABLE=/opt/ghidra/support/analyzeHeadless
ENTRYPOINT ["vulnweaver-binary-entrypoint"]
