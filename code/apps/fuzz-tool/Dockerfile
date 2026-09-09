FROM python:3.12-slim

ARG DEBIAN_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/debian
ARG DEBIAN_SECURITY_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/debian-security
ARG AFLPP_VERSION=4.33c
ENV PYTHONUNBUFFERED=1 PATH=/usr/local/afl/bin:$PATH

RUN sed -i \
      -e "s|http://deb.debian.org/debian|${DEBIAN_MIRROR}|g" \
      -e "s|https://deb.debian.org/debian|${DEBIAN_MIRROR}|g" \
      -e "s|http://deb.debian.org/debian-security|${DEBIAN_SECURITY_MIRROR}|g" \
      -e "s|https://deb.debian.org/debian-security|${DEBIAN_SECURITY_MIRROR}|g" \
      /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install --no-install-recommends -y \
      build-essential clang llvm-dev libclang-rt-19-dev gdb ca-certificates curl \
      libpango-1.0-0 libpangoft2-1.0-0 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/v${AFLPP_VERSION}.tar.gz" \
      -o /tmp/aflpp.tar.gz \
    && mkdir /tmp/aflpp && tar -xzf /tmp/aflpp.tar.gz -C /tmp/aflpp --strip-components=1 \
    && make -C /tmp/aflpp -j"$(nproc)" source-only \
    && make -C /tmp/aflpp install PREFIX=/usr/local/afl \
    && rm -rf /tmp/aflpp /tmp/aflpp.tar.gz \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin vulnweaver

COPY apps/fuzz-tool/vulnweaver-fuzz-entrypoint /usr/local/bin/vulnweaver-fuzz-entrypoint
RUN chmod 0555 /usr/local/bin/vulnweaver-fuzz-entrypoint

USER 10001:10001
ENTRYPOINT ["vulnweaver-fuzz-entrypoint"]
