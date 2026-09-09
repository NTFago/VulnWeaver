FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

COPY apps/proof-tool/vulnweaver-proof-entrypoint /usr/local/bin/vulnweaver-proof-entrypoint
RUN chmod 0555 /usr/local/bin/vulnweaver-proof-entrypoint \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin vulnweaver

USER 10001:10001
ENTRYPOINT ["vulnweaver-proof-entrypoint"]
