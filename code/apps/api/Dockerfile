FROM python:3.12-slim

ARG UV_DEFAULT_INDEX=https://pypi.tuna.tsinghua.edu.cn/simple
ENV PYTHONUNBUFFERED=1 \
    UV_DEFAULT_INDEX=${UV_DEFAULT_INDEX} \
    UV_LINK_MODE=copy \
    PATH=/app/.venv/bin:$PATH

WORKDIR /app

RUN python -m pip install --no-cache-dir \
    --index-url "${UV_DEFAULT_INDEX}" \
    "uv>=0.10,<0.11"

COPY pyproject.toml uv.lock README.md ./
COPY packages ./packages
COPY apps/api ./apps/api

RUN uv sync --frozen --no-dev --no-editable --package vulnweaver-api \
    && useradd --create-home --uid 10001 vulnweaver \
    && mkdir -p /var/lib/vulnweaver/artifacts \
    && chown -R vulnweaver:vulnweaver /var/lib/vulnweaver

USER vulnweaver

CMD ["vulnweaver-api"]
