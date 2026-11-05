# The gateway as a container. Build from the repository root:
#   docker build -t mcp-gateway:local .
# deploy/compose.yaml runs it non-root on a read-only filesystem. The config
# (upstreams, callers' key hashes, policies) is mounted at run time, never
# baked in, and the only thing it writes is the audit log, to a mounted folder.
FROM ghcr.io/astral-sh/uv:0.13.1 AS uv

FROM python:3.12-slim AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
# Built where it runs: uv writes this path into every script's first line (#!/app/.venv/bin/python).
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY src/ src/
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin gateway \
    && mkdir -p /var/log/mcp-gateway && chown gateway /var/log/mcp-gateway
COPY --from=build /app/.venv /app/.venv
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    MCP_GATEWAY_CONFIG=/run/secrets/mcp_gateway_config \
    MCP_GATEWAY_HOST=0.0.0.0 \
    MCP_GATEWAY_PORT=8000
USER gateway
EXPOSE 8000
# The start interval lets `docker compose up --wait` return within seconds.
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --start-interval=1s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"
CMD ["mcp-gateway", "serve"]
