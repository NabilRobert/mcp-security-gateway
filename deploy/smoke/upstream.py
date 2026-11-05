"""The smoke test's upstream: the `_meta` tests' echo server, over HTTP on :8000.

It answers `show_meta` with the `_meta` it received, so the client can
check the caller stamp the gateway adds (the stamp Juku's server reads).
"""

import uvicorn
from mcp.server.transport_security import TransportSecuritySettings
from meta_echo_server import build  # pyright: ignore[reportMissingImports] (mounted next to this file)

UPSTREAM_PORT = 8000
# The SDK accepts only localhost Host headers by default; the gateway calls
# this server by its name on the upstreams network, as it calls juku-mcp.
ALLOWED_HOSTS = ["echo-mcp:*"]

if __name__ == "__main__":
    security = TransportSecuritySettings(allowed_hosts=ALLOWED_HOSTS)
    app = build().streamable_http_app(streamable_http_path="/mcp", transport_security=security)
    uvicorn.run(app, host="0.0.0.0", port=UPSTREAM_PORT, log_level="warning")  # noqa: S104 (inside its container)
