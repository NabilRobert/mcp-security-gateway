# ADR-002: Proxy on the low-level `Server`, not on middleware or `MCPServer`

**Context:** the gateway must pass tool schemas through unchanged and see
every call.
**Options:**
- (a) the SDK's middleware;
- (b) `MCPServer`;
- (c) the low-level `Server`, with `on_list_tools` and `on_call_tool`
  forwarding through an SDK client session.

**Decision:** (c).
**Why:**
- (a): the SDK marks middleware as provisional: "Observe with it; don't
  build on it" (`docs/advanced/middleware.md`).
- (b): builds schemas from Python functions, which is the wrong direction
  for a proxy.
- (c): the low-level `Server` takes raw handlers and advertises only the
  capabilities it has handlers for (`docs/advanced/low-level-server.md`).
  So a tools-only route is tools-only on the wire too.

**Consequences:**
- Nothing is validated for us at this tier, so the gateway's own code
  checks arguments against policy.
- Whether results (structured content, `is_error`, `_meta`) survive the
  round trip unchanged is Spike 1.

Part of the [architecture decisions](README.md) (Phase 5).
