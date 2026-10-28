# ADR-013: Forward each call's `_meta`, with the caller stamped in

**Context:** Juku (Project 7) sends a single-use delegation token in each
call's `_meta` (`io.github.nabilrobert.juku/delegation`), and its MCP
server checks that the chain's acting agent is the key that made the call.
Agent tracing needs W3C `traceparent` there too. The gateway forwarded only
the tool name and arguments, so Juku's spike 6 found every call refused
behind it.

**Decision:**
- A call's `_meta` reaches the upstream unchanged: same keys, order and
  values.
- The gateway stamps the caller it authenticated under
  `io.github.nabilrobert.mcp-gateway/caller` (its config id), overwriting
  any value the client sent.
- Keys of the agent's own connection stay on that hop: the SDK's
  `io.modelcontextprotocol/*` keys (it sets its own upstream) and the
  progress token (a shared upstream connection carries many agents' calls,
  where tokens could clash, and the gateway doesn't relay progress).
- The gateway neither reads nor validates anything else in `_meta`. MCP
  2026-07-28 forbids passing the gateway's own credential through; an app's
  token, audience-bound to its own server, is not that.
- The audit log records `has_meta` and `is_caller_claim_overwritten`, never
  `_meta`'s contents, which can carry tokens.

**Options considered:**
- Juku's spike 6 patch (`gateway-meta-passthrough.patch`): the same idea,
  used as the starting point. It also forwarded the progress token, which
  the SDK names `progress_token` once parsed.
- Validating the delegation token in the gateway: it would need each app's
  public key and rules, and the token is for the app's server, not the
  gateway. The stamp keeps the gateway token-agnostic.
- Forwarding `_meta` without a stamp: the upstream couldn't tell which key
  called, so one agent could present another's chain.
- Putting the caller in an HTTP header: it only reaches HTTP upstreams, not
  stdio ones; `_meta` reaches both.

**Consequence:** the stamp means something only if the upstream is
reachable through the gateway alone. `tools/list` already passed its
request params through whole, `_meta` included; it gets no caller stamp,
since no upstream authorizes a listing.

Part of the [architecture decisions](README.md) (Phase 5).
