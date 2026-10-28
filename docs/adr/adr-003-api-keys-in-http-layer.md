# ADR-003: API keys checked in the gateway's own HTTP layer

**Context:** v1 uses Bearer API keys (Phase 1).
**Options:**
- (a) the SDK's `TokenVerifier`;
- (b) a small ASGI middleware of the gateway's own, in front of the SDK's
  streamable-HTTP app;
- (c) full OAuth.

**Decision:** (b).
**Why:**
- (a): the SDK requires `token_verifier=` and `auth=` together, and `auth`
  needs an `issuer_url`. It also publishes OAuth discovery metadata
  (`docs/run/authorization.md`), which would advertise an authorization
  server that doesn't exist. (An open SDK PR, #3292, would let a verifier
  work without `AuthSettings`; revisit if it lands.)
- (c): more than v1 needs.
- (b): refuses with 401 before any MCP session exists, which Phase 4
  requires.

**As built (slice A, 2026-10-26):** (b) is Starlette's own
`AuthenticationMiddleware`, with an `ApiKeyBackend` of ours and an
`on_error` that writes the refusal to the audit log and answers 401. It is
the framework the SDK's HTTP app already runs on, so nothing hand-rolled
sits in the request path. The handlers read the caller from
`ctx.request.scope["user"]`, as Spike 1 checked.

**Details:**
- Keys are 32 random bytes, shown once by `hash-key`. Only SHA-256 hashes
  are stored: a slow password hash is unnecessary for random keys of this
  length.
- Keys are compared with `hmac.compare_digest`.
- The caller id is put in the request scope for the handlers. Spike 1
  checks that the handlers can read it.

Part of the [architecture decisions](README.md) (Phase 5).
