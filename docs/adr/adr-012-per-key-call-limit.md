# ADR-012: A call limit per key, on the `limits` library

**Context:** a *could* in Phase 2. Without it one key can call as fast as
the upstream answers, and every output costs a scan.

**Decision:**
- `callers.<id>.rate_limit`, in the `limits` notation (`"120/minute"`, or
  several as `"120/minute; 5000/day"`), checked when the config loads.
- One moving-window limiter in memory, shared by all routes, so the limit
  is per key, not per route.
- It counts tool calls only, before the policy check, so a key can't spam
  denied calls either. Every window is tested before any is counted, so a
  call refused by one doesn't use up another.
- A refused call gets an error result, like a policy denial, and a
  `rate_limited` audit line. It is never forwarded.

**Options considered:**
- MCP-backbone's own limiter (`app/auth/rate_limit.py`): a fixed window
  counted in Postgres, tied to its `Workspace` model. The gateway has no
  database, so it can't be reused as it is.
- SlowAPI: limits per HTTP endpoint, but every MCP call on a route is the
  same endpoint, so it can't count tool calls or span routes.
- **`limits` (chosen):** the library under SlowAPI and Flask-Limiter, with
  async storage and moving windows. The gateway adds only the glue.
- A hand-built counter: no reason to write one.

**Consequence:** counts reset on restart and aren't shared between gateway
processes. A Redis storage would fix both, with one more service to run.

Part of the [architecture decisions](README.md) (Phase 5).
