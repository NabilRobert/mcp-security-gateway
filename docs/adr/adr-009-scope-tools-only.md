# ADR-009: Scope: tools only, one route per upstream

**Decision:**
- v1 serves only `tools/list` and `tools/call`. Resources, prompts,
  sampling and elicitation are not advertised, because the low-level
  `Server` advertises only what it has handlers for.
- One route per upstream, with tool names unchanged (Phase 3).

**Why:** both upstream servers only use tools, and unchanged names let the
existing harness suites run through the gateway as they are.

Part of the [architecture decisions](README.md) (Phase 5).
