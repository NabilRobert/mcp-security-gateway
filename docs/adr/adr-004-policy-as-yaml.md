# ADR-004: Policy as YAML, deny by default, simple argument matchers

**Decision:**
- Per caller and route: a list of allowed tools. Each tool can have
  `arguments: {name: {prefix: …} | {pattern: …}}`.
- `pattern` uses a full match, not a search.
- Path arguments are normalised (`..` resolved, symlinks not followed)
  before prefix matching, so `/data/../etc` can't pass a `/data/` prefix.
- An unknown key in the policy file is an error at start, which catches
  typos.

**Not chosen:**
- a general rule language (OPA/Rego, or CEL): too much for v1;
- SQL parsing: MCP-backbone already enforces read-only itself.

Part of the [architecture decisions](README.md) (Phase 5).
