# Phase 5 — Architecture and Decisions

Part of the [planning trail](../planning/README.md): phases 1–4 lead here,
and phases 6 and 7 build on it.

## Components

| Module | Job |
|---|---|
| `config` | Load and validate the YAML; compute the policy hash |
| `auth` | HTTP layer: Bearer key → caller, or 401 |
| `policy` | Pure: (caller, route, tool, arguments) → allow or deny with a reason |
| `upstream` | One SDK client session per upstream (HTTP or stdio), holding its credential |
| `proxy` | The low-level MCP `Server` per route: list, filter, forward, act |
| `detect` | Rules and model layers → verdicts. Pure apart from loading the model |
| `audit` | Append-only, hash-chained JSONL; `verify` command |
| `eval` | Offline detector scoring on the labelled set (no network, no model calls) |
| `cli` | `serve`, `verify-log`, `hash-key`, `eval-detector` |

The rule that matters: `policy`, `detect` (given a loaded model) and
`audit`'s verifier are pure and never import `upstream` or `proxy`. Their
tests and the detector evaluation then run with no server and no network.

## Stack

- **Python 3.12**, uv, ruff, pyright (strict), pytest, GitHub Actions: the
  same as MCP-backbone and the harness.
- **MCP:** the `mcp` SDK, pinned at 2.3.0 (the latest on PyPI,
  2026-10-26), as MCP-backbone.
- **Detector model:** `protectai/deberta-v3-base-prompt-injection-v2` at a
  pinned revision, run with `onnxruntime` on CPU (ADR-005).
- **Filesystem upstream:** `@modelcontextprotocol/server-filesystem` at the
  exact version the harness pins.

## Cross-cutting concerns

- **Secrets:** the config names environment variables; it never holds key
  values. Gateway keys are stored as SHA-256 hashes. Upstream credentials
  come from the environment and are never logged or returned.
- **Errors:**
  - `ConfigError` → exit 2 at start;
  - `PolicyDenied` → tool error to the agent;
  - `UpstreamError` → MCP error, `upstream_error`;
  - anything unexpected inside a call → `gateway_error`, fail closed.
- **Versioning:** every audit line carries `schema_version`, the gateway's
  git SHA, the policy hash and the detector versions.

## ADRs

One file per decision: its context, the decision, the options considered
and its consequences. They are kept as written; later findings are added
under each, dated.

| ADR | Decision |
|---|---|
| [ADR-001](adr-001-build-small-gateway.md) | Build a small gateway instead of adopting one |
| [ADR-002](adr-002-low-level-server-proxy.md) | Proxy on the low-level `Server`, not on middleware or `MCPServer` |
| [ADR-003](adr-003-api-keys-in-http-layer.md) | API keys checked in the gateway's own HTTP layer |
| [ADR-004](adr-004-policy-as-yaml.md) | Policy as YAML, deny by default, simple argument matchers |
| [ADR-005](adr-005-two-detector-layers.md) | Two detector layers: rules, then a local classifier |
| [ADR-006](adr-006-default-action-block.md) | Default action is `block` |
| [ADR-007](adr-007-hash-chained-audit-log.md) | Audit log as hash-chained JSONL |
| [ADR-008](adr-008-measurement-at-zero-cost.md) | Where the measurement lives, and how it runs at $0 |
| [ADR-009](adr-009-scope-tools-only.md) | Scope: tools only, one route per upstream |
| [ADR-010](adr-010-per-session-upstreams.md) | Per-session upstreams, keyed by `Mcp-Session-Id` |
| [ADR-011](adr-011-tool-description-scanning.md) | Tool descriptions are scanned, and a flagged tool is hidden |
| [ADR-012](adr-012-per-key-call-limit.md) | A call limit per key, on the `limits` library |
| [ADR-013](adr-013-forward-meta-stamp-caller.md) | Forward each call's `_meta`, with the caller stamped in |
| [ADR-014](adr-014-opentelemetry-tracing.md) | OpenTelemetry tracing, on the MCP SDK's own spans |
