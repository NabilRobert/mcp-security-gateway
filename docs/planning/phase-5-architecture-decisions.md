# Phase 5 — Architecture and Decisions

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

### ADR-001: Build a small gateway instead of adopting one
**Context:** good gateways already exist. Checked 2026-10-26 on GitHub and
PyPI:

| Gateway | Licence | Activity |
|---|---|---|
| IBM ContextForge | Apache-2.0 | about 4.7k stars, pushed 2026-10-25 |
| Docker MCP Gateway | MIT | about 1.6k stars, pushed 2026-10-26 |
| Microsoft MCP Gateway | MIT | about 900 stars, pushed 2026-10-21 |
| Enkrypt Secure MCP Gateway | Apache-2.0 | pushed 2026-10-22 |
| mcpgw | MIT | 0.1.0 |

**Options:**
- (a) adopt one and contribute;
- (b) build a small one;
- (c) both: build a small one, and later run the same attack suite against
  one of the above.

**Decision:** (b) now, (c) as a *could*.
**Why:** the portfolio needs code that a reviewer can read in about
15 minutes and that Arthur can defend line by line. The large gateways do
far more (registries, federation, UIs), and that would bury the part being
measured. The measurement is the contribution, and it works against any
gateway, so (c) stays open.
**Consequences:**
- The README says plainly that this isn't a production gateway and links
  the ones above.
- Feature claims about the other gateways are limited to what was checked
  (licence, activity, description), never their detection quality.

### ADR-002: Proxy on the low-level `Server`, not on middleware or `MCPServer`
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

### ADR-003: API keys checked in the gateway's own HTTP layer
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

### ADR-004: Policy as YAML, deny by default, simple argument matchers
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

### ADR-005: Two detector layers: rules, then a local classifier
**Options for the model layer** (Hugging Face metadata, 2026-10-26):

| Model | Licence | Gated | Weights |
|---|---|---|---|
| `protectai/deberta-v3-base-prompt-injection-v2` | Apache-2.0 | No | 738 MB, ONNX build included |
| `meta-llama/Llama-Prompt-Guard-2-22M` | Llama (custom) | Yes, manual approval | 283 MB |
| `meta-llama/Llama-Prompt-Guard-2-86M` | Llama (custom) | Yes | 1.1 GB |
| `deepset/deberta-v3-base-injection` | MIT | No | 738 MB, last updated 2024 |

A paid LLM judge is ruled out by the $0 budget.

**Decision:** ProtectAI v2, run as ONNX on CPU.
**Why:**
- It is permissively licensed, not gated, maintained (updated 2026-07),
  and widely used (about 660k downloads).
- The gated Meta models would need Arthur to accept a custom licence. Prompt
  Guard 2 22M stays the fallback if ProtectAI is too slow (Spike 3).

**Known limits, from its model card:**
- English only.
- It does not detect jailbreaks.
- It produces false positives on system prompts.
- The authors report 91.6% precision on their own held-out prompts. Those
  were prompts, not tool outputs such as database rows or source files, so
  false positives on tool outputs are Spike 4's question.

**Details:**
- The model reads at most 512 tokens, so text is scanned in 512-token
  windows that overlap by 64 tokens, up to the scan cap.
- The output is suspicious if **any** layer flags it.
- The threshold is tuned on `dev` only.
- If Spike 4 kills the model layer, v1 ships rules only (the Phase 1
  fallback) and says so.

**As built (slice E, 2026-10-27):**
- **What both layers read:** the text blocks plus the string values of
  `structured_content`; a JSON output is reduced to its string values
  (Spike 4, Variant B).
- **Rules:** 21 patterns, written from the dev template families only.
  Matching is case-insensitive, on NFKC-normalised text with whitespace
  collapsed.
- **Model:** ProtectAI v2 as ONNX, 512-token windows with an overlap of
  64, at most 16 windows (more is flagged), and a 2 s timeout that gives up
  on time (`abandon_on_cancel`) and fails closed.
- **Layering:** layers run in order and stop at the first flag.
- **Threshold 0.999**, by the rule fixed before scoring: the lowest of 0.99,
  0.995 and 0.999 with dev false positives ≤ 5%. Dev results, with
  timeouts counted as blocks, as the gateway treats them:

  | Threshold | Model: FP | Model: recall | Rules + model: FP | Rules + model: recall |
  |---|---|---|---|---|
  | 0.99 | 14.5% | 61.1% | 14.8% | 100% |
  | 0.995 | 11.1% | 55.8% | 11.5% | 100% |
  | 0.999 | 2.2% | 49.7% | 2.8% | 100% |

  - Rules alone on dev: 0% false positives, 100% recall. That is overfitted
    by construction; the test split is the real measure.
  - 12–21 scans per run timed out, mostly large outputs. Each one is a
    block, so latency (Spike 3) costs false positives, not just time.
- **Change from Phase 4:** an output larger than the scan cap is treated
  as unscanned and blocked unless `allow_unscanned_content` is set, instead
  of being cut and passed on. It is simpler, and it fails closed.

### ADR-006: Default action is `block`
**Options:**
- `block`: replace the output with a notice;
- `annotate`: "spotlighting": mark the output as untrusted data and tell
  the model not to follow instructions in it (Hines et al., 2024,
  arXiv:2403.14720);
- `log`.

**Decision:** `block` by default; `annotate` and `log` are available.
**Why:** `annotate` depends on the model obeying the marking, which is the
very thing the attack exploits. `block` doesn't depend on the model.
**Cost:** a false positive costs a whole tool output, so the normal-suite
pass rate through the gateway is measured.
**Measurement:** `annotate` is measured only if the model budget allows a
fourth configuration.

### ADR-007: Audit log as hash-chained JSONL
**Options:** SQLite; OpenTelemetry (the SDK ships an OTel middleware);
JSONL.
**Decision:** JSONL.
**Why:** an append-only text file is readable without tools and can be
diffed and committed next to a harness run. A hash chain makes an edit or
a deleted line visible.
**Details:**
- Each line has `prev` = the SHA-256 of the previous line's bytes.
- The first line chains from a fixed value plus the file's creation time.
- Lines are flushed after each write; `fsync` per line is a config switch,
  because Spike 6 measures what it costs.

**As built (slice C, 2026-10-27):**
- The first line chains from a fixed value (the creation time was dropped:
  it added nothing the chain doesn't already give).
- A torn last line from a crash is closed at the next start by a
  `recovered` line naming its hash, so the verifier tells a crash from an
  edit.
- The chain is checked at every start. A break is reported and recorded in
  the `start` line, not fatal, because refusing to start would let anyone
  who can edit the log keep the gateway down.
- `verify-log` also lists forwarded calls with no result.

**Limits:**
- A chain shows tampering. It doesn't prevent it: someone who can rewrite
  the whole file can rebuild the chain.
- Lines cut from the end can't be detected without an anchor kept
  elsewhere (shipping the log off the machine). Shipping the log off the machine
  would fix that, and is out of v1.
- OTel export is a *could*.

### ADR-008: Where the measurement lives, and how it runs at $0
**Decision:**
- **The detector evaluation** (labelled set, splits, scorer) lives in this
  repo under `eval/`, because it tests gateway code.
- **The agent measurement** lives in agent-eval-harness, on a branch there:
  - the attack suite;
  - an `answer_excludes` grader (the canary must not appear);
  - a `gateway` target;
  - the configuration recorded in run settings.
- **The $0 end-to-end check** uses Inspect's `mockllm` with scripted
  outputs (`custom_outputs`, `ModelOutput.for_tool_call`). It drives a
  **scripted "gullible agent"** that always does what an injection says.
  That proves, with no paid calls, that the path works and that the graders
  catch a successful attack. It's deterministic, so it shows mechanics, not
  model behaviour.
- **Real-model runs** need Arthur's budget.

**Consequence:** the first published numbers are the detector's
precision and recall, plus the gullible agent's before and after. Both are
labelled for what they are.

### ADR-009: Scope: tools only, one route per upstream
**Decision:**
- v1 serves only `tools/list` and `tools/call`. Resources, prompts,
  sampling and elicitation are not advertised, because the low-level
  `Server` advertises only what it has handlers for.
- One route per upstream, with tool names unchanged (Phase 3).

**Why:** both upstream servers only use tools, and unchanged names let the
existing harness suites run through the gateway as they are.
