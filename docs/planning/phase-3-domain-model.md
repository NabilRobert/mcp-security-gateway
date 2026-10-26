# Phase 3 — Domain Model

## Glossary

**The gateway**

- **Config**: one YAML file with the upstreams, callers, policies and
  detector settings. Its hash (the **policy hash**) is recorded with every
  audit line.
- **Upstream**: a named MCP server the gateway forwards to, reached over
  Streamable HTTP (a URL) or stdio (a command). It has its own credential if
  it needs one, such as MCP-backbone's key. The gateway holds that
  credential and the agent never sees it, so the key an agent has opens the
  gateway, not the server.
- **Route**: one gateway URL per upstream (`/mcp/<upstream>`). Tool names
  and schemas pass through unchanged, so an existing harness suite works
  against the gateway by changing only the target URL. (One endpoint
  merging several upstreams would need renamed tools; that's out of v1.)
- **Caller**: whoever holds a gateway API key, typically an agent or a
  harness run. It has an id, a key hash and one policy. The key itself is
  stored nowhere.
- **Policy**: for one caller, and per route, the tools it may call, each
  with optional **argument rules** (a path prefix, a pattern). Anything not
  listed is denied. It also sets the **action** taken on a suspicious
  output.
- **Session**: one MCP session, opened with one key and bound to that
  caller for its lifetime.
- **Detector**: one layer that inspects a tool output. v1 has two: `rules`
  (patterns) and `model` (a small local classifier). Each has a version:
  the rules file hash, or the model name plus its pinned revision.
- **Verdict**: a detector's result for one output: `clean` or
  `suspicious`, a score, the rule ids or label that matched, and the time
  taken. The output's verdict is the combined result of the layers.
- **Action**: what happens to a suspicious output: `block` (replaced by a
  short notice), `annotate` (wrapped and marked as untrusted data) or `log`
  (passed through, recorded).
- **Decision**: the outcome of one tool call, exactly one of:
  - `allowed` (passed through clean);
  - `denied` (by policy or an argument rule, never forwarded);
  - `blocked` or `annotated` (an action was taken on the output);
  - `upstream_error`;
  - `gateway_error` (the gateway failed, so it failed closed).
- **Audit record**: one JSONL line in the audit log. There are two per
  forwarded call: `call` before forwarding and `result` after, sharing a
  call id. A refused call has one `call` line with its decision. Every line
  carries the hash of the previous line.

**The measurement** (built in agent-eval-harness)

- **Attack task**: a harness task whose tool outputs contain a planted
  injection. It has normal graders (did it answer the question) and attack
  graders (did it call a forbidden tool; did the **canary** reach the
  answer).
- **Canary**: a unique string planted next to data the attack tries to leak.
  It shows up in the answer only if the attack worked.
- **Configuration**: how a run reaches the tools: `direct`, `gateway-off`
  (gateway, detection off) or `gateway-on`. It is recorded in the run's
  settings.
- **Labelled output**: one tool output with a label (`benign` or
  `injected`) and a split (`dev` or `test`), used to score the detectors
  offline with no model calls.

## Entities & relationships

- `Config` → many `Upstream`s, many `Caller`s, many `Policy`s, one detector
  setup.
- `Upstream` → one `Route`.
- `Caller` → one `Policy`. A `Policy` covers one or more `Route`s, with a
  list of tool rules for each.
- `Session` → one `Caller`, one `Route`, many `Call`s.
- `Call` → one `Decision`, zero or more `Verdict`s (none if it was refused
  before forwarding), and one or two audit records.
- Harness `Run` → one `Configuration`. When it goes through the gateway, it
  also records the gateway's git SHA, policy hash and detector versions.

## Invariants

- **Deny by default.** A tool, an argument, an unknown upstream tool,
  non-text content or a detector error is denied unless the policy allows
  it.
- **A refused call never reaches the upstream.** The policy and argument
  checks run before the call is forwarded.
- **No unaudited call.** The `call` line is written *before* forwarding. If
  it can't be written, the call is refused. A `call` with no `result` (a
  crash) is reported when the chain is verified.
- **No secret is ever logged.** No gateway key, no upstream credential, no
  argument matching the redaction rules. Outputs are stored only as size,
  hash and verdict.
- **The agent never holds the upstream credential.**
- **The agent gets exactly one of:** the upstream output unchanged, the
  annotated output, the block notice, or an error. It never gets output
  that wasn't scanned: text beyond the scan cap is cut off, not passed on.
- **The same output gets the same verdict.** Rules are deterministic. The
  model runs at a pinned revision with no sampling.
- **Transparent apart from filtering:** tool names, descriptions and
  schemas are passed through unchanged.
- **The detector test split stays unseen.** Rules and thresholds are tuned
  on `dev` only. `test` is scored once per detector version, and that is
  the number published.
