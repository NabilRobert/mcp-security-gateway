# Phase 2 — Requirements & Constraints

**Scope:** v1 is a local proxy that an agent connects to instead of an MCP
server. It covers tools only (no resources, prompts or sampling), and two
upstream servers: MCP-backbone and the reference filesystem server. It is
not deployed publicly (see the Phase 1 non-goals).

## Core functional scenarios

**Using it.** Arthur starts the gateway with one config file that names the
upstream servers, the API keys (stored as hashes) and a policy. An agent
connects to the gateway's URL with its key in an `Authorization: Bearer`
header. The gateway:
1. checks the key;
2. lists only the tools that key may use;
3. forwards each allowed call upstream;
4. checks the output for prompt injection and acts on what it finds;
5. returns the result;
6. writes one audit line per call.

The agent can't tell it isn't talking to the server directly, apart from
the tools it isn't allowed to see.

**Measuring it.** The same agent-eval-harness suites run in three
configurations:
- direct to the server;
- through the gateway with detection off;
- through the gateway with detection on.

Attack tasks plant injections in tool outputs. The report gives the attack
success rate and the normal pass rate side by side for each configuration,
per model, with intervals.

**Measuring the detector without a model.** A labelled set of tool outputs
(benign outputs recorded from the real suites, plus injected ones) is
scored offline: precision, recall and time per output for each detector
layer. This costs $0, so it is the first number published while the model
budget is $0.

## Resolved edge cases

- **No key, or a wrong key:** refused with HTTP 401 before any MCP session
  starts. The audit line records the refusal, the source address and a key
  fingerprint (first 8 characters of its hash), never the key.
- **Valid key, tool not allowed:** the tool is left out of `tools/list`. If
  the agent calls it anyway, the call is refused with a tool error ("denied
  by policy") and is never sent upstream.
- **Argument rules:** a policy can restrict a tool's arguments with simple
  matchers: a path prefix for filesystem tools, an allowed pattern for a
  string. A call that breaks a rule is refused like a denied tool. SQL is
  not parsed in v1; MCP-backbone already enforces read-only itself.
- **Injection found in an output:** the action is set per policy: `block`
  (replace the output with a short notice to the model), `annotate` (wrap
  the output in a marked untrusted-data block, plus a warning) or `log`
  only. Which one is the default is a Phase 5 ADR, decided by measurement.
- **The detector fails or times out:** the gateway **fails closed**. The
  output is blocked, and the audit line says why. A detector bug must not
  turn into a silent pass.
- **Upstream server down or erroring:** passed back as an MCP error, marked
  `upstream_error` in the audit log, never as "denied". The harness counts
  it as an infrastructure error, not an agent failure.
- **Very large outputs:** text is scanned up to a size cap (proposed
  256 KB). Anything beyond the cap is cut off and the cut is noted, so an
  attacker can't hide an injection past the scanned part.
- **Non-text content** (images, embedded resources): not scanned in v1.
  The policy decides whether it passes or is blocked (default: blocked), and
  the audit line marks it `unscanned`.
- **Tool list changes upstream:** the gateway re-filters on
  `notifications/tools/list_changed`, so a new upstream tool is hidden until
  the policy allows it (deny by default).
- **Secrets in the audit log:** keys are never logged. Arguments are logged
  after redaction rules (any field named like `key`, `token`, `password` or
  `secret`). Outputs are not stored, only their size, a hash and the
  detector's verdict.
- **Tampering with the audit log:** each line includes the hash of the
  previous line, so an edit or a deleted line in the middle shows up when
  the chain is verified.
- **Several agents at once:** each MCP session is bound to the key that
  opened it. Sessions don't share state.

## Must / should / could

| | Requirement |
|---|---|
| **Must** | API-key auth (hashed keys, constant-time compare); per-key tool allow-list, deny by default; a refused call never reaches upstream; JSONL audit log with redaction; output injection check (rules + local model) with the block / annotate / log actions; fail closed on detector errors; works in front of both upstream servers unchanged; offline detector evaluation (precision / recall / time); attack suite and the three-configuration measurement design in the harness |
| **Should** | Argument rules (path prefix, pattern); hash-chained audit log with a `verify` command; per-call latency overhead measured (p50 / p95); tool descriptions checked for injection at list time (poisoned upstream servers) |
| **Could** | Rate limit per key; OAuth instead of API keys; SQL-aware rules; a small read-only view of the audit log |
| **Won't (v1)** | Resources, prompts, sampling, elicitation; a public deployment; a paid LLM-judge detector |

## Non-functional requirements

| Category | Decision |
|---|---|
| Security | Deny by default everywhere (tools, unknown upstream tools, non-text content, detector errors). Keys only as hashes in config. No secret in logs, errors or test output; a test checks this. Dependencies pinned in `uv.lock`. |
| Latency | Measured, not promised. Proposed budget: rules < 5 ms per output, local model < 100 ms per output on a laptop CPU. Phase 6 tests whether that holds. |
| Cost | $0 to build and to run the detector. Only the with/without agent runs need model calls, and they wait for Arthur's budget. |
| Reproducibility | The audit log records the gateway's git SHA, policy hash and detector version. Harness runs through the gateway record the same in their settings, so a comparison names what changed. |
| Portability | Config is one YAML file; the log is plain JSONL. Both are readable without the tool. |
| Maintainability | Solo. A reviewer understands it from the README, the threat model and the ADRs in about 15 minutes. |

## Constraints

- **Time budget:** as fast as possible (Phase 1 decision). Phase docs stay
  minimal.
- **Team:** solo (Arthur + Claude).
- **Stack:** Python 3.12 with uv, ruff, pyright and pytest; the MCP Python
  SDK (2.3.0, as MCP-backbone). The filesystem server needs Node (`npx`).
- **Local model:** must run on CPU and be small, with a permissive licence
  and a pinned revision. Downloading it needs Arthur's OK first (name,
  source, size).
- **Model access:** none for now ($0 budget). Nothing in the build, the
  tests or CI calls a paid model.
- **Other repos:** the harness needs a new grader (the answer must *not*
  contain a canary), the attack suite and a gateway target. That work goes
  on a branch in the harness repo, not here. MCP-backbone stays unchanged;
  injected rows go into the harness's local, pinned copy of the demo data,
  never the live database.
- **Not public yet:** the repo stays local until Arthur decides to publish
  it. No server details in any doc.
