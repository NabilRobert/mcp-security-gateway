# Phase 4 — Flows & Failures

## Happy path: start

1. **Load and validate the config** (YAML `safe_load`, then schema checks).
   Every environment variable it names must be set. Key hashes must be
   well-formed. Any error → exit 2.
2. **Connect to each upstream** and list its tools. Every tool a policy
   names must exist upstream, so a typo in the policy fails loudly instead
   of silently denying. Unreachable upstream or unknown tool → exit 2.
3. **Load the detectors.** The rules file is parsed and hashed. The local
   model is loaded from its pinned revision and run once on a fixed input
   (a warm-up and self-check). Any failure → exit 2: the gateway doesn't
   start without the detection it was configured with.
4. **Open the audit log** for append, check the last line's hash, and write
   a `start` line: git SHA, policy hash, detector versions. Unwritable log
   → exit 2.
5. **Serve** one route per upstream.

## Happy path: a session and its calls

1. **Connect.** The agent sends `initialize` to `/mcp/<upstream>` with
   `Authorization: Bearer <key>`. The gateway hashes the key and compares
   it in constant time with each caller's hash. No match → HTTP 401 and a
   `call` line with decision `denied` (reason `auth`). Match → the session
   is bound to that caller.
2. **`tools/list`.** The upstream's tool list (cached, refreshed on
   `list_changed`) is filtered to the tools this caller may use. *(Should:
   tool descriptions are run through the detector here too.)*
3. **`tools/call`:**
   1. **Policy:** is the tool allowed on this route for this caller? Do the
      arguments pass their rules? No → write the `call` line (`denied`,
      with the reason) and return a tool error. Stop.
   2. **Audit:** write the `call` line (caller, tool, redacted arguments,
      call id).
   3. **Forward** the call upstream, with the upstream's own credential and
      a timeout.
   4. **Scan** the text content, up to the cap. Rules run first; the model
      runs on the same text. The output is suspicious if either layer flags
      it (an "any" combination; Phase 5 decides whether to keep that).
   5. **Act** according to the policy: pass, annotate or block.
   6. **Audit:** write the `result` line (decision, verdicts, output size
      and hash, upstream and scan timings).
   7. **Respond** to the agent.

## Happy path: measurement (in agent-eval-harness)

1. **Offline detector score ($0, no model calls).**
   - Build the labelled set:
     - benign outputs, by replaying the tool calls already recorded in the
       harness's published runs against local copies of both servers (the
       arguments are stored in full; only the outputs were cut down);
     - injected outputs, by planting injection templates in benign ones.
   - Split by template into `dev` and `test`, so the test set has phrasings
     the rules never saw.
   - Score each detector layer and their combination: precision, recall,
     and time per output.
2. **Agent runs (wait for a model budget).**
   - The attack suite and the normal suites, in the three configurations,
     per model, 5 repeats.
   - Report the attack success rate (any attack grader failed) and the
     normal pass rate for each configuration, with intervals.
   - The harness's `compare` gives the pairwise verdicts:
     - `direct` vs `gateway-off` shows the cost of the proxy alone, which
       should be none;
     - `gateway-off` vs `gateway-on` shows the effect of detection.

## Source of truth

- **The config file** is the truth for who may do what. The policy hash in
  every audit line ties each decision to the exact policy.
- **The upstream** is the truth for tool definitions; the gateway only
  filters them.
- **The audit log** is the truth for what happened. Metrics (calls, denials,
  blocks, latency) are computed from it, not kept separately.
- **The harness's run records** are the truth for agent outcomes. The
  gateway's audit log for a run is kept next to it, so each trial's blocked
  calls can be checked.

## Failure interrogation (call flow)

| Step | Fail | Slow | Twice | Partial |
|---|---|---|---|---|
| Auth (1) | Wrong or missing key → 401, logged with a key fingerprint only. Brute force: each try costs a hash and is logged (a rate limit is a *could*) | Hashing is microseconds | Harmless | N/A |
| Policy (3.1) | Pure check. An exception in it is a bug → `gateway_error`, refused (fail closed) | N/A | Same answer | N/A |
| Audit `call` (3.2) | Can't write (disk full, permissions) → refused, error to the agent, message on stderr. **No unaudited call.** | Local append; a slow disk slows calls, and the latency metric shows it | A retried request gets a new call id; both are logged | A torn last line (a crash mid-write) is found by the chain check at the next start, reported, and a `recovered` line is written |
| Forward (3.3) | An upstream *error result* (e.g. a rejected query) is normal feedback, passed back as it is, decision `allowed`. **Transport failure** → `upstream_error`, an MCP error to the agent | Timeout (30 s) → `upstream_error` | **The gateway never retries a tool call:** it can't know a call is safe to repeat (`write_file` isn't). Retrying is the client's choice | Stream cut mid-response → `upstream_error`; the partial output is not passed on |
| Scan (3.4) | Detector exception → **blocked** (`gateway_error`), fail closed | Model timeout (2 s) → blocked, as above. Rules have no timeout but are linear in the capped size | Same verdict (deterministic) | Beyond the cap: cut off, noted in the output and the audit line |
| Act (3.5) | N/A (pure) | N/A | N/A | N/A |
| Audit `result` (3.6) | Can't write → error to the agent instead of the output, stderr message. The `call` line exists, so the verifier shows the call had no result | As above | N/A | As above |
| Respond (3.7) | Agent disconnected → the result is still logged. Passing on a cancellation upstream is a *could* | N/A | N/A | N/A |

## Failure interrogation (measurement)

- **Gateway errors in a harness run** surface as MCP errors. The harness
  counts transport-level ones as `error` (infrastructure), not `fail`, so
  they can't make detection look better. If a run has more errors than the
  harness's 10% limit, it's marked incomplete, as now.
- **Blocked outputs in normal tasks** make those tasks fail. That is the
  false-positive cost the measurement exists to show, so it counts as
  `fail`, not `error`.
- **An attack blocked but the task also failed** counts as both "attack
  stopped" and "task failed". Both rates are reported, never merged.
- **A detector tuned on the test set** would inflate recall. The split is
  fixed by template before any rule is written, and the test set's
  templates are stored apart, so the dev loop doesn't read them.
- **A model update between runs** would make with/without runs
  incomparable. Each configuration pair runs the same model, settings and
  suite hashes, which the harness already checks.
