# Phase 6 — Risks, Spikes and the Walking Skeleton

## Risks, ranked by likelihood × impact

**Technical**

- **The detector flags normal tool outputs.** The model was trained on
  prompts, not on database rows or source files. A code file with
  "ignore" in a comment, or a row of customer notes, could be flagged.
  Every false positive blocks a whole output (ADR-006). **Likelihood: high.
  Impact: high** (the normal pass rate collapses). → Spike 4.
- **The proxy isn't transparent.** Structured content, `is_error`, `_meta`
  or `list_changed` could be lost or changed between the upstream and the
  agent. The protocol version negotiated with Inspect's client could also
  differ from the one negotiated with the upstream. **Likelihood: medium.
  Impact: high** (the harness numbers through the gateway would mean
  nothing). → Spike 1.
- **The model is too slow on CPU.** It's a 738 MB model, with several
  512-token windows per large output. **Likelihood: medium. Impact:
  medium** (latency grows, but correctness doesn't suffer). → Spike 3.
  Fallback: Prompt Guard 2 22M (gated; it needs Arthur's OK) or rules only.
- **The labelled set can't be built at $0.** The recorded tool calls might
  not replay against the local servers, for example if the pinned demo
  data differs from what the runs saw. **Likelihood: low–medium. Impact:
  medium.** → Spike 5.
- **The caller's identity can't reach the handlers.** The ASGI layer
  authenticates, but the low-level handlers might not see the result.
  **Likelihood: low. Impact: high** (no per-caller policy). → Spike 1.
- **Writing the audit log before every call adds latency.** **Likelihood:
  low. Impact: low.** → Spike 6.
- **SDK APIs move.** **Likelihood: high. Impact: low** with exact pins.

**Integration and process**

- **The model budget never arrives.** **Likelihood: medium. Impact:
  medium.** The $0 deliverables (detector precision and recall, the
  gullible-agent check, the overhead) still stand on their own, and the
  README says the real-model runs are pending.
- **The rules overfit the attacks we wrote.** **Likelihood: high. Impact:
  high** (an inflated recall is a false claim). → A split by template
  that is fixed before any rule is written (Phase 3). The test set is
  scored once per detector version.
- **Downloads are blocked or declined** (the model, the SDK packages).
  **Likelihood: medium. Impact: medium.** → Ask Arthur up front, with the
  name, source and size.
- **Over-claiming in public.** **Likelihood: medium. Impact: high** for a
  security project. → Every number is stated with its suite, its model and
  its limits, and "blocks X% on this suite" is never written as "blocks
  injection".

## Pre-mortem

*"It's a month from now and the project failed. Why?"*
1. The detector blocked a third of normal outputs. The gateway "worked",
   but it was unusable, and that was found only at the end. → Spike 4 runs
   first.
2. The harness numbers through the gateway differed from direct runs for a
   reason unrelated to security (a lost field), and nobody noticed. → The
   `direct` vs `gateway-off` comparison is a required check, not optional.
3. The README claimed protection the measurement didn't support. → Claims
   are written from the results, after the runs.

## Spikes (time-boxed, throwaway, all $0)

| # | Question | How | Pass if | Time box |
|---|---|---|---|---|
| 1 | Is the proxy transparent, and can the caller's identity reach the handlers? | A low-level `Server` route forwarding to MCP-backbone (local, pinned data) and to the filesystem server, behind a bare ASGI key check. Compare `tools/list` and every recorded call's result, direct vs through the proxy, as JSON | Tool lists identical; results identical (content, structured content, `is_error`, `_meta`); handler logs the right caller id | 2 h |
| 2 | Does the harness run through the gateway unchanged? | A `gateway` target in the harness, and a `mockllm` scripted trial that calls tools through the Spike 1 proxy | The trial runs, its tool calls are recorded and graded, and the target swap needs no suite change | 1 h |
| 3 | Is the model fast enough on CPU? | Download the ProtectAI ONNX model *(needs Arthur's OK: 738 MB, from Hugging Face)*. Time load, then p50 and p95 per 512-token window on 200 benign outputs | p95 < 100 ms per window on Arthur's laptop; load < 10 s | 1 h |
| 4 | Does the model flag normal tool outputs? | Score the Spike 5 benign outputs at the default threshold and at three others | False positives ≤ 5% at a threshold that still catches most of the dev injections. **Kill:** if no threshold gives FP ≤ 20% with recall ≥ 50%, the model layer is dropped (rules only) | 1 h |
| 5 | Can the labelled set be built from recorded runs? | Replay the tool calls in the harness's published runs against local MCP-backbone (pinned data) and the filesystem fixtures; count outputs and failures | ≥ 90% of recorded calls replay to a full output | 1 h |
| 6 | What does the audit log cost? | Time 1,000 forwarded calls with flush only, and with `fsync` per line | Overhead p95 < 5 ms with flush; the `fsync` cost recorded for ADR-007 | 30 min |

Order: 1 → 5 → 4 → 3 → 2 → 6. The transparency check comes first because
nothing else means anything without it. Spike 4 runs before the build
because it can kill the model layer.

## Walking skeleton

The thinnest end-to-end path, before any feature is deep:
- `serve` with one route (filesystem, stdio), one key, a one-tool
  allow-list, and an audit log with the hash chain;
- a detector that is a stub (always clean) behind the real interface;
- the harness's scripted `mockllm` trial runs through it, and the audit
  log verifies;
- CI runs ruff, pyright, pytest and the skeleton trial, with no network and
  no model.

Then the slices in Phase 7 deepen each part: auth, policy, detection, the
evaluation and the measurement.

## Spike results

*(Filled in as the spikes run.)*

### Spike 1 result: PASS — the proxy is transparent at the same protocol version (2026-10-26)

`spikes/s1_transparency.py`: a low-level `Server` route per upstream,
forwarding through an SDK client session, behind a bare ASGI Bearer check.
It was run against the local MCP-backbone (repro stack) and the pinned
filesystem server, replaying 60 distinct recorded tool calls per upstream
from the harness's runs. No model calls.

- **Auth:** a wrong key → HTTP 401, and no handler ran.
- **Identity:** the handler read the caller set by the ASGI layer
  (`ctx.request.state`) on all 180 calls, so ADR-003 works as designed.
- **MCP-backbone:** tool list identical (4 tools); 60/60 results identical.
- **Filesystem, agent side in legacy mode** (the same protocol version as
  the server): tool list identical (14 tools); 60/60 results identical.
  Both are raw JSON, with nothing stripped.
- **Filesystem, agent side at 2026-07-28** (Inspect's default), with the
  server still on 2025-11-25: results identical apart from the
  per-connection `_meta["io.modelcontextprotocol/serverInfo"]` stamp the
  SDK adds. The tool lists lose `execution: {"taskSupport": "forbidden"}`:
  - that field exists only in the 2025-11-25 types (`mcp_types/_v2025_11_25`);
  - its own docstring says "Absent means 'forbidden'";
  - so the SDK translated between versions, and the proxy lost nothing.

**What this changes:**
- "Transparent" is defined as identical JSON at the same protocol version.
  Across versions, the SDK's own translation is expected, and the
  transparency test (slice D) checks both.
- The stamp names the gateway, which is honest: the gateway is the server
  on that connection.
- Shutdown printed `ASGI callable returned without completing response`:
  sessions were still closing after the spike's server stopped. The real
  `serve` must close sessions before the upstream clients (slice A).

### Spike 5 result: PASS — the benign set builds from recorded runs at $0 (2026-10-26)

`spikes/s5_replay.py` replays every distinct recorded tool call from the
harness's runs, direct to the local MCP-backbone and the pinned filesystem
server, and writes the outputs to `eval/benign/outputs.jsonl`
(1,982 outputs, 1.2 MB). No model calls.

- **1,982 / 1,982 replayed to an output (100%):**
  - Pagila: 867 calls, 851 ok and 16 error results;
  - filesystem: 1,115 calls, 716 ok and 399 error results.
- **The first run found a replay artefact.** 511 filesystem calls failed
  with "path outside allowed directories", because each recorded trial
  used its own temporary copy of the fixture and the absolute paths named
  it. The prefixes are now rebased to the replay's copy, which also merged
  321 calls that only differed by that prefix.
- **The remaining error results are genuine:** 1,112 of the 1,115
  filesystem outputs have the same error status as in the original runs.
  Most are agents guessing file names that don't exist. They stay in the
  benign set, because a gateway sees error outputs too.
- **Size:** median 137 characters, p95 about 2,100, max 17,065. Most
  outputs fit in one 512-token window, and the largest needs about ten.
- **The local server's key appears nowhere in the set** (checked by
  script, without printing it).

**What this changes:**
- Spike 4 has 1,982 real benign outputs to score.
- The set is small next to the injected side's needs. The injected half
  is built from these outputs with planted templates (Phase 4), so it has
  the same mix of sources.

### Spikes 3 and 4, first run (2026-10-26): Spike 3 FAIL, Spike 4 KILL as drafted

`spikes/s34_model.py`, ProtectAI v2 (ONNX, revision `90c9989b1a34`), Apple
M2 CPU. 1,977 benign outputs; 540 dev injections (6 dev families × 3
templates × 30 benign hosts, planted at the start, middle or end). The test
families were not loaded.

- **Spike 3:**
  - load 1.4 s;
  - per 512-token window: p50 32 ms, **p95 416 ms** (target < 100 ms);
  - **FAIL.**
- **Spike 4** (false positives on benign outputs / dev recall):

  | Threshold | False positives | Dev recall |
  |---|---|---|
  | 0.5 | 53.9% | 77.6% |
  | 0.9 | 49.5% | 72.8% |
  | 0.99 | 33.1% | 59.3% |
  | 0.999 | 8.3% | 40.7% |
  | 0.9999 | 1.4% | 32.2% |

  No threshold meets FP ≤ 5% with most injections caught. None even meets
  the kill line (FP ≤ 20% with recall ≥ 50%): **KILL as drafted.**
- **What it flags:** Pagila query results score 1.0, even
  `{"status": "succeeded", "rows": [{"not_returned": 241}]}`. The model,
  trained on prompts, reacts to the JSON envelope, not to instructions.
- **The script's first verdict line said "PASS".** That was a bug: it
  checked only the false-positive rate, not recall. It is fixed, and the
  verdict above follows the criterion as written.

**One variant, declared here before it runs:**
- *Variant B* scores only a JSON output's string values (each on its own
  line), leaving out keys, numbers and punctuation. Non-JSON text is scored
  as it is. Same thresholds, same samples, same criteria.
- If Variant B also fails the kill line, the model layer is dropped (rules
  only, the Phase 1 fallback). No further variants are tried in v1.
- **Correction, found while implementing and before running.** The first
  run pasted injections into JSON outputs as raw text, which breaks the
  JSON, so its recall was inflated by the same JSON effect that causes the
  false positives. The rerun therefore:
  - plants each injection inside a string value when the host is JSON (the
    first, middle or last string, or a new `note` field when there is
    none), and as text otherwise;
  - scores both raw and Variant B on the same samples, so the comparison
    is like for like.

### Spike 4 rerun (2026-10-26): Variant B keeps the model layer, below target

The same 1,977 benign outputs and 540 dev injections, now planted
realistically. Raw and Variant B were scored on identical samples.

| Threshold | Raw: FP | Raw: dev recall | B: FP | B: dev recall |
|---|---|---|---|---|
| 0.5 | 53.9% | 81.5% | 25.7% | 77.0% |
| 0.9 | 49.5% | 77.0% | 21.7% | 73.7% |
| 0.99 | 33.1% | 64.1% | **10.9%** | **65.2%** |
| 0.999 | 8.3% | 44.1% | 0.9% | 48.1% |
| 0.9999 | 1.4% | 35.2% | 0.1% | 40.6% |

- **Raw: KILL.** No threshold has FP ≤ 20% with recall ≥ 50%.
- **Variant B: model layer kept, below target.**
  - At 0.99 it clears the kill line (10.9% FP, 65.2% recall), but no
    threshold meets the target (FP ≤ 5% with most injections caught).
  - At 0.999 it comes closest: 0.9% FP and 48.1% recall.
- **What B still flags:**
  - error messages that read like instructions ("Access denied - path
    outside allowed directories…", "ENOENT: no such file…");
  - a few schema-description query results.
- **Weakest dev families at 0.5:** exfiltration 58% and fake-completion
  58%. Override (93%) and hidden markup (89%) are the strongest.
- **The fixture's planted note** (5 real outputs): four score ≥ 0.9. The
  fifth scores 0.003: the note is inside a long multi-file read, so the
  model misses it even though it's in a scanned window.

**Spike 3 stays a FAIL** (p95 416 ms per window). Most windows are short
(p50 32 ms); full 512-token windows are slow on this CPU.

**What this changes (ADR-005, to be updated in slice E):**
- The model layer scores JSON string values only (Variant B).
- Its threshold is chosen on dev in slice E, between 0.99 and 0.999, for
  the trade-off stated in the README.
- Rules carry the families the model is weak on.
- The fallback to rules only stays open, because the target wasn't met.
- Latency needs a decision from Arthur (see the flags in the handover):
  - (a) int8 quantisation, which must be re-validated on dev;
  - (b) Prompt Guard 2 22M, which is gated and needs his licence
    acceptance;
  - (c) accept the latency and cap the windows per output.

