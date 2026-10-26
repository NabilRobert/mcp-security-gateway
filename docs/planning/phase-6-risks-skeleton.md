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
