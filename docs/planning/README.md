# Planning trail

Written before and during the build, in order. Each phase builds on the
previous one and is reviewed before the next starts. They're kept as they
were written, as a record of what was planned and why.

| Phase | What it settles |
|---|---|
| [1. Problem brief](phase-1-problem-brief.md) | The problem, who it's for, success metrics, non-goals |
| [2. Requirements and constraints](phase-2-requirements-constraints.md) | Scenarios, edge cases, must / should / could, constraints |
| [3. Domain model](phase-3-domain-model.md) | Entities and how they relate |
| [4. Flows and failures](phase-4-flows-failures.md) | The request flow and what happens when each step fails |
| [5. Architecture and decisions](../adr/README.md) | The ADRs: each decision, its alternatives, consequences and sources |
| [6. Risks and skeleton](phase-6-risks-skeleton.md) | The riskiest assumptions, tested with spikes before building |
| [7. Slices and plan](phase-7-slices-plan.md) | The work cut into vertical slices, with a fallback decided in advance |

The architecture decisions (Phase 5) live in [`docs/adr/`](../adr/README.md),
one file per ADR.

## Spikes

Each spike was declared, with its pass criteria, in Phase 6 before it ran,
and its result was recorded there. The spike code has left main; the
write-ups link to it on GitHub.

| Spike | Question | Result |
|---|---|---|
| [Spike 1](phase-6-risks-skeleton.md#spike-1-result-pass--the-proxy-is-transparent-at-the-same-protocol-version-2026-10-26) | Is a proxy on the low-level `Server` transparent? | PASS — the proxy is transparent at the same protocol version |
| [Spike 2](phase-6-risks-skeleton.md#spike-2-result-pass--the-harness-runs-through-the-gateway-with-only-the-target-changed-2026-10-26) | Does the harness run through the gateway with only the target changed? | PASS — the harness runs through the gateway with only the target changed |
| [Spikes 3 and 4](phase-6-risks-skeleton.md#spikes-3-and-4-first-run-2026-10-26-spike-3-fail-spike-4-kill-as-drafted) | Is the model fast enough on CPU, and does it flag normal outputs? | Spike 3 FAIL, Spike 4 KILL as drafted |
| [Spike 4 rerun](phase-6-risks-skeleton.md#spike-4-rerun-2026-10-26-variant-b-keeps-the-model-layer-below-target) | Variant B: reading only the string values of JSON | The model layer stays, below target |
| [Spike 5](phase-6-risks-skeleton.md#spike-5-result-pass--the-benign-set-builds-from-recorded-runs-at-0-2026-10-26) | Can the benign set be built from recorded runs at $0? | PASS — the benign set builds from recorded runs at $0 |
| [Spike 6](phase-6-risks-skeleton.md#spike-6-result-pass--the-audit-log-costs-microseconds-2026-10-26) | What does a hash-chained audit line cost? | PASS — the audit log costs microseconds |
| [Spike 7](phase-6-risks-skeleton.md#spike-7-result-fail-on-criterion-1-only--fastmcp-changes-every-tool-definition-2026-10-27) | Can FastMCP's proxy replace the hand-built one? | FAIL on criterion 1 only — FastMCP changes every tool definition |
| [Spike 3 follow-up](phase-6-risks-skeleton.md#spike-3-follow-up-int8-arthurs-choice-2026-10-27) | Does an int8 model keep its verdicts? | FAIL: int8 doesn't meet the acceptance rule; fp32 stays |
