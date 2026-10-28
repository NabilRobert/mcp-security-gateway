# What the gateway adds to a tool call ($0, 2026-10-28)

`scripts/measure_overhead.py` replays 60 recorded tool calls per upstream,
direct and through the gateway, interleaved call by call (1 warm-up round,
3 measured rounds, so 180 timed calls per cell). Everything is local on an
Apple M2 (no network hop), and the audit log runs with `fsync` on. The
script refuses to report if the upstream rate-limited any call: MCP-backbone
allows 2,000 queries per workspace per hour, and an earlier run that used
it up was discarded. Raw numbers are in `summary.json`.

| Gateway configuration | Pagila (HTTP→HTTP): added p50 / p95 | Filesystem (stdio→HTTP): added p50 / p95 | Calls blocked because the detector timed out |
|---|---|---|---|
| Detection off (the proxy alone) | 8.4 / 15.0 ms | 2.7 / 2.9 ms | 0 |
| Rules | 8.9 / 15.0 ms | 2.7 / 4.2 ms | 0 |
| Rules + model (fp32, 0.999, 2 s timeout, scan `s2`) | 18 / 1,078 ms | 87 / 2,020 ms | Pagila 2 of 240; filesystem 35 of 240 |

**The proxy itself costs a few milliseconds.** Auth, policy, the
hash-chained audit with `fsync`, and the rules add a median of about
3–9 ms per call. The filesystem figure also includes the agent speaking
HTTP to the gateway instead of stdio to the server.

**The model layer, before and after the fix** (scan `s1` → `s2`; filesystem
calls blocked by timeouts):

| Scan | Added p50 | Blocked by timeouts |
|---|---|---|
| `s1` | 567 ms | 85 of 240 (an earlier run: 121) |
| `s2` | 87 ms | 35 of 240 |

The `s1` scan had two faults:
1. It scanned the filesystem server's text twice, once as text and again as
   the structured content that repeats it.
2. A timed-out scan kept running and slowed the scans after it, until calls
   piled up at the timeout.

`s2` scans repeated text once, runs one scan at a time, and stops a
timed-out scan (onnxruntime's `RunOptions.terminate`).

**What's left:** the remaining timeouts are outputs so large that the
full-precision model genuinely needs more than 2 s on this CPU. These 60
replayed calls lean towards large outputs (directory trees, multi-file
reads). The false-positive rate over the whole held-out benign set, through
the gateway, is in [`../gateway-fp/`](../gateway-fp/README.md).

The 8 filesystem blocks under "rules" are correct: the fixture's planted
note (harness task f17), read once per round.
