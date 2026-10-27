# What the gateway adds to a tool call ($0, 2026-10-28)

`scripts/measure_overhead.py` replays 60 recorded tool calls per upstream,
direct and through the gateway, interleaved call by call (1 warm-up round,
3 measured rounds, so 180 timed calls per cell). Everything is local on an
Apple M2 (no network hop), and the audit log runs with `fsync` on. Raw
numbers are in `summary.json`.

| Gateway configuration | Pagila (HTTP→HTTP): added p50 / p95 | Filesystem (stdio→HTTP): added p50 / p95 | Calls blocked because the detector timed out |
|---|---|---|---|
| Detection off (the proxy alone) | 7.5 / 47.7 ms | 3.7 / 11.9 ms | 0 |
| Rules | 7.7 / 23.6 ms | 3.0 / 6.3 ms | 0 |
| Rules + model (fp32, 0.999, 2 s timeout) | 42 / 1,890 ms | 567 / 2,030 ms | Pagila 11 of 240; **filesystem 85 of 240** |

**The proxy itself costs a few milliseconds.**
- Auth, policy, the hash-chained audit with `fsync`, and the rules add a
  median of about 3–8 ms per call.
- The filesystem figure also includes the agent speaking HTTP to the
  gateway instead of stdio to the server.

**The model layer doesn't hold up inside the running gateway on this CPU.**
- With it on, 35% of filesystem calls (85/240) were blocked by detector
  timeouts. An earlier run of the same script gave 121/240.
- Those are blocks of normal outputs, so false positives. The offline
  test split's **1.2%** was measured outside the gateway, so it doesn't
  describe this path.
- **Two causes:**
  1. The gateway scans more text than the offline scorer did. It reads the
     text blocks *and* the string values of `structured_content`, and the
     filesystem server repeats the text in both, so every window is scanned
     twice.
  2. A scan abandoned at the timeout keeps running in its thread, so it
     competes with the next scans for the CPU, and calls pile up toward
     the timeout.
- The 8 filesystem blocks under "rules" are correct: the fixture's
  planted note (harness task f17), read once per round.

This is an open problem (see the main README's "Next"), not a tuning
detail.
