# False positives through the gateway ($0, 2026-10-28)

The offline test score reads stored output text. This measures the path the
gateway really takes: the live result (text plus structured content), a 2 s
timeout, and scans queued one at a time.

**How:**
- Every held-out (test-split) benign output, unique by text, had its
  recorded call replayed through the gateway to the real upstream.
- A call counts as blocked when the agent gets the gateway's "withheld"
  notice, whether the detector flagged it or timed out.
- The run is refused if the upstream rate-limited any call. None was.
- `scripts/measure_gateway_fp.py`; raw numbers in `summary.json`.

| Upstream | Benign outputs | Blocked | False-positive rate | Why blocked |
|---|---|---|---|---|
| Pagila (database) | 164 | 4 | 2.4% | 2 flagged by the detector, 2 timeouts |
| Filesystem | 241 | 6 | 2.5% | 6 timeouts |
| **All** | **405** | **10** | **2.5%** | |

Detector: rules + model (fp32, threshold 0.999, scan `s2`).

Offline, on the same split, the false-positive rate is 1.2%. **Through the
gateway it is about twice that,** almost all of the difference being large
outputs that time out on a laptop CPU.
