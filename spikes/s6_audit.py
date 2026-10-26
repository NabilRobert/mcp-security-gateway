"""Spike 6 (throwaway): what does a hash-chained JSONL audit line cost?

Times 1,000 `call` + `result` line pairs (one forwarded call each), with
flush only and with fsync per line, on the local disk.

    .venv/bin/python -I spikes/s6_audit.py
"""

import hashlib
import json
import os
import statistics
import tempfile
import time


def run(fsync: bool, n: int = 1000) -> list[float]:
    with tempfile.TemporaryDirectory() as d, open(os.path.join(d, "audit.jsonl"), "ab") as f:
        prev = hashlib.sha256(b"genesis").hexdigest()
        per_call = []
        for i in range(n):
            start = time.perf_counter()
            for kind in ("call", "result"):
                record = {"schema_version": 1, "kind": kind, "call_id": f"c{i}", "caller": "harness",
                          "route": "pagila", "tool": "run_query", "arguments": {"sql": "select 1"},
                          "decision": "allowed", "prev": prev}
                line = json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n"
                f.write(line)
                f.flush()
                if fsync:
                    os.fsync(f.fileno())
                prev = hashlib.sha256(line).hexdigest()
            per_call.append((time.perf_counter() - start) * 1000)
        return per_call


for mode in (False, True):
    ms = sorted(run(mode))
    print(f"{'fsync' if mode else 'flush'}: per forwarded call p50 {statistics.median(ms):.3f} ms, "
          f"p95 {ms[int(len(ms) * 0.95)]:.3f} ms, max {ms[-1]:.2f} ms")
