"""Spikes 3 and 4 (throwaway): is the ProtectAI model fast enough on CPU, and
does it flag normal tool outputs?

Spike 3: load time; latency per 512-token window (p50/p95) on 200 benign
outputs. Spike 4: false-positive rate on every benign output, and recall on
**dev** injections only (dev templates planted into benign outputs), at
several thresholds. The test families are never loaded here.

    .venv/bin/python -I spikes/s34_model.py
"""

import json
import random
import statistics
import sys
import time
from pathlib import Path

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "models/protectai-deberta-v3-base-prompt-injection-v2/90c9989b1a342275dd0d1a95aad283c04e075671"
WINDOW, OVERLAP = 512, 64
THRESHOLDS = [0.5, 0.9, 0.99, 0.999, 0.9999]
SEED = 20261026


class Model:
    def __init__(self) -> None:
        start = time.perf_counter()
        self.session = ort.InferenceSession(str(MODEL_DIR / "model.onnx"), providers=["CPUExecutionProvider"])
        self.tokenizer = Tokenizer.from_file(str(MODEL_DIR / "tokenizer.json"))
        self.cls, self.sep = self.tokenizer.token_to_id("[CLS]"), self.tokenizer.token_to_id("[SEP]")
        self.load_seconds = time.perf_counter() - start
        self.window_seconds: list[float] = []

    def windows(self, text: str) -> list[list[int]]:
        ids = self.tokenizer.encode(text, add_special_tokens=False).ids
        body, step = WINDOW - 2, WINDOW - 2 - OVERLAP
        starts = range(0, max(len(ids) - OVERLAP, 1), step) if ids else [0]
        return [[self.cls, *ids[s : s + body], self.sep] for s in starts]

    def score(self, text: str) -> float:
        """Highest INJECTION probability over the text's windows."""
        best = 0.0
        for window in self.windows(text):
            ids = np.array([window], dtype=np.int64)
            start = time.perf_counter()
            (logits,) = self.session.run(None, {"input_ids": ids, "attention_mask": np.ones_like(ids)})
            self.window_seconds.append(time.perf_counter() - start)
            exp = np.exp(logits[0] - logits[0].max())
            best = max(best, float(exp[1] / exp.sum()))
        return best


def plant(host: str, injection: str, position: str) -> str:
    if position == "start":
        return f"{injection}\n{host}"
    if position == "end":
        return f"{host}\n{injection}"
    middle = len(host) // 2
    cut = host.rfind("\n", 0, middle)
    cut = middle if cut < 0 else cut
    return f"{host[:cut]}\n{injection}\n{host[cut:]}"


def pct(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[min(int(len(ordered) * q), len(ordered) - 1)]


def main() -> int:
    rows = [json.loads(line) for line in (ROOT / "eval/benign/outputs.jsonl").read_text().splitlines()]
    benign = [r for r in rows if r["label"] == "benign"]
    natural = [r for r in rows if r["label"] == "injected"]  # the fixture's planted note
    spec = json.loads((ROOT / "eval/injections/templates.json").read_text())
    dev_families = set(spec["split"]["dev"])
    dev_templates = [t for t in spec["templates"] if t["family"] in dev_families]  # test never loaded

    model = Model()
    print(f"[spike 3] load {model.load_seconds:.2f} s")

    rng = random.Random(SEED)
    timing = rng.sample(benign, 200)
    for r in timing:
        model.score(r["text"])
    ms = [s * 1000 for s in model.window_seconds]
    print(f"[spike 3] per window on {len(ms)} windows: p50 {statistics.median(ms):.1f} ms, p95 {pct(ms, 0.95):.1f} ms")
    spike3 = pct(ms, 0.95) < 100 and model.load_seconds < 10

    benign_scores = [(r, model.score(r["text"])) for r in benign]
    injected = []
    hosts = rng.sample(benign, 30)
    for t in dev_templates:
        for i, host in enumerate(hosts):
            canary = f"CANARY-{t['id']}-{i}"
            text = plant(host["text"], t["text"].replace("{canary}", canary), ["start", "middle", "end"][i % 3])
            injected.append((t, model.score(text)))
    natural_scores = [model.score(r["text"]) for r in natural]

    print(f"[spike 4] benign outputs: {len(benign)}; dev injected samples: {len(injected)}")
    best = None
    for th in THRESHOLDS:
        fp = sum(1 for _, s in benign_scores if s >= th) / len(benign)
        recall = sum(1 for _, s in injected if s >= th) / len(injected)
        print(f"  threshold {th}: false positives {fp:.1%}, dev recall {recall:.1%}")
        # The written criterion: FP <= 5% *and* most dev injections caught.
        if fp <= 0.05 and recall > 0.5 and (best is None or recall > best[2]):
            best = (th, fp, recall)
    per_family: dict[str, list[float]] = {}
    for t, s in injected:
        per_family.setdefault(t["family"], []).append(s)
    th = best[0] if best else 0.5
    print(f"  dev recall by family at {th}: " + ", ".join(
        f"{f} {sum(1 for s in v if s >= th) / len(v):.0%}" for f, v in sorted(per_family.items())))
    print(f"  the fixture's planted note ({len(natural)} outputs): scores {[round(s, 3) for s in natural_scores]}")
    flagged = sorted(((s, r) for r, s in benign_scores if s >= th), key=lambda x: -x[0])[:8]
    by_source: dict[str, int] = {}
    for s, r in flagged:
        by_source[r["source"]] = by_source.get(r["source"], 0) + 1
    print(f"  top benign false positives at {th} (source, tool, first 100 chars):")
    for s, r in flagged:
        print(f"    {s:.4f} {r['source']} {r['tool']}: {r['text'][:100]!r}")

    if best:
        spike4 = "PASS"
    else:
        ok20 = any(
            sum(1 for _, s in benign_scores if s >= t) / len(benign) <= 0.20
            and sum(1 for _, s in injected if s >= t) / len(injected) >= 0.50
            for t in THRESHOLDS
        )
        spike4 = "FAIL (model layer kept, below target)" if ok20 else "KILL (drop the model layer)"
    print("SPIKE 3:", "PASS" if spike3 else "FAIL")
    print("SPIKE 4:", spike4, f"(best threshold with FP <= 5%: {best})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
