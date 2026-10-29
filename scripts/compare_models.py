"""Compare candidate model layers on the dev split, by the rule ProtectAI's
threshold was chosen with (ADR-005): the lowest of 0.99, 0.995 and 0.999
whose dev false-positive rate, rules + model, is at most 5%. $0: every
model runs locally.

Each model scans each dev sample once, as the gateway would (2 s timeout,
at most 16 windows). Its score is kept, so every threshold is read off the
same pass. A timed-out scan, or an output with too many windows, blocks the
output in the gateway, so it counts as flagged here at every threshold.
The model scans every sample, even ones the rules flag (in the gateway it
wouldn't), so its own recall is measured too: on dev the rules catch every
injection, having been written from it.

ProtectAI is scored again in the same run, as a check that this script
reproduces ADR-005's published dev numbers.

    .venv/bin/python -I scripts/compare_models.py [model ...]

Writes eval/results/model-comparison/summary.json. The test split is scored
separately, once per model at its chosen threshold, with `mcp-gateway
eval-detector --split test`; this script then copies each score it finds
into the summary.
"""

import asyncio
import json
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mcp_gateway.detect import LayeredDetector, ModelDetector, RulesDetector  # noqa: E402
from mcp_gateway.eval.score import Sample, load_samples  # noqa: E402

OUT = ROOT / "eval" / "results" / "model-comparison"
THRESHOLDS = (0.99, 0.995, 0.999)
# Prompt Guard 2's scores sit lower than ProtectAI's; 0.5 is Meta's
# documented default. Shown for comparison only: the choice uses THRESHOLDS.
REFERENCE_THRESHOLDS = (0.5, 0.9)
MAX_DEV_FALSE_POSITIVES = 0.05  # ADR-005's rule, fixed before ProtectAI was scored
TIMEOUT_S = 2.0  # the gateway's default
LATENCY_WINDOWS = 30  # full 512-token windows timed per model


def revision_dir(repo_folder: str) -> Path:
    [model_file] = (ROOT / "models" / repo_folder).glob("*/model.onnx")
    return model_file.parent


MODELS = {
    "protectai-v2": "protectai-deberta-v3-base-prompt-injection-v2",
    "prompt-guard-2-22m": "llama-prompt-guard-2-22m",
    "prompt-guard-2-86m": "llama-prompt-guard-2-86m",
}


@dataclass
class Scan:
    sample: Sample
    rules_flag: bool
    model_score: float | None  # None when the scan timed out
    blocked_anyway: bool  # timed out, or too many windows to scan
    ms: float


async def scan_all(model: ModelDetector, samples: list[Sample]) -> list[Scan]:
    rules = RulesDetector()
    scans: list[Scan] = []
    for sample in samples:
        rules_flag = (await rules.scan(sample.text)).suspicious
        start = time.perf_counter()
        try:
            verdict = await model.scan(sample.text)
        except TimeoutError:
            scans.append(Scan(sample, rules_flag, None, True, (time.perf_counter() - start) * 1000))
            continue
        too_many_windows = "too-many-windows" in verdict.matched
        ms = (time.perf_counter() - start) * 1000
        scans.append(Scan(sample, rules_flag, verdict.score, too_many_windows, ms))
    return scans


def is_flagged(scan: Scan, threshold: float, with_rules: bool) -> bool:
    if with_rules and scan.rules_flag:
        return True
    if scan.blocked_anyway:
        return True
    return scan.model_score is not None and scan.model_score >= threshold


def rates(scans: list[Scan], threshold: float, with_rules: bool) -> dict[str, float]:
    benign = [s for s in scans if not s.sample.injected]
    injected = [s for s in scans if s.sample.injected]
    false_positives = sum(is_flagged(s, threshold, with_rules) for s in benign)
    caught = sum(is_flagged(s, threshold, with_rules) for s in injected)
    return {
        "false_positive_rate": round(false_positives / len(benign), 4) if benign else 0.0,
        "recall": round(caught / len(injected), 4) if injected else 0.0,
    }


def chosen_threshold(scans: list[Scan]) -> float | None:
    for threshold in THRESHOLDS:
        if rates(scans, threshold, with_rules=True)["false_positive_rate"] <= MAX_DEV_FALSE_POSITIVES:
            return threshold
    return None


def window_latency_ms(model: ModelDetector) -> dict[str, float]:
    """Median and p95 of one full 512-token window, through the gateway's own scoring path."""
    import onnxruntime as ort  # pyright: ignore[reportMissingTypeStubs]

    text = "The weekly report lists every order, its customer and its status. " * 200
    [window] = model.windows(text)[:1]
    tokens = model.tokenizer.decode(window[1:-1])
    times: list[float] = []
    for _ in range(LATENCY_WINDOWS):
        start = time.perf_counter()
        model._score_sync(tokens, ort.RunOptions())  # pyright: ignore[reportPrivateUsage]
        times.append((time.perf_counter() - start) * 1000)
    return percentiles(times)


def test_score(directory: Path, threshold: float | None) -> dict[str, Any] | None:
    """The held-out score recorded for rules + this model at its chosen
    threshold, if it has been scored."""
    if threshold is None:
        return None
    detector = LayeredDetector([RulesDetector(), ModelDetector(directory, threshold=threshold, timeout_s=TIMEOUT_S)])
    recorded = ROOT / "eval" / "results" / f"{detector.version}.json"
    if not recorded.exists():
        return None
    score = json.loads(recorded.read_text())
    keep = ("detector", "benign", "injected", "false_positive_rate", "recall", "precision", "errors")
    return {key: score[key] for key in keep} | {"recall_by_family": score["recall_by_family"]}


def percentiles(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    return {"p50": round(statistics.median(values), 1), "p95": round(ordered[int(len(ordered) * 0.95) - 1], 1)}


async def measure(folder: str, samples: list[Sample]) -> dict[str, Any]:
    directory = revision_dir(folder)
    load_start = time.perf_counter()
    model = ModelDetector(directory, threshold=1.0, timeout_s=TIMEOUT_S)  # thresholds are applied to the scores
    load_s = time.perf_counter() - load_start
    scans = await scan_all(model, samples)
    return {
        "revision": directory.name,
        "onnx_mb": round((directory / "model.onnx").stat().st_size / 1e6),
        "load_s": round(load_s, 2),
        "blocked_by_timeout_or_size": sum(s.blocked_anyway for s in scans),
        "scan_ms": percentiles([s.ms for s in scans]),
        "window_ms": window_latency_ms(model),
        "thresholds": {
            str(t): {"model": rates(scans, t, with_rules=False), "rules_plus_model": rates(scans, t, with_rules=True)}
            for t in (*THRESHOLDS, *REFERENCE_THRESHOLDS)
        },
        "chosen_threshold": chosen_threshold(scans),
        "test": test_score(directory, chosen_threshold(scans)),
    }


async def main() -> int:
    """Measures the models named on the command line (all by default) and
    merges them into the summary, keeping the others' earlier results."""
    names = sys.argv[1:] or list(MODELS)
    samples = load_samples(ROOT, "dev")
    path = OUT / "summary.json"
    summary: dict[str, Any] = json.loads(path.read_text()) if path.exists() else {"models": {}}
    summary.update(
        split="dev",
        benign=sum(not s.injected for s in samples),
        injected=sum(s.injected for s in samples),
        rule=f"lowest of {THRESHOLDS} with rules + model dev FP <= {MAX_DEV_FALSE_POSITIVES:.0%}",
        reference_thresholds=f"{REFERENCE_THRESHOLDS}: reported for comparison, not used to choose",
        timeout_s=TIMEOUT_S,
    )
    for name in names:
        summary["models"][name] = await measure(MODELS[name], samples)
        print(name, json.dumps(summary["models"][name]))
    OUT.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
