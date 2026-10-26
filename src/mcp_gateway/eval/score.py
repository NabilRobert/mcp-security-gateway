"""Score detectors on the labelled set, one split at a time.

Samples for a split:
- benign: the replayed outputs in that split (eval/benign/outputs.jsonl);
- injected: every template of that split's families, planted into 30
  benign hosts from the same split (start, middle or end; inside a JSON
  string value when the host is JSON, as a real row would carry it), plus
  the fixture's real planted note where it falls in the split.

`test` is scored once per detector version: the result is written to
eval/results/ and a second run for the same version is refused.
"""

import json
import random
import statistics
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, cast

from mcp_gateway.detect import Detector
from mcp_gateway.eval.split import Split, benign_split

SEED = 20261027
HOSTS_PER_TEMPLATE = 30
POSITIONS = ("start", "middle", "end")


@dataclass(frozen=True)
class Sample:
    text: str
    injected: bool
    family: str  # "benign", a template family, or "fixture-f17"
    source: str


@dataclass
class Score:
    detector: str
    split: str
    benign: int
    injected: int
    false_positive_rate: float
    recall: float
    precision: float
    recall_by_family: dict[str, float]
    ms_p50: float
    ms_p95: float
    false_positive_examples: list[str] = field(default_factory=list[str])
    # Scans that failed or timed out. The gateway blocks those outputs (fail
    # closed), so they count as flagged here too.
    errors: int = 0


def load_samples(root: Path, split: Split) -> list[Sample]:
    rows = [json.loads(line) for line in (root / "eval/benign/outputs.jsonl").read_text().splitlines()]
    spec = json.loads((root / "eval/injections/templates.json").read_text())
    families = set(spec["split"][split])
    benign = [r for r in rows if r["label"] == "benign" and benign_split(r["text"]) == split]
    samples = [Sample(r["text"], False, "benign", r["source"]) for r in benign]
    samples += [
        Sample(r["text"], True, "fixture-f17", r["source"])
        for r in rows
        if r["label"] == "injected" and benign_split(r["text"]) == split
    ]
    rng = random.Random(SEED)  # noqa: S311 (sampling hosts, not security)
    hosts = rng.sample(benign, HOSTS_PER_TEMPLATE)
    for template in (t for t in spec["templates"] if t["family"] in families):
        for i, host in enumerate(hosts):
            injection = template["text"].replace("{canary}", f"CANARY-{template['id']}-{i}")
            samples.append(
                Sample(plant(host["text"], injection, POSITIONS[i % 3]), True, template["family"], host["source"])
            )
    return samples


def plant(host: str, injection: str, position: str) -> str:
    """Inside a JSON string value when the host is JSON, else as text."""
    try:
        data: Any = json.loads(host)
    except ValueError:
        return _plant_text(host, injection, position)
    slots: list[tuple[Any, Any]] = []

    def walk(node: Any) -> None:
        container: Any = node
        items: list[tuple[Any, Any]] = []
        if isinstance(node, dict):
            items = list(cast(dict[str, Any], node).items())
        elif isinstance(node, list):
            items = list(enumerate(cast(list[Any], node)))
        for key, value in items:
            if isinstance(value, str):
                slots.append((container, key))
            else:
                walk(value)

    walk(data)
    if slots:
        container, key = slots[{"start": 0, "middle": len(slots) // 2, "end": -1}[position]]
        container[key] = f"{container[key]} {injection}"
    elif isinstance(data, dict):
        cast(dict[str, Any], data)["note"] = injection
    elif isinstance(data, list) and data and isinstance(data[0], dict):
        cast(dict[str, Any], data[0])["note"] = injection
    else:
        return _plant_text(host, injection, position)
    return json.dumps(data, indent=2, ensure_ascii=False)


def _plant_text(host: str, injection: str, position: str) -> str:
    if position == "start":
        return f"{injection}\n{host}"
    if position == "end":
        return f"{host}\n{injection}"
    middle = len(host) // 2
    cut = host.rfind("\n", 0, middle)
    cut = middle if cut < 0 else cut
    return f"{host[:cut]}\n{injection}\n{host[cut:]}"


async def score(detector: Detector, samples: Sequence[Sample], split: str) -> Score:
    flagged: list[tuple[Sample, bool]] = []
    times: list[float] = []
    errors = 0
    for sample in samples:
        start = time.perf_counter()
        try:
            suspicious = (await detector.scan(sample.text)).suspicious
        except Exception:
            suspicious, errors = True, errors + 1
        flagged.append((sample, suspicious))
        times.append((time.perf_counter() - start) * 1000)
    benign = [hit for s, hit in flagged if not s.injected]
    injected = [hit for s, hit in flagged if s.injected]
    true_pos, false_pos = sum(injected), sum(benign)
    by_family: dict[str, list[bool]] = {}
    for s, hit in flagged:
        if s.injected:
            by_family.setdefault(s.family, []).append(hit)
    ordered = sorted(times)
    return Score(
        detector=detector.version,
        split=split,
        benign=len(benign),
        injected=len(injected),
        false_positive_rate=false_pos / len(benign) if benign else 0.0,
        recall=true_pos / len(injected) if injected else 0.0,
        precision=true_pos / (true_pos + false_pos) if true_pos + false_pos else 0.0,
        recall_by_family={f: sum(v) / len(v) for f, v in sorted(by_family.items())},
        ms_p50=statistics.median(ordered) if ordered else 0.0,
        ms_p95=ordered[min(int(len(ordered) * 0.95), len(ordered) - 1)] if ordered else 0.0,
        false_positive_examples=[s.text[:120] for s, hit in flagged if hit and not s.injected][:5],
        errors=errors,
    )


def record_test_score(root: Path, result: Score) -> Path:
    """Write a test-split score; refuse if this detector version already has one."""
    path = root / "eval" / "results" / f"{result.detector}.json"
    if path.exists():
        raise FileExistsError(f"{result.detector} was already scored on test ({path}); a new version is needed")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(result), indent=2, ensure_ascii=False) + "\n")
    return path
