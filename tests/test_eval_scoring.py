"""The evaluation code behind the published detector numbers (mutation triage,
2026-10-27): mutmut found the scorer itself had no test at all, and the
split assignment wasn't pinned, so a change could silently reshuffle the
published test set."""

import hashlib
import json
from pathlib import Path

import pytest

from mcp_gateway.detect import DetectorVerdict
from mcp_gateway.eval.score import HOSTS_PER_TEMPLATE, Sample, load_samples, plant, record_test_score, score
from mcp_gateway.eval.split import benign_split

pytestmark = pytest.mark.anyio

ROOT = Path(__file__).resolve().parents[1]


class FlagsBad:
    """Flags any text containing BAD; explodes on BOOM."""

    version = "flags-bad"

    async def scan(self, text: str) -> DetectorVerdict:
        if "BOOM" in text:
            raise RuntimeError("detector bug")
        return DetectorVerdict(suspicious="BAD" in text, score=1.0, layer="test")


async def test_score_computes_the_published_rates() -> None:
    samples = [
        Sample("fine", False, "benign", "s"),
        Sample("BAD but benign", False, "benign", "s"),
        Sample("fine too", False, "benign", "s"),
        Sample("fine again", False, "benign", "s"),
        Sample("BAD injection", True, "override", "s"),
        Sample("BAD injection two", True, "override", "s"),
        Sample("quiet injection", True, "conditional", "s"),
    ]
    result = await score(FlagsBad(), samples, "dev")
    assert (result.detector, result.split, result.benign, result.injected) == ("flags-bad", "dev", 4, 3)
    assert result.false_positive_rate == pytest.approx(1 / 4)
    assert result.recall == pytest.approx(2 / 3)
    assert result.precision == pytest.approx(2 / 3)
    assert result.recall_by_family == {"conditional": 0.0, "override": 1.0}
    assert result.false_positive_examples == ["BAD but benign"]
    assert result.errors == 0
    assert 0 <= result.ms_p50 <= result.ms_p95


async def test_a_detector_failure_counts_as_flagged_and_as_an_error() -> None:
    """The gateway blocks an output whose scan fails, so the score must too."""
    samples = [Sample("BOOM benign", False, "benign", "s"), Sample("BOOM injected", True, "override", "s")]
    result = await score(FlagsBad(), samples, "test")
    assert result.errors == 2
    assert result.false_positive_rate == 1.0 and result.recall == 1.0


async def test_empty_sides_score_zero_rather_than_crash() -> None:
    result = await score(FlagsBad(), [], "dev")
    assert (result.false_positive_rate, result.recall, result.precision, result.ms_p50) == (0.0, 0.0, 0.0, 0.0)


def strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [s for v in value for s in strings(v)]
    if isinstance(value, dict):
        return [s for v in value.values() for s in strings(v)]
    return []


@pytest.mark.parametrize(("position", "slot"), [("start", "a"), ("middle", "c"), ("end", "d")])
def test_plant_goes_inside_a_json_string_value(position: str, slot: str) -> None:
    host = json.dumps({"a": "x", "n": 1, "b": {"c": "y"}, "d": "z"})
    planted = json.loads(plant(host, "INJ", position))
    found = {k: v for k, v in {"a": planted["a"], "c": planted["b"]["c"], "d": planted["d"]}.items() if "INJ" in v}
    assert list(found) == [slot]
    assert found[slot].endswith(" INJ") and planted["n"] == 1


def test_plant_adds_a_note_when_json_has_no_strings() -> None:
    assert json.loads(plant(json.dumps({"n": 1}), "INJ", "start")) == {"n": 1, "note": "INJ"}
    assert json.loads(plant(json.dumps([{"n": 1}, {"n": 2}]), "INJ", "end"))[0] == {"n": 1, "note": "INJ"}


def test_plant_falls_back_to_text_for_json_it_cant_hold() -> None:
    assert plant("[1, 2]", "INJ", "start") == "INJ\n[1, 2]"


@pytest.mark.parametrize(
    ("position", "expected"),
    [
        ("start", "INJ\nline one\nline two\nline three"),
        ("end", "line one\nline two\nline three\nINJ"),
        ("middle", "line one\nINJ\n\nline two\nline three"),
    ],
)
def test_plant_in_text(position: str, expected: str) -> None:
    assert plant("line one\nline two\nline three", "INJ", position) == expected


def test_plant_in_text_without_line_breaks_splits_at_the_middle() -> None:
    assert plant("abcdef", "INJ", "middle") == "abc\nINJ\ndef"


def test_load_samples_builds_each_split_from_its_own_parts() -> None:
    rows = [json.loads(line) for line in (ROOT / "eval/benign/outputs.jsonl").read_text().splitlines()]
    spec = json.loads((ROOT / "eval/injections/templates.json").read_text())
    for split in ("dev", "test"):
        samples = load_samples(ROOT, split)
        benign = [r for r in rows if r["label"] == "benign" and benign_split(r["text"]) == split]
        natural = [r for r in rows if r["label"] == "injected" and benign_split(r["text"]) == split]
        templates = [t for t in spec["templates"] if t["family"] in spec["split"][split]]
        assert sum(not s.injected for s in samples) == len(benign)
        assert sum(s.family == "fixture-f17" for s in samples) == len(natural)
        planted = [s for s in samples if s.injected and s.family != "fixture-f17"]
        assert len(planted) == len(templates) * HOSTS_PER_TEMPLATE
        assert {s.family for s in planted} == set(spec["split"][split])
        assert all("CANARY-" in s.text for s in planted)


def test_the_published_split_is_pinned() -> None:
    """The test set behind the published numbers. Any change to the split
    function, or to the benign set, moves these and must be deliberate."""
    rows = [json.loads(line) for line in (ROOT / "eval/benign/outputs.jsonl").read_text().splitlines()]
    benign = [r for r in rows if r["label"] == "benign"]
    assert sum(benign_split(r["text"]) == "dev" for r in benign) == 858
    assert sum(benign_split(r["text"]) == "test" for r in benign) == 1119
    assert benign_split("hello") == ("dev" if int(hashlib.sha256(b"hello").hexdigest(), 16) % 2 == 0 else "test")


def test_record_test_score_writes_the_named_file(tmp_path: Path) -> None:
    from mcp_gateway.eval.score import Score

    result = Score("rules-abc", "test", 1, 2, 0.0, 0.5, 1.0, {"x": 0.5}, 0.1, 0.2, errors=1)
    path = record_test_score(tmp_path, result)
    assert path == tmp_path / "eval" / "results" / "rules-abc.json"
    saved = json.loads(path.read_text())
    assert saved["detector"] == "rules-abc" and saved["recall"] == 0.5 and saved["errors"] == 1
