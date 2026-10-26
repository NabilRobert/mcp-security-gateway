"""Detector interface. Slice A ships a stub that finds nothing; slice E adds
the rules and model layers behind the same interface (ADR-005)."""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class DetectorVerdict:
    suspicious: bool
    score: float
    layer: str
    matched: tuple[str, ...] = ()


class Detector(Protocol):
    version: str

    async def scan(self, text: str) -> DetectorVerdict: ...


class StubDetector:
    version = "stub-0"

    async def scan(self, text: str) -> DetectorVerdict:  # noqa: ARG002
        return DetectorVerdict(suspicious=False, score=0.0, layer="stub")
