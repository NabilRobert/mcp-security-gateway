"""The rules layer of the detector: hand-written patterns
(`rules/injection.yaml`), matched against normalised text. Fast, precise and
narrow; the model layer in `detect.py` does most of the catching.
"""

import hashlib
import re
import time
import unicodedata
from pathlib import Path

import yaml

from mcp_gateway.detect import SCAN_IMPLEMENTATION, DetectorVerdict, text_for_scanning

RULES_FILE = Path(__file__).parent / "rules" / "injection.yaml"

# Cyrillic and Greek letters that look like Latin ones, and the dotless i,
# none of which NFKC folds (single-letter entries of Unicode's
# confusables.txt). "Ignore" spelt with a Cyrillic o (U+043E) reads the same
# to a model, but no pattern matches it. Each letter becomes the one in the
# same place on the second line.
LOOK_ALIKES = str.maketrans(
    "аеһіјорсѕухԁԛԝӏАВЕКМНОРСТХІЈЅҮԚԜονιαρυıΑΒΕΖΗΙΚΜΝΟΡΤΥΧ",
    "aehijopcsyxdqwlABEKMHOPCTXIJSYQWoviapuiABEZHIKMNOPTYX",
)


def _normalise(text: str) -> str:
    """The text the rules read. NFKC folds full-width letters and the like.
    Format characters (zero-width space, word joiner, soft hyphen) are
    dropped, since they split a word for a pattern but not for a reader, as
    ai-flight-school's `normalised` does. Look-alike letters become Latin,
    and collapsing whitespace stops a line break from splitting a phrase."""
    folded = unicodedata.normalize("NFKC", text)
    visible = "".join(char for char in folded if unicodedata.category(char) != "Cf")
    return re.sub(r"\s+", " ", visible.translate(LOOK_ALIKES))


class RulesDetector:
    def __init__(self, path: Path = RULES_FILE) -> None:
        raw = path.read_bytes()
        spec = yaml.safe_load(raw)
        self.rules = [(r["id"], re.compile(r["pattern"], re.IGNORECASE)) for r in spec["rules"]]
        self.version = f"rules-{hashlib.sha256(raw).hexdigest()[:12]}-{SCAN_IMPLEMENTATION}"

    def match(self, text: str) -> tuple[str, ...]:
        normalised = _normalise(text)
        return tuple(rule_id for rule_id, pattern in self.rules if pattern.search(normalised))

    async def scan(self, text: str) -> DetectorVerdict:
        start = time.perf_counter()
        matched = self.match(text_for_scanning(text))
        return DetectorVerdict(
            suspicious=bool(matched),
            score=1.0 if matched else 0.0,
            layer="rules",
            matched=matched,
            ms=(time.perf_counter() - start) * 1000,
        )
