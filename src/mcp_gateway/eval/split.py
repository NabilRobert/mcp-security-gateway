"""The fixed dev/test split (2026-10-27, before any detector rule existed).

Injections are split by template family (eval/injections/templates.json,
fixed 2026-10-26). Benign outputs are split by a hash of their *text*, so
the benign half used to tune rules and thresholds is never the half scored
for the published number, and identical outputs (the same file read two
ways) can't land on both sides. (The first version hashed the output id,
which let identical texts cross; the split test caught it before the test
half was ever scored.)
"""

import hashlib
from typing import Literal

Split = Literal["dev", "test"]


def benign_split(text: str) -> Split:
    return "dev" if int(hashlib.sha256(text.encode()).hexdigest(), 16) % 2 == 0 else "test"
