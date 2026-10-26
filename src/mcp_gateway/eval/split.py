"""The fixed dev/test split (2026-10-27, before any detector rule existed).

Injections are split by template family (eval/injections/templates.json,
fixed 2026-10-26). Benign outputs are split by a hash of their id, so the
benign half used to tune rules and thresholds is never the half that is
scored for the published number.
"""

import hashlib
from typing import Literal

Split = Literal["dev", "test"]


def benign_split(output_id: str) -> Split:
    return "dev" if int(hashlib.sha256(output_id.encode()).hexdigest(), 16) % 2 == 0 else "test"
