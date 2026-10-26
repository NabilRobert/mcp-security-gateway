"""Append-only, hash-chained JSONL audit log (ADR-007).

Each line carries `prev`, the SHA-256 of the previous line's bytes, so an
edited or deleted line breaks the chain. A chain shows tampering; it can't
prevent someone who can rewrite the whole file from rebuilding it.
"""

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
GENESIS = hashlib.sha256(b"mcp-gateway audit log").hexdigest()


class AuditError(Exception):
    """The log can't be written. Callers must refuse the action (no unaudited call)."""


def line_hash(line: bytes) -> str:
    return hashlib.sha256(line).hexdigest()


class AuditLog:
    def __init__(self, path: Path, *, fsync: bool = True) -> None:
        self.path = path
        self.fsync = fsync
        self._prev = GENESIS
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() and path.stat().st_size:
                last = path.read_bytes().rstrip(b"\n").rsplit(b"\n", 1)[-1] + b"\n"
                self._prev = line_hash(last)
            self._file = path.open("ab")
        except OSError as exc:
            raise AuditError(f"can't open audit log {path}: {exc}") from exc

    def append(self, kind: str, **fields: Any) -> None:
        record = {
            "schema_version": SCHEMA_VERSION,
            "ts": datetime.now(UTC).isoformat(timespec="microseconds"),
            "kind": kind,
            **fields,
            "prev": self._prev,
        }
        line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
        try:
            self._file.write(line)
            self._file.flush()
            if self.fsync:
                os.fsync(self._file.fileno())
        except (OSError, ValueError) as exc:  # ValueError: write to a closed file
            raise AuditError(f"can't write audit log {self.path}: {exc}") from exc
        self._prev = line_hash(line)

    def close(self) -> None:
        self._file.close()


def verify_chain(path: Path) -> list[str]:
    """Problems found in the log's chain; an empty list means it verifies."""
    problems: list[str] = []
    prev = GENESIS
    for number, line in enumerate(path.read_bytes().splitlines(keepends=True), start=1):
        try:
            record = json.loads(line)
        except ValueError:
            problems.append(f"line {number}: not valid JSON")
            prev = line_hash(line)
            continue
        if record.get("prev") != prev:
            problems.append(f"line {number}: chain broken (an earlier line was changed or removed)")
        prev = line_hash(line)
    return problems
