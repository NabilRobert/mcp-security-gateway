"""Append-only, hash-chained JSONL audit log (ADR-007).

Each line carries `prev`, the SHA-256 of the previous line's bytes, so an
edited, inserted or deleted line breaks the chain. A chain shows tampering;
it can't prevent someone who can rewrite the whole file from rebuilding it,
and it can't show lines cut from the end. Shipping the log off the machine
would fix both, and is out of v1.

A crash mid-write leaves a torn last line. The next start closes it, writes
a `recovered` line naming its hash, and carries on, so the verifier can tell
a crash from an edit.
"""

import hashlib
import json
import os
from dataclasses import dataclass, field
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
        torn: bytes | None = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            data = path.read_bytes() if path.exists() else b""
            if data and not data.endswith(b"\n"):
                torn = data[data.rfind(b"\n") + 1 :] + b"\n"
            elif data:
                self._prev = line_hash(data.rstrip(b"\n").rsplit(b"\n", 1)[-1] + b"\n")
            self._file = path.open("ab")
            if torn is not None:
                self._file.write(b"\n")  # close the torn line so the next one doesn't merge into it
                self._prev = line_hash(torn)
        except OSError as exc:
            raise AuditError(f"can't open audit log {path}: {exc}") from exc
        if torn is not None:
            self.append("recovered", torn_line_sha256=line_hash(torn), torn_bytes=len(torn) - 1)

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


@dataclass
class Report:
    """What `verify_log` found. Only `problems` means the log was altered."""

    lines: int = 0
    problems: list[str] = field(default_factory=list[str])
    recoveries: list[str] = field(default_factory=list[str])
    unfinished_calls: list[str] = field(default_factory=list[str])


def verify_log(path: Path) -> Report:
    report = Report()
    raw = path.read_bytes().splitlines(keepends=True)
    records: list[dict[str, Any] | None] = []
    for line in raw:
        try:
            records.append(json.loads(line))
        except ValueError:
            records.append(None)
    prev = GENESIS
    forwarded: dict[str, int] = {}
    for index, (line, record) in enumerate(zip(raw, records, strict=True)):
        number = index + 1
        if record is None:
            after = records[index + 1] if index + 1 < len(records) else None
            if after and after.get("kind") == "recovered" and after.get("torn_line_sha256") == line_hash(line):
                report.recoveries.append(f"line {number}: torn by a crash, recovered at the next start")
            else:
                report.problems.append(f"line {number}: not valid JSON")
        else:
            if record.get("prev") != prev:
                report.problems.append(f"line {number}: chain broken (an earlier line was changed, added or removed)")
            if record.get("kind") == "call" and record.get("decision") == "forwarding":
                forwarded[str(record.get("call_id"))] = number
            elif record.get("kind") == "result":
                forwarded.pop(str(record.get("call_id")), None)
        prev = line_hash(line)
    report.lines = len(raw)
    report.unfinished_calls = [f"line {n}: call {cid} was forwarded but has no result" for cid, n in forwarded.items()]
    return report


def verify_chain(path: Path) -> list[str]:
    """Just the tampering problems; an empty list means the chain verifies."""
    return verify_log(path).problems
