"""What the gateway adds to a tool call (Phase 1: "overhead is measured";
Phase 2: p50 / p95). $0: no model is called.

Replays recorded tool calls (the harness's runs, as in Spikes 1 and 5)
against two local upstreams, direct and through the gateway, interleaved
call by call so machine-load drift hits both sides alike:
- pagila: the harness's local MCP-backbone over HTTP (direct is HTTP too,
  so the comparison is like for like);
- filesystem: the pinned reference server over stdio (direct is stdio; via
  the gateway the agent speaks HTTP, so the transport change is included).

Gateway configurations: detection off (the proxy alone), rules, and rules +
model (fp32, threshold 0.999). The audit log writes with fsync on, the
default. Writes eval/results/overhead/summary.json.

    .venv/bin/python -I scripts/measure_overhead.py
"""

import asyncio
import contextlib
import hashlib
import json
import os
import secrets
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import yaml
from mcp import Client, StdioServerParameters

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_benign_set as s5  # noqa: E402  (rebasing recorded fixture paths)
import recorded_calls as s1  # noqa: E402  (recorded calls, local key, clients)

MODEL = ROOT / "models/protectai-deberta-v3-base-prompt-injection-v2/90c9989b1a342275dd0d1a95aad283c04e075671"
OUT = ROOT / "eval" / "results" / "overhead"
PORT = 8081
CALLS = 60  # distinct recorded calls per upstream
ROUNDS = 3  # measured rounds, after one warm-up round
FS_TOOLS = [
    "read_file", "read_text_file", "read_media_file", "read_multiple_files", "write_file", "edit_file",
    "create_directory", "list_directory", "list_directory_with_sizes", "directory_tree", "move_file",
    "search_files", "get_file_info", "list_allowed_directories",
]  # fmt: skip
BACKBONE_TOOLS = ["list_tables", "describe_table", "sample_rows", "run_query"]
DETECTORS: dict[str, dict[str, Any]] = {
    "detection off": {"rules": False},
    "rules": {"rules": True},
    "rules + model": {"rules": True, "model": {"dir": str(MODEL), "threshold": 0.999, "timeout_s": 2.0}},
}


def pct(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[min(int(len(ordered) * q), len(ordered) - 1)]


def gateway_config(key: str, fixture: Path, detector: dict[str, Any], audit: Path) -> dict[str, Any]:
    return {
        "upstreams": {
            "pagila": {"transport": "http", "url": s1.PAGILA_URL, "auth_env": "MCP_BACKBONE_LOCAL_KEY"},
            "files": {"transport": "stdio", "command": "node", "args": [str(s1.FS_JS), str(fixture)]},
        },
        "callers": {"bench": {"key_sha256": hashlib.sha256(key.encode()).hexdigest(), "policy": "all"}},
        "policies": {
            "all": {
                "routes": {
                    "pagila": {"tools": {t: {} for t in BACKBONE_TOOLS}},
                    "files": {"tools": {t: {} for t in FS_TOOLS}},
                }
            }
        },
        "detector": detector,
        "audit": {"path": str(audit), "fsync": True},
    }


@contextlib.contextmanager
def running_gateway(config_path: Path, backbone_key: str) -> Any:
    gateway = subprocess.Popen(  # noqa: S603  (this repo's own CLI, fixed arguments)
        [str(ROOT / ".venv/bin/mcp-gateway"), "serve", "--config", str(config_path), "--port", str(PORT)],
        env={**os.environ, "MCP_BACKBONE_LOCAL_KEY": backbone_key},
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 60
        while True:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/healthz", timeout=2):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise SystemExit("the gateway didn't become healthy") from None
                time.sleep(0.2)
        yield
    finally:
        gateway.terminate()
        gateway.wait(timeout=30)


def decision_counts(audit: Path) -> dict[str, Any]:
    """How the gateway decided, from its audit log: a timed-out scan is a
    gateway_error (a block), so a slow detector shows up here."""
    counts: dict[str, int] = {}
    for line in audit.read_text().splitlines():
        record = json.loads(line)
        if record.get("kind") == "result":
            key = f"{record['route']}: {record['decision']}"
            counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


RATE_LIMITED = "rate limit of"  # MCP-backbone's refusal; a refused call is fast, so it would skew the timings
rate_limited = 0


async def timed(client: Client, tool: str, args: dict[str, Any]) -> float:
    global rate_limited
    start = time.perf_counter()
    result = await client.session.call_tool(tool, args)
    elapsed = (time.perf_counter() - start) * 1000
    if any(RATE_LIMITED in getattr(c, "text", "") for c in result.content):
        rate_limited += 1
    return elapsed


async def compare(direct: Client, via: Client, calls: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    for tool, args in calls:  # warm-up: connections, caches, the model's first runs
        await timed(direct, tool, args)
        await timed(via, tool, args)
    direct_ms: list[float] = []
    via_ms: list[float] = []
    for _ in range(ROUNDS):
        for tool, args in calls:
            direct_ms.append(await timed(direct, tool, args))
            via_ms.append(await timed(via, tool, args))
    added = [v - d for v, d in zip(via_ms, direct_ms, strict=True)]
    return {
        "calls_timed": len(direct_ms),
        "direct_ms": {"p50": round(statistics.median(direct_ms), 2), "p95": round(pct(direct_ms, 0.95), 2)},
        "gateway_ms": {"p50": round(statistics.median(via_ms), 2), "p95": round(pct(via_ms, 0.95), 2)},
        "added_ms": {"p50": round(statistics.median(added), 2), "p95": round(pct(added, 0.95), 2)},
    }


@contextlib.asynccontextmanager
async def fs_direct(fixture: Path) -> AsyncIterator[Client]:
    async with Client(StdioServerParameters(command="node", args=[str(s1.FS_JS), str(fixture)])) as client:
        yield client


async def measure(name: str, detector: dict[str, Any], backbone_key: str) -> dict[str, Any]:
    work = Path(os.path.realpath(tempfile.mkdtemp(prefix="overhead-")))
    fixture = work / s1.FIXTURE.name
    shutil.copytree(s1.FIXTURE, fixture)
    key = secrets.token_urlsafe(32)
    config_path = work / "gateway.yaml"
    config_path.write_text(yaml.safe_dump(gateway_config(key, fixture, detector, work / "audit.jsonl")))
    s1.MAX_CALLS = CALLS
    pagila_calls = s1.recorded_calls({"pagila"})
    fs_calls = [
        (tool, s5.rebase(args, str(fixture))) for tool, args in s1.recorded_calls({"filesystem", "filesystem-v2"})
    ]
    base = f"http://127.0.0.1:{PORT}/mcp"
    try:
        with running_gateway(config_path, backbone_key):
            async with (
                s1.http_client(s1.PAGILA_URL, backbone_key) as direct_pagila,
                s1.http_client(f"{base}/pagila/", key) as via_pagila,
                fs_direct(fixture) as direct_fs,
                s1.http_client(f"{base}/files/", key) as via_fs,
            ):
                result = {
                    "pagila (HTTP → HTTP)": await compare(direct_pagila, via_pagila, pagila_calls),
                    "filesystem (stdio → HTTP)": await compare(direct_fs, via_fs, fs_calls),
                }
    finally:
        result["decisions"] = decision_counts(work / "audit.jsonl")
        shutil.rmtree(work, ignore_errors=True)
    for upstream, r in result.items():
        if upstream == "decisions":
            print(f"{name:14} audit decisions: {r}")
            continue
        print(
            f"{name:14} {upstream:26} direct p50 {r['direct_ms']['p50']:7.2f} ms | gateway p50 "
            f"{r['gateway_ms']['p50']:7.2f} ms, p95 {r['gateway_ms']['p95']:7.2f} ms | added p50 "
            f"{r['added_ms']['p50']:6.2f} ms, p95 {r['added_ms']['p95']:7.2f} ms"
        )
    return result


async def main() -> int:
    backbone_key = s1.local_backbone_key()
    summary = {
        "measured_on": "Apple M2, macOS; everything local (no network hop)",
        "rounds": ROUNDS,
        "calls_per_upstream": CALLS,
        "audit_fsync": True,
        "configurations": {name: await measure(name, det, backbone_key) for name, det in DETECTORS.items()},
    }
    if rate_limited:
        print(
            f"REFUSED: {rate_limited} calls were rate-limited by the upstream; the timings are not valid. "
            "MCP-backbone's window is an hour; rerun after it resets."
        )
        return 1
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
