"""The harness's recorded tool calls, and the local upstreams they replay
against: shared by the measurement scripts, the benign-set builder and the
transparency test (tests/test_transparency.py).

Kept from Spike 1 (spikes/s1_transparency.py). The spike's own proxy and
runner were removed from main once its result was recorded in Phase 6; the
full spike is at https://github.com/NabilRobert/mcp-security-gateway/tree/ffc78c6/spikes.
"""

import contextlib
import json
import subprocess
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

HARNESS = Path(__file__).resolve().parents[2] / "agent-eval-harness"
FS_JS = HARNESS / "tools/fs-server/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"
FIXTURE = HARNESS / "suites/fixtures/acme-shop-v2"
PAGILA_URL = "http://127.0.0.1:8765/mcp/"
WRITE_TOOLS = {"write_file", "edit_file", "create_directory", "move_file"}
MAX_CALLS = 60  # per upstream


def local_backbone_key() -> str:
    """Read the local repro server's key from its container; never printed."""
    # Fixed arguments: docker compose on the harness's own file.
    command = [
        "docker",
        "compose",
        "-f",
        str(HARNESS / "repro/compose.yaml"),
        "exec",
        "-T",
        "mcp",
        "cat",
        "/out/repro.env",
    ]
    out = subprocess.run(  # noqa: S603
        command,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    for line in out.splitlines():
        name, _, value = line.partition("=")
        if name.strip() == "MCP_BACKBONE_LOCAL_KEY":
            return value.strip().strip('"')
    raise SystemExit("no MCP_BACKBONE_LOCAL_KEY in repro.env")


def recorded_calls(suite_names: set[str]) -> list[tuple[str, dict[str, Any]]]:
    """Distinct (tool, arguments) pairs from the harness's recorded runs."""
    seen: dict[str, tuple[str, dict[str, Any]]] = {}
    for run in sorted((HARNESS / "runs").iterdir()):
        meta = json.loads((run / "meta.json").read_text())
        suite = meta.get("suite")
        suite = suite.get("name") if isinstance(suite, dict) else suite
        if suite not in suite_names:
            continue
        for line in (run / "trials.jsonl").read_text().splitlines():
            for call in json.loads(line).get("tool_calls", []):
                tool, args = call["tool"], call.get("arguments") or {}
                if tool in WRITE_TOOLS or tool == "submit":
                    continue
                key = json.dumps([tool, args], sort_keys=True)
                seen.setdefault(key, (tool, args))
    return list(seen.values())[:MAX_CALLS]


STAMP = "io.modelcontextprotocol/serverInfo"


def dump(model: Any, strip_stamp: bool = False) -> Any:
    """JSON form. strip_stamp drops the SDK's per-connection serverInfo
    stamp from `_meta` (and `_meta` if that leaves it empty)."""
    data = model.model_dump(mode="json", by_alias=True, exclude_none=True)
    if strip_stamp:
        meta = data.get("_meta")
        if isinstance(meta, dict):
            meta.pop(STAMP, None)
            if not meta:
                del data["_meta"]
    return data


@contextlib.asynccontextmanager
async def http_client(url: str, key: str, mode: str = "auto") -> AsyncIterator[Client]:
    async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {key}"}, timeout=60) as http:
        async with Client(streamable_http_client(url, http_client=http), mode=mode) as client:  # type: ignore[arg-type]
            yield client


async def compare(
    label: str, direct: Client, via: Client, calls: list[tuple[str, dict[str, Any]]], strip: bool = True
) -> bool:
    ok = True
    d_raw, v_raw = dump(await direct.list_tools()), dump(await via.list_tools())
    if d_raw != v_raw:
        print(
            f"  tools/list raw diff: keys direct {sorted(d_raw)} via {sorted(v_raw)}; "
            f"_meta direct {d_raw.get('_meta')} via {v_raw.get('_meta')}; "
            f"tools equal: {d_raw['tools'] == v_raw['tools']}"
        )
    d_tools, v_tools = dump(await direct.list_tools(), strip), dump(await via.list_tools(), strip)
    same_tools = d_tools == v_tools
    print(f"[{label}] tools/list identical: {same_tools} ({len(d_tools['tools'])} tools)")
    ok &= same_tools
    diffs = 0
    for tool, args in calls:
        d = dump(await direct.session.call_tool(tool, args), strip)
        v = dump(await via.session.call_tool(tool, args), strip)
        if d != v:
            diffs += 1
            if diffs <= 3:
                print(f"  DIFF {tool} {json.dumps(args)[:80]}")
                print(f"    direct keys {sorted(d)} via keys {sorted(v)}")
                print(f"    direct {json.dumps(d)[:300]}")
                print(f"    via    {json.dumps(v)[:300]}")
    print(f"[{label}] calls replayed: {len(calls)}, identical: {len(calls) - diffs}")
    return ok and diffs == 0
