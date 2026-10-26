"""Spike 1 (throwaway): is a low-level-Server proxy transparent, and can the
caller's identity reach the handlers?

A proxy route per upstream (local MCP-backbone over HTTP; the pinned
filesystem server over stdio) behind a bare ASGI Bearer check. For each
upstream, compare tools/list and the results of recorded tool calls,
direct vs through the proxy, as JSON. No model calls.

    .venv/bin/python -I spikes/s1_transparency.py
"""

import asyncio
import contextlib
import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx2
import uvicorn
from mcp import Client, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client
from mcp.server import Server, ServerRequestContext
from mcp.types import CallToolRequestParams, CallToolResult, ListToolsResult, PaginatedRequestParams
from starlette.applications import Starlette
from starlette.routing import Mount

HARNESS = Path(__file__).resolve().parents[2] / "agent-eval-harness"
FS_JS = HARNESS / "tools/fs-server/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"
FIXTURE = HARNESS / "suites/fixtures/acme-shop-v2"
PAGILA_URL = "http://127.0.0.1:8765/mcp/"
WRITE_TOOLS = {"write_file", "edit_file", "create_directory", "move_file"}
MAX_CALLS = 60  # per upstream


def local_backbone_key() -> str:
    """Read the local repro server's key from its container; never printed."""
    out = subprocess.run(
        ["docker", "compose", "-f", str(HARNESS / "repro/compose.yaml"), "exec", "-T", "mcp", "cat", "/out/repro.env"],
        check=True, capture_output=True, text=True,
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


# --- the proxy -----------------------------------------------------------

SEEN_CALLERS: list[str | None] = []


def proxy_server(name: str, upstream: Client) -> Server:
    async def list_tools(ctx: ServerRequestContext, params: PaginatedRequestParams | None) -> ListToolsResult:
        return await upstream.list_tools()

    async def call_tool(ctx: ServerRequestContext, params: CallToolRequestParams) -> CallToolResult:
        request = ctx.request
        SEEN_CALLERS.append(getattr(getattr(request, "state", None), "caller", None))
        # session.call_tool: raw result, no client-side output validation
        result = await upstream.session.call_tool(params.name, params.arguments or {})
        assert isinstance(result, CallToolResult), type(result)
        return result

    return Server(name, on_list_tools=list_tools, on_call_tool=call_tool)


class BearerCheck:
    """Bare ASGI key check: 401 unless the Bearer matches; sets the caller."""

    def __init__(self, app: Any, key_hash: str) -> None:
        self.app, self.key_hash = app, key_hash

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            headers = dict(scope["headers"])
            token = headers.get(b"authorization", b"").removeprefix(b"Bearer ")
            digest = hashlib.sha256(token).hexdigest()
            if not secrets.compare_digest(digest, self.key_hash):
                await send({"type": "http.response.start", "status": 401, "headers": []})
                await send({"type": "http.response.body", "body": b""})
                return
            scope.setdefault("state", {})["caller"] = "spike-caller"
        await self.app(scope, receive, send)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


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
        print(f"  tools/list raw diff: keys direct {sorted(d_raw)} via {sorted(v_raw)}; "
              f"_meta direct {d_raw.get('_meta')} via {v_raw.get('_meta')}; tools equal: {d_raw['tools'] == v_raw['tools']}")
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


async def main() -> int:
    backbone_key = local_backbone_key()
    gateway_key = secrets.token_urlsafe(32)
    work = Path(os.path.realpath(tempfile.mkdtemp(prefix="spike1-fs-")))
    fixture_copy = work / FIXTURE.name
    shutil.copytree(FIXTURE, fixture_copy)
    fs_params = StdioServerParameters(command="node", args=[str(FS_JS), str(fixture_copy)])

    pagila_calls = recorded_calls({"pagila"})
    fs_calls = recorded_calls({"filesystem", "filesystem-v2"})
    port = free_port()
    base = f"http://127.0.0.1:{port}"

    try:
        async with contextlib.AsyncExitStack() as stack:
            up_pagila = await stack.enter_async_context(http_client(PAGILA_URL, backbone_key))
            up_fs = await stack.enter_async_context(Client(fs_params))
            servers = {"pagila": proxy_server("pagila", up_pagila), "filesystem": proxy_server("filesystem", up_fs)}
            apps = {n: s.streamable_http_app(streamable_http_path="/") for n, s in servers.items()}

            @contextlib.asynccontextmanager
            async def lifespan(app: Starlette) -> AsyncIterator[None]:
                async with contextlib.AsyncExitStack() as inner:
                    for sub in apps.values():
                        await inner.enter_async_context(sub.router.lifespan_context(sub))
                    yield

            root = Starlette(routes=[Mount(f"/mcp/{n}", app=a) for n, a in apps.items()], lifespan=lifespan)
            app = BearerCheck(root, hashlib.sha256(gateway_key.encode()).hexdigest())
            server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
            task = asyncio.create_task(server.serve())
            while not server.started:
                await asyncio.sleep(0.05)

            # wrong key -> 401, and no call reaches a handler
            async with httpx2.AsyncClient() as raw:
                r = await raw.post(f"{base}/mcp/pagila/", headers={"Authorization": "Bearer wrong"}, json={})
                print(f"[auth] wrong key -> HTTP {r.status_code}; handler calls so far: {len(SEEN_CALLERS)}")
                auth_ok = r.status_code == 401 and not SEEN_CALLERS

            via_pagila = await stack.enter_async_context(http_client(f"{base}/mcp/pagila/", gateway_key))
            via_fs = await stack.enter_async_context(http_client(f"{base}/mcp/filesystem/", gateway_key))
            direct_fs = await stack.enter_async_context(Client(fs_params))

            ok_pagila = await compare("pagila", up_pagila, via_pagila, pagila_calls)
            ok_fs = await compare("filesystem", direct_fs, via_fs, fs_calls)
            # Same protocol version on both legs: legacy agent side vs the
            # legacy filesystem server, raw JSON, nothing stripped.
            via_fs_legacy = await stack.enter_async_context(
                http_client(f"{base}/mcp/filesystem/", gateway_key, mode="legacy")
            )
            ok_fs_legacy = await compare("filesystem, legacy, raw", direct_fs, via_fs_legacy, fs_calls, strip=False)
            callers = set(SEEN_CALLERS)
            print(f"[identity] callers seen by the handler: {callers} over {len(SEEN_CALLERS)} calls")
            ident_ok = callers == {"spike-caller"}
            print(f"[protocol] client->gateway: {via_pagila.session.protocol_version if hasattr(via_pagila.session, 'protocol_version') else '?'}")
            server.should_exit = True
            await task
    finally:
        shutil.rmtree(work, ignore_errors=True)

    passed = auth_ok and ok_pagila and ok_fs_legacy and ident_ok
    print(f"(filesystem at 2026-07-28 vs the legacy server, stamp stripped: {'identical' if ok_fs else 'differs'})")
    print("SPIKE 1:", "PASS" if passed else "FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
