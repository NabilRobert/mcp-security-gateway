"""Spike 7 (throwaway): can FastMCP's proxy replace the hand-built one?

Criteria (declared in Phase 6 before running): Spike 1's transparency test
passes through a FastMCP proxy; a middleware reads the caller set by the
auth layer and refuses a call before it reaches the upstream; key checking
stays hashed and constant-time via a TokenVerifier subclass. Run with the
spike venv (FastMCP isn't in the project yet):

    .venv-spike7/bin/python -I spikes/s7_fastmcp.py
"""

import asyncio
import contextlib
import hashlib
import hmac
import os
import secrets
import shutil
import sys
import tempfile
import time
from collections.abc import AsyncIterator, Sequence
from pathlib import Path
from typing import Any

import httpx2
import uvicorn
from fastmcp.client.transports import StdioTransport, StreamableHttpTransport
from fastmcp.exceptions import ToolError
from fastmcp.server import create_proxy
from fastmcp.server.auth.auth import AccessToken, TokenVerifier
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import Middleware, MiddlewareContext
from mcp import Client, StdioServerParameters
from starlette.applications import Starlette
from starlette.routing import Mount

sys.path.insert(0, str(Path(__file__).parent))
import s1_transparency as s1  # noqa: E402

SEEN: list[str | None] = []


class HashedKeys(TokenVerifier):
    """Our key check behind FastMCP's interface: SHA-256 hashes only,
    constant-time, every caller compared."""

    def __init__(self, hashes: dict[str, str]) -> None:
        super().__init__()
        self._hashes = [(caller, bytes.fromhex(h)) for caller, h in hashes.items()]

    async def verify_token(self, token: str) -> AccessToken | None:
        digest = hashlib.sha256(token.encode()).digest()
        match = None
        for caller, stored in self._hashes:
            if hmac.compare_digest(digest, stored):
                match = caller
        if match is None:
            return None
        # Keep only a fingerprint in memory, not the key itself.
        return AccessToken(token=hashlib.sha256(token.encode()).hexdigest()[:8], client_id=match, scopes=[])


class Policy(Middleware):
    def __init__(self, denied: set[str]) -> None:
        self.denied = denied

    @staticmethod
    def caller() -> str:
        token = get_access_token()
        if token is None:
            raise ToolError("unauthenticated")
        return token.client_id

    async def on_list_tools(self, context: MiddlewareContext[Any], call_next: Any) -> Sequence[Any]:
        self.caller()
        tools = await call_next(context)
        return [t for t in tools if t.name not in self.denied]

    async def on_call_tool(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        SEEN.append(self.caller())
        if context.message.name in self.denied:
            raise ToolError(f"Denied by gateway policy: tool {context.message.name!r} not allowed.")
        return await call_next(context)


async def timed(client: Client, calls: list[tuple[str, dict[str, Any]]]) -> float:
    start = time.perf_counter()
    for tool, args in calls:
        await client.session.call_tool(tool, args)
    return (time.perf_counter() - start) / max(len(calls), 1) * 1000


async def main() -> int:
    backbone_key = s1.local_backbone_key()
    gateway_key = secrets.token_urlsafe(32)
    work = Path(os.path.realpath(tempfile.mkdtemp(prefix="spike7-fs-")))
    copy = work / s1.FIXTURE.name
    shutil.copytree(s1.FIXTURE, copy)
    fs_args = [str(s1.FS_JS), str(copy)]
    pagila_calls = s1.recorded_calls({"pagila"})
    fs_calls = s1.recorded_calls({"filesystem", "filesystem-v2"})
    port = s1.free_port()
    base = f"http://127.0.0.1:{port}"
    verifier = HashedKeys({"spike-caller": hashlib.sha256(gateway_key.encode()).hexdigest()})

    proxies = {
        "pagila": create_proxy(
            StreamableHttpTransport(s1.PAGILA_URL, headers={"Authorization": f"Bearer {backbone_key}"}),
            name="pagila", auth=verifier, middleware=[Policy(denied=set())],
        ),
        "filesystem": create_proxy(
            StdioTransport(command="node", args=fs_args),
            # The filesystem server only speaks the handshake era; FastMCP's
            # docs say to pin the backend mode for a single-era backend.
            mode="legacy",
            name="filesystem", auth=verifier, middleware=[Policy(denied={"write_file"})],
        ),
    }
    apps = {n: p.http_app(path="/") for n, p in proxies.items()}

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        async with contextlib.AsyncExitStack() as stack:
            for sub in apps.values():
                await stack.enter_async_context(sub.router.lifespan_context(sub))
            yield

    root = Starlette(routes=[Mount(f"/mcp/{n}", app=a) for n, a in apps.items()], lifespan=lifespan)
    server = uvicorn.Server(uvicorn.Config(root, host="127.0.0.1", port=port, log_level="warning"))
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.05)

    results: dict[str, bool] = {}
    try:
        async with httpx2.AsyncClient() as raw:
            r = await raw.post(f"{base}/mcp/pagila/", headers={"Authorization": "Bearer wrong",
                               "Accept": "application/json, text/event-stream"}, json={})
            print(f"[auth] wrong key -> HTTP {r.status_code}; www-authenticate: {r.headers.get('www-authenticate')!r}; "
                  f"middleware calls so far: {len(SEEN)}")
            results["auth"] = r.status_code == 401 and not SEEN
            wk = await raw.get(f"{base}/mcp/pagila/.well-known/oauth-protected-resource")
            print(f"[auth] discovery metadata route: HTTP {wk.status_code}")

        async with contextlib.AsyncExitStack() as stack:
            direct_pagila = await stack.enter_async_context(s1.http_client(s1.PAGILA_URL, backbone_key))
            via_pagila = await stack.enter_async_context(s1.http_client(f"{base}/mcp/pagila/", gateway_key))
            results["pagila"] = await s1.compare("pagila", direct_pagila, via_pagila, pagila_calls)

            direct_fs = await stack.enter_async_context(Client(StdioServerParameters(command="node", args=fs_args)))
            via_fs_legacy = await stack.enter_async_context(
                s1.http_client(f"{base}/mcp/filesystem/", gateway_key, mode="legacy"))
            # The proxy hides write_file, so compare the lists without it.
            d = [t for t in s1.dump(await direct_fs.list_tools())["tools"] if t["name"] != "write_file"]
            v = s1.dump(await via_fs_legacy.list_tools())["tools"]
            print(f"[filesystem, legacy, raw] tools/list identical apart from the hidden tool: {d == v} ({len(v)} tools)")
            print(f"[filesystem] identical once FastMCP's added title and _meta.fastmcp are removed: "
                  f"{[without_additions(x) for x in d] == [without_additions(x) for x in v]}")
            diffs = 0
            for tool, args in fs_calls:
                if s1.dump(await direct_fs.session.call_tool(tool, args)) != s1.dump(
                        await via_fs_legacy.session.call_tool(tool, args)):
                    diffs += 1
            print(f"[filesystem, legacy, raw] calls replayed: {len(fs_calls)}, identical: {len(fs_calls) - diffs}")
            results["filesystem"] = d == v and diffs == 0

            try:
                via_fs_auto = await stack.enter_async_context(s1.http_client(f"{base}/mcp/filesystem/", gateway_key))
                auto = await via_fs_auto.session.call_tool("read_text_file", {"path": "README.md"})
                print(f"[filesystem, agent at {via_fs_auto.session.protocol_version}] call works: {not auto.is_error}")
            except Exception as exc:  # the mirroring question
                print(f"[filesystem, agent at 2026-07-28] FAILED: {type(exc).__name__}: {s1_leaf(exc)}")

            denied = await via_fs_legacy.session.call_tool("write_file", {"path": "SPIKE7.txt", "content": "x"})
            print(f"[policy] write_file denied: is_error={denied.is_error}, "
                  f"text={denied.content[0].text if denied.content else None!r}; "  # type: ignore[union-attr]
                  f"file created upstream: {(copy / 'SPIKE7.txt').exists()}")
            results["deny"] = bool(denied.is_error) and not (copy / "SPIKE7.txt").exists()
            print(f"[identity] callers seen by the middleware: {set(SEEN)} over {len(SEEN)} calls")
            results["identity"] = set(SEEN) == {"spike-caller"}

            sample = fs_calls[:20]
            print(f"[latency] filesystem per call: direct {await timed(direct_fs, sample):.1f} ms, "
                  f"via FastMCP proxy {await timed(via_fs_legacy, sample):.1f} ms")
    finally:
        server.should_exit = True
        await task
        shutil.rmtree(work, ignore_errors=True)

    print({k: "ok" if v else "FAIL" for k, v in results.items()})
    passed = all(results.values())
    print("SPIKE 7:", "PASS" if passed else "FAIL")
    return 0 if passed else 1


def without_additions(tool: dict[str, Any]) -> dict[str, Any]:
    """A tool definition minus the two fields FastMCP adds to every tool."""
    tool = dict(tool)
    tool.pop("title", None)
    meta = {k: v for k, v in (tool.pop("_meta", None) or {}).items() if k != "fastmcp"}
    if meta:
        tool["_meta"] = meta
    return tool


def s1_leaf(exc: BaseException) -> str:
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    return f"{type(exc).__name__}: {exc}"


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
