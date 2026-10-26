"""Spike 2 helper (throwaway): serve the Spike 1 proxy until killed.

The gateway key arrives as a SHA-256 hash in SPIKE_GATEWAY_KEY_SHA256; the
port in SPIKE_PORT. Run with the gateway's venv.
"""

import asyncio
import contextlib
import os
import shutil
import sys
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

import uvicorn
from mcp import Client, StdioServerParameters
from starlette.applications import Starlette
from starlette.routing import Mount

sys.path.insert(0, str(Path(__file__).parent))
import s1_transparency as s1  # noqa: E402


async def main() -> None:
    port, key_hash = int(os.environ["SPIKE_PORT"]), os.environ["SPIKE_GATEWAY_KEY_SHA256"]
    work = Path(os.path.realpath(tempfile.mkdtemp(prefix="spike2-fs-")))
    copy = work / s1.FIXTURE.name
    shutil.copytree(s1.FIXTURE, copy)
    try:
        async with contextlib.AsyncExitStack() as stack:
            up_pagila = await stack.enter_async_context(s1.http_client(s1.PAGILA_URL, s1.local_backbone_key()))
            up_fs = await stack.enter_async_context(
                Client(StdioServerParameters(command="node", args=[str(s1.FS_JS), str(copy)]))
            )
            apps = {
                "pagila": s1.proxy_server("pagila", up_pagila).streamable_http_app(streamable_http_path="/"),
                "filesystem": s1.proxy_server("filesystem", up_fs).streamable_http_app(streamable_http_path="/"),
            }

            @contextlib.asynccontextmanager
            async def lifespan(app: Starlette) -> AsyncIterator[None]:
                async with contextlib.AsyncExitStack() as inner:
                    for sub in apps.values():
                        await inner.enter_async_context(sub.router.lifespan_context(sub))
                    yield

            root = Starlette(routes=[Mount(f"/mcp/{n}", app=a) for n, a in apps.items()], lifespan=lifespan)
            config = uvicorn.Config(s1.BearerCheck(root, key_hash), host="127.0.0.1", port=port, log_level="warning")
            await uvicorn.Server(config).serve()
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main())
