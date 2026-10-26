"""Wiring: upstream clients, routes, and the Starlette app around them.

Start-up order follows Phase 4: connect to every upstream and check that
each tool a policy names exists there (a typo fails loudly), open the audit
log, then serve. Shutdown closes the MCP sessions before the upstream
clients they forward to (Spike 1).
"""

import contextlib
import os
import sys
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, AsyncExitStack
from typing import cast

import httpx2
import uvicorn
from mcp import Client, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client
from mcp.types import PaginatedRequestParams, Tool
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import HTTPConnection
from starlette.routing import Mount

from mcp_gateway import __version__
from mcp_gateway.audit import AuditError, AuditLog
from mcp_gateway.auth import ApiKeyBackend, KeyRejected, unauthorized_handler
from mcp_gateway.config import ConfigError, GatewayConfig, HttpUpstream, StdioUpstream
from mcp_gateway.detect import Detector, StubDetector
from mcp_gateway.proxy import Route

Connect = Callable[[str, HttpUpstream | StdioUpstream], AbstractAsyncContextManager[Client]]


@contextlib.asynccontextmanager
async def connect_upstream(name: str, upstream: HttpUpstream | StdioUpstream) -> AsyncIterator[Client]:  # noqa: ARG001
    if isinstance(upstream, StdioUpstream):
        async with Client(StdioServerParameters(command=upstream.command, args=upstream.args)) as client:
            yield client
        return
    headers = {"Authorization": f"Bearer {os.environ[upstream.auth_env]}"} if upstream.auth_env else {}
    async with (
        httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30.0, read=60.0)) as http,
        Client(streamable_http_client(upstream.url, http_client=http)) as client,
    ):
        yield client


async def list_all_tools(client: Client) -> list[Tool]:
    tools: list[Tool] = []
    cursor: str | None = None
    while True:
        page = await client.session.list_tools(params=PaginatedRequestParams(cursor=cursor))
        tools.extend(page.tools)
        cursor = page.next_cursor
        if cursor is None:
            return tools


async def open_routes(
    stack: AsyncExitStack, config: GatewayConfig, audit: AuditLog, detector: Detector, connect: Connect
) -> dict[str, Route]:
    routes: dict[str, Route] = {}
    for name, upstream in config.upstreams.items():
        try:
            client = await stack.enter_async_context(connect(name, upstream))
            tools = {tool.name for tool in await list_all_tools(client)}
        except Exception as exc:
            cause = _leaf(exc)
            raise ConfigError(f"upstream {name!r} is unreachable: {type(cause).__name__}: {cause}") from exc
        for policy_id, policy in config.policies.items():
            route_policy = policy.routes.get(name)
            missing = sorted(set(route_policy.tools) - tools) if route_policy else []
            if missing:
                raise ConfigError(f"policy {policy_id!r} allows tools that {name!r} doesn't have: {missing}")
        routes[name] = Route(name, client, config, audit, detector)
    return routes


def build_app(config: GatewayConfig, routes: dict[str, Route], audit: AuditLog) -> Starlette:
    apps = {name: route.server().streamable_http_app(streamable_http_path="/") for name, route in routes.items()}

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        # Starlette doesn't run a mounted app's lifespan, and each route's
        # session manager lives in its own.
        async with AsyncExitStack() as stack:
            for sub in apps.values():
                await stack.enter_async_context(sub.router.lifespan_context(sub))
            yield

    def on_reject(conn: HTTPConnection, exc: KeyRejected) -> None:
        # The request is refused either way, so a log failure here is
        # reported, not raised (raising would turn the 401 into a 500).
        try:
            audit.append(
                "call",
                decision="denied",
                reason=f"auth: {exc.reason}",
                key_fingerprint=exc.fingerprint,
                client=conn.client.host if conn.client else None,
                path=conn.url.path,
            )
        except AuditError as error:
            print(f"mcp-gateway: {error}", file=sys.stderr)

    return Starlette(
        routes=[Mount(f"/mcp/{name}", app=app) for name, app in apps.items()],
        middleware=[
            Middleware(
                AuthenticationMiddleware,
                backend=ApiKeyBackend(config.callers),
                on_error=unauthorized_handler(on_reject),
            )
        ],
        lifespan=lifespan,
    )


async def serve(
    config: GatewayConfig,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    connect: Connect = connect_upstream,
    detector: Detector | None = None,
    started: Callable[[uvicorn.Server], None] | None = None,
) -> None:
    """Run until stopped. Raises ConfigError before serving if anything at
    start-up is wrong."""
    detector = detector or StubDetector()
    audit = AuditLog(config.audit.path, fsync=config.audit.fsync)
    try:
        await _serve(config, audit, detector, host=host, port=port, connect=connect, started=started)
    except BaseExceptionGroup as group:
        # A start-up error raised inside an upstream client's task group comes
        # out wrapped; surface it as itself so the CLI exits 2 with a message.
        found = group.subgroup(ConfigError)
        if found is None:
            raise
        raise _first(found) from group
    finally:
        audit.close()


def _leaf(exc: BaseException) -> BaseException:
    """The first real error inside (possibly nested) exception groups."""
    current: BaseException = exc
    while isinstance(current, BaseExceptionGroup):
        nested = cast(BaseExceptionGroup[BaseException], current).exceptions
        if not nested:
            break
        current = nested[0]
    return cast(BaseException, current)


def _first(group: BaseExceptionGroup[ConfigError]) -> ConfigError:
    inner = group.exceptions[0]
    return _first(inner) if isinstance(inner, BaseExceptionGroup) else inner


async def _serve(
    config: GatewayConfig,
    audit: AuditLog,
    detector: Detector,
    *,
    host: str,
    port: int,
    connect: Connect,
    started: Callable[[uvicorn.Server], None] | None,
) -> None:
    async with AsyncExitStack() as stack:
        routes = await open_routes(stack, config, audit, detector, connect)
        audit.append(
            "start",
            version=__version__,
            git_sha=os.environ.get("MCP_GATEWAY_GIT_SHA"),
            policy_sha256=config.policy_hash(),
            detector=detector.version,
            routes=sorted(routes),
        )
        server = uvicorn.Server(
            uvicorn.Config(build_app(config, routes, audit), host=host, port=port, log_level="warning", lifespan="on")
        )
        if started is not None:
            started(server)
        await server.serve()
