"""Wiring: upstream clients, routes, and the Starlette app around them.

Start-up order follows Phase 4: connect to every upstream and check that
each tool a policy names exists there (a typo fails loudly), open the audit
log, then serve. Shutdown closes the MCP sessions before the upstream
clients they forward to (Spike 1).
"""

import contextlib
import functools
import os
import sys
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, AsyncExitStack
from typing import cast

import anyio
import httpx2
import uvicorn
from anyio.abc import TaskGroup
from fastapi import FastAPI
from mcp import Client, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client
from mcp.server.streamable_http import MCP_SESSION_ID_HEADER
from mcp.types import PaginatedRequestParams, Tool
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Receive, Scope, Send

from mcp_gateway import __version__
from mcp_gateway.audit import AuditError, AuditLog, verify_chain
from mcp_gateway.auth import ApiKeyBackend, CallerUser, KeyRejected, unauthorized_handler
from mcp_gateway.config import ConfigError, DetectorSettings, GatewayConfig, HttpUpstream, StdioUpstream
from mcp_gateway.detect import Detector, LayeredDetector, ModelDetector, RulesDetector, StubDetector
from mcp_gateway.proxy import Route
from mcp_gateway.ratelimit import CallLimiter
from mcp_gateway.tracing import configure_tracing, shutdown_tracing
from mcp_gateway.upstreams import PerSessionUpstreams, SharedUpstream

Connect = Callable[[str, HttpUpstream | StdioUpstream], AbstractAsyncContextManager[Client]]


@contextlib.asynccontextmanager
async def connect_upstream(name: str, upstream: HttpUpstream | StdioUpstream) -> AsyncIterator[Client]:  # noqa: ARG001
    if isinstance(upstream, StdioUpstream):
        async with Client(
            StdioServerParameters(command=upstream.command, args=upstream.args, cwd=upstream.cwd)
        ) as client:
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
    stack: AsyncExitStack,
    config: GatewayConfig,
    audit: AuditLog,
    detector: Detector,
    connect: Connect,
    tasks: TaskGroup,
) -> dict[str, Route]:
    routes: dict[str, Route] = {}
    limiter = CallLimiter(config)
    for name, upstream in config.upstreams.items():
        per_session = isinstance(upstream, StdioUpstream) and upstream.per_session
        try:
            if per_session:
                # One probe process to check the tool list, then one per session.
                async with connect(name, upstream) as probe:
                    tools = {tool.name for tool in await list_all_tools(probe)}
            else:
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
        if per_session:
            sessions = PerSessionUpstreams(name, functools.partial(connect, name, upstream), tasks)
            stack.callback(sessions.close_all)  # runs before the task group waits for its tasks
            routes[name] = Route(name, sessions, config, audit, detector, limiter)
        else:
            routes[name] = Route(name, SharedUpstream(client), config, audit, detector, limiter)  # pyright: ignore[reportPossiblyUnboundVariable]
    return routes


OPEN_PATHS = frozenset({"/healthz"})


class SessionEndHook:
    """Tells a route when its client deletes a session (HTTP DELETE with an
    Mcp-Session-Id), after the SDK has handled the request."""

    def __init__(self, app: ASGIApp, routes: dict[str, Route]) -> None:
        self.app = app
        self.routes = routes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.app(scope, receive, send)
        if scope["type"] != "http" or scope.get("method") != "DELETE":
            return
        parts = str(scope.get("path", "")).strip("/").split("/")
        route = self.routes.get(parts[1]) if len(parts) >= 2 and parts[0] == "mcp" else None
        user = scope.get("user")
        session = dict(scope.get("headers", [])).get(MCP_SESSION_ID_HEADER.encode(), b"").decode()
        if route is not None and isinstance(user, CallerUser) and session:
            route.session_ended(session, user.caller_id)


def build_app(config: GatewayConfig, routes: dict[str, Route], audit: AuditLog) -> FastAPI:
    apps = {name: route.server().streamable_http_app(streamable_http_path="/") for name, route in routes.items()}

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        # A mounted app's lifespan isn't run by its parent, and each route's
        # MCP session manager lives in its own.
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

    # No interactive docs or OpenAPI schema: a security gateway shouldn't
    # describe itself to whoever asks.
    app = FastAPI(title="mcp-gateway", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    # Added first, so it runs inside the auth middleware and sees the caller.
    app.add_middleware(SessionEndHook, routes=routes)
    app.add_middleware(
        AuthenticationMiddleware,
        backend=ApiKeyBackend(config.callers, open_paths=OPEN_PATHS),
        on_error=unauthorized_handler(on_reject),
    )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
        return {"status": "ok", "version": __version__}

    for name, sub in apps.items():
        app.mount(f"/mcp/{name}", sub)
    return app


def build_detector(settings: DetectorSettings) -> Detector:
    """The configured layers, rules first. Failing to load the model is a
    start-up error: the gateway doesn't run without the detection it was
    configured with (Phase 4)."""
    layers: list[Detector] = []
    if settings.rules:
        layers.append(RulesDetector())
    if settings.model is not None:
        try:
            layers.append(
                ModelDetector(
                    settings.model.dir,
                    threshold=settings.model.threshold,
                    max_windows=settings.model.max_windows,
                    timeout_s=settings.model.timeout_s,
                )
            )
        except Exception as exc:
            raise ConfigError(f"can't load the detector model from {settings.model.dir}: {exc}") from exc
    return LayeredDetector(layers) if layers else StubDetector()


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
    detector = detector or build_detector(config.detector)
    audit = AuditLog(config.audit.path, fsync=config.audit.fsync)
    tracing = configure_tracing()  # None unless OTEL_EXPORTER_OTLP_ENDPOINT is set
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
        if tracing is not None:
            await anyio.to_thread.run_sync(shutdown_tracing, tracing)


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
        tasks = await stack.enter_async_context(anyio.create_task_group())
        routes = await open_routes(stack, config, audit, detector, connect, tasks)
        # A broken chain is reported, not fatal: refusing to start would let
        # anyone who can edit the log keep the gateway down.
        problems = verify_chain(config.audit.path)
        for problem in problems:
            print(f"mcp-gateway: audit log: {problem}", file=sys.stderr)
        audit.append(
            "start",
            chain_problems=len(problems),
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
