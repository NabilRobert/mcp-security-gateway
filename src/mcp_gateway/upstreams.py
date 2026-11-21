"""How a route reaches its upstream: one shared client, or one per MCP session.

Per-session (ADR-010) is for stdio servers that keep state between calls,
like a filesystem server on a working copy: each session gets its own
process, started on first use and stopped when the session ends, so one
agent's writes can't leak into another's run (Spike 2).

A session is its `Mcp-Session-Id`. (The SDK builds a new session object for
every request, so object identity can't be used.) It ends when the client
deletes it, which the gateway's HTTP layer reports, or after the SDK's own
idle timeout. A client's lifetime is owned by its own task, because an SDK
client must be closed in the task that opened it.
"""

import time
from collections import Counter
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
from typing import Protocol, cast

import anyio
import httpx2
from anyio.abc import TaskGroup
from mcp import Client
from mcp.shared.exceptions import MCPError
from mcp.types import PaginatedRequestParams, Tool
from mcp_types.jsonrpc import INVALID_REQUEST

from mcp_gateway.config import UpstreamSessionLimits

IDLE_TIMEOUT_S = 30 * 60  # the SDK's DEFAULT_SESSION_IDLE_TIMEOUT
REAP_EVERY_S = 60.0
MAX_TOOL_PAGES = 100


async def list_all_tools(client: Client) -> list[Tool]:
    """Every tool, across pages. The page cap is there because the cursor
    comes from the upstream, which isn't trusted to ever stop sending one."""
    tools: list[Tool] = []
    cursor: str | None = None
    for _ in range(MAX_TOOL_PAGES):
        page = await client.session.list_tools(params=PaginatedRequestParams(cursor=cursor))
        tools.extend(page.tools)
        cursor = page.next_cursor
        if cursor is None:
            return tools
    raise RuntimeError(f"upstream sent more than {MAX_TOOL_PAGES} pages of tools")


class ResponseTooLarge(httpx2.StreamError):
    """An upstream's HTTP response passed the route's `max_response_bytes`.
    A stream error, because that's what the SDK's client turns into an error
    answer to the one request; any other exception ends the whole client,
    and with it the route."""


class _CappedStream(httpx2.AsyncByteStream):
    def __init__(self, inner: httpx2.AsyncByteStream, max_bytes: int) -> None:
        self._inner = inner
        self._max_bytes = max_bytes

    async def __aiter__(self) -> AsyncIterator[bytes]:
        received = 0
        async for chunk in self._inner:
            received += len(chunk)
            if received > self._max_bytes:
                raise ResponseTooLarge(f"the upstream's response passed {self._max_bytes} bytes")
            yield chunk

    async def aclose(self) -> None:
        await self._inner.aclose()


class CappedTransport(httpx2.AsyncBaseTransport):
    """Reads at most `max_bytes` of each response, so an upstream can't make
    the gateway hold an answer of any size. Each streamable HTTP POST carries
    one answer. The bytes counted are as sent, so the client asks for no
    compression: a small compressed body can expand without limit."""

    def __init__(self, inner: httpx2.AsyncBaseTransport, max_bytes: int) -> None:
        self._inner = inner
        self._max_bytes = max_bytes

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        request.headers["Accept-Encoding"] = "identity"
        response = await self._inner.handle_async_request(request)
        response.stream = _CappedStream(cast(httpx2.AsyncByteStream, response.stream), self._max_bytes)
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()


class Upstreams(Protocol):
    async def for_session(self, session_id: str | None, caller: str) -> Client: ...

    def end(self, session_id: str) -> None: ...


class SharedUpstream:
    def __init__(self, client: Client) -> None:
        self.client = client

    async def for_session(self, session_id: str | None, caller: str) -> Client:  # noqa: ARG002
        return self.client

    def end(self, session_id: str) -> None:
        pass


class SessionBudget:
    """The caps on upstream sessions, shared by every per-session route: each
    session is a process, and any caller can open sessions."""

    def __init__(self, limits: UpstreamSessionLimits) -> None:
        self.limits = limits
        self._open_by_caller: Counter[str] = Counter()

    def reserve(self, caller: str) -> None:
        if self._open_by_caller.total() >= self.limits.max_total:
            raise MCPError(
                INVALID_REQUEST,
                f"the gateway already runs its limit of {self.limits.max_total} upstream sessions; "
                "try again once other sessions have ended",
            )
        if self._open_by_caller[caller] >= self.limits.max_per_caller:
            raise MCPError(
                INVALID_REQUEST,
                f"this key already has {self.limits.max_per_caller} upstream sessions open, its limit; "
                "close a client (ending its session) before opening another",
            )
        self._open_by_caller[caller] += 1

    def release(self, caller: str) -> None:
        self._open_by_caller[caller] -= 1
        if self._open_by_caller[caller] <= 0:
            del self._open_by_caller[caller]


@dataclass(eq=False)
class _Entry:
    caller: str
    ready: anyio.Event = field(default_factory=anyio.Event)
    done: anyio.Event = field(default_factory=anyio.Event)
    client: Client | None = None
    error: BaseException | None = None
    last_used: float = field(default_factory=time.monotonic)


class PerSessionUpstreams:
    def __init__(  # noqa: PLR0913 (the two timings are keyword-only, with defaults, for tests)
        self,
        name: str,
        open_client: Callable[[], AbstractAsyncContextManager[Client]],
        tasks: TaskGroup,
        budget: SessionBudget,
        *,
        idle_timeout_s: float = IDLE_TIMEOUT_S,
        reap_every_s: float = REAP_EVERY_S,
    ) -> None:
        self.name = name
        self._open = open_client
        self._tasks = tasks
        self._budget = budget
        self._entries: dict[str, _Entry] = {}
        self.idle_timeout_s = idle_timeout_s
        self.started = 0  # processes started, for tests
        self._reaper = anyio.CancelScope()
        tasks.start_soon(self._reap, reap_every_s)

    @property
    def running(self) -> int:
        return len(self._entries)

    async def for_session(self, session_id: str | None, caller: str) -> Client:
        if session_id is None:
            raise MCPError(
                INVALID_REQUEST,
                f"route {self.name!r} gives each session its own upstream, so it needs a session-based "
                "(initialize) client",
            )
        entry = self._entries.get(session_id)
        if entry is None:
            self._budget.reserve(caller)  # raises when a cap is reached; nothing is started then
            entry = self._entries[session_id] = _Entry(caller)
            self.started += 1
            self._tasks.start_soon(self._own, session_id, entry)
        entry.last_used = time.monotonic()
        await entry.ready.wait()
        if entry.client is None:
            raise MCPError(INVALID_REQUEST, f"upstream {self.name!r} failed to start for this session") from entry.error
        return entry.client

    def end(self, session_id: str) -> None:
        entry = self._entries.pop(session_id, None)
        if entry is not None:
            entry.done.set()

    async def _own(self, session_id: str, entry: _Entry) -> None:
        try:
            async with self._open() as client:
                entry.client = client
                entry.ready.set()
                await entry.done.wait()
        except Exception as exc:
            entry.error = exc
        finally:
            entry.client = None
            entry.ready.set()
            entry.done.set()
            self._budget.release(entry.caller)
            if self._entries.get(session_id) is entry:
                del self._entries[session_id]

    async def _reap(self, every_s: float) -> None:
        with self._reaper:
            while True:
                await anyio.sleep(every_s)
                cutoff = time.monotonic() - self.idle_timeout_s
                for session_id, entry in list(self._entries.items()):
                    if entry.last_used < cutoff:
                        self.end(session_id)

    def close_all(self) -> None:
        """At shutdown: stop every session's upstream and the reaper, so the
        task group that owns them can finish."""
        self._reaper.cancel()
        for session_id in list(self._entries):
            self.end(session_id)
