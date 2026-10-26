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
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
from typing import Protocol

import anyio
from anyio.abc import TaskGroup
from mcp import Client
from mcp.shared.exceptions import MCPError
from mcp_types.jsonrpc import INVALID_REQUEST

IDLE_TIMEOUT_S = 30 * 60  # the SDK's DEFAULT_SESSION_IDLE_TIMEOUT
REAP_EVERY_S = 60.0


class Upstreams(Protocol):
    async def for_session(self, session_id: str | None) -> Client: ...

    def end(self, session_id: str) -> None: ...


class SharedUpstream:
    def __init__(self, client: Client) -> None:
        self.client = client

    async def for_session(self, session_id: str | None) -> Client:  # noqa: ARG002
        return self.client

    def end(self, session_id: str) -> None:
        pass


@dataclass(eq=False)
class _Entry:
    ready: anyio.Event = field(default_factory=anyio.Event)
    done: anyio.Event = field(default_factory=anyio.Event)
    client: Client | None = None
    error: BaseException | None = None
    last_used: float = field(default_factory=time.monotonic)


class PerSessionUpstreams:
    def __init__(
        self,
        name: str,
        open_client: Callable[[], AbstractAsyncContextManager[Client]],
        tasks: TaskGroup,
        *,
        idle_timeout_s: float = IDLE_TIMEOUT_S,
        reap_every_s: float = REAP_EVERY_S,
    ) -> None:
        self.name = name
        self._open = open_client
        self._tasks = tasks
        self._entries: dict[str, _Entry] = {}
        self.idle_timeout_s = idle_timeout_s
        self.started = 0  # processes started, for tests
        self._reaper = anyio.CancelScope()
        tasks.start_soon(self._reap, reap_every_s)

    @property
    def running(self) -> int:
        return len(self._entries)

    async def for_session(self, session_id: str | None) -> Client:
        if session_id is None:
            raise MCPError(
                INVALID_REQUEST,
                f"route {self.name!r} gives each session its own upstream, so it needs a session-based "
                "(initialize) client",
            )
        entry = self._entries.get(session_id)
        if entry is None:
            entry = self._entries[session_id] = _Entry()
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
