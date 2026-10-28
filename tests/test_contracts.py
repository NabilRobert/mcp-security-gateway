"""What other code and readers rely on, pinned (mutation triage, 2026-10-27):
the audit log's fields and edge cases, the error codes an agent sees, the
upstream-failure path, the policy hash's stability, and the idle reaper.
Survivors showed none of these were held by a test."""

import asyncio
import contextlib
import hashlib
import json
import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import anyio
import httpx2
import pytest
from conftest import KEY_A, FakeUpstream, RunningGateway, agent, in_memory, make_config, running_gateway
from mcp import Client
from mcp.server import MCPServer
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolRequestParams
from starlette.requests import Request

from mcp_gateway import __version__
from mcp_gateway.audit import AuditLog, verify_log
from mcp_gateway.auth import CallerUser
from mcp_gateway.config import GatewayConfig
from mcp_gateway.detect import StubDetector, text_for_scanning
from mcp_gateway.proxy import UPSTREAM_ERROR, Route
from mcp_gateway.upstreams import PerSessionUpstreams, SharedUpstream

pytestmark = pytest.mark.anyio


def lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


# --- the audit log's edge cases ------------------------------------------------


def test_every_line_carries_the_envelope(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.jsonl", fsync=False)
    log.append("call", call_id="c1")
    log.close()
    [line] = lines(tmp_path / "a.jsonl")
    assert line["schema_version"] == 1 and line["kind"] == "call" and line["call_id"] == "c1"
    assert line["ts"].endswith("+00:00")  # UTC, not the host's local time
    assert len(line["prev"]) == 64


def test_the_chain_continues_after_a_one_line_log(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    for _ in range(2):
        log = AuditLog(path, fsync=False)
        log.append("start")
        log.close()
    assert verify_log(path).problems == []


def test_fsync_is_called_when_configured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (calls.append(fd), real(fd))[1])
    log = AuditLog(tmp_path / "a.jsonl", fsync=True)
    log.append("call")
    log.append("result")
    log.close()
    assert len(calls) == 2


def test_a_torn_line_that_is_still_last_is_a_problem_not_a_crash(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    log = AuditLog(path, fsync=False)
    log.append("call", call_id="c1")
    log.close()
    with path.open("ab") as f:
        f.write(b'{"kind":"res')  # crashed, and nothing has reopened the log yet
    report = verify_log(path)
    assert report.recoveries == [] and any("not valid JSON" in p for p in report.problems)


def test_a_recovery_line_with_the_wrong_hash_doesnt_excuse_garbage(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    log = AuditLog(path, fsync=False)
    log.append("call")
    log.close()
    with path.open("ab") as f:
        f.write(b"garbage\n")
        f.write(json.dumps({"kind": "recovered", "torn_line_sha256": "0" * 64, "prev": "x"}).encode() + b"\n")
    assert any("not valid JSON" in p for p in verify_log(path).problems)


def test_denied_calls_are_not_reported_as_unfinished(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    log = AuditLog(path, fsync=False)
    log.append("call", call_id="d1", decision="denied")
    log.append("call", call_id="f1", decision="forwarding")
    log.close()
    report = verify_log(path)
    assert len(report.unfinished_calls) == 1 and "f1" in report.unfinished_calls[0]


# --- what the gateway writes and returns ----------------------------------------


def slow_server() -> MCPServer:
    mcp = MCPServer("slow")

    @mcp.tool()
    async def slow(text: str) -> str:
        """Answers after 60 ms."""
        await asyncio.sleep(0.06)
        return f"done: {text}"

    return mcp


async def test_the_result_line_records_real_numbers(tmp_path: Path) -> None:
    config = make_config(
        tmp_path, policies={"reader": {"routes": {"fake": {"tools": {"slow": {}}}}}, "echo-only": {"routes": {}}}
    )
    up: Any = type("Up", (), {"server": staticmethod(slow_server)})()
    async with running_gateway(config, in_memory(up)) as base, agent(f"{base}/mcp/fake/", KEY_A) as client:
        await client.session.call_tool("slow", {"text": "hi", "password": "p"})
    call, result = [line for line in lines(config.audit.path) if line["kind"] in ("call", "result")]
    assert call["decision"] == "forwarding" and call["arguments"] == {"text": "hi", "password": "<redacted>"}
    assert result["decision"] == "allowed" and result["is_error"] is False
    text = "done: hi"
    # Structured content repeats the text, so it is scanned once, not twice.
    assert result["output_chars"] == len(text)
    assert result["output_sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert 50 <= result["upstream_ms"] < 5000  # milliseconds, measured around the upstream call
    assert result["detector"].startswith("rules-") and isinstance(result["scan_ms"], float)


async def test_the_start_line_names_what_is_running(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_GATEWAY_GIT_SHA", "abc1234")
    config = make_config(tmp_path)
    async with running_gateway(config, in_memory(FakeUpstream())):
        pass
    [start] = [line for line in lines(config.audit.path) if line["kind"] == "start"]
    assert start["version"] == __version__ and start["git_sha"] == "abc1234"
    assert start["policy_sha256"] == config.policy_hash() and start["routes"] == ["fake"]
    assert start["detector"].startswith("rules-") and start["chain_problems"] == 0


async def test_a_refused_key_line_records_where_it_came_from(gateway: RunningGateway) -> None:
    async with httpx2.AsyncClient() as http:
        await http.post(gateway.url(), headers={"Authorization": "Bearer nope"}, json={})
    [line] = [x for x in lines(gateway.config.audit.path) if x.get("decision") == "denied"]
    assert line["client"] == "127.0.0.1" and line["path"] == "/mcp/fake/"
    assert len(line["key_fingerprint"]) == 8


class BrokenSession:
    """Lists its tools, then fails every call."""

    async def list_tools(self, params: Any = None) -> Any:  # noqa: ARG002
        from mcp.types import ListToolsResult, Tool

        return ListToolsResult(tools=[Tool(name="echo", description="Echo the text back.", input_schema={})])

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:  # noqa: ARG002
        raise ConnectionError("upstream went away")


class BrokenClient:
    session = BrokenSession()


def route_with(tmp_path: Path, upstream: Any, audit: AuditLog | None = None) -> Route:
    config = make_config(tmp_path)
    return Route(
        "fake", SharedUpstream(upstream), config, audit or AuditLog(config.audit.path, fsync=False), StubDetector()
    )


def ctx() -> Any:
    c: Any = type("Ctx", (), {})()
    c.request = Request({"type": "http", "user": CallerUser("alpha"), "headers": [(b"mcp-session-id", b"s1")]})
    return c


async def test_an_upstream_failure_is_an_upstream_error(tmp_path: Path) -> None:
    route = route_with(tmp_path, BrokenClient())
    with pytest.raises(MCPError) as raised:
        await route._call_tool(ctx(), CallToolRequestParams(name="echo", arguments={"text": "x"}))  # pyright: ignore[reportPrivateUsage]
    assert raised.value.error.code == UPSTREAM_ERROR
    result = [line for line in lines(route.audit.path) if line["kind"] == "result"][-1]
    assert result["decision"] == "upstream_error" and result["error"] == "ConnectionError"
    assert result["call_id"] and result["caller"] == "alpha" and result["tool"] == "echo"


class UnlistableClient:
    """Fails to list its tools, so a call can't be screened (ADR-011)."""

    class session:
        calls = 0

        @staticmethod
        async def list_tools(params: Any = None) -> Any:  # noqa: ARG004
            raise ConnectionError("upstream went away")

        @classmethod
        async def call_tool(cls, name: str, arguments: dict[str, Any]) -> Any:  # noqa: ARG003
            cls.calls += 1


async def test_a_tool_that_cant_be_screened_is_an_upstream_error_and_not_forwarded(tmp_path: Path) -> None:
    route = route_with(tmp_path, UnlistableClient())
    with pytest.raises(MCPError) as raised:
        await route._call_tool(ctx(), CallToolRequestParams(name="echo", arguments={"text": "x"}))  # pyright: ignore[reportPrivateUsage]
    assert raised.value.error.code == UPSTREAM_ERROR and UnlistableClient.session.calls == 0
    call = [line for line in lines(route.audit.path) if line["kind"] == "call"][-1]
    assert call["decision"] == "upstream_error" and call["error"] == "ConnectionError" and call["tool"] == "echo"


async def test_an_unwritable_log_refuses_with_an_internal_error_on_stderr(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    config = make_config(tmp_path)
    audit = AuditLog(config.audit.path, fsync=False)
    audit.close()
    async with Client(FakeUpstream().server()) as upstream:
        route = route_with(tmp_path, upstream, audit)
        with pytest.raises(MCPError) as raised:
            await route._call_tool(ctx(), CallToolRequestParams(name="echo", arguments={"text": "x"}))  # pyright: ignore[reportPrivateUsage]
    assert raised.value.error.code == -32603  # INTERNAL_ERROR
    assert "call refused" in capfd.readouterr().err


async def test_a_denied_call_line_says_why(tmp_path: Path) -> None:
    route = route_with(tmp_path, BrokenClient())
    result = await route._call_tool(ctx(), CallToolRequestParams(name="delete_everything", arguments={}))  # pyright: ignore[reportPrivateUsage]
    assert result.is_error
    [line] = [x for x in lines(route.audit.path) if x.get("decision") == "denied"]
    assert line["kind"] == "call" and line["reason"] == "tool 'delete_everything' not allowed"


# --- the policy hash is stable, and moves when the policy does ------------------


def test_policy_hash_ignores_key_order_and_follows_the_policy(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    data = config.model_dump(mode="json")
    reordered = GatewayConfig.model_validate(dict(reversed(list(data.items()))))
    assert reordered.policy_hash() == config.policy_hash()
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    assert config.policy_hash() == hashlib.sha256(canonical.encode()).hexdigest()
    data["policies"]["echo-only"]["routes"]["fake"]["tools"]["read"] = {}
    assert GatewayConfig.model_validate(data).policy_hash() != config.policy_hash()


# --- the idle reaper --------------------------------------------------------------


async def test_an_idle_session_upstream_is_reaped() -> None:
    opened, closed = [], []

    @contextlib.asynccontextmanager
    async def open_client() -> AsyncIterator[Any]:
        opened.append(1)
        try:
            yield object()
        finally:
            closed.append(1)

    async with anyio.create_task_group() as tasks:
        sessions = PerSessionUpstreams("r", open_client, tasks, idle_timeout_s=0.05, reap_every_s=0.02)
        await sessions.for_session("s1")
        assert sessions.running == 1
        for _ in range(100):
            if closed:
                break
            await anyio.sleep(0.02)
        assert closed == [1] and sessions.running == 0
        await sessions.for_session("s1")  # a later request starts a fresh one
        assert opened == [1, 1]
        sessions.close_all()


async def test_a_busy_session_upstream_is_kept() -> None:
    @contextlib.asynccontextmanager
    async def open_client() -> AsyncIterator[Any]:
        yield object()

    async with anyio.create_task_group() as tasks:
        sessions = PerSessionUpstreams("r", open_client, tasks, idle_timeout_s=0.2, reap_every_s=0.02)
        for _ in range(15):
            await sessions.for_session("s1")
            await anyio.sleep(0.02)
        assert sessions.running == 1 and sessions.started == 1
        sessions.close_all()


# --- the scanner reads JSON arrays and indented JSON too ---------------------------


def test_json_arrays_and_indented_json_are_reduced_to_strings() -> None:
    assert text_for_scanning(json.dumps([{"a": "x"}, "y", 3])) == "x\ny"
    assert text_for_scanning("  \n" + json.dumps({"a": "x"})) == "x"


# --- the session-end hook only acts on a real session delete ---------------------


class Recorder:
    def __init__(self) -> None:
        self.ended: list[tuple[str, str]] = []

    def session_ended(self, session: str, caller: str) -> None:
        self.ended.append((session, caller))


async def run_hook(method: str, path: str, headers: list[tuple[bytes, bytes]], user: Any) -> Recorder:
    from mcp_gateway.app import SessionEndHook

    route = Recorder()

    async def app(scope: Any, receive: Any, send: Any) -> None:  # noqa: ARG001
        return None

    hook = SessionEndHook(app, {"fake": route})  # type: ignore[dict-item]
    scope: dict[str, Any] = {"type": "http", "method": method, "path": path, "headers": headers}
    if user is not None:
        scope["user"] = user
    await hook(scope, None, None)  # type: ignore[arg-type]  # the fake app reads neither
    return route


async def test_the_hook_ends_the_owners_session() -> None:
    route = await run_hook("DELETE", "/mcp/fake/", [(b"mcp-session-id", b"s1")], CallerUser("alpha"))
    assert route.ended == [("s1", "alpha")]


@pytest.mark.parametrize(
    ("method", "path", "headers", "user"),
    [
        ("DELETE", "/mcp/fake/", [], CallerUser("alpha")),  # no session id
        ("DELETE", "/other/fake/", [(b"mcp-session-id", b"s1")], CallerUser("alpha")),  # not an MCP route
        ("DELETE", "/mcp/unknown/", [(b"mcp-session-id", b"s1")], CallerUser("alpha")),  # unknown route
        ("DELETE", "/mcp/fake/", [(b"mcp-session-id", b"s1")], None),  # nobody authenticated
        ("POST", "/mcp/fake/", [(b"mcp-session-id", b"s1")], CallerUser("alpha")),  # not a delete
        ("DELETE", "/", [(b"mcp-session-id", b"s1")], CallerUser("alpha")),  # too short a path
    ],
)
async def test_the_hook_ignores_everything_else(method: str, path: str, headers: Any, user: Any) -> None:
    route = await run_hook(method, path, headers, user)
    assert route.ended == []


# --- session bindings don't grow forever ---------------------------------------


def test_idle_session_bindings_are_forgotten_past_the_cap(tmp_path: Path) -> None:
    import time

    route = route_with(tmp_path, BrokenClient())
    old = time.monotonic() - 10 * 60 * 60  # ten hours ago, past the idle timeout
    route._session_callers = {f"old-{i}": ("alpha", old) for i in range(10_001)}  # pyright: ignore[reportPrivateUsage]
    route._session_callers["recent"] = ("alpha", time.monotonic())  # pyright: ignore[reportPrivateUsage]
    route._caller(ctx())  # a new session ("s1") arrives  # pyright: ignore[reportPrivateUsage]
    assert set(route._session_callers) == {"recent", "s1"}  # pyright: ignore[reportPrivateUsage]


# --- detection off is built from the config, not only injected -----------------


def test_detection_off_builds_the_off_detector() -> None:
    from mcp_gateway.app import build_detector
    from mcp_gateway.config import DetectorSettings
    from mcp_gateway.detect import LayeredDetector

    assert build_detector(DetectorSettings(rules=False)).version == "off"
    rules_only = build_detector(DetectorSettings(rules=True))
    assert isinstance(rules_only, LayeredDetector) and rules_only.version.startswith("rules-")


def test_a_model_that_wont_load_is_a_config_error(tmp_path: Path) -> None:
    from mcp_gateway.app import build_detector
    from mcp_gateway.config import ConfigError, DetectorSettings, ModelSettings

    with pytest.raises(ConfigError, match="can't load the detector model"):
        build_detector(DetectorSettings(model=ModelSettings(dir=tmp_path, threshold=0.999)))
