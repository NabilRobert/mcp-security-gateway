"""Slice B, end to end: auth before any MCP session, per-caller policy, and
the proof that a refused call never reaches the upstream."""

import json
from dataclasses import dataclass
from typing import Any

import httpx2
import pytest
from conftest import KEY_A, KEY_B, RunningGateway, agent, make_config
from mcp.shared.exceptions import MCPError
from starlette.requests import Request

from mcp_gateway.audit import AuditLog
from mcp_gateway.auth import CallerUser, fingerprint
from mcp_gateway.detect import StubDetector
from mcp_gateway.proxy import Route

pytestmark = pytest.mark.anyio

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}},
}
HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def log_text(gw: RunningGateway) -> str:
    return gw.config.audit.path.read_text()


def denied_lines(gw: RunningGateway) -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in log_text(gw).splitlines()]
    return [line for line in lines if line.get("decision") == "denied"]


@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Bearer wrong-key"}, {"Authorization": f"Basic {KEY_A}"}, {"Authorization": "Bearer"}],
    ids=["no-header", "wrong-key", "not-bearer", "empty-key"],
)
async def test_bad_keys_get_401_before_any_session(gateway: RunningGateway, headers: dict[str, str]) -> None:
    async with httpx2.AsyncClient() as http:
        response = await http.post(gateway.url(), headers={**HEADERS, **headers}, json=INITIALIZE)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert "mcp-session-id" not in response.headers
    assert gateway.upstream.calls == []
    [line] = denied_lines(gateway)
    assert line["reason"].startswith("auth: ")


async def test_a_refused_key_is_logged_by_fingerprint_only(gateway: RunningGateway) -> None:
    wrong = "a-wrong-key-that-must-not-appear-in-the-log"
    async with httpx2.AsyncClient() as http:
        await http.post(gateway.url(), headers={**HEADERS, "Authorization": f"Bearer {wrong}"}, json=INITIALIZE)
    [line] = denied_lines(gateway)
    assert line["key_fingerprint"] == fingerprint(wrong)
    assert wrong not in log_text(gateway)


async def test_each_caller_sees_only_its_own_tools(gateway: RunningGateway) -> None:
    async with agent(gateway.url(), KEY_B) as client:
        tools = await client.list_tools()
    assert [t.name for t in tools.tools] == ["echo"]


async def test_a_denied_tool_is_refused_and_never_forwarded(gateway: RunningGateway) -> None:
    async with agent(gateway.url(), KEY_B) as client:
        result = await client.session.call_tool("read", {"path": "docs/a.md"})
        unlisted = await client.session.call_tool("delete_everything", {})
    assert result.is_error and "Denied by gateway policy" in result.content[0].text  # type: ignore[union-attr]
    assert unlisted.is_error
    assert gateway.upstream.calls == []
    assert [line["tool"] for line in denied_lines(gateway)] == ["read", "delete_everything"]


async def test_argument_rules_refuse_traversal(gateway: RunningGateway) -> None:
    async with agent(gateway.url(), KEY_A) as client:
        inside = await client.session.call_tool("read", {"path": "docs/guide.md"})
        outside = await client.session.call_tool("read", {"path": "docs/../.env"})
    assert not inside.is_error
    assert outside.is_error
    assert gateway.upstream.calls == [("read", {"path": "docs/guide.md"})]


async def test_no_key_ever_reaches_the_log(gateway: RunningGateway) -> None:
    async with agent(gateway.url(), KEY_A) as client:
        await client.session.call_tool("echo", {"text": "hi"})
    async with agent(gateway.url(), KEY_B) as client:
        await client.session.call_tool("read", {"path": "x"})
    text = log_text(gateway)
    assert KEY_A not in text and KEY_B not in text


async def test_secret_looking_arguments_are_redacted_in_the_log(gateway: RunningGateway) -> None:
    async with agent(gateway.url(), KEY_B) as client:
        await client.session.call_tool("echo", {"text": "hi", "api_key": "sk-live-123"})
    assert "sk-live-123" not in log_text(gateway)


# --- the session is bound to the caller that opened it ----------------------


class FakeSession:
    """Stands in for a ServerSession (which, unlike `object()`, can be weakly referenced)."""


@dataclass
class FakeCtx:
    session: object
    request: Request


def ctx_for(session: object, caller: str) -> FakeCtx:
    return FakeCtx(session, Request({"type": "http", "user": CallerUser(caller), "headers": []}))


def test_a_session_cannot_switch_callers(tmp_path: Any) -> None:
    config = make_config(tmp_path)
    route = Route("fake", None, config, AuditLog(config.audit.path, fsync=False), StubDetector())  # type: ignore[arg-type]
    session = FakeSession()
    assert route._caller(ctx_for(session, "alpha")) == "alpha"  # type: ignore[arg-type]
    assert route._caller(ctx_for(session, "alpha")) == "alpha"  # type: ignore[arg-type]
    with pytest.raises(MCPError, match="another caller"):
        route._caller(ctx_for(session, "bravo"))  # type: ignore[arg-type]
    assert route._caller(ctx_for(FakeSession(), "bravo")) == "bravo"  # type: ignore[arg-type]


def test_an_unauthenticated_request_fails_closed(tmp_path: Any) -> None:
    config = make_config(tmp_path)
    route = Route("fake", None, config, AuditLog(config.audit.path, fsync=False), StubDetector())  # type: ignore[arg-type]
    bare = FakeCtx(FakeSession(), Request({"type": "http", "headers": []}))
    with pytest.raises(MCPError, match="unauthenticated"):
        route._caller(bare)  # type: ignore[arg-type]
