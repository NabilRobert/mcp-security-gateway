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


async def test_healthz_needs_no_key_and_says_nothing_sensitive(gateway: RunningGateway) -> None:
    async with httpx2.AsyncClient() as http:
        response = await http.get(f"{gateway.base}/healthz")
    assert response.status_code == 200
    assert set(response.json()) == {"status", "version"}


@pytest.mark.parametrize("path", ["/healthz/", "/healthzx", "/docs", "/openapi.json", "/"])
async def test_only_the_exact_health_path_is_open(gateway: RunningGateway, path: str) -> None:
    async with httpx2.AsyncClient() as http:
        response = await http.get(f"{gateway.base}{path}")
    assert response.status_code == 401


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
async def test_no_api_docs_even_with_a_key(gateway: RunningGateway, path: str) -> None:
    async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {KEY_A}"}) as http:
        response = await http.get(f"{gateway.base}{path}")
    assert response.status_code == 404


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


@dataclass
class FakeCtx:
    request: Request


def ctx_for(session: str | None, caller: str | None) -> FakeCtx:
    headers = [(b"mcp-session-id", session.encode())] if session else []
    scope: dict[str, Any] = {"type": "http", "headers": headers}
    if caller is not None:
        scope["user"] = CallerUser(caller)
    return FakeCtx(Request(scope))


def make_route(tmp_path: Any) -> Route:
    config = make_config(tmp_path)
    return Route("fake", None, config, AuditLog(config.audit.path, fsync=False), StubDetector())  # type: ignore[arg-type]


def test_a_session_cannot_switch_callers(tmp_path: Any) -> None:
    route = make_route(tmp_path)
    assert route._caller(ctx_for("s1", "alpha")) == "alpha"  # type: ignore[arg-type]
    assert route._caller(ctx_for("s1", "alpha")) == "alpha"  # type: ignore[arg-type]
    with pytest.raises(MCPError, match="another caller"):
        route._caller(ctx_for("s1", "bravo"))  # type: ignore[arg-type]
    assert route._caller(ctx_for("s2", "bravo")) == "bravo"  # type: ignore[arg-type]


def test_only_the_owner_can_end_a_session(tmp_path: Any) -> None:
    route = make_route(tmp_path)
    ended: list[str] = []

    class Recorder:
        def end(self, session: str) -> None:
            ended.append(session)

    route.upstreams = Recorder()  # type: ignore[assignment]
    route._caller(ctx_for("s1", "alpha"))  # type: ignore[arg-type]
    route.session_ended("s1", "bravo")
    assert ended == []
    route.session_ended("s1", "alpha")
    assert ended == ["s1"]


def test_an_unauthenticated_request_fails_closed(tmp_path: Any) -> None:
    with pytest.raises(MCPError, match="unauthenticated"):
        make_route(tmp_path)._caller(ctx_for("s1", None))  # type: ignore[arg-type]


async def test_another_callers_key_cant_use_a_session_over_http(gateway: RunningGateway) -> None:
    """The real path: the SDK builds a new session object per request, so the
    binding must hold on the Mcp-Session-Id itself."""
    async with httpx2.AsyncClient() as http:
        opened = await http.post(
            gateway.url(), headers={**HEADERS, "Authorization": f"Bearer {KEY_A}"}, json=INITIALIZE
        )
        session = opened.headers["mcp-session-id"]
        session_headers = {**HEADERS, "mcp-session-id": session, "mcp-protocol-version": "2025-11-25"}
        await http.post(
            gateway.url(),
            headers={**session_headers, "Authorization": f"Bearer {KEY_A}"},
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        list_tools = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        own = await http.post(
            gateway.url(), headers={**session_headers, "Authorization": f"Bearer {KEY_A}"}, json=list_tools
        )
        other = await http.post(
            gateway.url(), headers={**session_headers, "Authorization": f"Bearer {KEY_B}"}, json=list_tools
        )
    assert own.status_code == 200 and "echo" in own.text
    assert "another caller" in other.text and "echo" not in other.text
