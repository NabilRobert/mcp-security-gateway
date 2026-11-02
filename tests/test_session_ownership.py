"""A session belongs to the key that opened it, whatever the request. The
check sits in the HTTP layer, so a request on someone else's session never
reaches the MCP SDK: POST, GET and DELETE alike, from the moment the session
is created."""

import json
from pathlib import Path
from typing import Any

import httpx2
import pytest
from conftest import KEY_A, KEY_B, FakeUpstream, in_memory, make_config, running_gateway

pytestmark = pytest.mark.anyio

HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
}
LIST_TOOLS = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}


def as_key(key: str, session: str | None = None) -> dict[str, str]:
    session_header = {"mcp-session-id": session} if session else {}
    return {**HEADERS, "Authorization": f"Bearer {key}", **session_header}


async def open_session(http: httpx2.AsyncClient, url: str) -> str:
    """Key A opens a session. It makes no tool request, so only creating the
    session can have bound it to A."""
    response = await http.post(url, headers=as_key(KEY_A), json=INITIALIZE)
    session = response.headers["mcp-session-id"]
    initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    await http.post(url, headers=as_key(KEY_A, session), json=initialized)
    return session


def audit_lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


async def test_another_key_cannot_end_a_session(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    async with running_gateway(cfg, in_memory(FakeUpstream())) as base, httpx2.AsyncClient(timeout=10) as http:
        url = f"{base}/mcp/fake/"
        session = await open_session(http, url)
        deleted = await http.delete(url, headers=as_key(KEY_B, session))
        still_there = await http.post(url, headers=as_key(KEY_A, session), json=LIST_TOOLS)
    assert deleted.status_code == 404
    assert still_there.status_code == 200


async def test_another_key_cannot_use_a_session_before_its_first_tool_request(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    async with running_gateway(cfg, in_memory(FakeUpstream())) as base, httpx2.AsyncClient(timeout=10) as http:
        url = f"{base}/mcp/fake/"
        session = await open_session(http, url)
        taken = await http.post(url, headers=as_key(KEY_B, session), json=LIST_TOOLS)
        owner = await http.post(url, headers=as_key(KEY_A, session), json=LIST_TOOLS)
    assert taken.status_code == 404
    assert owner.status_code == 200


async def test_another_key_cannot_open_a_sessions_event_stream(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    async with running_gateway(cfg, in_memory(FakeUpstream())) as base, httpx2.AsyncClient(timeout=10) as http:
        url = f"{base}/mcp/fake/"
        session = await open_session(http, url)
        async with http.stream("GET", url, headers=as_key(KEY_B, session)) as stream:
            status = stream.status_code
    assert status == 404


async def test_a_refused_session_request_is_audited_without_the_session_id(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    async with running_gateway(cfg, in_memory(FakeUpstream())) as base, httpx2.AsyncClient(timeout=10) as http:
        url = f"{base}/mcp/fake/"
        session = await open_session(http, url)
        await http.delete(url, headers=as_key(KEY_B, session))
    lines = audit_lines(cfg.audit.path)
    [refused] = [line for line in lines if line.get("decision") == "denied"]
    assert refused["caller"] == "bravo" and refused["route"] == "fake" and "session" in refused["reason"]
    assert session not in cfg.audit.path.read_text()


async def test_the_owner_can_end_its_own_session(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    async with running_gateway(cfg, in_memory(FakeUpstream())) as base, httpx2.AsyncClient(timeout=10) as http:
        url = f"{base}/mcp/fake/"
        session = await open_session(http, url)
        deleted = await http.delete(url, headers=as_key(KEY_A, session))
        gone = await http.post(url, headers=as_key(KEY_A, session), json=LIST_TOOLS)
    assert deleted.status_code == 200
    assert gone.status_code == 404
