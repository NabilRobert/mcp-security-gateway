"""Slice C: the audit log shows tampering, survives a crash, never holds a
secret, and refuses the call when it can't be written."""

import json
from pathlib import Path
from typing import Any

import httpx2
import pytest
from conftest import KEY_A, KEY_B, FakeUpstream, RunningGateway, agent, in_memory, make_config, running_gateway
from mcp import Client
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolRequestParams
from starlette.requests import Request
from typer.testing import CliRunner

from mcp_gateway.audit import AuditLog, verify_chain, verify_log
from mcp_gateway.auth import CallerUser
from mcp_gateway.cli import app as cli
from mcp_gateway.detect import StubDetector
from mcp_gateway.proxy import REDACTED, Route, redact
from mcp_gateway.upstreams import SharedUpstream

pytestmark = pytest.mark.anyio


def write_log(path: Path, n: int = 5) -> None:
    log = AuditLog(path, fsync=False)
    for i in range(n):
        log.append("call", call_id=f"c{i}", decision="denied", reason="test")
    log.close()


def lines(path: Path) -> list[bytes]:
    return path.read_bytes().splitlines(keepends=True)


def test_a_fresh_log_verifies(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    write_log(path)
    assert verify_chain(path) == []


def test_the_chain_continues_across_a_restart(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    write_log(path, 3)
    write_log(path, 3)
    assert len(lines(path)) == 6 and verify_chain(path) == []


@pytest.mark.parametrize("tamper", ["edit", "insert", "delete-middle", "delete-first", "reorder"])
def test_tampering_breaks_the_chain(tmp_path: Path, tamper: str) -> None:
    path = tmp_path / "a.jsonl"
    write_log(path)
    rows = lines(path)
    if tamper == "edit":
        rows[2] = rows[2].replace(b'"denied"', b'"allowed"')
    elif tamper == "insert":
        rows.insert(2, rows[1])
    elif tamper == "delete-middle":
        del rows[2]
    elif tamper == "delete-first":
        del rows[0]
    else:
        rows[1], rows[2] = rows[2], rows[1]
    path.write_bytes(b"".join(rows))
    assert verify_chain(path), f"{tamper} was not detected"


def test_a_torn_last_line_is_recovered_not_reported_as_tampering(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    write_log(path, 3)
    with path.open("ab") as f:
        f.write(b'{"kind":"call","call_id":"half-writ')  # a crash mid-write
    write_log(path, 2)  # the next start
    report = verify_log(path)
    assert report.problems == []
    assert len(report.recoveries) == 1
    recovered = json.loads(lines(path)[4])
    assert recovered["kind"] == "recovered" and recovered["torn_bytes"] == len(b'{"kind":"call","call_id":"half-writ')


def test_garbage_in_the_middle_is_tampering(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    write_log(path)
    rows = lines(path)
    rows.insert(2, b"not json at all\n")
    path.write_bytes(b"".join(rows))
    assert any("not valid JSON" in p for p in verify_chain(path))


def test_a_forwarded_call_without_a_result_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    log = AuditLog(path, fsync=False)
    log.append("call", call_id="done", decision="forwarding")
    log.append("result", call_id="done", decision="allowed")
    log.append("call", call_id="lost", decision="forwarding")
    log.close()
    report = verify_log(path)
    assert report.problems == []
    assert len(report.unfinished_calls) == 1 and "lost" in report.unfinished_calls[0]


def test_redaction_reaches_nested_values() -> None:
    args = {
        "query": "select 1",
        "api_key": "sk-1",
        "options": {"Authorization": "Bearer x", "depth": 2, "inner": [{"password": "p"}, {"name": "ok"}]},
        "session_token": "t",
        "Cookie": "c",
    }
    assert redact(args) == {
        "query": "select 1",
        "api_key": REDACTED,
        "options": {"Authorization": REDACTED, "depth": 2, "inner": [{"password": REDACTED}, {"name": "ok"}]},
        "session_token": REDACTED,
        "Cookie": REDACTED,
    }


def test_cli_verify_log_exit_codes(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    write_log(path)
    ok = CliRunner().invoke(cli, ["verify-log", str(path)])
    assert ok.exit_code == 0 and "chain intact" in ok.stdout
    rows = lines(path)
    del rows[1]
    path.write_bytes(b"".join(rows))
    bad = CliRunner().invoke(cli, ["verify-log", str(path)])
    assert bad.exit_code == 1 and "the log was altered" in bad.stdout


# --- the gateway side -------------------------------------------------------


class FakeSession:
    pass


async def test_a_call_is_refused_when_the_log_cant_be_written(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    audit = AuditLog(config.audit.path, fsync=False)
    audit.close()  # every write now fails
    fake = FakeUpstream()
    async with Client(fake.server()) as upstream:
        route = Route("fake", SharedUpstream(upstream), config, audit, StubDetector())
        ctx: Any = type("Ctx", (), {})()
        ctx.session = FakeSession()
        ctx.request = Request({"type": "http", "user": CallerUser("alpha"), "headers": []})
        with pytest.raises(MCPError, match="audit log"):
            await route._call_tool(ctx, CallToolRequestParams(name="echo", arguments={"text": "hi"}))  # pyright: ignore[reportPrivateUsage]
    assert fake.calls == []


async def test_start_reports_a_broken_chain_and_still_starts(tmp_path: Path, capfd: pytest.CaptureFixture[str]) -> None:
    config = make_config(tmp_path)
    write_log(config.audit.path)
    rows = lines(config.audit.path)
    del rows[1]
    config.audit.path.write_bytes(b"".join(rows))
    async with running_gateway(config, in_memory(FakeUpstream())) as base:
        async with httpx2.AsyncClient() as http:
            assert (await http.get(f"{base}/healthz")).status_code == 200
    assert "chain broken" in capfd.readouterr().err
    start = next(json.loads(r) for r in lines(config.audit.path) if b'"kind":"start"' in r)
    assert start["chain_problems"] >= 1


async def test_no_key_reaches_stderr_or_the_log(gateway: RunningGateway, capfd: pytest.CaptureFixture[str]) -> None:
    wrong = "an-unknown-key-that-must-not-be-printed"
    async with agent(gateway.url(), KEY_A) as client:
        await client.session.call_tool("echo", {"text": "hi"})
    async with agent(gateway.url(), KEY_B) as client:
        await client.session.call_tool("read", {"path": "docs/x"})
    async with httpx2.AsyncClient() as http:
        await http.post(gateway.url(), headers={"Authorization": f"Bearer {wrong}"}, json={})
    captured = capfd.readouterr()
    everything = captured.out + captured.err + gateway.config.audit.path.read_text()
    for key in (KEY_A, KEY_B, wrong):
        assert key not in everything
