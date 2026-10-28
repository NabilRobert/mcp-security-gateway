"""A SIGTERM (systemd, docker stop) stops the gateway cleanly: the audit
log gets its stop line, and queued spans are flushed before the process
exits. uvicorn re-raises the signal after its own shutdown, which used to
kill the process before any of that ran (found by Project 6)."""

import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml
from conftest import KEY_A, agent, free_port, make_config
from meta_echo_server import TOOL

pytestmark = pytest.mark.anyio

ECHO_SERVER = Path(__file__).with_name("meta_echo_server.py")


@contextmanager
def collector() -> Iterator[tuple[str, list[str]]]:
    """A stand-in OTLP endpoint that records the paths posted to it."""
    posted: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            posted.append(self.path)
            self.send_response(200)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", posted
    finally:
        server.shutdown()


def wait_healthy(port: int, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        assert process.poll() is None, "the gateway exited during start-up"
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise AssertionError("the gateway didn't become healthy")


async def test_sigterm_flushes_spans_and_logs_the_stop(tmp_path: Path) -> None:
    data = make_config(tmp_path).model_dump(mode="json")
    data["upstreams"] = {"echo": {"transport": "stdio", "command": sys.executable, "args": [str(ECHO_SERVER)]}}
    data["policies"] = {"reader": {"routes": {"echo": {"tools": {TOOL: {}}}}}, "echo-only": {"routes": {}}}
    config = tmp_path / "gateway.yaml"
    config.write_text(yaml.safe_dump(data))
    port = free_port()
    with collector() as (endpoint, posted):
        env = {
            **os.environ,
            "OTEL_EXPORTER_OTLP_ENDPOINT": endpoint,
            "OTEL_BSP_SCHEDULE_DELAY": "60000",  # nothing is sent until the shutdown flushes
        }
        process = subprocess.Popen(  # noqa: S603  (this repo's own CLI)
            [sys.executable, "-m", "mcp_gateway.cli", "serve", "--config", str(config), "--port", str(port)],
            env=env,
            stderr=subprocess.PIPE,
        )
        try:
            wait_healthy(port, process)
            async with agent(f"http://127.0.0.1:{port}/mcp/echo/", KEY_A) as client:
                assert not (await client.session.call_tool(TOOL, {})).is_error
            assert posted == []
            process.send_signal(signal.SIGTERM)
            code = process.wait(timeout=15)
        finally:
            if process.poll() is None:
                process.kill()
        stderr = process.stderr.read().decode() if process.stderr else ""
        assert code == 0, stderr
        assert "/v1/traces" in posted
    lines = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert lines[-1]["kind"] == "stop"
