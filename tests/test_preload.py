"""The SDK client's output-schema validation is loaded at start-up, so the
first call through a gateway doesn't stall on importing it (Project 6's
trace: 205 ms in `forward`, in no span)."""

import subprocess
import sys
from pathlib import Path

import pytest
from conftest import FakeUpstream, in_memory, make_config, running_gateway

from mcp_gateway import app

pytestmark = pytest.mark.anyio


def test_preloading_imports_jsonschema_in_a_fresh_process() -> None:
    code = (
        "import sys; from mcp_gateway.app import preload_output_validation; "
        "assert 'jsonschema' not in sys.modules; preload_output_validation(); "
        "assert 'jsonschema.validators' in sys.modules and 'referencing' in sys.modules"
    )
    subprocess.run([sys.executable, "-c", code], check=True)  # noqa: S603  (fixed code)


async def test_serving_preloads_before_the_first_call(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[bool] = []
    monkeypatch.setattr(app, "preload_output_validation", lambda: calls.append(True))
    async with running_gateway(make_config(tmp_path), in_memory(FakeUpstream())):
        assert calls == [True]
