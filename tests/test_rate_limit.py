"""The per-key call limit (ADR-012)."""

import json
from pathlib import Path
from typing import Any

import anyio
import pytest
from conftest import KEY_A, KEY_B, FakeUpstream, agent, in_memory, make_config, running_gateway
from mcp.types import CallToolResult, TextContent

from mcp_gateway.config import GatewayConfig
from mcp_gateway.ratelimit import CallLimiter

pytestmark = pytest.mark.anyio


def limited(tmp_path: Path, rate_limit: str | None = "2/minute") -> GatewayConfig:
    """alpha is limited; bravo isn't. Two routes onto the same fake upstream."""
    data = make_config(tmp_path).model_dump(mode="json")
    data["upstreams"]["other"] = data["upstreams"]["fake"]
    data["callers"]["alpha"]["rate_limit"] = rate_limit
    for policy in data["policies"].values():
        policy["routes"]["other"] = {"tools": {"echo": {}}}
    return GatewayConfig.model_validate(data)


def text(result: CallToolResult) -> str:
    return "\n".join(c.text for c in result.content if isinstance(c, TextContent))


def audit(cfg: GatewayConfig) -> list[dict[str, Any]]:
    return [json.loads(line) for line in cfg.audit.path.read_text().splitlines()]


async def test_past_the_limit_a_call_is_refused_and_never_forwarded(tmp_path: Path) -> None:
    fake, cfg = FakeUpstream(), limited(tmp_path)
    async with running_gateway(cfg, in_memory(fake)) as base, agent(f"{base}/mcp/fake/", KEY_A) as client:
        results = [await client.session.call_tool("echo", {"text": str(i)}) for i in range(3)]
    assert [r.is_error for r in results] == [False, False, True]
    assert "call limit (2 per 1 minute) is used up" in text(results[2])
    assert fake.calls == [("echo", {"text": "0"}), ("echo", {"text": "1"})]
    refused = [line for line in audit(cfg) if line.get("decision") == "rate_limited"]
    assert len(refused) == 1 and refused[0]["caller"] == "alpha" and refused[0]["limit"] == "2 per 1 minute"


async def test_the_limit_spans_routes_and_is_per_key(tmp_path: Path) -> None:
    fake, cfg = FakeUpstream(), limited(tmp_path)
    async with (
        running_gateway(cfg, in_memory(fake)) as base,
        agent(f"{base}/mcp/fake/", KEY_A) as on_fake,
        agent(f"{base}/mcp/other/", KEY_A) as on_other,
        agent(f"{base}/mcp/other/", KEY_B) as bravo,
    ):
        await on_fake.session.call_tool("echo", {"text": "a"})
        await on_fake.session.call_tool("echo", {"text": "b"})
        third = await on_other.session.call_tool("echo", {"text": "c"})
        others = [await bravo.session.call_tool("echo", {"text": "d"}) for _ in range(3)]
    assert third.is_error and "call limit" in text(third)
    assert not any(r.is_error for r in others)


async def test_denied_calls_count_too(tmp_path: Path) -> None:
    fake, cfg = FakeUpstream(), limited(tmp_path)
    async with running_gateway(cfg, in_memory(fake)) as base, agent(f"{base}/mcp/fake/", KEY_A) as client:
        await client.session.call_tool("delete_everything", {})
        await client.session.call_tool("delete_everything", {})
        allowed_tool = await client.session.call_tool("echo", {"text": "x"})
    assert allowed_tool.is_error and "call limit" in text(allowed_tool)
    assert fake.calls == []


async def test_a_call_refused_by_one_window_doesnt_use_up_another(tmp_path: Path) -> None:
    """The hour window is listed first: counting it before testing the
    second window would spend it on a refused call."""
    limiter = CallLimiter(limited(tmp_path, "2/hour; 1/second"))
    assert await limiter.take("alpha") is None
    assert await limiter.take("alpha") == "1 per 1 second"
    await anyio.sleep(1.1)
    assert await limiter.take("alpha") is None
    assert await limiter.take("alpha") == "2 per 1 hour"


async def test_no_limit_means_no_limit(tmp_path: Path) -> None:
    limiter = CallLimiter(limited(tmp_path, None))
    for _ in range(50):
        assert await limiter.take("alpha") is None


@pytest.mark.parametrize("bad", ["lots", "10/fortnight", ""])
def test_a_malformed_limit_is_a_config_error(tmp_path: Path, bad: str) -> None:
    with pytest.raises(ValueError, match="rate_limit"):
        limited(tmp_path, bad)
