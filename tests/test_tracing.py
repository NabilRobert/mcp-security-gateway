"""OpenTelemetry tracing (Project 6 slice 4, ADR-014): one trace from the
agent through the gateway to the upstream, outcomes without content, and a
dead viewer that changes nothing."""

import json
import socket
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal

import pytest
from conftest import KEY_A, TRACING, FakeUpstream, agent, in_memory, make_config, running_gateway
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind, StatusCode
from test_detection import INJECTION
from test_meta_passthrough import PROTOCOL_PREFIX, echo_gateway, meta_seen_upstream

from mcp_gateway import app, tracing
from mcp_gateway.config import GatewayConfig

pytestmark = pytest.mark.anyio

SENTINEL = "sentinel-7f3a-must-not-appear-in-spans"
MCP_SDK = "mcp-python-sdk"


@pytest.fixture
def spans() -> Iterator[InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    TRACING.active = provider
    try:
        yield exporter
    finally:
        TRACING.active = None
        provider.shutdown()


def sid(span: ReadableSpan) -> int:
    assert span.context is not None
    return span.context.span_id


def tid(span: ReadableSpan) -> int:
    assert span.context is not None
    return span.context.trace_id


def by_id(finished: tuple[ReadableSpan, ...]) -> dict[int, ReadableSpan]:
    return {sid(s): s for s in finished}


def ancestors(span: ReadableSpan, index: dict[int, ReadableSpan]) -> list[str]:
    names: list[str] = []
    while span.parent is not None and span.parent.span_id in index:
        span = index[span.parent.span_id]
        names.append(span.name)
    return names


def children(parent: ReadableSpan, finished: tuple[ReadableSpan, ...]) -> list[str]:
    kids = [s for s in finished if s.parent is not None and s.parent.span_id == sid(parent)]
    return [s.name for s in sorted(kids, key=lambda s: s.start_time or 0)]


@pytest.mark.parametrize("transport", ["http", "stdio"])
async def test_one_trace_from_the_agent_through_the_gateway_to_the_upstream(
    tmp_path: Path, spans: InMemorySpanExporter, transport: Literal["http", "stdio"]
) -> None:
    sent = {"io.github.nabilrobert.juku/delegation": "token-abc", "example.com/nested": {"n": [1, 2.5, None]}}
    async with echo_gateway(tmp_path, transport) as url:
        with TRACING.get_tracer("test-agent").start_as_current_span("agent turn"):
            seen = await meta_seen_upstream(url, sent)
    # Start-up (the gateway listing its upstreams' tools) makes traces of its
    # own; the agent's call is one trace.
    [turn] = [s for s in spans.get_finished_spans() if s.name == "agent turn"]
    finished = tuple(s for s in spans.get_finished_spans() if tid(s) == tid(turn))
    index = by_id(finished)

    calls = [s for s in finished if s.name == "tools/call show_meta" and s.kind == SpanKind.SERVER]
    [gateway_call] = [s for s in calls if s.attributes and s.attributes.get("mcp_gateway.route") == "echo"]
    assert "agent turn" in ancestors(gateway_call, index)
    assert children(gateway_call, finished) == ["rate_limit", "policy", "audit", "forward", "detect", "audit"]

    # The upstream request is the SDK's CLIENT span inside `forward`, and
    # the context it injected is what the upstream received.
    [forward] = [s for s in finished if s.name == "forward"]
    [upstream_request] = [s for s in finished if s.parent and s.parent.span_id == sid(forward)]
    assert upstream_request.kind == SpanKind.CLIENT
    _, trace_id, span_id, _ = seen["traceparent"].split("-")
    assert int(trace_id, 16) == tid(gateway_call)
    assert int(span_id, 16) == sid(upstream_request)
    if transport == "http":  # in-process, so its spans are exported here too
        [upstream_call] = [s for s in calls if s is not gateway_call]
        assert upstream_call.parent is not None and upstream_call.parent.span_id == sid(upstream_request)

    # Every other `_meta` key arrives as it was sent.
    rest = {
        k: v for k, v in seen.items() if not k.startswith(PROTOCOL_PREFIX) and k not in ("traceparent", "tracestate")
    }
    assert rest == {**sent, "io.github.nabilrobert.mcp-gateway/caller": "alpha"}


def content_config(tmp_path: Path, rate_limit: str | None = None) -> GatewayConfig:
    data = make_config(tmp_path).model_dump(mode="json")
    data["callers"]["alpha"]["rate_limit"] = rate_limit
    data["detector"] = {"rules": True}
    return GatewayConfig.model_validate(data)


def everything_in(finished: tuple[ReadableSpan, ...]) -> str:
    """All text a viewer could show: names, attributes, events, statuses."""
    parts: list[str] = []
    for s in finished:
        parts += [s.name, json.dumps(dict(s.attributes or {}), default=str), s.status.description or ""]
        parts += [e.name + json.dumps(dict(e.attributes or {}), default=str) for e in s.events]
        parts += [json.dumps(dict(s.resource.attributes), default=str)]
    return "\n".join(parts)


async def test_no_argument_output_or_reason_reaches_a_span(tmp_path: Path, spans: InMemorySpanExporter) -> None:
    cfg = content_config(tmp_path)
    async with running_gateway(cfg, in_memory(FakeUpstream())) as base, agent(f"{base}/mcp/fake/", KEY_A) as client:
        allowed = await client.session.call_tool("echo", {"text": SENTINEL})  # output quotes the argument
        denied = await client.session.call_tool("read", {"path": f"secret/{SENTINEL}"})  # the reason quotes it
        blocked = await client.session.call_tool("echo", {"text": f"{SENTINEL} {INJECTION}"})
    assert not allowed.is_error and denied.is_error and blocked.is_error
    assert SENTINEL not in everything_in(spans.get_finished_spans())


def stage_of(finished: tuple[ReadableSpan, ...], name: str, call_id: str) -> ReadableSpan:
    index = by_id(finished)
    for s in finished:
        parent = index.get(s.parent.span_id) if s.parent else None
        if s.name == name and parent is not None and (parent.attributes or {}).get("mcp_gateway.call_id") == call_id:
            return s
    raise AssertionError(f"no {name} span for {call_id}")


async def test_each_outcome_is_an_error_type_on_its_stage(tmp_path: Path, spans: InMemorySpanExporter) -> None:
    cfg = content_config(tmp_path, rate_limit="3/minute")
    async with running_gateway(cfg, in_memory(FakeUpstream())) as base, agent(f"{base}/mcp/fake/", KEY_A) as client:
        await client.session.call_tool("echo", {"text": "fine"})
        await client.session.call_tool("read", {"path": "secret/x"})
        await client.session.call_tool("echo", {"text": INJECTION})
        await client.session.call_tool("echo", {"text": "over the limit"})
    calls = [json.loads(line) for line in cfg.audit.path.read_text().splitlines()]
    ids = [c["call_id"] for c in calls if c["kind"] == "call"]
    finished = spans.get_finished_spans()
    calls_by_id = {(s.attributes or {}).get("mcp_gateway.call_id"): s for s in finished}

    def outcome(span: ReadableSpan) -> tuple[Any, StatusCode]:
        return (span.attributes or {}).get("error.type"), span.status.status_code

    allowed, denied, blocked, limited = ids
    assert outcome(stage_of(finished, "detect", allowed)) == (None, StatusCode.UNSET)
    assert calls_by_id[allowed].attributes["mcp_gateway.decision"] == "allowed"  # type: ignore[index]
    assert outcome(stage_of(finished, "policy", denied)) == ("denied", StatusCode.ERROR)
    assert calls_by_id[denied].attributes["mcp_gateway.decision"] == "denied"  # type: ignore[index]
    detect = stage_of(finished, "detect", blocked)
    assert outcome(detect) == ("blocked_suspicious", StatusCode.ERROR)
    assert detect.attributes is not None and "override-instructions" in detect.attributes["mcp_gateway.detect.matched"]  # type: ignore[operator]
    assert detect.attributes["mcp_gateway.detect.suspicious"] is True
    assert outcome(stage_of(finished, "rate_limit", limited)) == ("rate_limited", StatusCode.ERROR)
    assert calls_by_id[limited].attributes["mcp_gateway.decision"] == "rate_limited"  # type: ignore[index]
    assert all(
        s.status.description is None
        for s in finished
        if s.instrumentation_scope and s.instrumentation_scope.name == "mcp-gateway"
    )


def closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])  # closed again on return: nothing listens


def test_no_endpoint_no_exporter() -> None:
    assert tracing.build_provider({}) is None
    assert tracing.build_provider({"OTEL_EXPORTER_OTLP_ENDPOINT": "http://x:4318", "OTEL_SDK_DISABLED": "true"}) is None
    assert tracing.build_provider({"OTEL_EXPORTER_OTLP_ENDPOINT": "http://x:4318"}) is not None
    assert tracing.build_provider({"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://x:4318/v1/traces"}) is not None


def test_a_dead_viewer_cant_hold_up_the_shutdown() -> None:
    provider = tracing.build_provider({"OTEL_EXPORTER_OTLP_ENDPOINT": f"http://127.0.0.1:{closed_port()}"})
    assert provider is not None
    assert provider.resource.attributes["service.name"] == "mcp-gateway"
    tracer = provider.get_tracer("load")
    for _ in range(5000):  # more than one batch queued
        with tracer.start_as_current_span("x"):
            pass
    start = time.monotonic()
    tracing.shutdown_tracing(provider, timeout_s=1.0)
    assert time.monotonic() - start < 1.5


async def test_a_dead_viewer_changes_nothing_for_calls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", f"http://127.0.0.1:{closed_port()}")
    shut: list[Any] = []
    monkeypatch.setattr(app, "shutdown_tracing", lambda p: shut.append(p) or tracing.shutdown_tracing(p))
    fake = FakeUpstream()
    start = time.monotonic()
    async with (
        running_gateway(content_config(tmp_path), in_memory(fake)) as base,
        agent(f"{base}/mcp/fake/", KEY_A) as client,
    ):
        result = await client.session.call_tool("echo", {"text": "hi"})
    assert not result.is_error and fake.calls == [("echo", {"text": "hi"})]
    assert len(shut) == 1 and time.monotonic() - start < 10
