"""OpenTelemetry tracing, off unless an OTLP endpoint is configured.

The MCP SDK already opens a SERVER span per request (`tools/call <tool>`),
parented on the trace context in the request's `_meta`, and a CLIENT span
per upstream request, injecting the current context into that request's
`_meta`. So the gateway only installs an exporter, and opens one child span
per stage of a call (`rate_limit`, `policy`, `audit`, `forward`, `detect`).
Because the upstream call runs inside `forward`, the upstream's own spans
nest under the gateway's.

Spans carry outcomes, never content: no tool arguments, outputs, denial
reasons or exception messages, any of which can quote what the agent sent
(Project 6 conventions, rule 5). Decisions, detector verdicts, rule IDs,
counts and timings are fine.

Follows MCP-backbone's `app/tracing.py` (NabilRobert/MCP-backbone at
5f38bd2): the same environment variables, export timeout and capped
shutdown. It can't be imported from there, since it reads that server's own
settings.
"""

import os
import sys
import threading
from collections.abc import Generator, Mapping
from contextlib import contextmanager

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import Span, SpanKind, StatusCode
from opentelemetry.util.types import Attributes

from mcp_gateway import __version__

# Hands out no-op spans until a provider is installed, so the proxy can use
# it unconditionally.
tracer = trace.get_tracer("mcp-gateway")

# The exporter's default (10 s, plus retries) lets a dead viewer hold up a
# shutdown; MCP-backbone measured 6.5 s. 2 s per export, and 2 s for the
# whole shutdown, since a shutdown flushes every queued batch.
DEFAULT_EXPORT_TIMEOUT_S = 2.0
SHUTDOWN_TIMEOUT_S = 2.0


def build_span_processor(env: Mapping[str, str] = os.environ) -> SpanProcessor | None:
    """The background exporter, or None when no endpoint is set. Reads the
    standard variables the way the SDK does: the traces-only endpoint as
    given, the general one with /v1/traces added."""
    if env.get("OTEL_SDK_DISABLED", "").strip().lower() == "true":
        return None
    base = env.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    endpoint = env.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") or (f"{base.rstrip('/')}/v1/traces" if base else "")
    if not endpoint:
        return None
    timeout = env.get("OTEL_EXPORTER_OTLP_TRACES_TIMEOUT") or env.get("OTEL_EXPORTER_OTLP_TIMEOUT")
    return BatchSpanProcessor(
        OTLPSpanExporter(endpoint=endpoint, timeout=float(timeout) if timeout else DEFAULT_EXPORT_TIMEOUT_S)
    )


def build_provider(env: Mapping[str, str] = os.environ) -> TracerProvider | None:
    processor = build_span_processor(env)
    if processor is None:
        return None
    resource = Resource.create(
        {"service.name": env.get("OTEL_SERVICE_NAME") or "mcp-security-gateway", "service.version": __version__}
    )
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(processor)
    return provider


def configure_tracing() -> TracerProvider | None:
    """Installs the global provider when an endpoint is set, and returns it
    for the shutdown. Never raises: a gateway without traces beats one that
    won't start."""
    try:
        provider = build_provider()
        if provider is not None:
            trace.set_tracer_provider(provider)
        return provider
    except Exception as exc:  # see the docstring
        print(f"mcp-gateway: tracing not enabled: {type(exc).__name__}", file=sys.stderr)
        return None


def shutdown_tracing(provider: TracerProvider, timeout_s: float = SHUTDOWN_TIMEOUT_S) -> bool:
    """Flushes and stops the exporter, waiting at most `timeout_s`, so a dead
    viewer can't hold up a stop. Spans still queued then are lost: traces
    are a view, the audit log is the record. Returns whether it finished."""
    flusher = threading.Thread(target=provider.shutdown, name="tracing-shutdown", daemon=True)
    flusher.start()
    flusher.join(timeout_s)
    if flusher.is_alive():
        print(f"mcp-gateway: tracing: gave up flushing spans after {timeout_s:.0f} s", file=sys.stderr)
        return False
    return True


def mark(span: Span, error_type: str) -> None:
    """The outcome that ended a call at this stage. No status message: it's
    free text, and a reason can quote the call."""
    span.set_attribute("error.type", error_type)
    span.set_status(StatusCode.ERROR)


@contextmanager
def stage(name: str, *, attributes: Attributes = None) -> Generator[Span]:
    """One stage of a call, as a child of the current span. An exception
    escaping it is marked with its class name only (the SDK's own recording
    would copy the message) and goes on unchanged."""
    with tracer.start_as_current_span(
        name, kind=SpanKind.INTERNAL, attributes=attributes, record_exception=False, set_status_on_exception=False
    ) as span:
        try:
            yield span
        except Exception as exc:
            mark(span, type(exc).__qualname__)
            raise
