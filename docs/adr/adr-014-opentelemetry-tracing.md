# ADR-014: OpenTelemetry tracing, on the MCP SDK's own spans

**Context:** Project 6 (agent-observability) needs one trace from an
agent through the gateway into MCP-backbone and its database. The MCP SDK
(2.3.0) already opens a SERVER span per request, parented on the trace
context in `_meta`, and a CLIENT span per outgoing request, injecting the
current context into its `_meta`. Nothing is exported until a tracer
provider is installed. Project 6's conventions (`docs/conventions.md`,
"For the gateway") set the rules: stages as child spans, `error.type` for
denials and blocks, no content.

**Decision:**
- The OpenTelemetry SDK with the OTLP/HTTP exporter, installed only when
  `OTEL_EXPORTER_OTLP_ENDPOINT` (or the traces-only variant) is set.
- One INTERNAL span per stage of a call under the SDK's `tools/call`
  span: `rate_limit`, `policy`, `audit`, `forward`, `detect`, `audit`;
  `screen_tools` under `tools/list`. The upstream call runs inside
  `forward`, so the SDK injects the gateway's context into the upstream
  request and the upstream's spans nest under it. The rest of `_meta`
  passes through as before (ADR-013).
- Spans carry outcomes, never content: `error.type` on the stage that
  ended the call, no status messages, no arguments, outputs or reasons.
  Detector verdicts, rule IDs, scores, counts and timings are recorded.
  No content-capture switch: nothing the gateway would add needs one.
- Export in the background with a 2 s timeout; a stop waits at most 2 s,
  so a dead viewer only loses spans. The SDK's own exit hook is off, so
  the capped stop is the one flush. (Once it has run, the hook returns at
  once anyway, as Project 6 measured with a dead viewer and a full queue.)
- A SIGTERM (systemd, `docker stop`) unwinds like Ctrl-C. uvicorn re-raises
  the signal after its own shutdown, and with the default handler that
  killed the process before any cleanup ran: no flush, no upstream
  cleanup, no closed audit log (found by Project 6's end-to-end run). The
  gateway installs a handler that raises `SystemExit(0)` before serving,
  which is the one uvicorn restores. A clean stop now writes a `stop`
  line to the audit log.

**Options considered:**
- MCP-backbone's `app/tracing.py` (at `5f38bd2`): the right design, but it
  reads that server's own settings and isn't a package, so the gateway
  follows it rather than depending on it.
- OpenTelemetry's Starlette/FastAPI instrumentation: adds an HTTP span
  per request on top of the SDK's MCP spans, without the stages. Not
  needed for the trace.
- A vendor SDK (Logfire, OpenLLMetry): another dependency and service for
  what the plain SDK already does.

**Consequence:**
- With tracing off, the API's no-op spans pass a client's `traceparent`
  through unchanged; with it on, the upstream sees the gateway's span as
  its parent. Either way one trace.
- The first trace through a fresh gateway showed 205 ms inside `forward`
  in no span (Project 6, 2026-10-29). It was the MCP SDK client's first
  output-schema check importing jsonschema; later calls took 0.3 ms. The
  gateway now loads it at start-up: a fresh process's first call went
  from about 40 ms to about 6 ms, against 3–4 ms for later calls.
- A refusal by the auth middleware happens before any MCP request, so it
  has no span; it is in the audit log.
- Tests switch tracing on and off through a test-only provider, because
  the global provider can be set only once per process.

Part of the [architecture decisions](README.md) (Phase 5).
