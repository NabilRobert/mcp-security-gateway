"""One proxy route per upstream, on the SDK's low-level `Server` (ADR-002).

`tools/list` is passed through with the caller's disallowed tools removed.
`tools/call` is checked against policy, audited before it's forwarded, then
forwarded through the upstream's client session and audited again. A
refused call never reaches the upstream, and no call is forwarded without
its `call` line on disk.
"""

import contextlib
import sys
import time
from collections.abc import AsyncIterator
from typing import Any, cast

from mcp.server import Server, ServerRequestContext
from mcp.server.streamable_http import MCP_SESSION_ID_HEADER
from mcp.shared.exceptions import MCPError
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    RequestParamsMeta,
    TextContent,
    Tool,
)
from mcp_types.jsonrpc import INTERNAL_ERROR, INVALID_REQUEST
from opentelemetry import trace

from mcp_gateway.audit import AuditError, AuditLog
from mcp_gateway.auth import CallerUser
from mcp_gateway.calls import REDACTED, Call, redact, start_call
from mcp_gateway.config import GatewayConfig
from mcp_gateway.detect import Detector
from mcp_gateway.outputs import (
    UPSTREAM_ERROR,
    Inspection,
    ScreenedUpstreamError,
    annotated_result,
    blocked_span_error,
    detect_attributes,
    inspect_output,
    scan_text,
    screen_error,
)
from mcp_gateway.policy import allowed_tools, check_call
from mcp_gateway.ratelimit import CallLimiter
from mcp_gateway.tool_screen import ToolScreen, tool_text
from mcp_gateway.tracing import mark, stage
from mcp_gateway.upstreams import IDLE_TIMEOUT_S, Upstreams, list_all_tools

# Public names other modules and the tests take from here.
__all__ = ["REDACTED", "UPSTREAM_ERROR", "Route", "annotated_result", "redact", "scan_text", "tool_text"]


def session_id_of(ctx: ServerRequestContext[Any, Any]) -> str | None:
    request = ctx.request
    headers = getattr(request, "headers", None)
    value = headers.get(MCP_SESSION_ID_HEADER) if headers is not None else None
    return value if isinstance(value, str) and value else None


def _refused(message: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=message)], is_error=True)


class Route:
    def __init__(
        self,
        name: str,
        upstreams: Upstreams,
        config: GatewayConfig,
        audit: AuditLog,
        detector: Detector,
        limiter: CallLimiter | None = None,
    ) -> None:
        self.name = name
        # One limiter shared by every route, so a caller's limit spans them all.
        self.limiter = limiter or CallLimiter(config)
        self.upstreams = upstreams
        self.config = config
        self.audit = audit
        self.detector = detector
        self.policy_hash = config.policy_hash()
        # A session is bound to the caller that first used it (Phase 3), keyed
        # by its Mcp-Session-Id: the SDK builds a new session object for every
        # request, so object identity would bind nothing.
        self._session_callers: dict[str, tuple[str, float]] = {}
        self._tool_screen = ToolScreen(name, detector, self._try_append)

    def server(self) -> Server:
        return Server(f"mcp-gateway/{self.name}", on_list_tools=self._list_tools, on_call_tool=self._call_tool)

    def _caller(self, ctx: ServerRequestContext[Any, Any]) -> str:
        request = ctx.request
        user = request.scope.get("user") if request is not None and hasattr(request, "scope") else None
        if not isinstance(user, CallerUser):
            # Can't happen behind the auth middleware; fail closed if it does.
            raise MCPError(INVALID_REQUEST, "unauthenticated request")
        session = session_id_of(ctx)
        if session is not None:
            if not self.may_use_session(session, user.caller_id):
                raise MCPError(INVALID_REQUEST, "this session belongs to another caller")
            self.bind_session(session, user.caller_id)
        return user.caller_id

    def may_use_session(self, session: str, caller: str) -> bool:
        bound = self._session_callers.get(session)
        return bound is None or bound[0] == caller

    def bind_session(self, session: str, caller: str) -> None:
        now = time.monotonic()
        if session not in self._session_callers and len(self._session_callers) > 10_000:
            self._forget_idle(now)
        self._session_callers[session] = (caller, now)

    def session_refused(self, caller: str) -> None:
        """Audited without the id: on this request it's someone else's."""
        reason = "request on another caller's session"
        self._try_append("call", decision="denied", caller=caller, route=self.name, reason=reason)

    def _forget_idle(self, now: float) -> None:
        for session, (_, seen) in list(self._session_callers.items()):
            if now - seen > IDLE_TIMEOUT_S:
                del self._session_callers[session]

    def session_ended(self, session: str, caller: str) -> None:
        """The client deleted its session. Only its owner can end it here."""
        bound = self._session_callers.get(session)
        if bound is not None and bound[0] == caller:
            del self._session_callers[session]
            self.upstreams.end(session)

    async def _list_tools(
        self, ctx: ServerRequestContext[Any, Any], params: PaginatedRequestParams | None
    ) -> ListToolsResult:
        caller = self._caller(ctx)
        allowed = allowed_tools(self.config.policy_for(caller), self.name)
        upstream = await self.upstreams.for_session(session_id_of(ctx))
        async with self._audited_failures("list", {"caller": caller, "route": self.name}), self._screening_errors():
            result = await upstream.session.list_tools(params=params)
        tools = [t for t in result.tools if t.name in allowed]
        with stage("screen_tools") as span:
            flagged = await self._screen_tools(tools)
            span.set_attributes({"mcp_gateway.tools.screened": len(tools), "mcp_gateway.tools.hidden": len(flagged)})
        return result.model_copy(update={"tools": [t for t in tools if t.name not in flagged]})

    async def _screen_tools(self, tools: list[Tool]) -> set[str]:
        if not self.config.detector.scan_tool_descriptions:
            return set()
        return await self._tool_screen.flagged(tools)

    async def _call_tool(self, ctx: ServerRequestContext[Any, Any], params: CallToolRequestParams) -> CallToolResult:
        call = start_call(params, self._caller(ctx), self.name, self.policy_hash)
        refusal = await self._rate_limit_refusal(call) or await self._policy_refusal(ctx, call)
        if refusal is not None:
            return refusal
        self._write_call_line(call)
        start = time.perf_counter()
        result = await self._forward(ctx, call)
        inspection = await self._inspect(result, (time.perf_counter() - start) * 1000, call)
        self._write_result_line(call, inspection)
        return inspection.returned

    async def _rate_limit_refusal(self, call: Call) -> CallToolResult | None:
        """Counted before policy, so denied calls can't be spammed either."""
        with stage("rate_limit") as span:
            limit = await self.limiter.take(call.caller)
            if limit is not None:
                mark(span, "rate_limited")
        if limit is None:
            return None
        call.decided("rate_limited")
        self._try_append("call", decision="rate_limited", limit=limit, **call.record)
        return _refused(f"Refused by the gateway: this key's call limit ({limit}) is used up.")

    async def _policy_refusal(self, ctx: ServerRequestContext[Any, Any], call: Call) -> CallToolResult | None:
        with stage("policy") as span:
            reason = await self._denial_reason(ctx, call, span)
        if reason is None:
            return None
        call.decided("denied")
        self._try_append("call", decision="denied", reason=reason, **call.record)
        return _refused(f"Denied by gateway policy: {reason}.")

    async def _denial_reason(self, ctx: ServerRequestContext[Any, Any], call: Call, span: trace.Span) -> str | None:
        verdict = check_call(self.config.policy_for(call.caller), self.name, call.tool, call.arguments)
        if not verdict.allowed:
            mark(span, "denied")
            return verdict.reason
        async with self._audited_failures("call", call.record):
            is_flagged = await self._tool_is_flagged(ctx, call.tool)
        if is_flagged:
            mark(span, "tool_hidden")
            return f"tool {call.tool!r} hidden: its definition failed screening"
        return None

    def _write_call_line(self, call: Call) -> None:
        try:
            with stage("audit"):
                self.audit.append("call", decision="forwarding", **call.record)
        except AuditError as exc:
            call.decided("audit_failed")
            print(f"mcp-gateway: {exc}; call refused", file=sys.stderr)
            raise MCPError(INTERNAL_ERROR, "the gateway can't write its audit log, so the call was refused") from exc

    async def _inspect(self, result: CallToolResult, upstream_ms: float, call: Call) -> Inspection:
        with stage("detect") as span:
            policy = self.config.policy_for(call.caller)
            scan_cap = self.config.detector.scan_cap_chars
            inspection = await inspect_output(result, upstream_ms, policy, self.detector, scan_cap)
            span.set_attributes(detect_attributes(inspection.fields))
            error_type = blocked_span_error(inspection)
            if error_type is not None:
                mark(span, error_type)
        call.decided(inspection.decision)
        return inspection

    def _write_result_line(self, call: Call, inspection: Inspection) -> None:
        try:
            with stage("audit"):
                self.audit.append("result", decision=inspection.decision, **inspection.fields, **call.ids)
        except AuditError as exc:
            print(f"mcp-gateway: {exc}; output withheld", file=sys.stderr)
            raise MCPError(INTERNAL_ERROR, "the gateway can't write its audit log, so the output was withheld") from exc

    async def _forward(self, ctx: ServerRequestContext[Any, Any], call: Call) -> CallToolResult:
        async with self._audited_failures("result", call.ids, call.span):
            # Inside this span, so the SDK client parents the upstream request on it.
            with stage("forward"):
                upstream = await self.upstreams.for_session(session_id_of(ctx))
                meta = cast(RequestParamsMeta, call.forwarded_meta)
                async with self._screening_errors():
                    return await upstream.session.call_tool(call.tool, call.arguments, meta=meta)

    @contextlib.asynccontextmanager
    async def _audited_failures(
        self, kind: str, fields: dict[str, Any], call_span: trace.Span | None = None
    ) -> AsyncIterator[None]:
        """Around anything that talks to the upstream: a failure gets an
        `upstream_error` line, and the agent gets only what it may see."""

        def record_failure(**failure: Any) -> None:
            if call_span is not None:
                call_span.set_attribute("mcp_gateway.decision", "upstream_error")
            self._try_append(kind, decision="upstream_error", **failure, **fields)

        try:
            yield
        except ScreenedUpstreamError as exc:
            record_failure(**exc.audit_fields)
            raise exc.error from None
        except MCPError as exc:  # e.g. a per-session route asked for without a session
            record_failure(error=exc.error.message)
            raise
        except Exception as exc:  # transport or protocol failure upstream
            record_failure(error=type(exc).__name__)
            raise MCPError(UPSTREAM_ERROR, f"upstream {self.name!r} failed") from exc

    @contextlib.asynccontextmanager
    async def _screening_errors(self) -> AsyncIterator[None]:
        """Around a request to the upstream: its protocol errors are untrusted
        text, like its outputs, so they come out screened."""
        try:
            yield
        except MCPError as exc:
            scan_cap = self.config.detector.scan_cap_chars
            raise await screen_error(exc, self.name, self.detector, scan_cap) from exc

    async def _tool_is_flagged(self, ctx: ServerRequestContext[Any, Any], name: str) -> bool:
        """For a call: refuse a flagged tool even if the agent never listed
        tools. Unscreened tools are screened on the spot, and a tool the
        upstream no longer lists can't be, so it's refused too."""
        if not self.config.detector.scan_tool_descriptions:
            return False
        known = self._tool_screen.known_verdict(name)
        if known is not None:
            return known
        upstream = await self.upstreams.for_session(session_id_of(ctx))
        async with self._screening_errors():
            listed = await list_all_tools(upstream)
        definitions = [t for t in listed if t.name == name]
        if not definitions:
            return True
        return name in await self._screen_tools(definitions)

    def _try_append(self, kind: str, **fields: Any) -> None:
        """For lines whose failure can't make things less safe (the call is
        already refused or failed): report on stderr, don't raise."""
        try:
            self.audit.append(kind, **fields)
        except AuditError as exc:
            print(f"mcp-gateway: {exc}", file=sys.stderr)
