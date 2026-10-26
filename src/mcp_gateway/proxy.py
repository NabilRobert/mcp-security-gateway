"""One proxy route per upstream, on the SDK's low-level `Server` (ADR-002).

`tools/list` is passed through with the caller's disallowed tools removed.
`tools/call` is checked against policy, audited before it's forwarded, then
forwarded through the upstream's client session and audited again. A
refused call never reaches the upstream, and no call is forwarded without
its `call` line on disk.
"""

import hashlib
import re
import sys
import time
import uuid
from typing import Any
from weakref import WeakKeyDictionary

from mcp import Client
from mcp.server import Server, ServerRequestContext
from mcp.shared.exceptions import MCPError
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
)
from mcp_types.jsonrpc import INTERNAL_ERROR, INVALID_REQUEST

from mcp_gateway.audit import AuditError, AuditLog
from mcp_gateway.auth import CallerUser
from mcp_gateway.config import GatewayConfig
from mcp_gateway.detect import Detector
from mcp_gateway.policy import allowed_tools, check_call

UPSTREAM_ERROR = -32001  # the gateway's own code: the upstream failed, not the agent
SECRET_NAME = re.compile(r"key|token|password|secret", re.IGNORECASE)
REDACTED = "<redacted>"


def redact(arguments: dict[str, Any]) -> dict[str, Any]:
    """Arguments as logged: any field whose name looks like a secret is hidden."""
    return {k: REDACTED if SECRET_NAME.search(k) else v for k, v in arguments.items()}


def text_of(result: CallToolResult) -> str:
    return "\n".join(item.text for item in result.content if isinstance(item, TextContent))


class Route:
    def __init__(self, name: str, upstream: Client, config: GatewayConfig, audit: AuditLog, detector: Detector) -> None:
        self.name = name
        self.upstream = upstream
        self.config = config
        self.audit = audit
        self.detector = detector
        self.policy_hash = config.policy_hash()
        # A session is bound to the caller that opened it (Phase 3).
        self._session_callers: WeakKeyDictionary[object, str] = WeakKeyDictionary()

    def server(self) -> Server:
        return Server(f"mcp-gateway/{self.name}", on_list_tools=self._list_tools, on_call_tool=self._call_tool)

    def _caller(self, ctx: ServerRequestContext[Any, Any]) -> str:
        request = ctx.request
        user = request.scope.get("user") if request is not None and hasattr(request, "scope") else None
        if not isinstance(user, CallerUser):
            # Can't happen behind the auth middleware; fail closed if it does.
            raise MCPError(INVALID_REQUEST, "unauthenticated request")
        bound = self._session_callers.setdefault(ctx.session, user.caller_id)
        if bound != user.caller_id:
            raise MCPError(INVALID_REQUEST, "this session belongs to another caller")
        return user.caller_id

    async def _list_tools(
        self, ctx: ServerRequestContext[Any, Any], params: PaginatedRequestParams | None
    ) -> ListToolsResult:
        caller = self._caller(ctx)
        allowed = allowed_tools(self.config.policy_for(caller), self.name)
        result = await self.upstream.session.list_tools(params=params)
        return result.model_copy(update={"tools": [t for t in result.tools if t.name in allowed]})

    async def _call_tool(self, ctx: ServerRequestContext[Any, Any], params: CallToolRequestParams) -> CallToolResult:
        caller = self._caller(ctx)
        arguments = dict(params.arguments or {})
        record: dict[str, Any] = {
            "call_id": uuid.uuid4().hex,
            "caller": caller,
            "route": self.name,
            "tool": params.name,
            "arguments": redact(arguments),
            "policy_sha256": self.policy_hash,
        }
        verdict = check_call(self.config.policy_for(caller), self.name, params.name, arguments)
        if not verdict.allowed:
            self._try_append("call", decision="denied", reason=verdict.reason, **record)
            return CallToolResult(
                content=[TextContent(type="text", text=f"Denied by gateway policy: {verdict.reason}.")],
                is_error=True,
            )
        try:
            self.audit.append("call", decision="forwarding", **record)
        except AuditError as exc:
            print(f"mcp-gateway: {exc}; call refused", file=sys.stderr)
            raise MCPError(INTERNAL_ERROR, "the gateway can't write its audit log, so the call was refused") from exc

        start = time.perf_counter()
        try:
            result = await self.upstream.session.call_tool(params.name, arguments)
        except Exception as exc:  # transport or protocol failure upstream
            self._try_append("result", decision="upstream_error", error=type(exc).__name__, **_ids(record))
            raise MCPError(UPSTREAM_ERROR, f"upstream {self.name!r} failed") from exc
        upstream_ms = (time.perf_counter() - start) * 1000

        text = text_of(result)
        scan = await self.detector.scan(text)
        try:
            self.audit.append(
                "result",
                decision="allowed",
                is_error=bool(result.is_error),
                output_chars=len(text),
                output_sha256=hashlib.sha256(text.encode()).hexdigest(),
                upstream_ms=round(upstream_ms, 3),
                detector=self.detector.version,
                suspicious=scan.suspicious,
                **_ids(record),
            )
        except AuditError as exc:
            print(f"mcp-gateway: {exc}; output withheld", file=sys.stderr)
            raise MCPError(INTERNAL_ERROR, "the gateway can't write its audit log, so the output was withheld") from exc
        return result

    def _try_append(self, kind: str, **fields: Any) -> None:
        """For lines whose failure can't make things less safe (the call is
        already refused or failed): report on stderr, don't raise."""
        try:
            self.audit.append(kind, **fields)
        except AuditError as exc:
            print(f"mcp-gateway: {exc}", file=sys.stderr)


def _ids(record: dict[str, Any]) -> dict[str, Any]:
    return {k: record[k] for k in ("call_id", "caller", "route", "tool")}
