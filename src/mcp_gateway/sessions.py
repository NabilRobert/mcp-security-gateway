"""The HTTP-layer check that keeps an MCP session to the key that opened it.

`proxy.py: Route` holds who owns each session; this runs around every request
to a route, including the ones the SDK answers without calling the route.
"""

from mcp.server.streamable_http import MCP_SESSION_ID_HEADER
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mcp_gateway.auth import CallerUser
from mcp_gateway.proxy import Route


class SessionGuard:
    """Keeps each MCP session to the key that opened it, in the HTTP layer:
    the SDK serves GET and DELETE on a session without calling a handler, so
    a check in the proxy can't cover them. A session is bound when the SDK
    issues its id, and a request on another key's session gets the same 404
    as an unknown session, so this doesn't confirm that a session exists."""

    def __init__(self, app: ASGIApp, routes: dict[str, Route]) -> None:
        self.app = app
        self.routes = routes

    def _route_of(self, scope: Scope) -> Route | None:
        parts = str(scope.get("path", "")).strip("/").split("/")
        return self.routes.get(parts[1]) if len(parts) >= 2 and parts[0] == "mcp" else None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        route = self._route_of(scope) if scope["type"] == "http" else None
        user = scope.get("user")
        if route is None or not isinstance(user, CallerUser):
            await self.app(scope, receive, send)
            return
        caller = user.caller_id
        session = dict(scope.get("headers", [])).get(MCP_SESSION_ID_HEADER.encode(), b"").decode()
        if session and not route.may_use_session(session, caller):
            route.session_refused(caller)
            await PlainTextResponse("session not found", status_code=404)(scope, receive, send)
            return

        async def bind_issued_session(message: Message) -> None:
            if message["type"] == "http.response.start":
                issued = dict(message.get("headers", [])).get(MCP_SESSION_ID_HEADER.encode())
                if issued:
                    route.bind_session(issued.decode(), caller)
            await send(message)

        await self.app(scope, receive, bind_issued_session)
        if scope.get("method") == "DELETE" and session:
            route.session_ended(session, caller)
