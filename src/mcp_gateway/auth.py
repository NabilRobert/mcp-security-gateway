"""API-key authentication on Starlette's own auth system (ADR-003).

The backend runs before any MCP session exists: a missing or wrong key is
an `AuthenticationError`, which `unauthorized` turns into HTTP 401. Only
SHA-256 hashes of keys are stored; keys are 32 random bytes, so a slow
password hash would add nothing. Every comparison is constant-time, and
every caller is compared, so timing doesn't reveal which hash matched.
"""

import hashlib
import hmac
import secrets
from collections.abc import Callable, Mapping

from starlette.authentication import AuthCredentials, AuthenticationBackend, AuthenticationError, BaseUser
from starlette.requests import HTTPConnection
from starlette.responses import PlainTextResponse, Response

from mcp_gateway.config import Caller


class CallerUser(BaseUser):
    def __init__(self, caller_id: str) -> None:
        self.caller_id = caller_id

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def display_name(self) -> str:
        return self.caller_id

    @property
    def identity(self) -> str:
        return self.caller_id


class KeyRejected(AuthenticationError):
    def __init__(self, reason: str, fingerprint: str | None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.fingerprint = fingerprint


def key_sha256(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def fingerprint(key: str) -> str:
    """First 8 hex characters of the key's hash: enough to tell keys apart in
    the audit log, useless for recovering the key."""
    return key_sha256(key)[:8]


def new_key() -> tuple[str, str]:
    """A fresh key and its hash. The key is shown once and stored nowhere."""
    key = secrets.token_urlsafe(32)
    return key, key_sha256(key)


class ApiKeyBackend(AuthenticationBackend):
    def __init__(self, callers: Mapping[str, Caller], open_paths: frozenset[str] = frozenset()) -> None:
        self._hashes = [(caller_id, bytes.fromhex(c.key_sha256)) for caller_id, c in callers.items()]
        # Exact paths that need no key (the health check). Everything else,
        # every MCP route included, does.
        self._open_paths = open_paths

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, BaseUser] | None:
        if conn.url.path in self._open_paths:
            return None
        header = conn.headers.get("authorization", "")
        scheme, _, key = header.partition(" ")
        key = key.strip()
        if scheme.lower() != "bearer" or not key:
            raise KeyRejected("missing bearer key", None)
        digest = hashlib.sha256(key.encode()).digest()
        match: str | None = None
        for caller_id, stored in self._hashes:  # no early exit
            if hmac.compare_digest(digest, stored):
                match = caller_id
        if match is None:
            raise KeyRejected("invalid key", fingerprint(key))
        return AuthCredentials(["gateway"]), CallerUser(match)


def unauthorized_handler(on_reject: Callable[[HTTPConnection, KeyRejected], None]) -> Callable[..., Response]:
    """Starlette `on_error`: record the refusal, answer 401."""

    def handle(conn: HTTPConnection, exc: AuthenticationError) -> Response:
        if isinstance(exc, KeyRejected):
            on_reject(conn, exc)
        return PlainTextResponse("unauthorized", status_code=401, headers={"WWW-Authenticate": "Bearer"})

    return handle
