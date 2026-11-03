"""One `tools/call` on its way through a route: what's logged about it and
what's forwarded.

A call's `_meta` is forwarded unchanged (an app's delegation token, W3C trace
context), with the authenticated caller stamped into it. The gateway neither
reads nor logs what else `_meta` holds.
"""

import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

from mcp.types import CallToolRequestParams
from opentelemetry import trace

# A field is secret if a word of its name is one of these. Words, not
# substrings: `keyword`, `monkey_count` and `tokenizer` aren't secrets, and a
# substring match hid them from the log. Names written as one lowercase word
# can't be split, so the usual compounds are listed whole.
SECRET_WORDS = frozenset(
    {"key", "token", "password", "passwd", "secret", "authorization", "credential", "cookie"}
    | {"keys", "tokens", "passwords", "secrets", "credentials", "cookies"}
    | {"apikey", "accesskey", "privatekey", "secretkey", "accesstoken", "authtoken", "apitoken"}
    | {"bearertoken", "idtoken", "refreshtoken", "sessiontoken", "clientsecret"}
)
# Splits `X-Auth-Token`, `api_key`, `accessToken` and `APIKey` into words.
NAME_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
REDACTED = "<redacted>"

# The authenticated caller's id, stamped into every forwarded call's `_meta`,
# so an upstream can check that a delegation chain's acting agent is the key
# that made the call (Juku's ADR-018, spike 6). Whatever a client sends under
# this key is overwritten: a client can't claim to be another caller.
CALLER_META_KEY = "io.github.nabilrobert.mcp-gateway/caller"
# `_meta` keys that belong to the agent's connection, not to the call, so they
# stay on that hop. The SDK sets its own `io.modelcontextprotocol/*` keys on
# the upstream connection. A progress token names a request on the agent's
# connection; one upstream connection carries many agents' calls, where two
# agents' tokens could clash, and the gateway doesn't relay progress anyway.
PROTOCOL_META_PREFIX = "io.modelcontextprotocol/"
# The SDK's name for the wire's `progressToken` once it has parsed `_meta`.
PROGRESS_TOKEN_META_KEY = "progress_token"  # noqa: S105 (a key name, not a secret)


def redact(value: Any) -> Any:
    """Arguments as logged: any field, at any depth, whose name looks like a
    secret is hidden."""
    if isinstance(value, dict):
        items = cast(dict[str, Any], value).items()
        return {k: REDACTED if is_secret_name(str(k)) else redact(v) for k, v in items}
    if isinstance(value, list):
        return [redact(v) for v in cast(list[Any], value)]
    return value


def is_secret_name(name: str) -> bool:
    return any(word.lower() in SECRET_WORDS for word in NAME_WORD.findall(name))


def end_to_end_meta(meta: Mapping[str, Any] | None) -> dict[str, Any]:
    """The client's `_meta`, in its order, minus the keys of its own connection."""
    kept: dict[str, Any] = {}
    for key, value in (meta or {}).items():
        if key.startswith(PROTOCOL_META_PREFIX) or key == PROGRESS_TOKEN_META_KEY:
            continue
        kept[key] = value
    return kept


@dataclass
class Call:
    tool: str
    caller: str
    arguments: dict[str, Any]
    forwarded_meta: dict[str, Any]
    record: dict[str, Any]  # the fields every line about this call carries
    span: trace.Span  # the SDK's `tools/call <tool>` span

    def decided(self, decision: str) -> None:
        self.span.set_attribute("mcp_gateway.decision", decision)

    @property
    def ids(self) -> dict[str, Any]:
        return {k: self.record[k] for k in ("call_id", "caller", "route", "tool")}


def start_call(params: CallToolRequestParams, caller: str, route: str, policy_hash: str) -> Call:
    arguments = dict(params.arguments or {})
    client_meta = end_to_end_meta(params.meta)
    claimed_caller = client_meta.get(CALLER_META_KEY, caller)
    record: dict[str, Any] = {
        "call_id": uuid.uuid4().hex,
        "caller": caller,
        "route": route,
        "tool": params.name,
        "arguments": redact(arguments),
        # Only that `_meta` came, never what it held: it can carry tokens.
        "has_meta": bool(client_meta),
        "is_caller_claim_overwritten": claimed_caller != caller,
        "policy_sha256": policy_hash,
    }
    # The SDK's `tools/call <tool>` span: who called, and (later) the outcome.
    span = trace.get_current_span()
    span.set_attributes(
        {"mcp_gateway.caller": caller, "mcp_gateway.route": route, "mcp_gateway.call_id": record["call_id"]}
    )
    forwarded_meta = {**client_meta, CALLER_META_KEY: caller}
    return Call(params.name, caller, arguments, forwarded_meta, record, span)
