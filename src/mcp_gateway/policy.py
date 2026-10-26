"""Pure policy decisions: may this caller call this tool with these arguments?

Deny by default (ADR-004). Nothing here does I/O, so every rule is tested
without a server.
"""

import posixpath
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

from mcp_gateway.config import ArgRule, Policy


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reason: str


ALLOW = Verdict(True, "allowed")


def allowed_tools(policy: Policy, route: str) -> frozenset[str]:
    route_policy = policy.routes.get(route)
    return frozenset(route_policy.tools) if route_policy else frozenset()


def check_call(policy: Policy, route: str, tool: str, arguments: Mapping[str, Any]) -> Verdict:
    route_policy = policy.routes.get(route)
    if route_policy is None:
        return Verdict(False, f"route {route!r} not allowed")
    rule = route_policy.tools.get(tool)
    if rule is None:
        return Verdict(False, f"tool {tool!r} not allowed")
    for name, arg_rule in rule.arguments.items():
        if name not in arguments:
            # An unconstrained default could be anything (a filesystem
            # tool's default path is the root), so a governed argument must
            # be given.
            return Verdict(False, f"argument {name!r} is required by policy")
        given: Any = arguments[name]
        values: list[Any] = cast(list[Any], given) if isinstance(given, list) else [given]
        for value in values:
            if not isinstance(value, str):
                return Verdict(False, f"argument {name!r} must be a string")
            if not _matches(arg_rule, value):
                return Verdict(False, f"argument {name!r} not allowed by policy")
    return ALLOW


def _matches(rule: ArgRule, value: str) -> bool:
    if rule.pattern is not None:
        return re.fullmatch(rule.pattern, value) is not None
    assert rule.prefix is not None
    return path_within(value, rule.prefix)


def path_within(value: str, prefix: str) -> bool:
    """Is `value` inside `prefix`, after resolving `.` and `..`?

    Symlinks aren't followed here (the gateway can't see the upstream's
    disk); the upstream server's own confinement still applies. Absolute
    and relative paths never match each other.
    """
    if "\x00" in value or "\\" in value:
        return False
    if value.startswith("/") != prefix.startswith("/"):
        return False
    norm = posixpath.normpath(value)
    if norm == ".." or norm.startswith("../"):
        return False
    base = posixpath.normpath(prefix)
    if base == ".":
        return True
    return norm == base or norm.startswith(base.rstrip("/") + "/")
