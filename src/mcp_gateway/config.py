"""The gateway's one config file: upstreams, callers, policies, audit.

Every model forbids unknown keys, so a typo in the YAML fails at start
instead of silently loosening a policy (ADR-004). The config names
environment variables; it never holds a secret value itself.
"""

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Annotated, Literal, Self

import yaml
from limits import parse_many
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

NAME = r"^[a-z0-9][a-z0-9-]{0,62}$"


class ConfigError(Exception):
    """The config can't be used; the gateway refuses to start (exit 2)."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class HttpUpstream(_Model):
    transport: Literal["http"]
    url: str
    # Name of the env var holding the upstream's own key, sent as
    # `Authorization: Bearer`. The agent never sees it (Phase 3).
    auth_env: str | None = None


class StdioUpstream(_Model):
    transport: Literal["stdio"]
    command: str
    args: list[str] = []
    # The SDK starts stdio servers with a minimal environment, not the
    # gateway's; a working directory is the clean way to point `python -m`
    # at a package.
    cwd: Path | None = None
    # A fresh process for every MCP session, for servers that keep state
    # between calls (ADR-010). Needs session-based clients.
    per_session: bool = False


Upstream = Annotated[HttpUpstream | StdioUpstream, Field(discriminator="transport")]


class ArgRule(_Model):
    """A restriction on one argument: exactly one of `prefix` or `pattern`."""

    prefix: str | None = None
    pattern: str | None = None

    @model_validator(mode="after")
    def _one_matcher(self) -> Self:
        if (self.prefix is None) == (self.pattern is None):
            raise ValueError("an argument rule needs exactly one of `prefix` or `pattern`")
        if self.pattern is not None:
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ValueError(f"invalid pattern {self.pattern!r}: {exc}") from exc
        return self


class ToolRule(_Model):
    arguments: dict[str, ArgRule] = {}


class RoutePolicy(_Model):
    """The tools a caller may use on one route. Anything not listed is denied."""

    tools: dict[str, ToolRule]


class Policy(_Model):
    routes: dict[str, RoutePolicy]
    # What happens to a tool output the detector flags (ADR-006).
    on_suspicious: Literal["block", "annotate", "log"] = "block"
    # Content the detector can't read (images, audio, embedded resources,
    # text beyond the scan cap) is blocked unless this is set.
    allow_unscanned_content: bool = False


class Caller(_Model):
    key_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    policy: str
    # Tool calls allowed per window, across all routes, in the `limits`
    # library's notation: "60/minute", or several as "60/minute; 1000/day".
    # None means no limit.
    rate_limit: str | None = None

    @field_validator("rate_limit")
    @classmethod
    def _parses(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                parse_many(value)
            except ValueError as exc:
                raise ValueError(f"rate_limit {value!r} isn't like '60/minute' or '60/minute; 1000/day'") from exc
        return value

    @field_validator("key_sha256", mode="before")
    @classmethod
    def _quoted(cls, value: object) -> object:
        # YAML reads an unquoted all-digit hash as an integer (octal, with a
        # leading zero); converting it back would give the wrong hash.
        if not isinstance(value, str):
            raise ValueError("quote key_sha256 in the YAML: unquoted, a hash can be read as a number")
        return value


class ModelSettings(_Model):
    dir: Path
    threshold: Annotated[float, Field(gt=0, lt=1)]
    max_windows: Annotated[int, Field(ge=1)] = 16
    timeout_s: Annotated[float, Field(gt=0)] = 2.0


class DetectorSettings(_Model):
    """Both layers off is the measurement's `gateway-off` configuration."""

    rules: bool = True
    model: ModelSettings | None = None
    scan_cap_chars: Annotated[int, Field(ge=1)] = 262_144


class AuditSettings(_Model):
    path: Path
    fsync: bool = True


class GatewayConfig(_Model):
    upstreams: dict[Annotated[str, Field(pattern=NAME)], Upstream]
    callers: dict[Annotated[str, Field(pattern=NAME)], Caller]
    policies: dict[Annotated[str, Field(pattern=NAME)], Policy]
    audit: AuditSettings
    detector: DetectorSettings = DetectorSettings()

    @model_validator(mode="after")
    def _references(self) -> Self:
        for caller_id, caller in self.callers.items():
            if caller.policy not in self.policies:
                raise ValueError(f"caller {caller_id!r} names unknown policy {caller.policy!r}")
        for policy_id, policy in self.policies.items():
            for route in policy.routes:
                if route not in self.upstreams:
                    raise ValueError(f"policy {policy_id!r} names unknown route {route!r}")
        hashes = [c.key_sha256 for c in self.callers.values()]
        if len(set(hashes)) != len(hashes):
            raise ValueError("two callers share a key")
        return self

    def policy_for(self, caller_id: str) -> Policy:
        return self.policies[self.callers[caller_id].policy]

    def policy_hash(self) -> str:
        """SHA-256 of the canonical config, recorded with every audit line."""
        canonical = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()


def load_config(path: Path) -> GatewayConfig:
    try:
        raw = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"can't read {path}: {exc}") from exc
    try:
        config = GatewayConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"invalid config {path}:\n{exc}") from exc
    for name, upstream in config.upstreams.items():
        if isinstance(upstream, HttpUpstream) and upstream.auth_env and not os.environ.get(upstream.auth_env):
            raise ConfigError(f"upstream {name!r}: environment variable {upstream.auth_env} is not set")
    return config
