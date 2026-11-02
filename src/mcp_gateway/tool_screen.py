"""Screening tool definitions: a poisoned description or schema reaches a
model like an output does, so everything a model can read of a tool goes
through the detector when tools are listed or called.
"""

import hashlib
from collections.abc import Callable
from typing import Any, cast

from mcp.types import Tool

from mcp_gateway.detect import Detector, json_keys, string_leaves

SCHEMA_STRUCTURE_KEYWORDS = frozenset({"$schema", "$id", "$ref", "type", "format", "required"})
SCHEMA_DATA_KEYWORDS = frozenset({"default", "const", "enum", "examples"})
SCHEMA_NAME_KEYWORDS = frozenset({"properties", "patternProperties", "$defs", "definitions"})


def tool_text(tool: Tool) -> str:
    """Everything a model can read of a tool definition."""
    annotation_title = tool.annotations.title if tool.annotations else None
    parts = [tool.name, tool.title, tool.description, annotation_title]
    parts += [*schema_text(tool.input_schema), *schema_text(tool.output_schema)]
    return "\n".join(p for p in parts if p)


def schema_text(schema: Any) -> list[str]:
    """Every string in a JSON Schema except its structural keywords. Under
    `default`, `enum` and the like, any key is data; under `properties`, keys
    are parameter names, which a model reads too."""
    if isinstance(schema, list):
        return [text for item in cast(list[Any], schema) for text in schema_text(item)]
    if not isinstance(schema, dict):
        return [schema] if isinstance(schema, str) else []
    found: list[str] = []
    for key, value in cast(dict[str, Any], schema).items():
        if key in SCHEMA_STRUCTURE_KEYWORDS:
            continue
        if key in SCHEMA_DATA_KEYWORDS:
            found.extend([*string_leaves(value), *json_keys(value)])
        elif key in SCHEMA_NAME_KEYWORDS and isinstance(value, dict):
            found.extend(cast(dict[str, Any], value))
            found.extend(schema_text(list(cast(dict[str, Any], value).values())))
        else:
            found.extend(schema_text(value))
    return found


class ToolScreen:
    """A route's verdicts on its tools. A definition is scanned once per
    version of its text; a flag is audited when first seen. A detector failure
    hides the tool without caching it."""

    def __init__(self, route: str, detector: Detector, audit: Callable[..., None]) -> None:
        self.route = route
        self.detector = detector
        self.audit = audit
        # Tool name -> (hash of its definition text, flagged?)
        self._verdicts: dict[str, tuple[str, bool]] = {}

    def known_verdict(self, name: str) -> bool | None:
        cached = self._verdicts.get(name)
        return cached[1] if cached is not None else None

    async def flagged(self, tools: list[Tool]) -> set[str]:
        # By name: an upstream listing one name twice gets one verdict on both.
        texts: dict[str, list[str]] = {}
        for tool in tools:
            texts.setdefault(tool.name, []).append(tool_text(tool))
        flagged: set[str] = set()
        for name, definitions in texts.items():
            if await self._is_flagged(name, "\n".join(definitions)):
                flagged.add(name)
        return flagged

    async def _is_flagged(self, name: str, text: str) -> bool:
        digest = hashlib.sha256(text.encode()).hexdigest()
        cached = self._verdicts.get(name)
        if cached is not None and cached[0] == digest:
            return cached[1]
        line = {"route": self.route, "tool": name, "definition_sha256": digest}
        try:
            verdict = await self.detector.scan(text)
        except Exception as exc:  # fail closed: hidden for now, not cached, so the next listing retries
            self.audit("tool_flagged", **line, reason=f"detector failed: {type(exc).__name__}")
            return True
        self._verdicts[name] = (digest, verdict.suspicious)
        if verdict.suspicious:
            self.audit("tool_flagged", **line, layer=verdict.layer, matched=list(verdict.matched))
        return verdict.suspicious
