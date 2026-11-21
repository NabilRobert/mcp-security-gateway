"""Screening tool definitions: a poisoned description or schema reaches a
model like an output does, so everything a model can read of a tool goes
through the detector when tools are listed or called.
"""

import hashlib
from collections.abc import Callable
from typing import Any, cast

from mcp.types import Tool

from mcp_gateway.detect import Detector, json_keys, string_leaves

# The usual values of `type`, `format` and `$schema` are fixed tokens, not
# text a model is meant to read, so they stay out of the scan. Any other
# value under those keywords is scanned, since a model reads it all the same.
JSON_TYPES = frozenset({"string", "number", "integer", "boolean", "object", "array", "null"})
# JSON Schema 2020-12's formats, plus OpenAPI's.
FORMATS = frozenset({
    "date-time", "date", "time", "duration", "email", "idn-email", "hostname", "idn-hostname",
    "ipv4", "ipv6", "uri", "uri-reference", "iri", "iri-reference", "uuid", "uri-template",
    "json-pointer", "relative-json-pointer", "regex",
    "int32", "int64", "float", "double", "byte", "binary", "password",
})  # fmt: skip
META_SCHEMAS = frozenset({
    "http://json-schema.org/draft-04/schema#", "http://json-schema.org/draft-06/schema#",
    "http://json-schema.org/draft-07/schema#", "https://json-schema.org/draft/2019-09/schema",
    "https://json-schema.org/draft/2020-12/schema",
})  # fmt: skip
KNOWN_VALUES = {"type": JSON_TYPES, "format": FORMATS, "$schema": META_SCHEMAS}
SCHEMA_DATA_KEYWORDS = frozenset({"default", "const", "enum", "examples"})
SCHEMA_NAME_KEYWORDS = frozenset({"properties", "patternProperties", "$defs", "definitions"})
# Every keyword of JSON Schema drafts 4 to 2020-12. A key outside this list
# is a custom one ("x-note"), and its name is text a model reads.
SCHEMA_KEYWORDS = frozenset(
    {
        "$schema", "$id", "id", "$ref", "$anchor", "$dynamicRef", "$dynamicAnchor", "$recursiveRef",
        "$recursiveAnchor", "$vocabulary", "$comment", "$defs", "definitions",
        "allOf", "anyOf", "oneOf", "not", "if", "then", "else", "dependentSchemas", "dependencies",
        "prefixItems", "items", "additionalItems", "contains", "properties", "patternProperties",
        "additionalProperties", "propertyNames", "unevaluatedItems", "unevaluatedProperties",
        "type", "enum", "const", "multipleOf", "maximum", "exclusiveMaximum", "minimum", "exclusiveMinimum",
        "maxLength", "minLength", "pattern", "maxItems", "minItems", "uniqueItems", "maxContains",
        "minContains", "maxProperties", "minProperties", "required", "dependentRequired",
        "title", "description", "default", "deprecated", "readOnly", "writeOnly", "examples",
        "format", "contentEncoding", "contentMediaType", "contentSchema",
    }
)  # fmt: skip


def tool_text(tool: Tool) -> str:
    """Everything a model can read of a tool definition."""
    annotation_title = tool.annotations.title if tool.annotations else None
    parts = [tool.name, tool.title, tool.description, annotation_title]
    parts += [*schema_text(tool.input_schema), *schema_text(tool.output_schema)]
    return "\n".join(p for p in parts if p)


def schema_text(schema: Any) -> list[str]:
    """Every string and key in a JSON Schema, except keyword names and the
    usual values of `type`, `format` and `$schema`. Under `default`, `enum`
    and the like, any key is data; under `properties`, keys are parameter
    names, which a model reads too."""
    if isinstance(schema, list):
        return [text for item in cast(list[Any], schema) for text in schema_text(item)]
    if not isinstance(schema, dict):
        return [schema] if isinstance(schema, str) else []
    found: list[str] = []
    for key, value in cast(dict[str, Any], schema).items():
        if key not in SCHEMA_KEYWORDS:
            found.append(key)
        if key in KNOWN_VALUES:
            found.extend(text for text in string_leaves(value) if text not in KNOWN_VALUES[key])
            found.extend(json_keys(value))
        elif key in SCHEMA_DATA_KEYWORDS:
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
