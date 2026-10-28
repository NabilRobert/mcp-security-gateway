# ADR-011: Tool descriptions are scanned, and a flagged tool is hidden

**Context:**
- A tool's description is read by the model like a tool output, so a
  malicious upstream can inject through it (MCPTox, Phase 1). It was a
  *should* in Phase 2 and cut from v1 (Phase 7).

**Decision:**
- `detector.scan_tool_descriptions` (on by default). At `tools/list`, each
  allowed tool's title, description and the `description` values in its
  input schema are joined and scanned by the same detector as outputs.
- A flagged tool is **hidden**, not rewritten: an edited description would
  break the promise that tool definitions pass through unchanged, and
  annotating it still puts the text in front of the model.
- Calls to a flagged tool are refused. A call to a tool not screened yet
  (the agent never listed tools) lists the upstream's tools and screens it
  first, so skipping `tools/list` doesn't skip the check.
- Verdicts are cached per route by tool name and the definition's SHA-256,
  so a changed definition is scanned again on the next listing. Each newly
  flagged tool gets one `tool_flagged` audit line.
- A detector error or timeout hides the tool, as it blocks an output. The
  failure isn't cached, so one slow scan doesn't hide a tool for good: the
  next listing tries again.

**Options considered:**
- **The gateway's own detector (chosen):** the rules and the classifier
  already measured on outputs; the new code is only the glue at
  `tools/list` and `tools/call`.
- mcp-scan (Invariant Labs): scans tool descriptions from the client's
  side, when servers are installed, not inline on every listing. It
  complements the gateway rather than replacing this check.
- Rewriting or annotating flagged descriptions: rejected above.

**Consequence:**
- A false positive hides a benign tool the agent can't work around, which
  costs more than a blocked output. The real upstreams' 18 tools all pass
  (`scripts/check_tool_descriptions.py`).
- Listing costs a scan per changed tool; unchanged tools are cached.

Part of the [architecture decisions](README.md) (Phase 5).
