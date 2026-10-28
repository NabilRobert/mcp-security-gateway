# ADR-010: Per-session upstreams, keyed by `Mcp-Session-Id`

**Context:**
- Spike 2 found that every session on a stdio route shares one upstream
  process. A gullible agent's `write_file` changed the fixture for every
  later trial.
- While building the fix, slice F found that the SDK (2.3.0) builds a
  **new session object for every request**, even on the legacy protocol.
- Slice B's "a session is bound to its caller" keyed on that object, so on
  a real connection it bound nothing. Its unit test used fake session
  objects and passed anyway.

**Decision:**
- A session is its `Mcp-Session-Id`. The caller binding keys on it; a real
  HTTP test now proves another caller's key is refused on an existing
  session.
- A stdio upstream can be `per_session: true`. Each session gets its own
  process, started on first use. It is stopped when the client deletes the
  session (an HTTP-layer hook sees the `DELETE`, and only the owning caller
  can end it) or after the SDK's 30-minute idle timeout.
- Each process is owned by its own task, because an SDK client must be
  closed in the task that opened it.
- A client without a session (protocol 2026-07-28 and later) is refused on
  a per-session route, rather than silently sharing a process.
- Stdio upstreams take a `cwd`: the SDK starts them with a minimal
  environment, so this is how `python -m` finds a package.

**For the harness:**
- The upstream command is the harness's own launcher
  (`python -m agent_eval.fs_server FIXTURE`, `cwd` set to the harness), and
  it already copies the fixture per process.
- Isolation per trial needs no harness-specific code in the gateway.
- Inspect connects with `ClientSession.initialize()`, so it has sessions.

**Not chosen:**
- FastMCP's fresh backend per request (Spike 7): it would lose state
  between the calls of one trial.
- Keying on the SDK's session object: it doesn't live past one request.

Part of the [architecture decisions](README.md) (Phase 5).
