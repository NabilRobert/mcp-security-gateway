# ADR-007: Audit log as hash-chained JSONL

**Options:** SQLite; OpenTelemetry (the SDK ships an OTel middleware);
JSONL.
**Decision:** JSONL.
**Why:** an append-only text file is readable without tools and can be
diffed and committed next to a harness run. A hash chain makes an edit or
a deleted line visible.
**Details:**
- Each line has `prev` = the SHA-256 of the previous line's bytes.
- The first line chains from a fixed value plus the file's creation time.
- Lines are flushed after each write; `fsync` per line is a config switch,
  because Spike 6 measures what it costs.

**As built (slice C, 2026-10-27):**
- The first line chains from a fixed value (the creation time was dropped:
  it added nothing the chain doesn't already give).
- A torn last line from a crash is closed at the next start by a
  `recovered` line naming its hash, so the verifier tells a crash from an
  edit.
- The chain is checked at every start. A break is reported and recorded in
  the `start` line, not fatal, because refusing to start would let anyone
  who can edit the log keep the gateway down.
- `verify-log` also lists forwarded calls with no result.

**Limits:**
- A chain shows tampering. It doesn't prevent it: someone who can rewrite
  the whole file can rebuild the chain.
- Lines cut from the end can't be detected without an anchor kept
  elsewhere (shipping the log off the machine). Shipping the log off the machine
  would fix that, and is out of v1.
- OTel export is a *could*.

Part of the [architecture decisions](README.md) (Phase 5).
