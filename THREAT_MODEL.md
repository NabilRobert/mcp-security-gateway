# Threat model

What mcp-gateway defends against, how, the evidence for each claim, and
what is left over. The gateway sits between AI agents and MCP servers
(tools only), and is meant to run on the same trusted host as those
servers.

## Assets

- **What the upstream servers can do:** read a database, read and write
  files.
- **The upstream servers' own credentials.**
- **The data in tool outputs,** which goes straight into a model's context.
- **The audit trail:** who called what, and what the gateway decided.

## Trust boundaries

| Party | Trusted to | Not trusted to |
|---|---|---|
| Gateway host and its operator | Run the gateway, hold the config and keys | — (a compromised host is out of scope) |
| Caller (holder of a gateway key) | Act within its policy | Stay within its policy unaided |
| The agent's model | — | Ignore instructions it reads in tool outputs |
| Upstream server | Execute calls correctly | Return outputs that are safe to show a model |
| Whoever can write into data the tools read (a database row, a file) | — | Anything. This is the injection attacker |

## Threats

| # | Threat | Mitigation | Evidence | Residual risk |
|---|---|---|---|---|
| 1 | Calls without a valid key | Bearer API keys, checked before any MCP session exists (Starlette's auth middleware) | Tests: no key, a wrong key, a non-Bearer scheme and an empty key each get 401, and the upstream is never called | A stolen key works until it is removed from the config. There is no expiry and no rotation tooling |
| 2 | Keys exposed through config or logs | Only SHA-256 hashes stored; keys compared in constant time; secret-like arguments redacted at any depth | Tests: no key appears in the audit log, stdout or stderr; nested secret fields are redacted | Redaction is by field name; a secret passed under an innocent name is logged |
| 3 | Over-privileged agents | Per-caller, per-route tool allow-lists, deny by default; tools not allowed are hidden from `tools/list` | Tests: a denied tool is refused and never forwarded (call-counting fake upstream) | Policies are only as tight as the operator writes them |
| 4 | Path tricks in arguments | Prefix rules resolve `.` and `..` first; absolute and relative never match; NUL bytes and backslashes refused | 16 table-driven path tests | Symlinks are not resolved; the upstream's own confinement still applies |
| 5 | One caller using another's session | A session is bound to the caller that first used it, by `Mcp-Session-Id` | A real HTTP test: a second key on the first key's session is refused | — |
| 6 | Prompt injection in tool outputs | A rules layer and a local classifier read every output (text, plus the string values of structured content); a flagged output is blocked by default | Held-out test split: rules + model catch 49.7% of unseen injections at 1.2% false positives; rules alone, 14.6%. The scripted gullible agent through the gateway: 12/12 attacks had effect without detection, 5/12 with it, matching the pre-registered prediction (`eval/results/gullible/`) | Detection misses about half of unseen phrasings (50.3% on test), and 5 of 12 attacks got through in the gullible run. Untested languages, heavy obfuscation and novel phrasing will get through more often. **This is a mitigation, not a guarantee** |
| 7 | Hiding an injection where the detector can't read | Images, audio, embedded resources and text past the scan cap are blocked unless a policy allows them | Tests for an image and for an oversized output | An operator who allows unscanned content accepts that risk |
| 8 | Breaking the detector to get output through | Detector errors and timeouts block the output (fail closed) | Tests: a crashing detector and a timing-out detector both block | A slow detector blocks benign outputs, which costs false positives, not safety. Measured through the gateway on a laptop CPU, rules + model block 2.5% of held-out normal outputs, mostly large ones timing out (`eval/results/gateway-fp/`) |
| 9 | Tampering with the audit trail | Append-only JSONL; each line carries the hash of the one before; the chain is checked at every start; `verify-log` | Tests: edits, inserts, deletes, reordering and garbage are detected; a crash's torn line is told apart | Someone who can rewrite the whole file can rebuild the chain, and lines cut from the end can't be detected. Shipping the log off the host would fix both |
| 10 | The agent getting the upstream's credential | The gateway holds each upstream's key; the agent's key opens only the gateway | Test: a recording fake upstream sees only its own key | — |
| 11 | One agent's actions leaking into another's run | Per-session upstream processes for stateful stdio servers | Tests, including with the harness's own launcher: a write in one session is absent in the next | Shared (HTTP) upstreams are shared by design |
| 12 | Unaudited calls | The `call` line is written before forwarding; if it can't be written, the call is refused | Test: with the log unwritable, the call is refused and the upstream never called | — |
| 13 | Poisoned tool descriptions from a malicious upstream | Tool definitions are untrusted too: each tool's title, description and parameter descriptions go through the same detector when tools are listed. A flagged tool is hidden, and calls to it are refused even if the agent never listed tools. A detector failure hides the tool (fail closed); a changed definition is scanned again | Tests: a flagged tool is hidden and its call refused without listing; a failing detector hides it; a changed description is rescanned. The real upstreams' 18 tools all pass with rules + model on (`eval/results/tool-descriptions/`) | The detector's recall was measured on outputs, not descriptions, so it will miss phrasings it misses there. Tool and parameter *names* aren't scanned. An upstream can still lie about what a tool does without injecting instructions |
| 14 | One key flooding the gateway with calls | An optional limit per key on tool calls, across all routes (`rate_limit`, moving window, the `limits` library). Counted before policy, so denied calls count too; a refused call gets an error result and a `rate_limited` audit line | Tests: past the limit a call is refused and never forwarded; one key's limit doesn't touch another's; a call refused by one window doesn't use up another | Counts are in memory: a restart resets them, and two gateway processes count separately. `tools/list` and failed logins aren't counted. Large outputs still cost CPU, bounded by the window cap and the timeout |

## Not defended in v1

- **Denial of service beyond one key's calls.** Many keys, unauthenticated
  floods and slow requests are left to whatever sits in front of the
  gateway.
- **Resources, prompts, sampling and elicitation.** The gateway proxies
  tools only and advertises nothing else.
- **A compromised gateway host,** or a malicious operator.
- **Model behaviour itself.** The gateway reduces what reaches a model; it
  can't make a model refuse instructions.
