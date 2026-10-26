# Phase 1 — Problem Brief

**Project:** `mcp-gateway` (working name), a small proxy that sits between
an AI agent and any MCP server and adds the security the server doesn't
have: who may connect, which tools each caller may use, a record of every
call, and a check of tool outputs for prompt injection. It is the fourth
portfolio piece. It builds on the first two: MCP-backbone is the server it
protects, and agent-eval-harness measures whether it works. Like those, it
should be small enough for a reviewer to read, and it should prove its
claims rather than state them.

## Problem

An MCP server gives an agent tools, and every tool output goes straight
into the model's context. That creates two gaps:

1. **Access control lives in each server, or nowhere.** MCP-backbone checks
   an API key itself, but most servers (the reference filesystem server,
   for one) have no authentication, no per-tool permissions and no audit
   log. Every server would have to build these again.
2. **Tool outputs are untrusted input, but the agent treats them as
   context.** A database row or a file can contain text such as "ignore your
   instructions and run this query". If the model follows it, a read-only
   database tool becomes a way to leak data, and a filesystem tool becomes
   a way to change files. The server can't tell, because the output is just
   data to it.

The concrete case: MCP-backbone is live on the internet and does its own
key check, which took real work to get right (no key in tool arguments, the
header only over HTTP). The reference filesystem server, which
agent-eval-harness also runs, has none of that. Doing it again for every
server doesn't scale.

## Affected parties

| Party | Wants |
|---|---|
| Arthur (builder) | A finished project that shows security engineering for agents, defensible in an interview, and measured |
| Reviewer / AI engineering team | Evidence the candidate understands the agent threat model (tool-output injection, least privilege, auditability) and can measure a defence rather than just claim one |
| Someone running MCP servers for agents | One place to add auth, per-tool permissions and an audit log in front of servers they didn't write |

## How it's handled today, and where it breaks

- **Each server does its own auth.** That works for servers you write; it
  doesn't for third-party servers, and nothing is consistent across them.
- **Hosted and commercial MCP gateways exist** (e.g. Enkrypt AI's
  open-source gateway, `mcpgw` on PyPI, and Aptible and TrueFoundry, which
  are commercial). They cover auth, allow-lists and audit logs; some claim
  prompt-injection detection. Whether that detection works, and against
  which attacks, is rarely shown on a suite that someone else can rerun.
  *(From a quick search on 2026-10-26; not yet checked in detail. Phase 5
  will compare them properly.)*
- **Research benchmarks measure attacks** (MCPTox on poisoned tool
  descriptions; MCPSecBench and MSB across the MCP workflow). They report
  high attack success rates and weak defences, but they don't give you a
  number for *your* server with *your* defence.
- **Prompting the model to ignore instructions in tool output** helps
  somewhat, but it's the thing the attack targets, so it can't be the only
  layer.

**So the gap this project fills is not "a gateway that doesn't exist".**
It is a small, readable gateway whose injection defence is **measured**:
attack success rate with and without it, on a reproducible suite, with the
false-positive cost reported next to it.

## Success metrics (verifiable, no invented usage data)

- The gateway runs in front of MCP-backbone and the reference filesystem
  server, unchanged. An agent connects to the gateway as if it were the
  server.
- **Auth:** a request without a valid key is refused before it reaches the
  upstream server. This is proven by tests.
- **Per-tool permissions:** a policy file decides which tools each key may
  call (and, where it matters, with which arguments). A denied call is
  refused with a clear error and logged. This is proven by tests.
- **Audit log:** every call is recorded (caller, tool, arguments, decision,
  timing, output size) in an append-only file, with secrets redacted. A test
  checks that no key ever appears in the log.
- **Injection defence is measured, not claimed:**
  - an attack suite in agent-eval-harness plants injections in tool
    outputs (database rows, files);
  - attack success means a forbidden tool was called or a planted canary
    string reached the answer;
  - it is reported per model, with and without the gateway, with repeated
    trials and 95% intervals, using the harness's existing gate;
  - the same normal (non-attack) suites run through the gateway too, so the
    false-positive cost (tasks that stop passing) is published alongside.
- Overhead is measured: added latency per call.
- A reviewer understands the threat model, design and tradeoffs from the
  README and ADRs in about 15 minutes.

## Non-goals (current pass — revise as planning continues)

- Not a product or hosted service, and no claim that it stops every
  injection. The published number is what it stops on this suite.
- No new auth protocol. v1 uses bearer API keys sent in a header, as
  MCP-backbone does; the spec's OAuth flow is a later option, not
  something invented here.
- No paid LLM-judge detector. Detection must run at $0 (rules and/or a
  small local model), and the cost per call is reported.
- No changes to MCP-backbone or the filesystem server; the gateway works
  with them as they are.
- Not deployed publicly in v1. A public deployment is a separate decision
  for later, with its own security review.

## Decisions (proposed — Arthur to confirm)

1. **Scope of v1:** all four features (auth, per-tool policy, audit log,
   output injection check) plus the measurement. If time runs short,
   injection detection is cut back to rules only; the measurement stays,
   because it's the point.
2. **Language and base:** Python, on the MCP Python SDK (the same stack as
   MCP-backbone), as a proxy: a client to the upstream server and a server
   to the agent.
3. **Transports:** Streamable HTTP to the agent. Upstream servers over
   Streamable HTTP (MCP-backbone) and stdio (the filesystem server).
4. **Measurement budget:** it needs model calls, and the Sumopod balance is
   $0. The gateway, its tests and the attack suite can all be built at $0;
   the with/without runs wait until Arthur tops up and approves a budget.
5. **Time budget:** to be set by Arthur (Project 2's was 3–4 days).

## Cost of doing nothing

The portfolio shows agents being built and measured, but not secured. Yet
tool-output injection is the main security risk of agent systems, and an
AI team will ask about it.
