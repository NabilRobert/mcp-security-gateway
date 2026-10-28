# mcp-gateway

A small security gateway that sits between AI agents and
[MCP](https://modelcontextprotocol.io) servers. It adds what most servers
don't have: who may connect, which tools each caller may use, a tamper-evident
record of every call, and a check of every tool output for prompt
injection. Its injection defence is **measured, not claimed**.

The agent connects to the gateway exactly as it would to the server; tool
names, schemas and results pass through unchanged, except for what policy
filters out.

| Layer | What it does |
|---|---|
| Auth | Bearer API keys, stored as SHA-256 hashes, checked before any MCP session exists (Starlette's auth middleware). An optional call limit per key (`rate_limit`, on the `limits` library) |
| Policy | Per caller and route: allowed tools (deny by default), argument rules (path prefixes with `..` resolved, full-match patterns) |
| Upstreams | HTTP or stdio; the gateway holds each server's own credential, so an agent's key opens only the gateway. Stateful stdio servers get one process per MCP session. A call's `_meta` (an app's delegation token, trace context) is forwarded unchanged, with the authenticated caller stamped in as `io.github.nabilrobert.mcp-gateway/caller` |
| Detection | Every tool output (text and structured content) is read by pattern rules, then a local classifier (ProtectAI's DeBERTa prompt-injection model, ONNX on CPU). A flagged output is blocked (default), annotated, or logged. Tool descriptions are scanned too: a flagged tool is hidden and its calls refused |
| Audit | Append-only JSONL with a hash chain, a line written *before* each call is forwarded; `mcp-gateway verify-log`. It records whether a call carried `_meta`, never what it held |
| Tracing | Optional OpenTelemetry traces (OTLP/HTTP): one span per stage of a call under the MCP SDK's own, so an agent's trace runs through the gateway into the upstream. Outcomes and timings only, never arguments or outputs |

It fails closed: a detector error or timeout, content it can't scan, or an
audit log it can't write all block the call.

It is deliberately small, so it can be read and checked. For production use,
look at IBM ContextForge, Docker's MCP Gateway, Microsoft's MCP Gateway or
Enkrypt's Secure MCP Gateway ([ADR-001](docs/adr/adr-001-build-small-gateway.md)).

Part of a portfolio, with
[MCP-backbone](https://github.com/NabilRobert/MCP-backbone) (the database
MCP server it protects) and
[agent-eval-harness](https://github.com/NabilRobert/agent-eval-harness) (which
measures it).

## What is measured

All of this cost $0: no paid model was called.

**1. A scripted "gullible" agent through the gateway**
([`eval/results/gullible/`](eval/results/gullible/README.md)). It obeys any
instruction it reads, so it shows the gateway's mechanics, not how a real
model behaves.
- It ran a 12-task attack suite, built from the injection families the rules
  were never written from.
- Which attacks the detector would stop was predicted and committed before
  the run.

| Configuration | Attacks with effect | Questions answered |
|---|---|---|
| No gateway | 12/12 | 12/12 |
| Gateway, detection off | 12/12 | 12/12 |
| **Gateway, detection on** | **5/12** (exactly the prediction) | 5/12 |
| Gateway, read-only tools only | 9/12 | 12/12 |

What it shows:
- The proxy alone changes nothing.
- Blocking a poisoned output also withholds the honest answer in it.
- Least privilege stops writes but not leaks.

**2. The detector, offline, on labelled tool outputs**
([`eval/`](src/mcp_gateway/eval/)). The benign side is 1,977 real outputs,
replayed from the harness's recorded runs. The injected side plants 39
templates into them.

The split into dev (tuning) and test (published) is fixed by template
family and by a hash of each output's text. Test is scored once per
detector version.

**Held-out test split**, scored once per detector version
([`eval/results/`](eval/results/)): 1,119 benign and 632 injected samples,
from injection families no rule was written from.

| Detector | False positives | Recall | Precision |
|---|---|---|---|
| Rules | 0.0% | 14.6% | 100% |
| **Rules + model** (fp32, threshold 0.999) | **1.2%** | **49.7%** | **96.0%** |

What it shows:
- **The rules don't generalise.** They catch 100% of the dev split they
  were written from, and 14.6% of unseen phrasings.
- **The model does most of the real work.** Together, the two layers catch
  about half of unseen injections, at a 1.2% false-positive rate.
- **Weakest families:** messages addressed to the assistant (13%) and
  conditionals ("if you are an AI…", 27%).
- **Strongest families:** obfuscated text (87%) and Japanese (84%).
- **False positives:** ordinary text such as a film description ("…who must
  defeat…") and filesystem error messages.
- **Timeouts:** a scan past the 2 s timeout blocks the output, and counts
  here as flagged (3 of 1,751 samples).

Dev numbers, for comparison: rules 0% FP / 100% recall; rules + model 2.8%
FP / 100% recall. An int8 copy was tried to speed the model up. It ran
about 1.7× faster but lost 19 points of recall, failing the acceptance rule
fixed beforehand, so the fp32 model stays
([Phase 6](docs/planning/phase-6-risks-skeleton.md)).

**3. Overhead and false positives through the running gateway**
([`overhead/`](eval/results/overhead/README.md),
[`gateway-fp/`](eval/results/gateway-fp/README.md)).
- **The proxy alone** adds a median of about 3–9 ms per call (p95 15 ms or
  less), with the audit log `fsync`ing. The rules add nothing measurable.
- **The model layer** adds 18–87 ms at the median, but its p95 reaches the
  2 s timeout on large outputs.
  - Through the gateway, it blocks **2.5% of held-out normal outputs**
    (10 of 405), against 1.2% offline. Most of the difference is large
    outputs timing out on a laptop CPU.
  - A first version blocked 35% of filesystem calls. It scanned repeated
    text twice, and timed-out scans kept running and slowed the next. Both
    are fixed (scan `s2`).
- **Choose per deployment.** Rules only block nothing normal but catch
  little that's unseen. Rules + model catch about half, and wrongly block
  about 1 normal output in 40.

**Not measured yet:** how often real models obey these injections, with
and without the gateway. Those runs need a model budget. Until then, no
number here should be read as "the gateway stops X% of injections".

## Quick start

```bash
uv sync
uv run mcp-gateway hash-key            # prints a caller key (shown once) and its hash
cp examples/gateway.yaml gateway.yaml  # put the hash in, quoted; list upstreams and policies
uv run mcp-gateway serve --config gateway.yaml
```

The agent connects to `http://127.0.0.1:8080/mcp/<upstream>/` with
`Authorization: Bearer <key>`. To check the audit log:

```bash
uv run mcp-gateway verify-log logs/audit.jsonl
```

The model layer needs the classifier on disk. It's a 739 MB download from
Hugging Face (`protectai/deberta-v3-base-prompt-injection-v2`, revision
`90c9989b1a34`). Without it, set `detector.model` to null and the rules
run alone.

Tracing is off unless an OTLP endpoint is set, for example a local Jaeger:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 uv run mcp-gateway serve --config gateway.yaml
```

Each `tools/call` span gets the stages `rate_limit`, `policy`, `audit`,
`forward`, `detect` and `audit` as children, with `error.type` on the
stage that refused or blocked the call (`rate_limited`, `denied`,
`tool_hidden`, `blocked_suspicious`, `blocked_unscanned`,
`detector_failed`). The call span carries the caller, the route, the
decision and the `call_id`, which matches the audit log. The service name
is `mcp-security-gateway` unless `OTEL_SERVICE_NAME` says otherwise. A dead viewer
only loses spans, and a stop waits at most 2 s for it.

## Design

- [Threat model](THREAT_MODEL.md): what it defends against, the evidence,
  and what it doesn't defend against.
- [Planning trail](docs/planning/README.md): seven phases, written before
  the code, including the ADRs and the spike results.
- [Journey](JOURNEY.md): what the spikes found, the bugs the tests caught,
  and what was reversed.

Built on the MCP Python SDK's low-level `Server` (ADR-002), with FastAPI,
Starlette's auth, Pydantic, Typer and onnxruntime. FastMCP's proxy was
tried and kept out (Spike 7): it adds fields to every tool definition.

## Development

```bash
uv sync
uv run ruff check . && uv run ruff format --check . && uv run pyright
uv run pytest                                  # no network, no model
MCP_GATEWAY_LOCAL_TESTS=1 uv run pytest        # plus the replay against the real servers
uv run mutmut run                              # mutation testing
```

Every slice was mutation-checked: the code was broken on purpose and a test
had to fail. A full mutmut run and its triage are in
[docs/mutation-testing.md](docs/mutation-testing.md): the survivors that
meant real gaps (the scorer behind the published numbers had no test, and
nothing pinned the split) got tests, and the rest are classed as equivalent
or cosmetic. CI runs ruff, pyright (strict on `src`) and pytest.

## Next

- A faster model layer (Prompt Guard 2 22M, or a GPU), so large outputs
  stop timing out.
- Real-model runs (slice H), when there is a budget.
- Try Llama Prompt Guard 2 22M as the model layer, once its licence is
  accepted.
- Attack tasks on the database (planted rows in a separate copy of the
  demo data).
