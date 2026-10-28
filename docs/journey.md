# Journey

How mcp-gateway was built, in order: what was planned, what the spikes
found, what broke, and what was decided. The decisions and their reasons
are in the [ADRs](adr/README.md); this is
the story around them.

## Why

The portfolio already had an MCP server
([MCP-backbone](https://github.com/NabilRobert/MCP-backbone)) and a way to
measure agents
([agent-eval-harness](https://github.com/NabilRobert/agent-eval-harness)).
What it lacked was security for agents. The main risk there is
**prompt injection in tool outputs:** a database row or a file that tells
the model to do something else. The harness already had one such task
(f17), and one model in its runs had obeyed it.

Good MCP gateways already exist (IBM ContextForge, Docker's, Microsoft's,
Enkrypt's). So the goal wasn't a new gateway. It was a small one whose
injection defence is **measured**: attack success with and without it, with
the false-positive cost next to it.

## Planning

The same seven planning phases as the earlier projects, written before any
code, each short and reviewed by Arthur. Two choices shaped everything
after:
- **Detection must cost $0.** That ruled out a paid LLM judge and left
  rules and a small local classifier.
- **Every claim needs a number.** That meant a held-out split for the
  detector, and a scripted control agent for the end-to-end path while the
  model budget is zero.

## Spikes: three surprises

- **The classifier hated JSON.** On real tool outputs replayed from the
  harness's runs, ProtectAI's model flagged 54% of normal outputs. A row
  saying `{"not_returned": 241}` scored 1.0. The rule written beforehand
  killed it.

  Before running anything, I declared one variant: score only a JSON
  output's string values. It cut false positives to about a quarter. While
  building that, I also found that my own planting method had inflated the
  first run's recall, and I fixed the method before the rerun. The model
  layer survived, below its target.
- **The model was slow on CPU.** p95 was 416 ms per 512-token window, and
  large outputs took seconds. Arthur chose int8 quantisation.
- **FastMCP almost replaced the proxy.** Arthur asked for frameworks over
  hand-built code. FastMCP's proxy passed through all 120 replayed calls
  unchanged, and its middleware and auth hooks worked. But it adds a
  generated `title` and `_meta.fastmcp` to every tool definition, which
  the criterion fixed in advance didn't allow. Arthur kept the SDK proxy.
  FastAPI, Typer, Starlette's auth, mutmut and pytest-timeout did replace
  hand-built pieces.

## Bugs the tests caught

- **Session binding bound nothing.** "A session can't switch callers" keyed
  on the SDK's session object. But SDK 2.3.0 builds a new session object
  for every request, so on a real connection the check never fired. Its
  unit test used fake session objects and passed anyway.

  It was found while building per-session upstreams, and fixed by keying
  on `Mcp-Session-Id`. A real HTTP test now proves it.
- **The detector's timeout never fired.** A thread can't be interrupted, so
  a slow scan would have hung the call instead of failing closed. Fixed
  with anyio's `abandon_on_cancel`.
- **The dev/test split leaked.** The benign split hashed output ids, and
  identical texts (the same file read two ways) landed on both sides. The
  split test caught it before the test half was ever scored.
- **YAML read a key hash as a number.** An unquoted all-digit SHA-256 became
  an integer. The example config was committed with exactly that mistake,
  and the config now asks for quotes.
- **Exception groups hid start-up errors.** A bad upstream crashed with a
  traceback instead of exiting 2 with the real cause.
- Two regex flaws in my own rules: `\b` before `.env`, and "same sentence"
  gaps that stopped at the dot in a file name.

Every slice was mutation-checked: the code was broken on purpose to see a
test fail. Two mutants made the suite *hang* rather than fail, so
pytest-timeout now turns a hang into a failure.

## The $0 measurement

The harness's scripted gullible agent obeys whatever it reads. It ran a
12-task attack suite through the gateway, built from the injection
families the rules were never written from. The prediction of which
attacks the detector would stop was committed first. The result matched it
exactly:
- 12/12 attacks had an effect with detection off;
- 5/12 with it on.

It also showed two costs plainly. A blocked output takes the honest answer
with it. And a read-only allow-list stops writes but not leaks.

## The held-out score

The test split was scored once, at the end. The rules, written from the dev
families, fell from 100% recall on dev to **14.6%** on unseen phrasings.
That is the overfitting the split was built to expose. With the model, the
two layers caught **49.7%** at **1.2%** false positives. The honest headline
is "about half", and it is the one the README leads with.

## Measuring it where it runs

The detector's offline score said 1.2% false positives. Measured through
the running gateway, the first version blocked **35%** of normal filesystem
calls. The gateway scanned the server's repeated text twice, and a scan
that timed out kept running and slowed every scan after it.

After the fix (one scan at a time, timed-out scans stopped, repeated text
scanned once), it blocks **2.5%** of held-out normal outputs. That is still
twice the offline figure, because large outputs time out on a laptop CPU.

The measurement also tripped over MCP-backbone's own rate limit: 810 of
867 calls in one run were refusals, fast and wrong. Every timing script now
refuses to report if any call was rate-limited.

## Not done yet

- Real-model runs. They need a budget; until then, every published number
  says what it is and isn't.
