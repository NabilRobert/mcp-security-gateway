# Mutation testing

[mutmut](https://github.com/boxed/mutmut) changes the code one small edit at
a time: a `False` becomes `None`, a `<` becomes `<=`, a string gains `XX`.
It then runs the tests. A mutant the tests don't notice (a **survivor**) is
behaviour no test pins down. Config: `[tool.mutmut]` in `pyproject.toml`.
Run it with `uv run mutmut run`; it takes about 25 minutes on a laptop.

During the build, each slice was also mutation-checked by hand: targeted
mutants, one at a time (see the commits). This page is the full run and
its triage.

## Before triage (2026-10-27)

1,792 mutants:

| Result | Count |
|---|---|
| Caught by a test | 1,062 |
| Survived | 447 |
| No test reached the code | 251 |
| Timed out | 8 |

## Triage: what the survivors meant

**Real gaps → tests added.**
- **The scorer behind the published detector numbers had no test at all:**
  91 mutants of `eval.score.score` were untouched. Planting, sample
  building and `record_test_score` were thin too.
  → `tests/test_eval_scoring.py` (rates, failures counted as flagged,
  planting positions, per-split counts).
- **Nothing pinned the dev/test split.** An edit to `benign_split` would
  have silently reshuffled the published test set.
  → A test pins the 858 / 1,119 benign assignment.
- **The audit log's contract.** Nothing held:
  - the field names and the UTC timestamp;
  - the fields of the start and refused-key lines;
  - reopening a one-line log;
  - a torn line that is still the last line;
  - a recovery line with the wrong hash;
  - the `fsync` path;
  - denied calls being reported as unfinished. An `and` → `or` mutant
    survived here: a real bug path with no test.

  → `tests/test_contracts.py`.
- **Error paths.** The upstream-failure path had no test: its audit line,
  and the `-32001` code the agent gets. Nor did the `-32603` code and the
  stderr message when the log can't be written.
  → `tests/test_contracts.py`.
- **The policy hash.** Nothing proved it ignores key order, so a recorded
  hash could have drifted between runs. → A test.
- **The idle reaper.** Per-session upstreams are reaped after the idle
  timeout, and nothing tested it. → Two tests: an idle session is reaped,
  a busy one is kept.
- **Policy refusals were checked as falsy,** so `Verdict(None, …)`
  survived. → They are asserted `is False`, with exact reasons.
- **JSON arrays and indented JSON** in the scanner. → A test.

**Equivalent mutants** (they can't change behaviour, so no test can catch
them):
- Header-name case. Starlette's headers and HTTP are case-insensitive.
- `docs_url=None` / `redoc_url=None` removed: FastAPI serves no docs
  without an OpenAPI URL, which stays off.
- The connector's `name` argument. Both connectors ignore it.
- `LayeredDetector`'s initial verdict. It requires at least one layer, so
  the value is always overwritten.
- A 33-byte key instead of 32: as random, and no less safe.
- `rsplit(…, 2)` and `[+1]` on a two-element split.

**Cosmetic** (message wording and labels nobody parses): 401 body text,
refusal messages beyond those now pinned, the FastAPI title, the
`AuthCredentials` scope label, and log text. Accepted.

**Out of reach of mutmut here:**
- **The model layer** (`ModelDetector`). mutmut's working copy doesn't
  include the 750 MB model, so those tests skip there. They run locally
  (`tests/test_detection.py`) and in the dev/test scoring.
- **Pagination** of an upstream's tool list. Neither upstream paginates;
  it's left untested and noted.

## After triage

The same 1,792 mutants, after two rounds of tests (the suite grew from 123
to 165 tests):

| Result | Before | After |
|---|---|---|
| Caught | 1,062 | 1,357 |
| Survived | 447 | 333 |
| No test reached the code | 251 | 102 |
| Timed out | 8 | 0 |

**Reading "survived" honestly:**
- 55 of the 333 are `ModelDetector.__init__`. A new test reaches the
  constructor only to prove a missing model fails cleanly, so these moved
  from "no test reached" to "survived". They belong with the model layer,
  which is out of mutmut's reach here (the other 102 unreached are the
  model's remaining methods).
- **Excluding the model layer, survivors fell from 447 to 278 (−38%), and
  unreached code from 94 mutants to 0.**

| Module | Caught | Survived (before → after) | No test reached (before → after) |
|---|---|---|---|
| `app` | 268 | 86 → 59 | 0 → 0 |
| `audit` | 156 | 42 → 28 | 0 → 0 |
| `auth` | 56 | 23 → 22 | 0 → 0 |
| `config` | 22 | 11 → 3 | 0 → 0 |
| `detect` (model layer included) | 94 | 33 → 86 | 157 → 102 |
| `eval.score` | 281 | 95 → 48 | 91 → 0 |
| `eval.split` | 16 | 4 → 0 | 0 → 0 |
| `policy` | 90 | 12 → 5 | 0 → 0 |
| `proxy` | 330 | 116 → 68 | 3 → 0 |
| `upstreams` | 44 | 25 → 14 | 0 → 0 |

The second round added tests for:
- the session-end hook's guards: a `DELETE` without a session id, to a
  non-MCP path, or unauthenticated is ignored. A mutant that crashed on a
  missing header had survived;
- the session-binding memory cap;
- detection off built from config.

**The remaining survivors were spot-checked:**
- the timing arithmetic behind the published latency figures (p50/p95);
- message and label text;
- the memory-cap threshold's exact value;
- conditions that are equivalent behind the auth middleware.

None changes a security decision. They are accepted, not hidden: rerun
`mutmut run` and `mutmut results` to see each one.
