# ADR-008: Where the measurement lives, and how it runs at $0

**Decision:**
- **The detector evaluation** (labelled set, splits, scorer) lives in this
  repo under `eval/`, because it tests gateway code.
- **The agent measurement** lives in agent-eval-harness, on a branch there:
  - the attack suite;
  - an `answer_excludes` grader (the canary must not appear);
  - a `gateway` target;
  - the configuration recorded in run settings.
- **The $0 end-to-end check** uses Inspect's `mockllm` with scripted
  outputs (`custom_outputs`, `ModelOutput.for_tool_call`). It drives a
  **scripted "gullible agent"** that always does what an injection says.
  That proves, with no paid calls, that the path works and that the graders
  catch a successful attack. It's deterministic, so it shows mechanics, not
  model behaviour.
- **Real-model runs** need Arthur's budget.

**Consequence:** the first published numbers are the detector's
precision and recall, plus the gullible agent's before and after. Both are
labelled for what they are.

Part of the [architecture decisions](README.md) (Phase 5).
