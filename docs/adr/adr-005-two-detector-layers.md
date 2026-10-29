# ADR-005: Two detector layers: rules, then a local classifier

**Options for the model layer** (Hugging Face metadata, 2026-10-26):

| Model | Licence | Gated | Weights |
|---|---|---|---|
| `protectai/deberta-v3-base-prompt-injection-v2` | Apache-2.0 | No | 738 MB, ONNX build included |
| `meta-llama/Llama-Prompt-Guard-2-22M` | Llama (custom) | Yes, manual approval | 283 MB |
| `meta-llama/Llama-Prompt-Guard-2-86M` | Llama (custom) | Yes | 1.1 GB |
| `deepset/deberta-v3-base-injection` | MIT | No | 738 MB, last updated 2024 |

A paid LLM judge is ruled out by the $0 budget.

**Decision:** ProtectAI v2, run as ONNX on CPU.
**Why:**
- It is permissively licensed, not gated, maintained (updated 2026-07),
  and widely used (about 660k downloads).
- The gated Meta models would need Arthur to accept a custom licence. Prompt
  Guard 2 22M stays the fallback if ProtectAI is too slow (Spike 3).

**Known limits, from its model card:**
- English only.
- It does not detect jailbreaks.
- It produces false positives on system prompts.
- The authors report 91.6% precision on their own held-out prompts. Those
  were prompts, not tool outputs such as database rows or source files, so
  false positives on tool outputs are Spike 4's question.

**Details:**
- The model reads at most 512 tokens, so text is scanned in 512-token
  windows that overlap by 64 tokens, up to the scan cap.
- The output is suspicious if **any** layer flags it.
- The threshold is tuned on `dev` only.
- If Spike 4 kills the model layer, v1 ships rules only (the Phase 1
  fallback) and says so.

**As built (slice E, 2026-10-27):**
- **What both layers read:** the text blocks plus the string values of
  `structured_content`; a JSON output is reduced to its string values
  (Spike 4, Variant B).
- **Rules:** 21 patterns, written from the dev template families only.
  Matching is case-insensitive, on NFKC-normalised text with whitespace
  collapsed.
- **Model:** ProtectAI v2 as ONNX, 512-token windows with an overlap of
  64, at most 16 windows (more is flagged), and a 2 s timeout that gives up
  on time (`abandon_on_cancel`) and fails closed.
- **Layering:** layers run in order and stop at the first flag.
- **Threshold 0.999**, by the rule fixed before scoring: the lowest of 0.99,
  0.995 and 0.999 with dev false positives ≤ 5%. Dev results, with
  timeouts counted as blocks, as the gateway treats them:

  | Threshold | Model: FP | Model: recall | Rules + model: FP | Rules + model: recall |
  |---|---|---|---|---|
  | 0.99 | 14.5% | 61.1% | 14.8% | 100% |
  | 0.995 | 11.1% | 55.8% | 11.5% | 100% |
  | 0.999 | 2.2% | 49.7% | 2.8% | 100% |

  - Rules alone on dev: 0% false positives, 100% recall. That is overfitted
    by construction; the test split is the real measure.
  - 12–21 scans per run timed out, mostly large outputs. Each one is a
    block, so latency (Spike 3) costs false positives, not just time.
- **Held-out test score** (2026-10-27, once per version, in
  `eval/results/`): 1,119 benign and 632 injected samples.

  | Detector | False positives | Recall | Precision |
  |---|---|---|---|
  | Rules | 0.0% | 14.6% | 100% |
  | Rules + model | 1.2% | 49.7% | 96.0% |

  - The rules mostly learned the dev phrasings (100% on dev, 14.6% on test).
  - The model carries the generalisation.
  - Weakest families: assistant-addressed (13%) and conditional (27%).
    Strongest: obfuscated (87%) and Japanese (84%).
- **Through the running gateway** (2026-10-28):
  - The first version, scan `s1`, blocked 35% of filesystem calls on
    timeouts. Repeated text was scanned twice, and a timed-out scan kept
    running and slowed the next.
  - Scan `s2` scans repeated text once, runs one scan at a time, and stops
    a timed-out scan (`RunOptions.terminate`).
  - Measured through the gateway on the held-out benign outputs, it blocks
    **2.5%** (offline: 1.2%), mostly large outputs timing out on a laptop
    CPU.
- **Change from Phase 4:** an output larger than the scan cap is treated
  as unscanned and blocked unless `allow_unscanned_content` is set, instead
  of being cut and passed on. It is simpler, and it fails closed.

**Found while trying Prompt Guard 2 (2026-10-29):** the model layer used a
tokenizer.json as shipped. Meta's Prompt Guard 2 ships its file with
padding and truncation at 512 tokens, so each window would have been mostly
`[PAD]`, and only an output's first 512 tokens would ever have been scanned:
the gateway would have failed open on anything further down. The tokenizer
is now always loaded with both turned off, and the windowing does that job.
ProtectAI's file has neither, so its scores and its detector version don't
change.

**Prompt Guard 2 measured as a replacement (2026-10-29):** Meta's Llama
Prompt Guard 2, 22M and 86M, converted to ONNX (outputs checked against
PyTorch: largest probability difference 0.000014, no threshold flipped),
run through the gateway's own model layer. Each threshold was chosen on
dev by the rule above, and test was scored once per model.

| Rules + model, held-out test | Threshold | False positives | Recall | One window, median |
|---|---|---|---|---|
| Rules alone | — | 0.0% | 14.6% | — |
| **ProtectAI v2** (current) | 0.999 | 1.2% | **49.7%** | 455 ms |
| Prompt Guard 2 22M | 0.99 | 0.9% | 19.3% | 146 ms |
| Prompt Guard 2 86M | 0.999 | 2.1% | 18.5% | 439 ms |

- Both Prompt Guard models add about 4–5 points over the rules alone, where
  ProtectAI adds 35. Both catch 0% of the messages addressed to the
  assistant, the conditionals and the Japanese family on test.
- Their scores sit lower than ProtectAI's. At Meta's default of 0.5, on dev,
  22M reaches 23% recall and 86M 35% (8.5% false positives), still below
  ProtectAI at 0.999 (49.7%, 1.6%).
- 22M is about three times as fast (one 512-token window, timed back to
  back with the others) and wrongly flagged none of Juku's refusal
  messages, which ProtectAI flags; neither model flagged Juku's planted
  marker text (shared notes, 2026-10-29).
- The scoring runs shared the laptop with other work (load average up to
  26), so their timeout counts are high, 86M's most (23 on test). A
  timed-out scan counts as flagged, so this flatters recall slightly; it
  can't explain the gap.
- **Recommendation: keep ProtectAI as the model layer.**
  `scripts/compare_models.py` regenerates
  `eval/results/model-comparison/summary.json`.

Part of the [architecture decisions](README.md) (Phase 5).
