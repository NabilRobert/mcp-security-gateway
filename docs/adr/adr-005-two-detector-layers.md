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

**Prompt Guard 2 measured as a replacement (2026-10-29):** it caught far
fewer unseen injections, so ProtectAI stays. See
[ADR-015](adr-015-keep-protectai-over-prompt-guard-2.md).

**JSON keys that read like prose are scanned, on their own (2026-11-02, scan
`s5`):** a JSON output was reduced to its string values, so its keys were never
read. Three attempts:

- `s3` added the keys to that text. Test recall fell from 49.7% to 41.0%: the
  extra tokens diluted the model's windows, so real injections fell under
  0.999. The rules-plus-model dev score hid it, because the rules catch all
  of dev, so changes to scanning are now checked on the model alone first.
- `s4` scanned every key as a separate text. Recall held and no benign output in
  the labelled set was flagged, but a bare list of field names (`flags`,
  `new_checkout`, `dark_mode`, `owner`, `note`) scored 0.99999, because it isn't
  text the classifier was trained on. That blocked one gullible-agent attack by
  accident, and would block the same harmless file. Dropped.
- `s5` leaves the value text as it was and scans, as a second text, only the
  keys that read like prose: four or more words (split on spaces, `_`, `-` and
  camelCase), or non-ASCII. Ordinary field names cost no second scan.

| Held-out test | False positives | Recall | Precision |
|---|---|---|---|
| Rules (`s5`) | 0.0% | 14.6% | 100% |
| Rules + model (`s5`) | 1.1% | 49.7% | 96.3% |
| Rules + model (`s2`, before) | 1.2% | 49.7% | 96.0% |

- Recall is unchanged in every family; the one fewer false positive is one
  fewer timeout.
- The test split was scored for all three attempts, which bends its
  scored-once rule, so it's recorded here. `s3`'s drop was seen on test, and
  led to `s4`. `s5` came from the gullible run. No threshold or rule was tuned
  on test, and `s5` was held to dev first, with the model alone.
- The threshold rule still gives 0.999: on dev, rules + model has 1.5% false
  positives there, and 10.3% at 0.995.
- Through the gateway: 2.5%, as before. The gullible agent: 5/12, as predicted.
- **Limit:** a key of up to three ASCII words isn't read by the model. Three
  words is little room for an instruction, but it isn't none.

Part of the [architecture decisions](README.md) (Phase 5).
