# ADR-015: Keep ProtectAI as the model layer, not Prompt Guard 2

**Context:**
- ProtectAI v2 (ADR-005) catches about half of unseen injections, and
  large outputs time out on a laptop CPU. Meta's Llama Prompt Guard 2 was
  the preferred long-run alternative (Phase 6): smaller, and trained for
  prompt injection and jailbreaks.
- Arthur accepted its licence and approved the downloads on 2026-10-29.

**Options considered:**

| Option | Held-out test, rules + model | One 512-token window, median | Outcome |
|---|---|---|---|
| **ProtectAI v2**, threshold 0.999 | 1.2% FP, **49.7%** recall | 455 ms | **Kept** |
| Prompt Guard 2 22M, threshold 0.99 | 0.9% FP, 19.3% recall | 146 ms | Rejected |
| Prompt Guard 2 86M, threshold 0.999 | 2.1% FP, 18.5% recall | 439 ms | Rejected |

The rules alone catch 14.6% on test, so Prompt Guard 2 adds about 4–5
points over them, where ProtectAI adds 35.

**Decision (Arthur, 2026-10-29: "keep ProtectAI"):** ProtectAI v2 stays
the model layer, unchanged.

**Method ($0, all local):**
- Both Prompt Guard models were converted to ONNX and run through the
  gateway's own model layer. The ONNX outputs match PyTorch's: the largest
  probability difference on 78 dev texts was 0.000014, and no text crossed
  any threshold differently.
- Each threshold was chosen on dev by ADR-005's rule (the lowest of 0.99,
  0.995 and 0.999 with dev false positives at most 5%), and test was
  scored once per model.
- Window latency was timed back to back for all three models.

**Why it lost:**
- On test, both Prompt Guard models catch 0% of the messages addressed to
  the assistant, the conditionals and the Japanese family.
- Its scores sit lower than ProtectAI's, so it was also read at Meta's
  default threshold of 0.5, on dev only and for comparison: 22M reaches
  23% recall and 86M 35% (at 8.5% false positives). ProtectAI at 0.999
  has 49.7% at 1.6%.
- Where 22M is better: it's about three times as fast, and it didn't flag
  Juku's security-refusal messages, which ProtectAI does. On Juku's
  planted marker text, none of the three flags it on score (shared notes,
  2026-10-29).
- The scoring runs shared the laptop with other work (load average up to
  26), so their timeout counts are high (86M: 23 on test). A timed-out
  scan counts as flagged, which flatters recall slightly; it can't explain
  the gap.

**Found on the way:** the model layer used a tokenizer file's own padding
and truncation, which Prompt Guard 2's file sets to 512. That would have
limited every scan to an output's first 512 tokens. Fixed in PR #10;
ADR-005 has the note.

**To reproduce:**
- `scripts/compare_models.py` regenerates
  `eval/results/model-comparison/summary.json` (dev for every model, and
  each model's test score once recorded).
- The models live in `models/` (git-ignored), each converted with
  optimum-onnx 0.1.0, optimum 2.1.0, torch 2.15.0 and transformers 4.57.6,
  in a throwaway environment that is not a gateway dependency:

  ```bash
  uv run --isolated --no-project --python 3.12 --with "optimum-onnx[onnxruntime]" --with torch --with transformers \
      optimum-cli export onnx --model models/<model>/<revision>/ --task text-classification <output-dir>
  ```

  The exported `model.onnx` goes next to the model's own `tokenizer.json`.

Part of the [architecture decisions](README.md) (Phase 5).
