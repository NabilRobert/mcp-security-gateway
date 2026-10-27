"""Make the int8 version of the detector model (Arthur's choice for the
latency problem, Spike 3): onnxruntime's dynamic quantisation of the MatMul
weights to int8, per channel, with activations quantised at run time.

The defaults don't work for this model: quantising every op (the embedding
lookups included) made it score every text near 0.01, and per-tensor MatMul
weights did the same. Only MatMul, per channel, kept its verdicts (Phase 6,
Spike 3 follow-up). Deterministic for the same input
model and onnxruntime version; the output's hash is part of the detector
version, so a different file can't pass as the same detector.

    .venv/bin/python -I scripts/quantize_model.py
"""

import hashlib
import sys
from pathlib import Path

from onnxruntime.quantization import QuantType, quantize_dynamic  # pyright: ignore[reportMissingTypeStubs]

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "models/protectai-deberta-v3-base-prompt-injection-v2/90c9989b1a342275dd0d1a95aad283c04e075671"
TARGET = ROOT / "models/protectai-deberta-v3-base-prompt-injection-v2-int8"


def main() -> int:
    TARGET.mkdir(parents=True, exist_ok=True)
    for name in ("config.json", "special_tokens_map.json", "tokenizer_config.json", "tokenizer.json"):
        (TARGET / name).write_bytes((SOURCE / name).read_bytes())
    quantize_dynamic(
        str(SOURCE / "model.onnx"),
        str(TARGET / "model.onnx"),
        weight_type=QuantType.QInt8,
        op_types_to_quantize=["MatMul"],
        per_channel=True,
    )
    for path in (SOURCE / "model.onnx", TARGET / "model.onnx"):
        print(
            f"{path.relative_to(ROOT)}: {path.stat().st_size / 1e6:.0f} MB, "
            f"sha256 {hashlib.sha256(path.read_bytes()).hexdigest()[:16]}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
