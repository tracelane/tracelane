"""Export Llama Prompt Guard 2 22M to INT8 ONNX for in-process Rust inference.

Output: ``llama-prompt-guard-2-22m-int8.onnx`` (~25MB) in this directory.

Usage::

    pip install "optimum[onnxruntime]" transformers
    export HF_TOKEN=<HuggingFace token with read access to
                    meta-llama/Llama-Prompt-Guard-2-22M>
    python export.py

The Rust gateway loads this file at startup via the `ort` crate and
verifies the SHA-256 against ``SHA256SUMS`` — a mismatch is a build
failure (see ``crates/gateway/src/predictive/prompt_guard.rs`` once
the inference wiring lands).

License note: Llama Prompt Guard 2 is distributed under the Llama
Community License. Verify terms at https://www.llama.com/llama3/license/
before V1 ship — we document the dependency separately in
``LICENSE-PROMPT-GUARD-2.md`` (founder to add).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

OUT_DIR = Path(__file__).parent
MODEL_ID = "meta-llama/Llama-Prompt-Guard-2-22M"
OUT_FILE = OUT_DIR / "llama-prompt-guard-2-22m-int8.onnx"


def main() -> int:
    if not os.environ.get("HF_TOKEN"):
        print("ERROR: HF_TOKEN env var required", file=sys.stderr)
        print(
            "       see README.md — needs read access to "
            "meta-llama/Llama-Prompt-Guard-2-22M",
            file=sys.stderr,
        )
        return 1

    try:
        from optimum.onnxruntime import (  # type: ignore[import-not-found]
            ORTModelForSequenceClassification,
            ORTQuantizer,
        )
        from optimum.onnxruntime.configuration import (  # type: ignore[import-not-found]
            AutoQuantizationConfig,
        )
        from transformers import AutoTokenizer  # type: ignore[import-not-found]
    except ImportError as exc:
        print(f"ERROR: missing dependency: {exc}", file=sys.stderr)
        print(
            "       pip install 'optimum[onnxruntime]' transformers",
            file=sys.stderr,
        )
        return 1

    print(f"Downloading {MODEL_ID} → ONNX FP32...")
    fp32_dir = OUT_DIR / "fp32"
    ort_model = ORTModelForSequenceClassification.from_pretrained(
        MODEL_ID, export=True, token=os.environ["HF_TOKEN"]
    )
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, token=os.environ["HF_TOKEN"])
    ort_model.save_pretrained(fp32_dir)
    tokenizer.save_pretrained(fp32_dir)

    print("Quantizing to INT8 (avx2, dynamic, per-tensor)...")
    quantizer = ORTQuantizer.from_pretrained(fp32_dir)
    qconfig = AutoQuantizationConfig.avx2(is_static=False, per_channel=False)
    quantizer.quantize(save_dir=OUT_DIR, quantization_config=qconfig)

    quantized_path = OUT_DIR / "model_quantized.onnx"
    if not quantized_path.exists():
        print(
            f"ERROR: quantized output not found at {quantized_path}",
            file=sys.stderr,
        )
        return 1
    quantized_path.rename(OUT_FILE)
    size_kb = OUT_FILE.stat().st_size // 1024

    print(f"OK: {OUT_FILE} ({size_kb} KB)")
    print()
    print("Next: regenerate SHA256SUMS and commit:")
    print(f"  cd {OUT_DIR}")
    if sys.platform == "win32":
        print("  Get-FileHash llama-prompt-guard-2-22m-int8.onnx -Algorithm SHA256")
    else:
        print("  sha256sum llama-prompt-guard-2-22m-int8.onnx > SHA256SUMS")
    print()
    print(
        "Cleanup: 'fp32/' is the unquantized intermediate; safe to delete "
        "once SHA256SUMS is regenerated:"
    )
    print(f"  rm -rf {fp32_dir}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
