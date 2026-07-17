"""
Export the distilled SLM Judge to ONNX for Rust gateway inference.

Usage:
    python export_onnx.py \\
        --checkpoint slm_judge_1b.pt \\
        --output ../../crates/gateway/models/slm_judge.onnx

The exported model takes:
    Input  "input_ids":      [batch, seq_len]  int64
    Input  "attention_mask": [batch, seq_len]  int64
    Output "scores":         [batch, 3]        float32  [flow, tool, hallucination]

Latency target: <50ms p99 on NVIDIA L4.
"""

from __future__ import annotations

from pathlib import Path

import click
import torch
import onnx
import onnxruntime as ort


@click.command()
@click.option("--checkpoint", required=True, help="Path to .pt distilled checkpoint")
@click.option(
    "--output",
    default="../../crates/gateway/models/slm_judge.onnx",
)
@click.option("--max-length", default=512, type=int)
@click.option("--opset", default=17, type=int)
def main(checkpoint: str, output: str, max_length: int, opset: int) -> None:
    """Export distilled SLM Judge to ONNX."""
    from transformers import AutoTokenizer, AutoModel  # type: ignore[import]
    from distill import SlmJudgeHead

    state = torch.load(checkpoint, map_location="cpu", weights_only=False)
    student_model_id = state["student_model_id"]
    hidden_size = state["hidden_size"]

    AutoTokenizer.from_pretrained(student_model_id)
    encoder = AutoModel.from_pretrained(student_model_id)
    encoder.load_state_dict(state["encoder_state"])

    head = SlmJudgeHead(hidden_size)
    head.load_state_dict(state["head_state"])

    class JudgeModel(torch.nn.Module):
        def __init__(self, enc, h) -> None:
            super().__init__()
            self.enc = enc
            self.head = h

        def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
            out = self.enc(input_ids=input_ids, attention_mask=attention_mask)
            cls_emb = out.last_hidden_state[:, 0, :]
            return self.head(cls_emb)

    model = JudgeModel(encoder, head)
    model.eval()

    dummy_ids = torch.zeros(1, max_length, dtype=torch.long)
    dummy_mask = torch.ones(1, max_length, dtype=torch.long)

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    torch.onnx.export(
        model,
        (dummy_ids, dummy_mask),
        str(output_path),
        input_names=["input_ids", "attention_mask"],
        output_names=["scores"],
        dynamic_axes={
            "input_ids": {0: "batch", 1: "seq_len"},
            "attention_mask": {0: "batch", 1: "seq_len"},
            "scores": {0: "batch"},
        },
        opset_version=opset,
        do_constant_folding=True,
    )

    # Validate
    model_proto = onnx.load(str(output_path))
    onnx.checker.check_model(model_proto)

    session = ort.InferenceSession(str(output_path), providers=["CPUExecutionProvider"])
    scores = session.run(
        None,
        {
            "input_ids": dummy_ids.numpy(),
            "attention_mask": dummy_mask.numpy(),
        },
    )[0]

    assert scores.shape == (1, 3), f"Unexpected scores shape: {scores.shape}"
    print(f"✓ Exported to {output_path} ({output_path.stat().st_size // 1024}KB)")
    print(
        f"  Scores on dummy input: flow={scores[0, 0]:.3f} tool={scores[0, 1]:.3f} hallucination={scores[0, 2]:.3f}"
    )


if __name__ == "__main__":
    main()
