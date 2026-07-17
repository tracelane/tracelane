"""
Export the trained Trajectory Guard model to ONNX for Rust gateway inference.

Usage:
    python export_onnx.py --checkpoint checkpoints/trajectory_guard_best.pt
    python export_onnx.py --checkpoint checkpoints/trajectory_guard_best.pt \
        --output ../../crates/gateway/models/trajectory_guard.onnx

The exported ONNX model takes:
    Input  "trajectory": [batch, seq_len, feature_dim]  float32
    Output "reconstruction": [batch, seq_len, feature_dim]  float32
    Output "reconstruction_error": [batch]  float32

The Rust gateway uses `ort` crate to load and run this model inline.
"""

from __future__ import annotations

from pathlib import Path

import click
import onnx
import onnxruntime as ort
import torch

from dataset import FEATURE_NAMES, MAX_SEQ_LEN
from model import SiameseTrajectoryRAE


@click.command()
@click.option("--checkpoint", required=True, help="Path to .pt checkpoint file")
@click.option(
    "--output",
    default="../../crates/gateway/models/trajectory_guard.onnx",
    help="Output ONNX file path",
)
@click.option("--seq-len", default=MAX_SEQ_LEN, type=int)
@click.option("--latent-dim", default=64, type=int)
@click.option("--hidden-dim", default=128, type=int)
@click.option("--opset", default=17, type=int, help="ONNX opset version")
def main(
    checkpoint: str,
    output: str,
    seq_len: int,
    latent_dim: int,
    hidden_dim: int,
    opset: int,
) -> None:
    """Export Trajectory Guard checkpoint to ONNX."""
    feature_dim = len(FEATURE_NAMES)

    # Load model
    model = SiameseTrajectoryRAE(
        feature_dim=feature_dim,
        hidden_dim=hidden_dim,
        latent_dim=latent_dim,
    )
    state = torch.load(checkpoint, map_location="cpu", weights_only=True)
    model.load_state_dict(state)
    model.eval()

    # Create a wrapper that also outputs reconstruction error
    class ExportWrapper(torch.nn.Module):
        def __init__(self, inner: SiameseTrajectoryRAE) -> None:
            super().__init__()
            self.inner = inner

        def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
            recon, _ = self.inner(x)
            error = ((x - recon) ** 2).mean(dim=(1, 2))
            return recon, error

    wrapped = ExportWrapper(model)

    # Dummy input for tracing
    dummy = torch.zeros(1, seq_len, feature_dim)

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    torch.onnx.export(
        wrapped,
        dummy,
        str(output_path),
        input_names=["trajectory"],
        output_names=["reconstruction", "reconstruction_error"],
        dynamic_axes={
            "trajectory": {0: "batch", 1: "seq_len"},
            "reconstruction": {0: "batch", 1: "seq_len"},
            "reconstruction_error": {0: "batch"},
        },
        opset_version=opset,
        do_constant_folding=True,
    )

    # Validate the exported model
    model_proto = onnx.load(str(output_path))
    onnx.checker.check_model(model_proto)

    # Run a quick ORT sanity check
    session = ort.InferenceSession(str(output_path))
    dummy_np = dummy.numpy()
    recon_np, error_np = session.run(None, {"trajectory": dummy_np})

    assert recon_np.shape == (1, seq_len, feature_dim), f"Unexpected recon shape: {recon_np.shape}"
    assert error_np.shape == (1,), f"Unexpected error shape: {error_np.shape}"

    print(f"✓ Exported to {output_path} ({output_path.stat().st_size // 1024}KB)")
    print(f"  Reconstruction error on zero input: {error_np[0]:.4f}")
    print(f"  ONNX opset: {opset}")
    print(f"  Model inputs:  {[i.name for i in session.get_inputs()]}")
    print(f"  Model outputs: {[o.name for o in session.get_outputs()]}")


if __name__ == "__main__":
    main()
