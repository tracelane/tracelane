"""
Modal deployment for SLM Judge inference endpoint.

Deploys the distilled 1B judge as a serverless GPU endpoint on Modal.
Auto-scales: 0 → N L4 GPUs based on request volume.

Usage:
    modal deploy deploy_modal.py                  # deploy to Modal
    modal run deploy_modal.py::judge_endpoint     # local test

Environment:
    TRACELANE_SLM_JUDGE_ONNX — path to the exported ONNX model in Modal volume
    MODAL_TOKEN_ID            — Modal API token (set in GitHub secret)
    MODAL_TOKEN_SECRET        — Modal API secret
"""

from __future__ import annotations

import os

import modal

# ---------------------------------------------------------------------------
# Modal app definition
# ---------------------------------------------------------------------------

app = modal.App("tracelane-slm-judge")

# Persistent volume for the ONNX model file
model_volume = modal.Volume.from_name("tracelane-models", create_if_missing=True)
MODEL_MOUNT_PATH = "/models"

# GPU image with ONNX Runtime GPU
image = modal.Image.debian_slim(python_version="3.12").pip_install(
    [
        "onnxruntime-gpu==1.18.0",
        "numpy>=1.26.0",
        "pydantic>=2.7.0",
    ]
)


@app.cls(
    gpu=modal.gpu.L4(count=1),
    image=image,
    volumes={MODEL_MOUNT_PATH: model_volume},
    min_containers=0,  # scale to zero when idle
    max_containers=10,
    container_idle_timeout=60,
)
class JudgeEndpoint:
    """Serverless SLM Judge inference on Modal L4 GPU."""

    @modal.enter()
    def load_model(self) -> None:
        import onnxruntime as ort

        model_path = os.environ.get(
            "TRACELANE_SLM_JUDGE_ONNX", f"{MODEL_MOUNT_PATH}/slm_judge.onnx"
        )
        self.session = ort.InferenceSession(
            model_path,
            providers=["CUDAExecutionProvider", "CPUExecutionProvider"],
        )
        self.input_names = [i.name for i in self.session.get_inputs()]

    @modal.method()
    def judge(
        self, input_ids: list[list[int]], attention_mask: list[list[int]]
    ) -> list[list[float]]:
        """
        Run SLM judge inference.

        Returns: list of [flow_adherence, tool_sanity, hallucination] scores per input.
        Latency target: <50ms p99 on L4.
        """
        import numpy as np

        ids_arr = np.array(input_ids, dtype=np.int64)
        mask_arr = np.array(attention_mask, dtype=np.int64)
        scores = self.session.run(
            None,
            {
                "input_ids": ids_arr,
                "attention_mask": mask_arr,
            },
        )[0]
        return scores.tolist()


@app.local_entrypoint()
def main() -> None:
    """Quick smoke test: judge a dummy input."""
    dummy_ids = [[0] * 32]
    dummy_mask = [[1] * 32]
    endpoint = JudgeEndpoint()
    scores = endpoint.judge.remote(dummy_ids, dummy_mask)
    print(
        f"Scores: flow={scores[0][0]:.3f} tool={scores[0][1]:.3f} hallucination={scores[0][2]:.3f}"
    )
