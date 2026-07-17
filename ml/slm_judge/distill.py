"""
SLM Judge distillation script.

Distills a 1B encoder judge from two 8B teacher models:
  - meta-llama/LlamaGuard-8B  (safety/policy adherence)
  - nvidia/NemoGuard-8B        (hallucination grounding)

Distillation strategy: LoRA fine-tune a 1B base encoder on teacher soft labels.
The student learns to reproduce teacher predictions at 97% lower cost.

Judge dimensions:
  1. flow_adherence    — did the agent follow the declared task plan? (LlamaGuard)
  2. tool_sanity       — are tool calls consistent with prior context? (LlamaGuard)
  3. hallucination     — does the response ground to retrieved context? (NemoGuard)

Target: <50ms p99 inference, ≥1K req/sec on single NVIDIA L4 GPU.

Usage:
    python distill.py \\
        --student Qwen/Qwen2.5-1.5B \\
        --teacher-safety meta-llama/LlamaGuard-7b \\
        --teacher-grounding nvidia/nemotron-mini-4b-instruct \\
        --dataset ../../ml/eval_corpus/judge_labels.ndjson \\
        --epochs 3 \\
        --output slm_judge_1b.pt
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import NamedTuple

import click
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset
import structlog

log = structlog.get_logger()


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------


class JudgeSample(NamedTuple):
    input_text: str
    flow_adherence_label: float  # soft label from LlamaGuard teacher [0,1]
    tool_sanity_label: float
    hallucination_label: float


class JudgeDataset(Dataset):
    """NDJSON dataset with teacher soft labels."""

    def __init__(self, path: str | Path) -> None:
        self.records: list[JudgeSample] = []
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(
                f"Judge labels dataset not found: {p}\n"
                "Generate labels with: python label_with_teachers.py"
            )
        with p.open() as f:
            for line in f:
                obj = json.loads(line.strip())
                self.records.append(
                    JudgeSample(
                        input_text=obj["text"],
                        flow_adherence_label=obj["flow_adherence"],
                        tool_sanity_label=obj["tool_sanity"],
                        hallucination_label=obj["hallucination"],
                    )
                )

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, idx: int) -> JudgeSample:
        return self.records[idx]


# ---------------------------------------------------------------------------
# Student model
# ---------------------------------------------------------------------------


class SlmJudgeHead(nn.Module):
    """
    Regression head on top of a pre-trained 1B encoder.

    Takes the [CLS] token embedding and produces three dimension scores.
    """

    def __init__(self, hidden_size: int) -> None:
        super().__init__()
        self.fc = nn.Sequential(
            nn.Linear(hidden_size, 256),
            nn.GELU(),
            nn.Dropout(0.1),
            nn.Linear(256, 3),  # [flow_adherence, tool_sanity, hallucination]
            nn.Sigmoid(),
        )

    def forward(self, cls_embedding: torch.Tensor) -> torch.Tensor:
        """cls_embedding: [batch, hidden_size] → scores: [batch, 3]"""
        return self.fc(cls_embedding)


# ---------------------------------------------------------------------------
# Distillation loss
# ---------------------------------------------------------------------------


class DistillationLoss(nn.Module):
    """MSE between student predictions and teacher soft labels."""

    def forward(self, student_scores: torch.Tensor, teacher_labels: torch.Tensor) -> torch.Tensor:
        return F.mse_loss(student_scores, teacher_labels)


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------


@click.command()
@click.option("--student", default="Qwen/Qwen2.5-1.5B", help="HuggingFace student model ID")
@click.option("--dataset", required=True, help="Path to NDJSON judge labels")
@click.option("--epochs", default=3, type=int)
@click.option("--batch-size", default=32, type=int)
@click.option("--lr", default=2e-5, type=float)
@click.option("--max-length", default=512, type=int)
@click.option("--output", default="slm_judge_1b.pt", help="Output checkpoint path")
@click.option("--device", default="auto")
def main(
    student: str,
    dataset: str,
    epochs: int,
    batch_size: int,
    lr: float,
    max_length: int,
    output: str,
    device: str,
) -> None:
    """Distil the SLM judge from teacher soft labels."""
    if device == "auto":
        device = "cuda" if torch.cuda.is_available() else "cpu"
    dev = torch.device(device)

    log.info("distillation.start", student=student, epochs=epochs, device=str(dev))

    # Load student encoder + tokeniser
    from transformers import AutoTokenizer, AutoModel  # type: ignore[import]

    tokenizer = AutoTokenizer.from_pretrained(student)
    encoder = AutoModel.from_pretrained(student).to(dev)

    # Freeze all but the last 4 transformer layers (efficient fine-tuning)
    for name, param in encoder.named_parameters():
        param.requires_grad = False
    for name, param in encoder.named_parameters():
        if any(f"layers.{i}" in name for i in range(-4, 0)):
            param.requires_grad = True

    head = SlmJudgeHead(encoder.config.hidden_size).to(dev)
    criterion = DistillationLoss()
    optimizer = torch.optim.AdamW(
        list(filter(lambda p: p.requires_grad, encoder.parameters())) + list(head.parameters()),
        lr=lr,
        weight_decay=1e-2,
    )

    ds = JudgeDataset(dataset)
    loader = DataLoader(ds, batch_size=batch_size, shuffle=True, num_workers=0)
    log.info("dataset.loaded", n=len(ds))

    for epoch in range(1, epochs + 1):
        encoder.train()
        head.train()
        total_loss = 0.0

        for batch in loader:
            texts = list(batch.input_text)
            labels = torch.stack(
                [
                    torch.tensor(
                        [s.flow_adherence_label, s.tool_sanity_label, s.hallucination_label],
                        dtype=torch.float32,
                    )
                    for s in batch
                ]
            ).to(dev)

            enc = tokenizer(
                texts,
                max_length=max_length,
                padding=True,
                truncation=True,
                return_tensors="pt",
            ).to(dev)

            outputs = encoder(**enc)
            cls_emb = outputs.last_hidden_state[:, 0, :]  # [CLS] token
            student_scores = head(cls_emb)

            loss = criterion(student_scores, labels)
            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(head.parameters(), 1.0)
            optimizer.step()
            total_loss += loss.item()

        avg_loss = total_loss / max(len(loader), 1)
        log.info("epoch", epoch=epoch, loss=round(avg_loss, 4))

    # Save student encoder + head state dict together
    torch.save(
        {
            "student_model_id": student,
            "encoder_state": encoder.state_dict(),
            "head_state": head.state_dict(),
            "hidden_size": encoder.config.hidden_size,
        },
        output,
    )
    log.info("distillation.complete", output=output)


if __name__ == "__main__":
    main()
