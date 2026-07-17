"""
Trace pair dataset for Trajectory Guard training.

Reads from eval_corpus/trace_pairs.dvc (DVC-versioned dataset).
Each sample is a pair of traces: (normal, failure_or_normal) with a label.

Dataset format (NDJSON, each line):
  {
    "trace_id_1": "...",
    "trace_id_2": "...",
    "label": 0,   # 0 = different class, 1 = same class
    "spans_1": [  # list of span feature dicts
      { "llm.token_count.prompt": 150, "llm.latency_ms": 320, ... }
    ],
    "spans_2": [...]
  }
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import NamedTuple

import numpy as np
import torch
from torch.utils.data import Dataset

FEATURE_NAMES = [
    "llm.token_count.prompt",
    "llm.token_count.completion",
    "llm.latency_ms",
    "tracelane.step_index",
    "tracelane.tool_call_count",
    "tracelane.taint.data_access",
    "tracelane.taint.channel_access",
    "tracelane.taint.untrusted_input",
]

MAX_SEQ_LEN = 32  # truncate/pad traces longer than this
MAX_TOKENS = 200_000.0
MAX_LATENCY_LOG = 10.0  # log(100_000ms)
MAX_STEPS = 100.0


class TracePair(NamedTuple):
    spans_1: torch.Tensor  # [seq_len, feature_dim]
    spans_2: torch.Tensor
    label: torch.Tensor  # scalar float 0.0 or 1.0


def _extract_features(span: dict) -> list[float]:
    """Convert a span dict to a fixed-length feature vector."""
    prompt_tokens = min(span.get("llm.token_count.prompt", 0) / MAX_TOKENS, 1.0)
    compl_tokens = min(span.get("llm.token_count.completion", 0) / MAX_TOKENS, 1.0)
    latency = min(math.log1p(max(span.get("llm.latency_ms", 0), 0)) / MAX_LATENCY_LOG, 1.0)
    step_idx = min(span.get("tracelane.step_index", 0) / MAX_STEPS, 1.0)
    tool_calls = min(span.get("tracelane.tool_call_count", 0) / 20.0, 1.0)
    data_access = float(bool(span.get("tracelane.taint.data_access", False)))
    channel_access = float(bool(span.get("tracelane.taint.channel_access", False)))
    untrusted_input = float(bool(span.get("tracelane.taint.untrusted_input", False)))

    return [
        prompt_tokens,
        compl_tokens,
        latency,
        step_idx,
        tool_calls,
        data_access,
        channel_access,
        untrusted_input,
    ]


def _spans_to_tensor(spans: list[dict], seq_len: int = MAX_SEQ_LEN) -> torch.Tensor:
    """Convert a list of span dicts to a padded [seq_len, feature_dim] tensor."""
    features = [_extract_features(s) for s in spans[:seq_len]]
    if len(features) < seq_len:
        padding = [[0.0] * len(FEATURE_NAMES)] * (seq_len - len(features))
        features.extend(padding)
    arr = np.array(features, dtype=np.float32)
    return torch.from_numpy(arr)


class TracePairDataset(Dataset):
    """PyTorch Dataset of trace pairs loaded from NDJSON files."""

    def __init__(self, ndjson_path: str | Path, seq_len: int = MAX_SEQ_LEN) -> None:
        self.seq_len = seq_len
        self.records: list[dict] = []

        path = Path(ndjson_path)
        if not path.exists():
            raise FileNotFoundError(
                f"Dataset not found: {path}\nRun: dvc pull eval_corpus/trace_pairs.dvc"
            )

        with path.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    self.records.append(json.loads(line))

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, idx: int) -> TracePair:
        rec = self.records[idx]
        t1 = _spans_to_tensor(rec["spans_1"], self.seq_len)
        t2 = _spans_to_tensor(rec["spans_2"], self.seq_len)
        label = torch.tensor(float(rec["label"]), dtype=torch.float32)
        return TracePair(t1, t2, label)


def create_synthetic_dataset(n_pairs: int = 1000, seq_len: int = MAX_SEQ_LEN) -> Dataset:
    """
    Create a synthetic dataset for unit tests and CI without DVC.

    Normal traces: low reconstruction error, low taint scores.
    Failure traces: high taint scores, anomalous latency patterns.
    """

    class SyntheticDataset(Dataset):
        def __init__(self, n: int, seq_len: int) -> None:
            self.n = n
            self.seq_len = seq_len

        def __len__(self) -> int:
            return self.n

        def __getitem__(self, idx: int) -> TracePair:
            torch.manual_seed(idx)
            is_normal = idx % 2 == 0

            # Normal: low latency, no taint, structured steps
            normal = torch.zeros(self.seq_len, len(FEATURE_NAMES))
            normal[:, 0] = 0.3  # prompt tokens
            normal[:, 2] = 0.2  # latency
            normal[:, 3] = torch.arange(self.seq_len, dtype=torch.float) / self.seq_len

            # Failure: high taint, erratic latency
            failure = torch.zeros(self.seq_len, len(FEATURE_NAMES))
            failure[:, 2] = 0.9 + torch.randn(self.seq_len) * 0.05  # high latency
            failure[:, 5] = 1.0  # data_access
            failure[:, 6] = 1.0  # channel_access
            failure[:, 7] = 1.0  # untrusted_input

            if is_normal:
                t1 = normal + torch.randn_like(normal) * 0.01
                t2 = normal + torch.randn_like(normal) * 0.01
                label = torch.tensor(1.0)  # same class
            else:
                t1 = normal + torch.randn_like(normal) * 0.01
                t2 = failure
                label = torch.tensor(0.0)  # different class

            return TracePair(t1.clamp(0, 1), t2.clamp(0, 1), label)

    return SyntheticDataset(n_pairs, seq_len)
