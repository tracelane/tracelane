"""
Trajectory Guard training script.

Usage:
    cd ml/trajectory_guard
    python train.py --dataset ../../ml/eval_corpus/trace_pairs.ndjson --epochs 50
    python train.py --synthetic --epochs 5  # quick sanity check without DVC

Output:
    checkpoints/trajectory_guard_best.pt
    checkpoints/trajectory_guard_final.pt

Then export to ONNX:
    python export_onnx.py --checkpoint checkpoints/trajectory_guard_best.pt
"""

from __future__ import annotations

from pathlib import Path

import click
import structlog
import torch
from torch.utils.data import DataLoader, random_split

from dataset import FEATURE_NAMES, MAX_SEQ_LEN, TracePairDataset, create_synthetic_dataset
from model import SiameseLoss, SiameseTrajectoryRAE

log = structlog.get_logger()

CHECKPOINT_DIR = Path("checkpoints")


@click.command()
@click.option("--dataset", default=None, help="Path to NDJSON trace pairs dataset")
@click.option("--synthetic", is_flag=True, default=False, help="Use synthetic dataset (no DVC)")
@click.option("--epochs", default=50, type=int)
@click.option("--batch-size", default=64, type=int)
@click.option("--lr", default=1e-3, type=float)
@click.option("--latent-dim", default=64, type=int)
@click.option("--hidden-dim", default=128, type=int)
@click.option("--seq-len", default=MAX_SEQ_LEN, type=int)
@click.option("--val-split", default=0.1, type=float)
@click.option("--device", default="auto", help="'cpu', 'cuda', 'mps', or 'auto'")
def main(
    dataset: str | None,
    synthetic: bool,
    epochs: int,
    batch_size: int,
    lr: float,
    latent_dim: int,
    hidden_dim: int,
    seq_len: int,
    val_split: float,
    device: str,
) -> None:
    """Train the Siamese RAE Trajectory Guard model."""
    if device == "auto":
        if torch.cuda.is_available():
            device = "cuda"
        elif torch.backends.mps.is_available():
            device = "mps"
        else:
            device = "cpu"

    dev = torch.device(device)
    log.info("training.start", device=str(dev), epochs=epochs, batch_size=batch_size)

    # Dataset
    if synthetic:
        full_dataset = create_synthetic_dataset(n_pairs=4000, seq_len=seq_len)
        log.info("dataset.synthetic", n=len(full_dataset))
    elif dataset:
        full_dataset = TracePairDataset(dataset, seq_len=seq_len)
        log.info("dataset.loaded", path=dataset, n=len(full_dataset))
    else:
        raise click.UsageError("Provide --dataset or --synthetic")

    n_val = max(1, int(len(full_dataset) * val_split))
    n_train = len(full_dataset) - n_val
    train_ds, val_ds = random_split(full_dataset, [n_train, n_val])

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True, num_workers=0)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False, num_workers=0)

    # Model
    model = SiameseTrajectoryRAE(
        feature_dim=len(FEATURE_NAMES),
        hidden_dim=hidden_dim,
        latent_dim=latent_dim,
    ).to(dev)

    criterion = SiameseLoss(alpha=0.5, margin=1.0)
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    CHECKPOINT_DIR.mkdir(exist_ok=True)
    best_val_loss = float("inf")

    for epoch in range(1, epochs + 1):
        # --- Training ---
        model.train()
        train_loss = 0.0
        for batch in train_loader:
            spans1, spans2, labels = batch
            spans1, spans2, labels = spans1.to(dev), spans2.to(dev), labels.to(dev)

            optimizer.zero_grad()
            recon1, recon2, lat1, lat2 = model.siamese_forward(spans1, spans2)
            loss = criterion(recon1, recon2, spans1, spans2, lat1, lat2, labels)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            train_loss += loss.item()

        scheduler.step()
        train_loss /= len(train_loader)

        # --- Validation ---
        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for batch in val_loader:
                spans1, spans2, labels = batch
                spans1, spans2, labels = spans1.to(dev), spans2.to(dev), labels.to(dev)
                recon1, recon2, lat1, lat2 = model.siamese_forward(spans1, spans2)
                loss = criterion(recon1, recon2, spans1, spans2, lat1, lat2, labels)
                val_loss += loss.item()
        val_loss /= max(len(val_loader), 1)

        log.info(
            "epoch",
            epoch=epoch,
            train_loss=round(train_loss, 4),
            val_loss=round(val_loss, 4),
            lr=round(scheduler.get_last_lr()[0], 6),
        )

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            torch.save(model.state_dict(), CHECKPOINT_DIR / "trajectory_guard_best.pt")
            log.info("checkpoint.saved", path="trajectory_guard_best.pt")

    torch.save(model.state_dict(), CHECKPOINT_DIR / "trajectory_guard_final.pt")
    log.info("training.complete", best_val_loss=round(best_val_loss, 4))


if __name__ == "__main__":
    main()
