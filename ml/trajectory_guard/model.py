"""
Siamese recurrent autoencoder for trajectory-level anomaly detection.

Architecture based on arXiv 2601.00516 (Siamese RAE for time-series anomaly detection).
Trained on 50K trace pairs: (normal_trace, failure_trace).

The model encodes a sequence of span feature vectors into a fixed-size latent
representation. The reconstruction error from the decoder indicates anomaly severity.
A high error on a live trace (compared to the training distribution) signals an
anomalous trajectory.

Input shape:  [batch, seq_len, feature_dim]
Output shape: [batch, seq_len, feature_dim]  (reconstruction)
Latent shape: [batch, latent_dim]

Feature dimensions (per span, 8 features):
  0. llm.token_count.prompt       (normalised)
  1. llm.token_count.completion   (normalised)
  2. llm.latency_ms               (log-normalised)
  3. tracelane.step_index         (normalised by max_steps)
  4. tracelane.tool_call_count    (normalised)
  5. tracelane.taint.data_access  (binary 0/1)
  6. tracelane.taint.channel_access (binary 0/1)
  7. tracelane.taint.untrusted_input (binary 0/1)
"""

from __future__ import annotations

import torch
import torch.nn as nn

FEATURE_DIM = 8
LATENT_DIM = 64
HIDDEN_DIM = 128
NUM_LAYERS = 2


class TrajectoryEncoder(nn.Module):
    """GRU encoder: sequence of span features → latent vector."""

    def __init__(
        self,
        feature_dim: int = FEATURE_DIM,
        hidden_dim: int = HIDDEN_DIM,
        latent_dim: int = LATENT_DIM,
        num_layers: int = NUM_LAYERS,
    ) -> None:
        super().__init__()
        self.gru = nn.GRU(
            input_size=feature_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.1 if num_layers > 1 else 0.0,
        )
        self.fc = nn.Linear(hidden_dim, latent_dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """x: [batch, seq_len, feature_dim] → latent: [batch, latent_dim]"""
        _, h = self.gru(x)
        # Take the last layer's hidden state
        return self.fc(h[-1])


class TrajectoryDecoder(nn.Module):
    """GRU decoder: latent vector + sequence length → reconstructed features."""

    def __init__(
        self,
        feature_dim: int = FEATURE_DIM,
        hidden_dim: int = HIDDEN_DIM,
        latent_dim: int = LATENT_DIM,
        num_layers: int = NUM_LAYERS,
    ) -> None:
        super().__init__()
        self.latent_to_hidden = nn.Linear(latent_dim, hidden_dim)
        self.gru = nn.GRU(
            input_size=feature_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.1 if num_layers > 1 else 0.0,
        )
        self.fc = nn.Linear(hidden_dim, feature_dim)

    def forward(self, latent: torch.Tensor, target: torch.Tensor) -> torch.Tensor:
        """
        latent: [batch, latent_dim]
        target: [batch, seq_len, feature_dim]  (teacher forcing during training)
        → reconstruction: [batch, seq_len, feature_dim]
        """
        batch_size = latent.size(0)
        # Expand latent to hidden state for each GRU layer
        h0 = (
            self.latent_to_hidden(latent)
            .unsqueeze(0)
            .expand(self.gru.num_layers, batch_size, -1)
            .contiguous()
        )
        out, _ = self.gru(target, h0)
        return self.fc(out)


class SiameseTrajectoryRAE(nn.Module):
    """
    Siamese Recurrent Autoencoder for trajectory anomaly detection.

    During training: takes (normal_trace, failure_trace) pairs and learns
    a latent space where normal traces cluster tightly together.

    During inference: encodes a single trace and returns reconstruction error
    as the anomaly score.
    """

    def __init__(
        self,
        feature_dim: int = FEATURE_DIM,
        hidden_dim: int = HIDDEN_DIM,
        latent_dim: int = LATENT_DIM,
        num_layers: int = NUM_LAYERS,
    ) -> None:
        super().__init__()
        self.encoder = TrajectoryEncoder(feature_dim, hidden_dim, latent_dim, num_layers)
        self.decoder = TrajectoryDecoder(feature_dim, hidden_dim, latent_dim, num_layers)
        self.feature_dim = feature_dim
        self.latent_dim = latent_dim

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        """
        Single-path forward pass (inference mode).
        x: [batch, seq_len, feature_dim]
        → (reconstruction, latent)
        """
        latent = self.encoder(x)
        reconstruction = self.decoder(latent, x)
        return reconstruction, latent

    def siamese_forward(
        self, x1: torch.Tensor, x2: torch.Tensor
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Siamese forward pass (training mode).
        x1: [batch, seq_len, feature_dim]  (normal trace)
        x2: [batch, seq_len, feature_dim]  (failure trace or second normal trace)
        → (recon1, recon2, latent1, latent2)
        """
        latent1 = self.encoder(x1)
        latent2 = self.encoder(x2)
        recon1 = self.decoder(latent1, x1)
        recon2 = self.decoder(latent2, x2)
        return recon1, recon2, latent1, latent2

    def reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        """
        Compute mean squared reconstruction error per sample.
        x: [batch, seq_len, feature_dim]
        → error: [batch]  (scalar per sample)
        """
        recon, _ = self(x)
        return ((x - recon) ** 2).mean(dim=(1, 2))


class SiameseLoss(nn.Module):
    """
    Combined reconstruction + contrastive loss.

    L = recon_loss + alpha * contrastive_loss

    contrastive_loss: pulls latents of similar traces together, pushes
    latents of (normal, failure) pairs apart (margin loss).
    """

    def __init__(self, alpha: float = 0.5, margin: float = 1.0) -> None:
        super().__init__()
        self.alpha = alpha
        self.margin = margin
        self.mse = nn.MSELoss()

    def forward(
        self,
        recon1: torch.Tensor,
        recon2: torch.Tensor,
        x1: torch.Tensor,
        x2: torch.Tensor,
        latent1: torch.Tensor,
        latent2: torch.Tensor,
        label: torch.Tensor,
    ) -> torch.Tensor:
        """
        label: [batch]  — 1 if (x1, x2) are same class (both normal or both failure),
                          0 if they are different classes
        """
        recon_loss = self.mse(recon1, x1) + self.mse(recon2, x2)

        # Contrastive loss (Hadsell et al. 2006)
        dist = torch.nn.functional.pairwise_distance(latent1, latent2)
        contrastive = label * dist.pow(2) + (1 - label) * torch.clamp(
            self.margin - dist, min=0
        ).pow(2)
        contrastive_loss = contrastive.mean()

        return recon_loss + self.alpha * contrastive_loss
