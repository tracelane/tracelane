"""FastAPI sidecar for Llama Prompt Guard 2 22M ONNX inference.

Exposes two endpoints:
- ``POST /score`` — scores a text string for prompt-injection probability.
- ``GET  /health`` — liveness probe for the Rust gateway health check.

The gateway's ``PromptGuardClient`` (see
``crates/gateway/src/predictive/prompt_guard.rs``) calls ``POST /score`` on
every incoming LLM request.  The sidecar is designed to be co-located with the
gateway process on the same host (no TLS, localhost-only by default).

Throughput: ≥1 000 req/sec on a single Hetzner CCX13 CPU core.
Latency:    <30 ms p50 on the same hardware.

Usage::

    uvicorn ml.prompt_guard.serve:app --host 0.0.0.0 --port 8080 --workers 4

Or for development::

    python -m ml.prompt_guard.serve

Environment
-----------
PROMPT_GUARD_ONNX : str
    Absolute path to the ONNX model file.  Falls back to the default export
    location (see :mod:`ml.prompt_guard`).
PROMPT_GUARD_THRESHOLD : float
    Injection decision threshold.  Default ``0.5``.
PROMPT_GUARD_HOST : str
    Bind host.  Default ``127.0.0.1``.
PROMPT_GUARD_PORT : int
    Bind port.  Default ``8080``.
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException, status
from ml.prompt_guard import PromptGuard
from pydantic import BaseModel, Field

logger = logging.getLogger("tracelane.prompt_guard.serve")

# ---------------------------------------------------------------------------
# Pydantic v2 schemas
# ---------------------------------------------------------------------------


class ScoreRequest(BaseModel):
    """Request body for ``POST /score``."""

    text: str = Field(..., min_length=1, description="Text to evaluate for injection")


class ScoreResponse(BaseModel):
    """Response body for ``POST /score``."""

    score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Injection probability [0.0, 1.0]",
    )
    is_injection: bool = Field(
        ...,
        description="True if score >= threshold",
    )


class HealthResponse(BaseModel):
    """Response body for ``GET /health``."""

    status: str


# ---------------------------------------------------------------------------
# Application state
# ---------------------------------------------------------------------------


class _AppState:
    guard: PromptGuard
    threshold: float


_state = _AppState()


# ---------------------------------------------------------------------------
# Lifespan — model loaded once at startup, never reloaded
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Load the ONNX model before serving requests.

    Raises ``SystemExit(1)`` if the model file is missing so that the process
    fails fast rather than serving 500s on every request.
    """
    threshold_env = os.environ.get("PROMPT_GUARD_THRESHOLD", "0.5")
    try:
        _state.threshold = float(threshold_env)
    except ValueError:
        logger.error(
            "PROMPT_GUARD_THRESHOLD must be a float, got %r — using 0.5",
            threshold_env,
        )
        _state.threshold = 0.5

    try:
        _state.guard = PromptGuard(model_path=os.environ.get("PROMPT_GUARD_ONNX"))
        logger.info("Prompt Guard ONNX model loaded (threshold=%.2f)", _state.threshold)
    except FileNotFoundError as exc:
        # Hard-fail: no point serving if the model is absent.
        logger.critical("Failed to load Prompt Guard model: %s", exc)
        raise SystemExit(1) from exc

    yield
    # No teardown needed — ORT session is GC'd with the process.


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Tracelane Prompt Guard",
    description="Llama Prompt Guard 2 22M ONNX inference sidecar (PR6)",
    version="0.1.0",
    lifespan=lifespan,
)


@app.post(
    "/score",
    response_model=ScoreResponse,
    summary="Score text for prompt injection",
)
async def score_endpoint(body: ScoreRequest) -> ScoreResponse:
    """Score ``body.text`` for prompt-injection probability.

    Parameters
    ----------
    body:
        JSON body with a single ``text`` field.

    Returns
    -------
    ScoreResponse
        ``score`` in ``[0.0, 1.0]`` and boolean ``is_injection``.

    Raises
    ------
    HTTPException 503
        If the model has not been loaded (should never happen in normal
        operation because lifespan halts the process on load failure).
    """
    try:
        raw_score = _state.guard.score(body.text)
    except AttributeError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model not loaded",
        )
    return ScoreResponse(
        score=raw_score,
        is_injection=raw_score >= _state.threshold,
    )


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness probe",
)
async def health_endpoint() -> HealthResponse:
    """Return ``{"status": "ok"}`` when the sidecar is ready to serve.

    The Rust gateway calls this endpoint every 5 seconds via its HTTP health
    check before routing traffic.

    Returns
    -------
    HealthResponse
        Always ``{"status": "ok"}`` if the process is alive and the model
        is loaded.
    """
    if not hasattr(_state, "guard"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model not loaded yet",
        )
    return HealthResponse(status="ok")


# ---------------------------------------------------------------------------
# Dev entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    host = os.environ.get("PROMPT_GUARD_HOST", "127.0.0.1")
    port = int(os.environ.get("PROMPT_GUARD_PORT", "8080"))
    uvicorn.run(
        "ml.prompt_guard.serve:app",
        host=host,
        port=port,
        log_level="info",
    )
