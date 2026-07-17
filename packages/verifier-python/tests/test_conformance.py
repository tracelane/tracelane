"""Conformance tests against canonical vectors in ``evals/audit-ledger/``.

Mirrors `packages/verifier-rust/tests/conformance.rs` and the TypeScript
test suite. All three verifiers MUST agree on each vector.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from tracelane_audit_verifier import FormatVersion, VerifyOptions, verify_ledger


def _vector(name: str) -> Path:
    pkg_root = Path(__file__).resolve().parent.parent
    return pkg_root.parent.parent / "evals" / "audit-ledger" / name


def _trusted_tenant_pubkey() -> bytes:
    meta = json.loads(_vector("anchor-vectors.meta.json").read_text(encoding="utf-8"))
    return base64.b64decode(meta["trusted_tenant_ed25519_pubkey_b64"])


def test_good_vector_passes_chain_check() -> None:
    path = _vector("good.ndjson")
    if not path.exists():
        pytest.skip(f"vector not found at {path}")
    report = verify_ledger(path, VerifyOptions(offline=True))
    assert report.hash_chain_valid, f"errors: {report.errors}"
    assert report.rows_seen == 100


def test_eval_verdict_vector_passes_chain_check() -> None:
    # Wedge item 3: promotion-record event; middle row's eval_run_id is JSON
    # null (manual override) — pins null canonicalization cross-language.
    path = _vector("eval-verdict.ndjson")
    if not path.exists():
        pytest.skip(f"vector not found at {path}")
    report = verify_ledger(path, VerifyOptions(offline=True))
    assert report.hash_chain_valid, f"errors: {report.errors}"
    assert report.rows_seen == 3


def test_tampered_vector_fails_chain_check() -> None:
    path = _vector("tampered.ndjson")
    if not path.exists():
        pytest.skip(f"vector not found at {path}")
    report = verify_ledger(path, VerifyOptions(offline=True))
    assert not report.hash_chain_valid
    assert report.errors


def test_no_anchor_vector_chain_still_valid() -> None:
    path = _vector("no-anchor.ndjson")
    if not path.exists():
        pytest.skip(f"vector not found at {path}")
    report = verify_ledger(path, VerifyOptions(offline=True))
    assert report.hash_chain_valid
    assert report.rekor_anchors_seen == 0


def test_v2_1_boundary_number_vector_passes() -> None:
    # JS-unsafe number class (1.0, >2^53, 1e2, 0.50). Hashed byte-for-byte, so
    # it verifies identically across all three verifiers.
    path = _vector("boundary-numbers.v2_1.ndjson")
    if not path.exists():
        pytest.skip(f"vector not found at {path}")
    report = verify_ledger(path, VerifyOptions(offline=True))
    assert report.hash_chain_valid, f"errors: {report.errors}"
    assert report.rows_seen == 2


def test_legacy_v2_object_vector_still_verifies_in_python() -> None:
    # The SAME data as a legacy v2 OBJECT payload. Python's json re-derive
    # matches the Rust writer's serde output for these numbers, so it verifies
    # the identical vector fails). Documents WHY Path 2 (verbatim) was needed.
    path = _vector("boundary-numbers.v2-legacy.ndjson")
    if not path.exists():
        pytest.skip(f"vector not found at {path}")
    report = verify_ledger(path, VerifyOptions(offline=True))
    assert report.hash_chain_valid, f"errors: {report.errors}"


# ---------------------------------------------------------------------
# ADR-062 Amendment 1 — OFFLINE anchor verification (real Rekor v2).
# Mirrors the TypeScript "ADR-062 anchor verification" describe block.
# ---------------------------------------------------------------------


def test_anchored_v1_verifies_fully_with_trusted_key() -> None:
    path = _vector("anchored.v1.ndjson")
    if not path.exists() or not _vector("anchor-vectors.meta.json").exists():
        pytest.skip(f"vector not found at {path}")
    trusted = _trusted_tenant_pubkey()
    report = verify_ledger(
        path,
        VerifyOptions(format_version=FormatVersion.V2_1, tenant_pubkey=trusted),
    )
    assert report.hash_chain_valid, f"errors: {report.errors}"
    assert report.errors == []
    assert report.signatures_valid
    assert report.rekor_anchors_resolved == 1
    assert report.anchors_included == 1  # Layer 2 inclusion + Layer 3 checkpoint
    assert report.strip_detected is False


def test_forged_anchor_rejected_at_trusted_key_gate() -> None:
    # A genuinely-log-included Rekor entry, but signed under an ATTACKER key.
    path = _vector("forged-anchor.ndjson")
    if not path.exists() or not _vector("anchor-vectors.meta.json").exists():
        pytest.skip(f"vector not found at {path}")
    trusted = _trusted_tenant_pubkey()
    report = verify_ledger(
        path,
        VerifyOptions(format_version=FormatVersion.V2_1, tenant_pubkey=trusted),
    )
    assert report.hash_chain_valid  # the chain itself is fine
    assert not report.signatures_valid  # but the anchor is rejected
    assert report.anchors_included == 0
    assert any(e.kind == "untrusted_tenant_key" for e in report.errors)


def test_chain_only_mode_asserts_no_anchor() -> None:
    # No trusted key -> never green: assert nothing about the anchor.
    path = _vector("anchored.v1.ndjson")
    if not path.exists():
        pytest.skip(f"vector not found at {path}")
    report = verify_ledger(path, VerifyOptions(format_version=FormatVersion.V2_1))
    assert report.hash_chain_valid
    assert report.rekor_anchors_resolved == 0
    assert report.anchors_included == 0
