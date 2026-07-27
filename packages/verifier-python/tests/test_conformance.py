"""Conformance tests against canonical vectors in ``evals/audit-ledger/``.

Mirrors `packages/verifier-rust/tests/conformance.rs` and the TypeScript
test suite. All three verifiers MUST agree on each vector.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

import tracelane_audit_verifier as _tav
from tracelane_audit_verifier import (
    FormatVersion,
    VerifyOptions,
    VerifyReport,
    verify_ledger,
)


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
    # ADR-050: payload is the verbatim canonical STRING carrying the
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
    # green here — this was a JS-specific divergence (see the TS suite, where
    # the identical vector fails). Documents WHY Path 2 (verbatim) was needed.
    path = _vector("boundary-numbers.v2-legacy.ndjson")
    if not path.exists():
        pytest.skip(f"vector not found at {path}")
    report = verify_ledger(path, VerifyOptions(offline=True))
    assert report.hash_chain_valid, f"errors: {report.errors}"


# ---------------------------------------------------------------------
# ADR-062 — OFFLINE anchor verification (real Rekor v2).
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


# ---------------------------------------------------------------------
# ADR-070 — WINDOWED verify (genesis retention-truncated, rooted at a public
# Rekor anchor). Mirrors the Rust `windowed_*` unit tests and the TypeScript
# windowed suite so all three verifiers stay behaviorally identical. A fully-
# INCLUDED anchor requires a real captured Rekor entry (the anchored.v1 vector,
# whose batch covers seq 0 — genesis-present, not windowable), so — exactly as
# the Rust/TS unit tests do — these inject the resolved anchor start via
# `_verify_chain(..., included_starts)` directly.
# ---------------------------------------------------------------------

_WTENANT = "00000000-0000-0000-0000-0000000000c1"


def _build_v2_1_chain(tenant: str, n: int) -> list[dict]:
    """A valid N-row v2.1 chain (seq 0..n-1), genesis-rooted, hashes computed."""
    tuid = _tav._uuid_bytes(tenant)
    prev = _tav._genesis_v2(tuid)
    rows: list[dict] = []
    for seq in range(n):
        payload = json.dumps({"i": seq}, separators=(",", ":"))
        rh = _tav._row_hash_v2(prev, tuid, seq, "evt", "actor", payload)
        rows.append(
            {
                "tenant_id": tenant,
                "seq": seq,
                "event_type": "evt",
                "actor": "actor",
                "payload": payload,
                "prev_hash": "" if seq == 0 else prev.hex(),
                "row_hash": rh.hex(),
            }
        )
        prev = rh
    return rows


def _windowed_opts() -> VerifyOptions:
    return VerifyOptions(offline=True, format_version=FormatVersion.V2_1)


def test_windowed_roots_at_anchor_reports_scope_not_min_loaded() -> None:
    # Genesis truncated: only seq 10..14 loaded; a public anchor roots at seq 12.
    rows = _build_v2_1_chain(_WTENANT, 15)[10:]
    report = VerifyReport(ledger_path="w")
    _tav._verify_chain(report, rows, _windowed_opts(), {_WTENANT: 12})
    assert report.hash_chain_valid, f"errors: {report.errors}"
    assert report.trust_established
    # Scope is the ANCHOR start (12), NOT the earliest loaded seq (10).
    assert report.verified_from_seq == 12
    assert report.errors == []


def test_windowed_in_scope_tamper_is_red() -> None:
    rows = _build_v2_1_chain(_WTENANT, 15)[10:]
    # Tamper a row INSIDE the verified scope (seq 13), keep its stale row_hash.
    for r in rows:
        if r["seq"] == 13:
            r["payload"] = json.dumps({"i": 13, "x": True}, separators=(",", ":"))
    report = VerifyReport(ledger_path="w")
    _tav._verify_chain(report, rows, _windowed_opts(), {_WTENANT: 12})
    assert not report.hash_chain_valid
    assert any(e.kind == "row_hash_mismatch" and e.seq == 13 for e in report.errors)


def test_windowed_no_anchor_is_unrooted_red_never_green() -> None:
    # Windowed (min seq 10 > 0) with NO included anchor -> unrooted -> RED.
    rows = _build_v2_1_chain(_WTENANT, 15)[10:]
    report = VerifyReport(ledger_path="w")
    _tav._verify_chain(report, rows, _windowed_opts(), {})
    assert report.trust_established is False
    assert any(e.kind == "unrooted_window" for e in report.errors)
    assert report.verified_from_seq == 0


def test_genesis_present_is_full_verify_ignores_included_starts() -> None:
    # seq 0 present -> full genesis verify; a stray included_starts is IGNORED.
    rows = _build_v2_1_chain(_WTENANT, 15)
    report = VerifyReport(ledger_path="w")
    _tav._verify_chain(report, rows, _windowed_opts(), {_WTENANT: 5})
    assert report.hash_chain_valid, f"errors: {report.errors}"
    assert report.trust_established
    assert report.verified_from_seq == 0


def test_multitenant_aggregate_is_latest_start_not_earliest() -> None:
    # Tenant A is genesis-rooted (start 0); tenant B is windowed, rooted at a
    # resolved anchor (start 10). The report-level verified_from_seq must be the
    # MAX per-tenant start (10), never the MIN (0): a min aggregate would read
    # "genesis->tip for ALL" and hide B's pre-anchor gap. Mirrors the Rust
    # `multitenant_aggregate_is_latest_start_not_earliest` test.
    tenant_a = "00000000-0000-0000-0000-0000000000a1"
    tenant_b = "00000000-0000-0000-0000-0000000000b1"
    rows_a = _build_v2_1_chain(tenant_a, 2)  # genesis rows seq 0,1

    # Tenant B: windowed seq 10,11, chained from an anchor seed prev_hash.
    tuid_b = _tav._uuid_bytes(tenant_b)
    prev = b"\x09" * 32
    rows_b: list[dict] = []
    for seq in (10, 11):
        payload = json.dumps({"i": seq}, separators=(",", ":"))
        rh = _tav._row_hash_v2(prev, tuid_b, seq, "evt", "actor", payload)
        rows_b.append(
            {
                "tenant_id": tenant_b,
                "seq": seq,
                "event_type": "evt",
                "actor": "actor",
                "payload": payload,
                "prev_hash": prev.hex(),
                "row_hash": rh.hex(),
            }
        )
        prev = rh

    report = VerifyReport(ledger_path="mt")
    # Only tenant B needs an injected anchor start; A is genesis-present (0).
    _tav._verify_chain(report, rows_a + rows_b, _windowed_opts(), {tenant_b: 10})
    assert report.hash_chain_valid, f"errors: {report.errors}"
    assert report.trust_established
    # aggregate MUST be MAX (windowed B = 10), never MIN (genesis A = 0).
    assert report.verified_from_seq == 10
