//! Conformance tests against the canonical vectors in `evals/audit-ledger/`.
//!
//! All three reference verifiers (Rust, Python, TypeScript) MUST produce the
//! same `(hash_chain_valid, rekor_anchors_seen, error count)` tuple for each
//! vector. Vector content is shared; logic must converge.

use std::path::PathBuf;
use tracelane_audit_verifier::{VerifyOptions, verify_ledger};

fn vector(name: &str) -> PathBuf {
    // Resolve relative to the workspace root. tests/ lives in package, so we
    // walk up two levels.
    let pkg = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    pkg.parent()
        .and_then(|p| p.parent())
        .map(|root| root.join("evals").join("audit-ledger").join(name))
        .expect("workspace root resolution")
}

#[test]
fn good_vector_passes_chain_check() {
    let path = vector("good.ndjson");
    if !path.exists() {
        eprintln!("skipping: vector not found at {:?}", path);
        return;
    }
    let report = verify_ledger(&path, &VerifyOptions::offline()).expect("io ok");
    assert!(
        report.hash_chain_valid,
        "good.ndjson must verify; errors: {:?}",
        report.errors
    );
    assert_eq!(report.rows_seen, 100, "good.ndjson has 100 rows");
}

#[test]
fn eval_verdict_vector_passes_chain_check() {
    // Wedge item 3: the promotion-record event. Middle row's `eval_run_id` is
    // JSON null (manual override) — proves null canonicalizes identically here.
    let path = vector("eval-verdict.ndjson");
    if !path.exists() {
        return;
    }
    let report = verify_ledger(&path, &VerifyOptions::offline()).expect("io ok");
    assert!(
        report.hash_chain_valid,
        "eval-verdict.ndjson must verify; errors: {:?}",
        report.errors
    );
    assert_eq!(report.rows_seen, 3, "eval-verdict.ndjson has 3 rows");
}

#[test]
fn tampered_vector_fails_chain_check() {
    let path = vector("tampered.ndjson");
    if !path.exists() {
        return;
    }
    let report = verify_ledger(&path, &VerifyOptions::offline()).expect("io ok");
    assert!(!report.hash_chain_valid, "tampered.ndjson MUST fail");
    assert!(
        !report.errors.is_empty(),
        "expected at least one error on tampered vector"
    );
}

#[test]
fn no_anchor_vector_chain_still_valid() {
    let path = vector("no-anchor.ndjson");
    if !path.exists() {
        return;
    }
    let report = verify_ledger(&path, &VerifyOptions::offline()).expect("io ok");
    // Hash chain is independent of Rekor anchors — must still pass.
    assert!(
        report.hash_chain_valid,
        "no-anchor.ndjson chain must still verify"
    );
    assert_eq!(report.rekor_anchors_seen, 0);
}

#[test]
fn v2_1_boundary_number_vector_passes() {
    // JS-unsafe number class (1.0, >2^53, 1e2, 0.50). Hashed byte-for-byte, so
    // it verifies identically across all three verifiers.
    let path = vector("boundary-numbers.v2_1.ndjson");
    if !path.exists() {
        return;
    }
    let report = verify_ledger(&path, &VerifyOptions::offline()).expect("io ok");
    assert!(
        report.hash_chain_valid,
        "v2.1 boundary vector must verify verbatim; errors: {:?}",
        report.errors
    );
    assert_eq!(report.rows_seen, 2);
}

#[test]
fn legacy_v2_object_vector_still_verifies_in_rust() {
    // The SAME data as a legacy v2 OBJECT payload. Rust's serde re-derive
    // matches the writer's canonical form for these numbers, so it verifies
    // the identical vector). Documents WHY Path 2 (verbatim) was needed.
    let path = vector("boundary-numbers.v2-legacy.ndjson");
    if !path.exists() {
        return;
    }
    let report = verify_ledger(&path, &VerifyOptions::offline()).expect("io ok");
    assert!(
        report.hash_chain_valid,
        "legacy v2 object vector must verify under Rust re-derive; errors: {:?}",
        report.errors
    );
}

// ---- ADR-062 anchor verification (offline, real Rekor v2) ----------------

/// Minimal base64 decode for the test-only meta pubkey (mirrors the verifier's
/// stdlib-free decoder — no new dev-dep for one call).
fn b64(s: &str) -> Vec<u8> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let (mut acc, mut bits) = (0u32, 0u32);
    let mut out = Vec::new();
    for &c in s.trim().trim_end_matches('=').as_bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        let v = val(c).expect("base64");
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn trusted_pubkey() -> [u8; 32] {
    let meta: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(vector("anchor-vectors.meta.json")).unwrap())
            .unwrap();
    let bytes = b64(meta["trusted_tenant_ed25519_pubkey_b64"].as_str().unwrap());
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    k
}

#[test]
fn anchored_v1_verifies_fully_with_trusted_key() {
    let path = vector("anchored.v1.ndjson");
    if !path.exists() {
        return;
    }
    let opts = VerifyOptions::offline()
        .with_format(tracelane_audit_verifier::FormatVersion::V2_1)
        .with_tenant_pubkey(trusted_pubkey());
    let report = verify_ledger(&path, &opts).expect("io ok");
    assert!(report.hash_chain_valid, "errors: {:?}", report.errors);
    assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
    assert!(report.signatures_valid);
    assert_eq!(report.rekor_anchors_resolved, 1);
    assert_eq!(
        report.anchors_included, 1,
        "Layer 2 inclusion + Layer 3 checkpoint"
    );
    assert!(!report.strip_detected);
}

#[test]
fn forged_anchor_rejected_at_trusted_key_gate() {
    // A genuinely-log-included Rekor entry, but signed under an ATTACKER key.
    let path = vector("forged-anchor.ndjson");
    if !path.exists() {
        return;
    }
    let opts = VerifyOptions::offline()
        .with_format(tracelane_audit_verifier::FormatVersion::V2_1)
        .with_tenant_pubkey(trusted_pubkey());
    let report = verify_ledger(&path, &opts).expect("io ok");
    assert!(report.hash_chain_valid, "the chain itself is fine");
    assert!(!report.signatures_valid, "the anchor must be rejected");
    assert_eq!(report.anchors_included, 0);
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.kind == "untrusted_tenant_key"),
        "expected untrusted_tenant_key; got {:?}",
        report.errors
    );
}

#[test]
fn chain_only_mode_asserts_no_anchor() {
    let path = vector("anchored.v1.ndjson");
    if !path.exists() {
        return;
    }
    // No tenant_pubkey → chain-only; never green on anchors.
    let opts = VerifyOptions::offline().with_format(tracelane_audit_verifier::FormatVersion::V2_1);
    let report = verify_ledger(&path, &opts).expect("io ok");
    assert!(report.hash_chain_valid);
    assert_eq!(report.rekor_anchors_resolved, 0);
    assert_eq!(report.anchors_included, 0);
}
