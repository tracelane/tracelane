//! Regenerate the canonical audit-ledger conformance vectors in
//! `evals/audit-ledger/`.
//!
//! Output:
//!   - `good.ndjson`      — 100-row chain in v2 format, internally consistent.
//!   - `tampered.ndjson`  — same chain but row #50 payload is mutated
//!     without re-hashing, so `row_hash_mismatch` MUST fire at seq=50.
//!   - `no-anchor.ndjson` — 100-row chain with no `rekor_entry_id` on
//!     any row (proves chain validity is independent of Rekor).
//!   - `eval-verdict.ndjson` — 3-row chain of `eval.verdict` promotion-record
//!     events (wedge item 3); middle row carries `eval_run_id: null` to pin
//!     JSON-null canonicalization across all three language verifiers.
//!
//! Run: `cargo run -p tracelane-audit-verifier --example gen_audit_fixtures`
//!
//! The vectors are byte-stable across runs: timestamps are derived from
//! a fixed epoch + seq, payloads are deterministic. This is required
//! because the Python and TypeScript verifiers consume the same files
//! and any drift will break cross-language conformance.

use std::fs::File;
use std::io::Write as _;
use std::path::PathBuf;

use serde_json::json;
use sha2::{Digest, Sha256};

const TENANT_A: &str = "00000000-0000-0000-0000-000000000001";
const ROW_COUNT: u64 = 100;

const DOMAIN_ROW_V2: &[u8] = b"tracelane-audit-row-v2\0";
const DOMAIN_GENESIS_V2: &[u8] = b"tracelane-audit-v2-genesis\0";

fn sha256(b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().into()
}

fn write_lp(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u64).to_be_bytes());
    buf.extend_from_slice(b);
}

fn uuid_bytes(s: &str) -> [u8; 16] {
    let cleaned: String = s.chars().filter(|c| *c != '-').collect();
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&cleaned[2 * i..2 * i + 2], 16).expect("hex");
    }
    out
}

fn genesis(tenant: &[u8; 16]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(DOMAIN_GENESIS_V2.len() + 16);
    buf.extend_from_slice(DOMAIN_GENESIS_V2);
    buf.extend_from_slice(tenant);
    sha256(&buf)
}

fn row_hash(
    prev: &[u8; 32],
    tenant: &[u8; 16],
    seq: u64,
    event_type: &str,
    actor: &str,
    canonical_payload: &str,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(
        DOMAIN_ROW_V2.len()
            + 8
            + 16
            + 8
            + 8
            + event_type.len()
            + 8
            + actor.len()
            + 8
            + canonical_payload.len()
            + 8
            + 32,
    );
    buf.extend_from_slice(DOMAIN_ROW_V2);
    write_lp(&mut buf, tenant);
    buf.extend_from_slice(&seq.to_be_bytes());
    write_lp(&mut buf, event_type.as_bytes());
    write_lp(&mut buf, actor.as_bytes());
    write_lp(&mut buf, canonical_payload.as_bytes());
    write_lp(&mut buf, prev);
    sha256(&buf)
}

fn canonical_json(v: &serde_json::Value) -> String {
    let mut out = String::new();
    write_canon(v, &mut out);
    out
}

fn write_canon(v: &serde_json::Value, out: &mut String) {
    use std::fmt::Write as _;
    match v {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        serde_json::Value::Number(n) => {
            let _ = write!(out, "{n}");
        }
        serde_json::Value::String(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    // Match audit_format::canonicalize_into exactly — \b and \f
                    // get short escapes, not \u00xx, else fixtures silently drift
                    // from real gateway output on those bytes.
                    '\x08' => out.push_str("\\b"),
                    '\x0c' => out.push_str("\\f"),
                    c if (c as u32) < 0x20 => {
                        let _ = write!(out, "\\u{:04x}", c as u32);
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        serde_json::Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canon(x, out);
            }
            out.push(']');
        }
        serde_json::Value::Object(m) => {
            let mut k: Vec<&String> = m.keys().collect();
            k.sort();
            out.push('{');
            for (i, key) in k.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canon(&serde_json::Value::String((*key).clone()), out);
                out.push(':');
                write_canon(&m[*key], out);
            }
            out.push('}');
        }
    }
}

fn make_row(
    seq: u64,
    prev: &[u8; 32],
    tenant_uuid: &[u8; 16],
    include_anchor: bool,
) -> ([u8; 32], serde_json::Value) {
    let even = seq.is_multiple_of(2);
    let event_type = if even { "request" } else { "response" };
    let actor = if even { "user1" } else { "system" };
    let payload = json!({
        "step": seq,
        "action": if even { "call" } else { "reply" },
        "tokens": seq * 7,
    });
    let canon = canonical_json(&payload);
    let h = row_hash(prev, tenant_uuid, seq, event_type, actor, &canon);

    // Synthetic Rekor UUID — content is opaque; conformance only cares
    // that rows sharing a UUID belong to the same anchor batch.
    let anchor = if include_anchor {
        Some(format!("{:064x}", seq / 10)) // 10 rows per batch
    } else {
        None
    };

    let event_time = format!(
        "2026-05-14T00:{:02}:{:02}.000000Z",
        (seq / 60) % 60,
        seq % 60
    );

    let row = json!({
        "tenant_id": TENANT_A,
        "seq": seq,
        "event_time": event_time,
        "event_type": event_type,
        "actor": actor,
        "payload": payload,
        "prev_hash": hex::encode(prev),
        "row_hash": hex::encode(h),
        "rekor_entry_id": anchor,
    });
    (h, row)
}

fn write_ndjson(path: &PathBuf, rows: &[serde_json::Value]) -> std::io::Result<()> {
    let mut f = File::create(path)?;
    for row in rows {
        writeln!(f, "{}", serde_json::to_string(row).unwrap())?;
    }
    Ok(())
}

fn main() -> std::io::Result<()> {
    let tenant_uuid = uuid_bytes(TENANT_A);
    let mut prev = genesis(&tenant_uuid);

    // Good chain — 100 rows with rekor_entry_id batched in groups of 10.
    let mut good_rows = Vec::with_capacity(ROW_COUNT as usize);
    for seq in 0..ROW_COUNT {
        let (h, row) = make_row(seq, &prev, &tenant_uuid, true);
        good_rows.push(row);
        prev = h;
    }

    // Tampered: copy good_rows, mutate row #50's payload without rehashing.
    let mut tampered_rows = good_rows.clone();
    tampered_rows[50]["payload"] = json!({"step": 50, "action": "tampered", "tokens": 9999});

    // No-anchor: 100 rows with rekor_entry_id stripped to null on every row.
    let mut prev = genesis(&tenant_uuid);
    let mut no_anchor_rows = Vec::with_capacity(ROW_COUNT as usize);
    for seq in 0..ROW_COUNT {
        let (h, row) = make_row(seq, &prev, &tenant_uuid, false);
        no_anchor_rows.push(row);
        prev = h;
    }

    // Resolve output dir relative to crate dir.
    let pkg = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out_dir = pkg
        .parent()
        .and_then(|p| p.parent())
        .map(|root| root.join("evals").join("audit-ledger"))
        .expect("workspace root");
    std::fs::create_dir_all(&out_dir)?;

    // eval.verdict — the hero promotion-record event (wedge item 3). Pins the
    // exact payload wire shape the gateway emits AND exercises a JSON `null`
    // (`eval_run_id` on a manual override — no eval ran), the one canonical-JSON
    // path good.ndjson never touches. Cross-language null drift dies here.
    let ev_verdicts = [
        json!({
            "prompt": "checkout-classifier", "promotion_id": "11111111-1111-1111-1111-111111111111",
            "from_env": "staging", "to_env": "production",
            "to_version_id": "22222222-2222-2222-2222-222222222222",
            "decision": "promoted", "eval_run_id": "33333333-3333-3333-3333-333333333333",
        }),
        json!({
            "prompt": "checkout-classifier", "promotion_id": "44444444-4444-4444-4444-444444444444",
            "from_env": "staging", "to_env": "production",
            "to_version_id": "55555555-5555-5555-5555-555555555555",
            "decision": "manual_override", "eval_run_id": null,
        }),
        json!({
            "prompt": "checkout-classifier", "promotion_id": "66666666-6666-6666-6666-666666666666",
            "from_env": "production", "to_env": "staging",
            "to_version_id": "77777777-7777-7777-7777-777777777777",
            "decision": "blocked_by_eval", "eval_run_id": "88888888-8888-8888-8888-888888888888",
        }),
    ];
    let mut prev = genesis(&tenant_uuid);
    let mut ev_rows = Vec::with_capacity(ev_verdicts.len());
    for (seq, payload) in ev_verdicts.iter().enumerate() {
        let seq = seq as u64;
        let canon = canonical_json(payload);
        let h = row_hash(
            &prev,
            &tenant_uuid,
            seq,
            "eval.verdict",
            "user@acme.test",
            &canon,
        );
        ev_rows.push(json!({
            "tenant_id": TENANT_A, "seq": seq,
            "event_time": format!("2026-05-14T01:00:{seq:02}.000000Z"),
            "event_type": "eval.verdict", "actor": "user@acme.test", "payload": payload,
            "prev_hash": hex::encode(prev), "row_hash": hex::encode(h),
            "rekor_entry_id": null,
        }));
        prev = h;
    }

    write_ndjson(&out_dir.join("good.ndjson"), &good_rows)?;
    write_ndjson(&out_dir.join("tampered.ndjson"), &tampered_rows)?;
    write_ndjson(&out_dir.join("no-anchor.ndjson"), &no_anchor_rows)?;
    write_ndjson(&out_dir.join("eval-verdict.ndjson"), &ev_rows)?;

    println!("wrote {ROW_COUNT}-row vectors to {}", out_dir.display());
    Ok(())
}
