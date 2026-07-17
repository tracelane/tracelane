//! Canonical encoding for the v2 tamper-evident audit ledger.
//!
//! ## Why v2
//!
//! Phase-0 security review):
//!
//! 1. **Hash input was ambiguous.** v1 concatenated fields with `|` as
//!    a separator. The `actor` field is an attacker-controlled string
//!    (set from JWT-sub or API-key label); a value like
//!    `alice|0|request|bob` would re-partition the hash input and let
//!    an attacker construct two semantically-different rows with the
//!    same `row_hash`.
//!
//! 2. **Merkle tree had no leaf/node domain separator** (RFC 6962
//!    §2.1). A single-leaf tree and a two-leaf tree of duplicated
//!    leaves can produce the same root → second-preimage attack.
//!
//! 3. **Genesis `prev_hash` was the empty string.** An attacker who
//!    can choose a tenant's first row can forge a parallel chain with
//!    matching genesis.
//!
//! ## v2 contract
//!
//! ### Row hash
//!
//! ```text
//! row_hash = SHA256(
//!     DOMAIN_ROW_V2
//!         || lp(tenant_id_bytes)        // 16-byte UUID
//!         || u64_be(seq)
//!         || lp(event_type)
//!         || lp(actor)
//!         || lp(payload_canonical_json) // RFC 8785 JCS — sorted keys, no whitespace
//!         || lp(prev_hash)              // 32 bytes
//! )
//! ```
//!
//! where `lp(x) = u64_be(len(x)) || x`. Length-prefixing prevents
//! field-boundary ambiguity; `u64_be(seq)` prevents decimal-stringification
//! ambiguity.
//!
//! ### Genesis seed
//!
//! ```text
//! prev_hash[seq=0] = SHA256(DOMAIN_GENESIS_V2 || tenant_id_bytes)
//! ```
//!
//! The seed is deterministic (the same tenant always gets the same
//! seed, so restart resumes correctly) but unforgeable (the domain
//! tag binds it to `tracelane-audit-v2-genesis`).
//!
//! ### Merkle tree (RFC 6962 §2.1)
//!
//! - `leaf(data) = SHA256(0x00 || data)` — domain tag distinguishes
//!   leaves from internal nodes.
//! - `node(left, right) = SHA256(0x01 || left || right)`.
//! - Odd-length levels: the lone right element is **promoted** to the
//!   next level without rehashing. (v1's duplicate-last produced the
//!   second-preimage collision; promotion is the RFC 6962 fix.)
//! - All operations on raw bytes; no hex encoding inside the tree.
//!
//! ## Backwards compatibility
//!
//! The v1 functions `compute_row_hash` and `compute_merkle_root` in
//! `audit.rs` remain so existing ClickHouse rows are still verifiable.
//! New writes use v2 exclusively; the migration plan is in
//! `decisions/ADR-013-audit-ledger-v2.md` (track separately).

use ring::digest::{self, SHA256, SHA256_OUTPUT_LEN};
use serde_json::Value;
use tracelane_shared::TenantId;

/// Domain-separation tag for the v2 row hash. Trailing NUL is part of
/// the tag (it cannot collide with any UTF-8 string a future field
/// might carry because the next byte is a u64 length prefix).
pub const DOMAIN_ROW_V2: &[u8] = b"tracelane-audit-row-v2\0";

/// Domain-separation tag for the v2 genesis seed.
pub const DOMAIN_GENESIS_V2: &[u8] = b"tracelane-audit-v2-genesis\0";

/// RFC 6962 §2.1 leaf prefix.
pub const MERKLE_LEAF_PREFIX: u8 = 0x00;

/// RFC 6962 §2.1 node prefix.
pub const MERKLE_NODE_PREFIX: u8 = 0x01;

/// One SHA-256 output (32 bytes). Use this type rather than
/// `[u8; 32]` so a future migration to e.g. SHA-512 catches every
/// call-site through the type checker.
pub type Hash = [u8; SHA256_OUTPUT_LEN];

/// Compute the v2 row hash. See module-level docs for the canonical
/// encoding.
///
/// `prev_hash` is the raw 32-byte SHA-256 of the previous row, or
/// `genesis_prev_hash(tenant_id)` for seq=0.
///
/// `payload_canonical_json` MUST be the RFC 8785 (JCS) canonical
/// serialization of the payload — caller's responsibility. The
/// `canonical_payload` helper below is the recommended source.
pub fn row_hash_v2(
    prev_hash: &Hash,
    tenant_id: &TenantId,
    seq: u64,
    event_type: &str,
    actor: &str,
    payload_canonical_json: &str,
) -> Hash {
    // Pre-size the buffer so the hash compute is one allocation +
    // one SHA-256 pass. Length is bounded by the field sizes; for a
    // 64 KB payload the buffer is ~64 KB.
    let mut buf = Vec::with_capacity(
        DOMAIN_ROW_V2.len()
            + 8 + 16                              // tenant_id (u64 len + 16 bytes)
            + 8                                   // seq (u64 BE)
            + 8 + event_type.len()
            + 8 + actor.len()
            + 8 + payload_canonical_json.len()
            + 8 + prev_hash.len(),
    );
    buf.extend_from_slice(DOMAIN_ROW_V2);
    write_length_prefixed(&mut buf, tenant_id.as_uuid().as_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    write_length_prefixed(&mut buf, event_type.as_bytes());
    write_length_prefixed(&mut buf, actor.as_bytes());
    write_length_prefixed(&mut buf, payload_canonical_json.as_bytes());
    write_length_prefixed(&mut buf, prev_hash);

    let d = digest::digest(&SHA256, &buf);
    let mut out = [0u8; SHA256_OUTPUT_LEN];
    out.copy_from_slice(d.as_ref());
    out
}

/// Deterministic genesis seed for tenant `tenant_id`. Same tenant →
/// same seed across process restarts.
pub fn genesis_prev_hash(tenant_id: &TenantId) -> Hash {
    let mut buf = Vec::with_capacity(DOMAIN_GENESIS_V2.len() + 16);
    buf.extend_from_slice(DOMAIN_GENESIS_V2);
    buf.extend_from_slice(tenant_id.as_uuid().as_bytes());
    let d = digest::digest(&SHA256, &buf);
    let mut out = [0u8; SHA256_OUTPUT_LEN];
    out.copy_from_slice(d.as_ref());
    out
}

/// RFC 6962 §2.1 Merkle root over a slice of leaf bytes.
///
/// `leaves` is the sequence of `row_hash_v2` outputs in append order.
/// Returns the root hash. For empty input, returns `SHA256("")` per
/// RFC 6962 §2.1.
pub fn merkle_root_v2(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        let d = digest::digest(&SHA256, b"");
        let mut out = [0u8; SHA256_OUTPUT_LEN];
        out.copy_from_slice(d.as_ref());
        return out;
    }

    // Level 0: hash each leaf with the LEAF prefix.
    let mut level: Vec<Hash> = leaves.iter().map(leaf_hash).collect();

    while level.len() > 1 {
        let mut next: Vec<Hash> = Vec::with_capacity(level.len().div_ceil(2));
        let mut iter = level.chunks_exact(2);
        for pair in &mut iter {
            next.push(node_hash(&pair[0], &pair[1]));
        }
        // Lone right element (odd-length level): promote without
        // rehashing. RFC 6962 §2.1.
        if let [lone] = iter.remainder() {
            next.push(*lone);
        }
        level = next;
    }
    level[0]
}

/// `leaf(data) = SHA256(0x00 || data)`.
fn leaf_hash(data: &Hash) -> Hash {
    let mut buf = Vec::with_capacity(1 + SHA256_OUTPUT_LEN);
    buf.push(MERKLE_LEAF_PREFIX);
    buf.extend_from_slice(data);
    let d = digest::digest(&SHA256, &buf);
    let mut out = [0u8; SHA256_OUTPUT_LEN];
    out.copy_from_slice(d.as_ref());
    out
}

/// `node(left, right) = SHA256(0x01 || left || right)`.
fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut buf = Vec::with_capacity(1 + 2 * SHA256_OUTPUT_LEN);
    buf.push(MERKLE_NODE_PREFIX);
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    let d = digest::digest(&SHA256, &buf);
    let mut out = [0u8; SHA256_OUTPUT_LEN];
    out.copy_from_slice(d.as_ref());
    out
}

/// RFC 8785 JSON Canonicalization Scheme (subset sufficient for our
/// payloads). Object keys are sorted lexicographically, arrays
/// preserve order, no whitespace, numbers in their shortest form,
/// strings escaped per JSON RFC 8259.
///
/// The library `serde_jcs` would also work, but we don't pull it in
/// because our payloads are restricted to scalars + objects + arrays
/// (no NaN, no -0, no extreme floats). A 30-line implementation
/// covers the cases we generate.
pub fn canonical_payload(value: &Value) -> String {
    let mut out = String::new();
    canonicalize_into(value, &mut out);
    out
}

fn canonicalize_into(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            // serde_json normalises ints; for floats we still use the
            // serde_json Display which is closest to the JCS "shortest
            // exact" form. Tracelane payloads don't carry IEEE-754
            // edge cases; if that changes, swap in `ryu` here.
            out.push_str(&n.to_string());
        }
        Value::String(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    '\x08' => out.push_str("\\b"),
                    '\x0c' => out.push_str("\\f"),
                    c if (c as u32) < 0x20 => {
                        use std::fmt::Write as _;
                        let _ = write!(out, "\\u{:04x}", c as u32);
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonicalize_into(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Sort keys lexicographically per RFC 8785 §3.2.3. Map iteration
            // ordering is implementation-defined; sort explicitly.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonicalize_into(&Value::String((*k).clone()), out);
                out.push(':');
                canonicalize_into(&map[*k], out);
            }
            out.push('}');
        }
    }
}

fn write_length_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Convenience: lowercase-hex encoding of a Hash. Used at the
/// storage boundary (ClickHouse `row_hash` column is TEXT) and at
/// the Rekor wire boundary (`hashedrekord.spec.data.hash.value`).
pub fn hex_encode(h: &Hash) -> String {
    let mut out = String::with_capacity(2 * SHA256_OUTPUT_LEN);
    for b in h {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Inverse of `hex_encode` — used by verifiers / re-parsing tests.
///
/// # Errors
/// Returns `Err` on non-hex chars or wrong length.
pub fn hex_decode(s: &str) -> Result<Hash, &'static str> {
    if s.len() != 2 * SHA256_OUTPUT_LEN {
        return Err("hex hash must be 64 chars");
    }
    let mut out = [0u8; SHA256_OUTPUT_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(s.as_bytes()[2 * i]).ok_or("non-hex char")?;
        let lo = hex_nibble(s.as_bytes()[2 * i + 1]).ok_or("non-hex char")?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;

    fn tenant_a() -> TenantId {
        TenantId::from_jwt_claim(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap())
    }

    fn tenant_b() -> TenantId {
        TenantId::from_jwt_claim(Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap())
    }

    // ---- row_hash_v2 ----------------------------------------------------

    #[test]
    fn row_hash_is_deterministic() {
        let p = canonical_payload(&json!({"x": 1}));
        let prev = genesis_prev_hash(&tenant_a());
        let h1 = row_hash_v2(&prev, &tenant_a(), 0, "request", "alice", &p);
        let h2 = row_hash_v2(&prev, &tenant_a(), 0, "request", "alice", &p);
        assert_eq!(h1, h2);
    }

    #[test]
    fn row_hash_changes_with_prev() {
        let p = canonical_payload(&json!({}));
        let h1 = row_hash_v2(&[0; 32], &tenant_a(), 0, "request", "alice", &p);
        let h2 = row_hash_v2(&[1; 32], &tenant_a(), 0, "request", "alice", &p);
        assert_ne!(h1, h2);
    }

    #[test]
    fn row_hash_changes_with_tenant() {
        let p = canonical_payload(&json!({}));
        let prev = [0; 32];
        let h1 = row_hash_v2(&prev, &tenant_a(), 0, "request", "alice", &p);
        let h2 = row_hash_v2(&prev, &tenant_b(), 0, "request", "alice", &p);
        assert_ne!(h1, h2);
    }

    #[test]
    fn row_hash_resists_field_boundary_attack() {
        // these two distinct logical rows would hash to the same value
        // because the `|` separator can be re-partitioned.
        //
        // Logical row 1: actor="alice", event_type="request"
        // Logical row 2: actor="alice|0|request|bob", event_type=""
        //
        // v1 hash input "tenant|0|request|alice|payload|prev" would equal
        // "tenant|0||alice|0|request|bob|payload|prev" if you squint at
        // the field separators.
        let p = canonical_payload(&json!({}));
        let prev = [0; 32];
        let h1 = row_hash_v2(&prev, &tenant_a(), 0, "request", "alice", &p);
        let h2 = row_hash_v2(&prev, &tenant_a(), 0, "", "alice|0|request|bob", &p);
        assert_ne!(
            h1, h2,
            "field-boundary attack must NOT produce matching hashes"
        );
    }

    #[test]
    fn row_hash_resists_seq_stringification_attack() {
        // Without u64-BE framing, seq=10 + actor="" could collide with
        // seq=1 + actor="0" because "1|0|" == "10|" via the separator.
        let p = canonical_payload(&json!({}));
        let prev = [0; 32];
        let h_seq10 = row_hash_v2(&prev, &tenant_a(), 10, "request", "", &p);
        let h_seq1 = row_hash_v2(&prev, &tenant_a(), 1, "request", "0", &p);
        assert_ne!(h_seq10, h_seq1);
    }

    // ---- merkle_root_v2 -------------------------------------------------

    #[test]
    fn merkle_root_empty_is_sha256_empty() {
        let root = merkle_root_v2(&[]);
        let expected = digest::digest(&SHA256, b"");
        assert_eq!(&root, expected.as_ref());
    }

    #[test]
    fn merkle_root_single_leaf_is_leaf_hash() {
        let leaf: Hash = [42; 32];
        let root = merkle_root_v2(&[leaf]);
        // Single-leaf root MUST equal SHA256(0x00 || leaf), not the leaf itself.
        let mut buf = vec![MERKLE_LEAF_PREFIX];
        buf.extend_from_slice(&leaf);
        let expected = digest::digest(&SHA256, &buf);
        assert_eq!(&root, expected.as_ref());
    }

    #[test]
    fn merkle_root_rfc6962_two_leaves() {
        // For two leaves L0, L1:
        //   root = SHA256(0x01 || SHA256(0x00 || L0) || SHA256(0x00 || L1))
        let l0: Hash = [0xAA; 32];
        let l1: Hash = [0xBB; 32];
        let root = merkle_root_v2(&[l0, l1]);

        let n0 = digest::digest(&SHA256, &[&[MERKLE_LEAF_PREFIX][..], &l0].concat());
        let n1 = digest::digest(&SHA256, &[&[MERKLE_LEAF_PREFIX][..], &l1].concat());
        let mut node_buf = vec![MERKLE_NODE_PREFIX];
        node_buf.extend_from_slice(n0.as_ref());
        node_buf.extend_from_slice(n1.as_ref());
        let expected = digest::digest(&SHA256, &node_buf);
        assert_eq!(&root, expected.as_ref());
    }

    #[test]
    fn merkle_root_resists_second_preimage_attack() {
        // a single-leaf tree and a 2-leaf tree of (raw_hash, raw_hash)
        // can produce the same root because both collapse to a SHA-256
        // of similar-looking inputs.
        let leaf: Hash = [7; 32];
        let single = merkle_root_v2(&[leaf]);

        // 2-leaf tree with duplicate leaves. v1 (no domain sep) would
        // collapse to SHA256(hex(leaf) || hex(leaf)) which matches the
        // v1 single-leaf case after the spurious double-hash.
        let double = merkle_root_v2(&[leaf, leaf]);

        assert_ne!(
            single, double,
            "single-leaf vs duplicated-leaf trees MUST differ (RFC 6962 §2.1)"
        );
    }

    #[test]
    fn merkle_root_promotes_lone_odd_leaf_not_duplicates() {
        // Three leaves: [a, b, c]. Per RFC 6962, level 1 is
        // [node(a,b), c], where `c` is *promoted* not rehashed. Level 2
        // is [node(node(a,b), c)].
        //
        // v1 duplicated `c` → [a, b, c, c] → tree of 4. The two roots
        // MUST differ.
        let a: Hash = [1; 32];
        let b: Hash = [2; 32];
        let c: Hash = [3; 32];
        let three = merkle_root_v2(&[a, b, c]);
        let four = merkle_root_v2(&[a, b, c, c]);
        assert_ne!(three, four);
    }

    // ---- genesis_prev_hash ---------------------------------------------

    #[test]
    fn genesis_seed_is_deterministic_per_tenant() {
        let g1 = genesis_prev_hash(&tenant_a());
        let g2 = genesis_prev_hash(&tenant_a());
        assert_eq!(g1, g2);
    }

    #[test]
    fn genesis_seed_differs_across_tenants() {
        let g_a = genesis_prev_hash(&tenant_a());
        let g_b = genesis_prev_hash(&tenant_b());
        assert_ne!(g_a, g_b);
    }

    #[test]
    fn genesis_seed_is_nonzero_and_nonempty() {
        let g = genesis_prev_hash(&tenant_a());
        assert_ne!(g, [0u8; 32], "genesis MUST NOT be all zeros");
    }

    // ---- canonical_payload (JCS subset) --------------------------------

    #[test]
    fn canonical_sorts_object_keys() {
        let v = json!({"b": 1, "a": 2, "c": 3});
        assert_eq!(canonical_payload(&v), r#"{"a":2,"b":1,"c":3}"#);
    }

    #[test]
    fn canonical_array_preserves_order() {
        let v = json!([3, 1, 2]);
        assert_eq!(canonical_payload(&v), "[3,1,2]");
    }

    #[test]
    fn canonical_escapes_control_chars_in_strings() {
        let v = json!({"k": "a\nb"});
        assert_eq!(canonical_payload(&v), r#"{"k":"a\nb"}"#);
    }

    #[test]
    fn canonical_nested_objects_recursively_sorted() {
        let v = json!({"outer": {"z": 1, "a": 2}, "alpha": []});
        assert_eq!(
            canonical_payload(&v),
            r#"{"alpha":[],"outer":{"a":2,"z":1}}"#
        );
    }

    // ---- hex codec ------------------------------------------------------

    #[test]
    fn hex_roundtrips() {
        let h: Hash = [0xAB; 32];
        let s = hex_encode(&h);
        assert_eq!(s.len(), 64);
        let back = hex_decode(&s).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn hex_decode_rejects_wrong_length() {
        assert!(hex_decode("abcd").is_err());
    }

    #[test]
    fn hex_decode_rejects_non_hex_chars() {
        let s = "g".repeat(64);
        assert!(hex_decode(&s).is_err());
    }
}
