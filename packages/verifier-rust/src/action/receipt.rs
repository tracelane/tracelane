//! Tool-server countersignatures over a protected execution's receipt (ACT-17).
//! Shared by the gateway (writer) and the offline verifier, so both sign-check one statement.
use super::canonical_json;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const DOMAIN: &str = "tracelane.tool-receipt.v3";

/// Written in `execution_started` when a receipt key is registered for the tool server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Expected {
    pub receipt_key_id: String,
    /// SHA-256 (hex) of the attestation header value the gateway sent.
    pub attestation_digest: String,
}
/// Written in `execution_succeeded`: the tool's Ed25519 signature (hex) over [`statement`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Countersignature {
    pub receipt_key_id: String,
    pub tool_receipt: Uuid,
    pub signature: String,
}
/// The call a countersignature belongs to. Signed, so one genuine signature cannot be
/// replayed onto another execution, tenant or tool server, nor claimed for another action or
/// arguments (`action_id` and `request_digest` are the start row's).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub execution_id: Uuid,
    /// The action and request digest the start row records (and the attestation carries).
    pub action_id: Uuid,
    pub request_digest: String,
    pub tenant_id: Uuid,
    pub server_id: Uuid,
}
pub fn key_id(public: &[u8]) -> String {
    hex::encode(crate::sha256(public))
}
/// The 8 small-order Ed25519 point encodings (a key from this set verifies for many messages).
const SMALL_ORDER: [[u8; 32]; 8] = [
    hex_literal_32(*b"0100000000000000000000000000000000000000000000000000000000000000"),
    hex_literal_32(*b"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    hex_literal_32(*b"0000000000000000000000000000000000000000000000000000000000000000"),
    hex_literal_32(*b"0000000000000000000000000000000000000000000000000000000000000080"),
    hex_literal_32(*b"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    hex_literal_32(*b"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    hex_literal_32(*b"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    hex_literal_32(*b"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
];
const fn nibble(c: u8) -> u8 {
    if c <= b'9' { c - b'0' } else { c - b'a' + 10 }
}
const fn hex_literal_32(h: [u8; 64]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(h[2 * i]) << 4 | nibble(h[2 * i + 1]);
        i += 1;
    }
    out
}
/// A receipt key must be 32 bytes, a canonical point encoding (y < 2^255-19) and not small
/// order under either sign bit.
#[must_use]
pub fn valid_public_key(public: &[u8]) -> bool {
    let Ok(k) = <[u8; 32]>::try_from(public) else {
        return false;
    };
    // Compare with the sign bit cleared: ring decodes a sign-bit variant of x = 0 points.
    let mut masked = k;
    masked[31] &= 0x7f;
    if SMALL_ORDER.iter().any(|s| {
        let mut t = *s;
        t[31] &= 0x7f;
        t == masked
    }) {
        return false;
    }
    // y is the low 255 bits, little-endian; compare against p = 2^255-19 from the top byte down.
    let mut y = k;
    y[31] &= 0x7f;
    for i in (0..32).rev() {
        let p = match i {
            31 => 0x7f,
            0 => 0xed,
            _ => 0xff,
        };
        if y[i] != p {
            return y[i] < p;
        }
    }
    false
}
/// The exact RFC 8785 bytes a tool server signs. The outcome is fixed: only a success is
/// countersigned, so a signature over any other outcome never verifies.
/// # Errors
/// Fail-CLOSED on a value that cannot be canonicalized.
pub fn statement(expected: &Expected, binding: &Binding, tool_receipt: Uuid) -> Result<String> {
    canonical_json(
        &serde_json::json!({"domain":DOMAIN,"attestation_digest":expected.attestation_digest,
            "execution_id":binding.execution_id,"tenant_id":binding.tenant_id,
            "action_id":binding.action_id,"request_digest":binding.request_digest,
            "server_id":binding.server_id,
            "receipt_key_id":expected.receipt_key_id,"tool_receipt":tool_receipt,"outcome":"succeeded"})
        .to_string(),
    )
}
/// # Errors
/// Fail-CLOSED: a key that is not the expected one, a malformed signature, or a signature
/// over a different attestation, execution, tenant, server, receipt id or outcome is an error.
pub fn verify(
    public: &[u8],
    expected: &Expected,
    binding: &Binding,
    c: &Countersignature,
) -> Result<()> {
    ensure!(
        valid_public_key(public)
            && key_id(public) == expected.receipt_key_id
            && c.receipt_key_id == expected.receipt_key_id,
        "countersignature key mismatch"
    );
    let signature = hex::decode(&c.signature)
        .ok()
        .filter(|_| !c.signature.bytes().any(|b| b.is_ascii_uppercase()))
        .filter(|s| s.len() == 64)
        .context("countersignature invalid")?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public)
        .verify(
            statement(expected, binding, c.tool_receipt)?.as_bytes(),
            &signature,
        )
        .map_err(|_| anyhow::anyhow!("countersignature invalid"))
}
/// Digest of the gateway's countersigned success receipt, as `execution_succeeded` records it.
/// # Errors
/// Fail-CLOSED on a value that cannot be canonicalized.
pub fn receipt_digest(execution_id: Uuid, c: &Countersignature) -> Result<String> {
    let receipt = serde_json::json!({"execution_id":execution_id,"state":"succeeded","tool_receipt":c.tool_receipt,"countersignature":c});
    Ok(key_id(canonical_json(&receipt.to_string())?.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::super::{ActionPayload, Envelope, semantics, tests::fixture};
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::collections::BTreeMap;
    type Chain = (Vec<Envelope>, BTreeMap<String, Vec<u8>>);
    const STARTED: usize = 7;
    const DONE: usize = 8;
    fn key(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
    }
    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }
    fn expected(k: &Ed25519KeyPair) -> Expected {
        Expected {
            receipt_key_id: key_id(k.public_key().as_ref()),
            attestation_digest: "1".repeat(64),
        }
    }
    /// The fixture's execution: start row id(6), tenant id(1), contract server id(9).
    fn bind() -> Binding {
        Binding {
            execution_id: id(6),
            action_id: id(2),
            request_digest: "e".repeat(64),
            tenant_id: id(1),
            server_id: id(9),
        }
    }
    fn sign_for(k: &Ed25519KeyPair, x: &Expected, b: &Binding, receipt: Uuid) -> Countersignature {
        Countersignature {
            receipt_key_id: x.receipt_key_id.clone(),
            tool_receipt: receipt,
            signature: hex::encode(k.sign(statement(x, b, receipt).unwrap().as_bytes())),
        }
    }
    fn sign(k: &Ed25519KeyPair, x: &Expected, receipt: Uuid) -> Countersignature {
        sign_for(k, x, &bind(), receipt)
    }
    fn registration(k: &Ed25519KeyPair, server: Uuid, event: u128) -> Envelope {
        let public = k.public_key().as_ref();
        Envelope {
            schema_version: 1,
            event_id: id(event),
            action_id: server,
            tenant_id: id(1),
            agent_key_id: None,
            occurred_at: "2026-10-30T12:00:00Z".parse().unwrap(),
            request_digest: key_id(public),
            body: ActionPayload::ToolReceiptKeyRegistered {
                server_id: server,
                receipt_key_id: key_id(public),
                public_key: hex::encode(public),
            },
        }
    }
    fn set(e: &mut [Envelope], x: Option<Expected>, c: Option<Countersignature>) {
        if let ActionPayload::ExecutionStarted {
            receipt_expected, ..
        } = &mut e[STARTED].body
        {
            *receipt_expected = x;
        }
        if let ActionPayload::ExecutionSucceeded {
            execution_id,
            receipt_digest: digest,
            countersignature,
        } = &mut e[DONE].body
        {
            if let Some(c) = &c {
                *digest = receipt_digest(*execution_id, c).unwrap();
            }
            *countersignature = c;
        }
    }
    /// The fixture chain with `k` registered for the contract's server and a call it countersigned.
    fn chain(k: &Ed25519KeyPair) -> Chain {
        let (mut e, a) = fixture();
        e.insert(0, registration(k, id(9), 50));
        let x = expected(k);
        set(&mut e, Some(x.clone()), Some(sign(k, &x, id(77))));
        (e, a)
    }
    fn fails((e, a): &Chain, message: &str) {
        assert_eq!(semantics(e, a).unwrap_err().to_string(), message);
    }
    #[test]
    fn statement_is_jcs_with_domain() {
        let x = Expected {
            receipt_key_id: "a".repeat(64),
            attestation_digest: "b".repeat(64),
        };
        assert_eq!(
            statement(&x, &bind(), id(1)).unwrap(),
            format!(
                r#"{{"action_id":"{}","attestation_digest":"{}","domain":"tracelane.tool-receipt.v3","execution_id":"{}","outcome":"succeeded","receipt_key_id":"{}","request_digest":"{}","server_id":"{}","tenant_id":"{}","tool_receipt":"{}"}}"#,
                id(2),
                "b".repeat(64),
                id(6),
                "a".repeat(64),
                "e".repeat(64),
                id(9),
                id(1),
                id(1)
            )
        );
    }
    #[test]
    fn valid_countersignature_verifies() {
        let k = key(7);
        let x = expected(&k);
        verify(k.public_key().as_ref(), &x, &bind(), &sign(&k, &x, id(77))).unwrap();
    }
    #[test]
    fn semantics_counts_countersigned() {
        let (e, a) = chain(&key(7));
        let s = semantics(&e, &a).unwrap();
        assert_eq!((s.countersigned, s.uncountersigned), (1, 0));
    }
    #[test]
    fn semantics_counts_uncountersigned() {
        let (e, a) = fixture();
        let s = semantics(&e, &a).unwrap();
        assert_eq!((s.countersigned, s.uncountersigned), (0, 1));
    }
    #[test]
    fn rotation_uses_latest_registration() {
        let (mut e, a) = chain(&key(7));
        let new = key(8);
        e.insert(1, registration(&new, id(9), 51));
        fails(&(e.clone(), a.clone()), "receipt key expectation mismatch");
        let x = expected(&new);
        set(&mut e[1..], Some(x.clone()), Some(sign(&new, &x, id(77))));
        assert_eq!(semantics(&e, &a).unwrap().countersigned, 1);
    }
    #[test]
    fn other_server_key_leaves_uncountersigned() {
        let (mut e, a) = fixture();
        e.insert(0, registration(&key(7), id(10), 50));
        assert_eq!(semantics(&e, &a).unwrap().uncountersigned, 1);
    }
    #[test]
    fn unknown_outcome_with_expectation_accepted() {
        let (mut e, a) = chain(&key(7));
        e[DONE].body = ActionPayload::ExecutionUnknown {
            execution_id: id(6),
            receipt_digest: None,
        };
        let s = semantics(&e, &a).unwrap();
        assert_eq!((s.countersigned, s.unknown.len()), (0, 1));
    }
    #[test]
    fn semantics_rejects_forged_signature() {
        let (mut e, a) = chain(&key(7));
        let x = expected(&key(7));
        let mut c = sign(&key(7), &x, id(77));
        c.signature = "0".repeat(128);
        set(&mut e, Some(x), Some(c));
        fails(&(e, a), "countersignature invalid");
    }
    #[test]
    fn semantics_rejects_replayed_receipt() {
        // A receipt the tool signed for another call's attestation, pasted onto this one.
        let (mut e, a) = chain(&key(7));
        let mut other = expected(&key(7));
        other.attestation_digest = "2".repeat(64);
        set(
            &mut e,
            Some(expected(&key(7))),
            Some(sign(&key(7), &other, id(77))),
        );
        fails(&(e, a), "countersignature invalid");
    }
    #[test]
    fn semantics_rejects_key_substitution() {
        // Signed by a key the ledger never registered, under the registered key's id.
        let (mut e, a) = chain(&key(7));
        let x = expected(&key(7));
        set(&mut e, Some(x.clone()), Some(sign(&key(9), &x, id(77))));
        fails(&(e, a), "countersignature invalid");
    }
    #[test]
    fn semantics_rejects_stripped_countersignature() {
        let (mut e, a) = chain(&key(7));
        set(&mut e, Some(expected(&key(7))), None);
        fails(&(e, a), "countersignature mismatch");
    }
    #[test]
    fn semantics_rejects_missing_expectation() {
        let (mut e, a) = chain(&key(7));
        set(&mut e, None, None);
        fails(&(e, a), "receipt key expectation mismatch");
    }
    #[test]
    fn semantics_rejects_different_outcome() {
        let (mut e, a) = chain(&key(7));
        let x = expected(&key(7));
        let failed = statement(&x, &bind(), id(77))
            .unwrap()
            .replace("succeeded", "failed");
        let mut c = sign(&key(7), &x, id(77));
        c.signature = hex::encode(key(7).sign(failed.as_bytes()));
        set(&mut e, Some(x), Some(c));
        fails(&(e, a), "countersignature invalid");
    }
    #[test]
    fn semantics_rejects_receipt_id_swap() {
        let (mut e, a) = chain(&key(7));
        if let ActionPayload::ExecutionSucceeded { receipt_digest, .. } = &mut e[DONE].body {
            *receipt_digest = "d".repeat(64);
        }
        fails(&(e, a), "countersigned receipt digest mismatch");
    }
    #[test]
    fn registration_with_wrong_key_id_rejected() {
        let (mut e, a) = chain(&key(7));
        e[0].request_digest = "f".repeat(64);
        fails(&(e.clone(), a.clone()), "invalid receipt key registration");
        e[0] = registration(&key(7), id(9), 50);
        if let ActionPayload::ToolReceiptKeyRegistered { public_key, .. } = &mut e[0].body {
            *public_key = "ab".repeat(31);
        }
        fails(&(e, a), "invalid receipt key registration");
    }
    #[test]
    fn semantics_rejects_unexpected_countersignature() {
        let (mut e, a) = fixture();
        let x = expected(&key(7));
        if let ActionPayload::ExecutionSucceeded {
            countersignature, ..
        } = &mut e[DONE - 1].body
        {
            *countersignature = Some(sign(&key(7), &x, id(77)));
        }
        fails(&(e, a), "countersignature mismatch");
    }
    /// A second countersigned execution of the same server: the fixture's action chain cloned
    /// under fresh ids (action 12, approval 15, execution 16), start digest "2"*64.
    fn two_executions(k: &Ed25519KeyPair) -> Chain {
        let (mut e, a) = chain(k);
        let swaps = [(2, 12), (5, 15), (6, 16), (7, 17), (77, 78)];
        let mut more = Vec::new();
        for (n, p) in e[2..=DONE].iter().enumerate() {
            let mut text = serde_json::to_string(p).unwrap();
            for (from, to) in swaps {
                text = text.replace(&id(from).to_string(), &id(to).to_string());
            }
            text = text.replace(&p.event_id.to_string(), &id(200 + n as u128).to_string());
            more.push(serde_json::from_str::<Envelope>(&text).unwrap());
        }
        let n = more.len();
        let x = Expected {
            attestation_digest: "2".repeat(64),
            ..expected(k)
        };
        let b = Binding {
            execution_id: id(16),
            action_id: id(12),
            ..bind()
        };
        let c = sign_for(k, &x, &b, id(78));
        if let ActionPayload::ExecutionStarted {
            receipt_expected, ..
        } = &mut more[n - 2].body
        {
            *receipt_expected = Some(x);
        }
        if let ActionPayload::ExecutionSucceeded {
            execution_id,
            receipt_digest: d,
            countersignature,
        } = &mut more[n - 1].body
        {
            *d = receipt_digest(*execution_id, &c).unwrap();
            *countersignature = Some(c);
        }
        e.extend(more);
        (e, a)
    }
    #[test]
    fn two_genuine_executions_verify() {
        let (e, a) = two_executions(&key(7));
        assert_eq!(semantics(&e, &a).unwrap().countersigned, 2);
    }
    #[test]
    fn small_order_and_noncanonical_keys_refused() {
        let identity = format!("01{}", "00".repeat(31));
        let p_minus_one = format!("ec{}7f", "ff".repeat(30));
        let y_eq_p = format!("ed{}7f", "ff".repeat(30));
        let y_gt_p = format!("ee{}7f", "ff".repeat(30));
        // Sign-bit variants of small-order points: ring decodes them (x = 0 negates to 0).
        let identity_signed = format!("01{}80", "00".repeat(30));
        let order2_signed = format!("ec{}", "ff".repeat(31));
        for bad in [
            identity,
            p_minus_one,
            y_eq_p,
            y_gt_p,
            "00".repeat(32),
            identity_signed,
            order2_signed,
        ] {
            assert!(!valid_public_key(&hex::decode(&bad).unwrap()), "{bad}");
        }
        assert!(!valid_public_key(&[1; 31]));
        assert!(valid_public_key(key(7).public_key().as_ref()));
    }
    #[test]
    fn identity_key_registration_rejected() {
        let (mut e, a) = chain(&key(7));
        let identity = [&[1u8][..], &[0u8; 31]].concat();
        e[0] = registration(&key(7), id(9), 50);
        if let ActionPayload::ToolReceiptKeyRegistered {
            public_key,
            receipt_key_id,
            ..
        } = &mut e[0].body
        {
            *public_key = hex::encode(&identity);
            *receipt_key_id = key_id(&identity);
        }
        e[0].request_digest = key_id(&identity);
        fails(&(e, a), "invalid receipt key registration");
    }
    #[test]
    fn identity_key_never_verifies() {
        let identity = [&[1u8][..], &[0u8; 31]].concat();
        let x = Expected {
            receipt_key_id: key_id(&identity),
            attestation_digest: "1".repeat(64),
        };
        let c = Countersignature {
            receipt_key_id: x.receipt_key_id.clone(),
            tool_receipt: id(77),
            signature: "00".repeat(64),
        };
        assert!(verify(&identity, &x, &bind(), &c).is_err());
    }
    #[test]
    fn registration_with_agent_key_rejected() {
        let (mut e, a) = chain(&key(7));
        e[0].agent_key_id = Some(id(8));
        fails(&(e, a), "invalid receipt key registration");
    }
    #[test]
    fn uppercase_signature_rejected() {
        let (mut e, a) = chain(&key(7));
        let x = expected(&key(7));
        let mut c = sign(&key(7), &x, id(77));
        c.signature = c.signature.to_uppercase();
        set(&mut e, Some(x), Some(c));
        fails(&(e, a), "countersignature invalid");
    }
    #[test]
    fn receipt_key_equal_to_attestation_key_rejected() {
        let (mut e, a) = chain(&key(7));
        let own = expected(&key(7)).receipt_key_id;
        if let ActionPayload::ExecutionStarted {
            attestation_key_id, ..
        } = &mut e[STARTED].body
        {
            *attestation_key_id = own;
        }
        fails(&(e, a), "receipt key expectation mismatch");
    }
    #[test]
    fn replay_onto_other_execution_rejected() {
        // A genuine signature for execution id(6), pasted onto the same digest and receipt of id(5).
        let (mut e, a) = chain(&key(7));
        let x = expected(&key(7));
        let other = Binding {
            execution_id: id(5),
            ..bind()
        };
        set(
            &mut e,
            Some(x.clone()),
            Some(sign_for(&key(7), &x, &other, id(77))),
        );
        fails(&(e, a), "countersignature invalid");
    }
    #[test]
    fn signature_over_other_request_or_action_rejected() {
        // Same attestation digest and execution, but the tool signed other arguments / action.
        for other in [
            Binding {
                request_digest: "f".repeat(64),
                ..bind()
            },
            Binding {
                action_id: id(12),
                ..bind()
            },
        ] {
            let (mut e, a) = chain(&key(7));
            let x = expected(&key(7));
            set(
                &mut e,
                Some(x.clone()),
                Some(sign_for(&key(7), &x, &other, id(77))),
            );
            fails(&(e, a), "countersignature invalid");
        }
    }
    #[test]
    fn replay_onto_other_tenant_or_server_rejected() {
        for other in [
            Binding {
                tenant_id: id(2),
                ..bind()
            },
            Binding {
                server_id: id(10),
                ..bind()
            },
        ] {
            let (mut e, a) = chain(&key(7));
            let x = expected(&key(7));
            set(
                &mut e,
                Some(x.clone()),
                Some(sign_for(&key(7), &x, &other, id(77))),
            );
            fails(&(e, a), "countersignature invalid");
        }
    }
    #[test]
    fn duplicate_attestation_digest_rejected() {
        let (mut e, a) = two_executions(&key(7));
        let n = e.len();
        if let ActionPayload::ExecutionStarted {
            receipt_expected, ..
        } = &mut e[n - 2].body
        {
            receipt_expected.as_mut().unwrap().attestation_digest = "1".repeat(64);
        }
        fails(&(e, a), "duplicate attestation digest");
    }
    #[test]
    fn reused_tool_receipt_on_bound_executions_verifies() {
        // Each statement binds its own execution_id, so a tool that reuses a receipt id is not
        // a replay. The gateway accepts it, so the verifier must too, or one such tool would
        // break every later export of the workspace.
        let (mut e, a) = two_executions(&key(7));
        let n = e.len();
        let x = Expected {
            attestation_digest: "2".repeat(64),
            ..expected(&key(7))
        };
        let b = Binding {
            execution_id: id(16),
            action_id: id(12),
            ..bind()
        };
        let c = sign_for(&key(7), &x, &b, id(77));
        if let ActionPayload::ExecutionSucceeded {
            execution_id,
            receipt_digest: d,
            countersignature,
        } = &mut e[n - 1].body
        {
            *d = receipt_digest(*execution_id, &c).unwrap();
            *countersignature = Some(c);
        }
        assert_eq!(semantics(&e, &a).unwrap().countersigned, 2);
    }
    #[test]
    fn unparseable_contract_server_id_fails_closed() {
        let (mut e, mut a) = chain(&key(7));
        let (old, bytes) = a
            .iter()
            .find(|(_, v)| String::from_utf8_lossy(v).contains("server_id"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .unwrap();
        a.remove(&old);
        let bad = String::from_utf8(bytes)
            .unwrap()
            .replace(&id(9).to_string(), "not-a-uuid");
        let hash = hex::encode(crate::sha256(bad.as_bytes()));
        a.insert(hash.clone(), bad.into_bytes());
        if let ActionPayload::PolicyActivated { contract_hash, .. } = &mut e[1].body {
            *contract_hash = hash;
        }
        fails(&(e, a), "invalid contract server_id");
    }
}
