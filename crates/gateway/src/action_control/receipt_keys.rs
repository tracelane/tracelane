//! Tool-server receipt keys (ACT-17): one Ed25519 public key per (tenant, server), registered
//! through the control plane like an agent key and recorded in the action ledger, where an
//! offline verifier reads it. `execution` reads the key inside the reservation transaction.
use super::*;
use crate::{
    auth::Claims,
    control_plane::ControlActor,
    db::audit_chain_state::AtomicBatchAppend,
    db::control_audit::{self, Change},
    server::AppState,
};
pub use tracelane_audit_verifier::action::receipt::{self, Binding, Countersignature, Expected};

pub type Refusal = (u16, &'static str);
const UNAVAILABLE: Refusal = (503, "evidence_unavailable");
const INVALID: Refusal = (400, "invalid_receipt_key");
const NOT_FOUND: Refusal = (404, "mcp_server_not_found");
fn unavailable<E>(_: E) -> Refusal {
    UNAVAILABLE
}
/// The key a reserved execution must be countersigned with, and the statement it must cover.
pub struct ReceiptKey {
    pub(crate) public: Vec<u8>,
    pub(crate) expected: Expected,
    /// The call the signature must be bound to (execution, action, arguments, tenant, server).
    pub(crate) binding: Binding,
}
/// Reads the key registered for (tenant, server) and binds it to the attestation about to be
/// sent. Call after the tenant row lock, so a registration is either wholly before or after.
/// # Errors
/// A read error fails CLOSED (the reservation rolls back, nothing is sent). `Ok(None)` is
/// "no key registered": fail-OPEN, the call proceeds with today's unsigned receipt.
pub(crate) async fn load_tx(
    tx: &Transaction<'_>,
    tenant: &TenantId,
    server: Uuid,
    execution: Uuid,
    action: Uuid,
    request_digest: &str,
    attestation: &str,
) -> Result<Option<ReceiptKey>> {
    let row = tx
        .query_opt(
            "SELECT receipt_key_id,public_key FROM action_tool_receipt_keys WHERE tenant_id=$1 AND server_id=$2",
            &[tenant.as_uuid(), &server],
        )
        .await?;
    Ok(row.map(|r| ReceiptKey {
        public: r.get(1),
        expected: Expected {
            receipt_key_id: r.get(0),
            attestation_digest: sha(attestation.as_bytes()),
        },
        binding: Binding {
            execution_id: execution,
            action_id: action,
            request_digest: request_digest.to_owned(),
            tenant_id: *tenant.as_uuid(),
            server_id: server,
        },
    }))
}
/// Decides whether a tool's success may be recorded, and with which countersignature.
/// # Errors
/// Fail-OPEN when no key is registered: `Ok(None)`, and any signature the tool sent is ignored.
/// Fail-CLOSED when a key is registered: a missing, malformed or non-verifying signature is an
/// error, and the caller records the outcome as Unknown, never Succeeded.
pub(crate) fn countersigned(
    key: Option<&ReceiptKey>,
    tool_receipt: Uuid,
    signature: Option<&str>,
) -> Result<Option<Countersignature>> {
    let Some(key) = key else { return Ok(None) };
    let c = Countersignature {
        receipt_key_id: key.expected.receipt_key_id.clone(),
        tool_receipt,
        signature: signature.context("countersignature_missing")?.to_owned(),
    };
    receipt::verify(&key.public, &key.expected, &key.binding, &c)?;
    Ok(Some(c))
}
fn parse(body: &[u8]) -> Result<[u8; 32], Refusal> {
    // Strict parse: exactly one member, 64 lowercase hex characters.
    let doc = crate::strict_json::from_slice(body).map_err(|_| INVALID)?;
    let key = doc
        .as_object()
        .filter(|o| o.len() == 1)
        .and_then(|o| o.get("public_key"))
        .and_then(Value::as_str)
        .filter(|k| !k.bytes().any(|b| b.is_ascii_uppercase()))
        .ok_or(INVALID)?;
    hex::decode(key)
        .ok()
        .filter(|k| receipt::valid_public_key(k))
        .and_then(|k| k.try_into().ok())
        .ok_or(INVALID)
}
/// The gateway's own attestation key must never countersign its own attestations.
/// # Errors
/// Fail-CLOSED: registering the gateway's key is refused.
fn refuse_gateway_key(
    signer: Option<&execution::AttestationSigner>,
    public: &[u8; 32],
) -> Result<(), Refusal> {
    match signer {
        Some(s) if s.public_key() == public.as_slice() => Err(INVALID),
        _ => Ok(()),
    }
}
/// `PUT /v1/mcp-servers/{id}/receipt-key`: register or rotate the server's receipt key.
/// # Errors
/// Fail-CLOSED: the flag, the body, server ownership, the ledger row and the control-audit
/// row all refuse before the commit. Only the derived ledger copy fails OPEN.
#[tracing::instrument(skip_all, fields(tenant_id=%claims.tenant_id))]
pub async fn register(
    state: &AppState,
    claims: &Claims,
    actor: &ControlActor,
    server: &str,
    body: &[u8],
) -> Result<Value, Refusal> {
    let pool = state.pg.as_ref().ok_or(UNAVAILABLE)?;
    let cache = state.entitlements.as_ref().ok_or(UNAVAILABLE)?;
    let resolved = cache.resolved(*claims.tenant_id.as_uuid()).await;
    let limits = &crate::mcp_policy::settings().map_err(unavailable)?.limits;
    if body.len() > limits.max_request_bytes {
        return Err(INVALID);
    }
    let public = parse(body)?;
    refuse_gateway_key(state.action_signer.as_deref(), &public)?;
    let server: Uuid = server.parse().map_err(|_| NOT_FOUND)?;
    let timeout = std::time::Duration::from_secs(limits.call_timeout_secs);
    let (out, rows) = tokio::time::timeout(
        timeout,
        commit(pool, claims, actor, &resolved, timeout, server, &public),
    )
    .await
    .map_err(unavailable)??;
    execution::after_commit(Some(&state.audit_chain), claims, vec![rows], timeout);
    Ok(out)
}
/// One transaction: table row, ledger row and control-audit row.
/// # Errors
/// Fail-CLOSED; the transaction is dropped (rolled back) on any error.
pub(crate) async fn commit(
    pool: &deadpool_postgres::Pool,
    claims: &Claims,
    actor: &ControlActor,
    resolved: &crate::entitlement_cache::ResolvedEntitlements,
    timeout: std::time::Duration,
    server: Uuid,
    public: &[u8; 32],
) -> Result<(Value, AtomicBatchAppend), Refusal> {
    if !enabled(Some(resolved)) {
        return Err((409, "action_control_disabled"));
    }
    let tenant = claims.tenant_id.as_uuid();
    let mut db = pool.get().await.map_err(unavailable)?;
    let tx = db.transaction().await.map_err(unavailable)?;
    execution::deadline_tx(&tx, timeout)
        .await
        .map_err(unavailable)?;
    // The lock `reserve_tx` takes before it reads the key: registrations and starts are serial.
    tx.query_one("SELECT id FROM tenants WHERE id=$1 FOR UPDATE", &[tenant])
        .await
        .map_err(unavailable)?;
    let owned = tx
        .query_opt(
            "SELECT 1 FROM mcp_servers WHERE tenant_id=$1 AND id=$2 AND archived_at IS NULL FOR SHARE",
            &[tenant, &server],
        )
        .await
        .map_err(unavailable)?;
    if owned.is_none() {
        return Err(NOT_FOUND);
    }
    let key_id = receipt::key_id(public);
    let prior = tx
        .query_opt(
            "SELECT receipt_key_id FROM action_tool_receipt_keys WHERE tenant_id=$1 AND server_id=$2",
            &[tenant, &server],
        )
        .await
        .map_err(unavailable)?
        .map(|r| json!({"receipt_key_id":r.get::<_, String>(0)}));
    tx.execute(
        "INSERT INTO action_tool_receipt_keys(tenant_id,server_id,receipt_key_id,public_key) VALUES ($1,$2,$3,$4) ON CONFLICT (tenant_id,server_id) DO UPDATE SET receipt_key_id=EXCLUDED.receipt_key_id,public_key=EXCLUDED.public_key,registered_at=now()",
        &[tenant, &server, &key_id, &public.as_slice()],
    )
    .await
    .map_err(unavailable)?;
    let event = ActionEvent {
        event_id: Uuid::new_v4(),
        action_id: server,
        occurred_at: Utc::now(),
        request_digest: key_id.clone(),
        body: ActionPayload::ToolReceiptKeyRegistered {
            server_id: server,
            receipt_key_id: key_id.clone(),
            public_key: hex::encode(public),
        },
    };
    // No agent key on the registration row, whoever authenticated (the verifier refuses one).
    let rows = append_for_actor_tx(
        &tx,
        &claims.tenant_id,
        None,
        Some(claims.auth_method),
        &[event],
    )
    .await
    .map_err(unavailable)?
    .ok_or(UNAVAILABLE)?;
    let out = json!({"server_id":server,"receipt_key_id":key_id});
    control_audit::record(
        &tx,
        &actor.tenant_id,
        &actor.audit,
        Change {
            action: "mcp_server.receipt_key.set",
            target_type: "mcp_server",
            target_id: server.to_string(),
            before: prior,
            after: Some(out.clone()),
        },
    )
    .await
    .map_err(unavailable)?;
    tx.commit().await.map_err(unavailable)?;
    Ok((out, rows))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    pub(crate) fn pair(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
    }
    pub(crate) const TENANT: Uuid = Uuid::from_u128(1);
    pub(crate) const SERVER: Uuid = Uuid::from_u128(2);
    pub(crate) const EXECUTION: Uuid = Uuid::from_u128(3);
    pub(crate) fn binding() -> Binding {
        Binding {
            execution_id: EXECUTION,
            action_id: Uuid::from_u128(4),
            request_digest: "e".repeat(64),
            tenant_id: TENANT,
            server_id: SERVER,
        }
    }
    pub(crate) fn key(pair: &Ed25519KeyPair, attestation: &str) -> ReceiptKey {
        ReceiptKey {
            binding: binding(),
            public: pair.public_key().as_ref().to_vec(),
            expected: Expected {
                receipt_key_id: receipt::key_id(pair.public_key().as_ref()),
                attestation_digest: sha(attestation.as_bytes()),
            },
        }
    }
    /// What a tool server does: sign the statement for the attestation header it received.
    pub(crate) fn tool_sign(pair: &Ed25519KeyPair, attestation: &str, id: Uuid) -> String {
        tool_sign_for(pair, attestation, &binding(), id)
    }
    pub(crate) fn tool_sign_for(
        pair: &Ed25519KeyPair,
        attestation: &str,
        binding: &Binding,
        id: Uuid,
    ) -> String {
        let statement = receipt::statement(&key(pair, attestation).expected, binding, id).unwrap();
        hex::encode(pair.sign(statement.as_bytes()))
    }
    /// What a real tool server does: read tenant and execution from the attestation it received
    /// (its own server id is pinned), then sign the bound statement.
    pub(crate) fn tool_sign_header(
        pair: &Ed25519KeyPair,
        header: &str,
        server: Uuid,
        id: Uuid,
    ) -> String {
        tool_sign_for(pair, header, &header_binding(header, server), id)
    }
    /// The binding a tool derives from the attestation it received (and its own server id).
    pub(crate) fn header_binding(header: &str, server: Uuid) -> Binding {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let body = URL_SAFE_NO_PAD
            .decode(header.split('.').next().unwrap())
            .unwrap();
        let a: Value = serde_json::from_slice(&body).unwrap();
        let uuid = |k: &str| a[k].as_str().unwrap().parse::<Uuid>().unwrap();
        Binding {
            execution_id: uuid("execution_id"),
            action_id: uuid("action_id"),
            request_digest: a["request_digest"].as_str().unwrap().to_owned(),
            tenant_id: uuid("tenant_id"),
            server_id: server,
        }
    }
    #[test]
    fn accepts_valid_countersignature() {
        let (p, id) = (pair(7), Uuid::new_v4());
        let c = countersigned(Some(&key(&p, "a.b")), id, Some(&tool_sign(&p, "a.b", id)))
            .unwrap()
            .unwrap();
        assert_eq!(c.tool_receipt, id);
        receipt::verify(
            p.public_key().as_ref(),
            &key(&p, "a.b").expected,
            &binding(),
            &c,
        )
        .unwrap();
    }
    #[test]
    fn no_registered_key_ignores_signature() {
        let id = Uuid::new_v4();
        assert_eq!(countersigned(None, id, None).unwrap(), None);
        assert_eq!(countersigned(None, id, Some("not-hex")).unwrap(), None);
    }
    #[test]
    fn rejects_missing_signature_when_key_registered() {
        assert!(countersigned(Some(&key(&pair(7), "a.b")), Uuid::new_v4(), None).is_err());
    }
    #[test]
    fn rejects_signature_over_other_attestation() {
        // Replay: a receipt the tool signed for another call's attestation.
        let (p, id) = (pair(7), Uuid::new_v4());
        let replayed = tool_sign(&p, "other.call", id);
        assert!(countersigned(Some(&key(&p, "a.b")), id, Some(&replayed)).is_err());
        let other_receipt = tool_sign(&p, "a.b", Uuid::new_v4());
        assert!(countersigned(Some(&key(&p, "a.b")), id, Some(&other_receipt)).is_err());
    }
    #[test]
    fn rejects_signature_bound_to_other_execution_tenant_or_server() {
        // Replay: one genuine signature for (digest, receipt) pasted onto another call.
        let (p, id) = (pair(7), Uuid::new_v4());
        let k = key(&p, "a.b");
        for other in [
            Binding {
                execution_id: Uuid::from_u128(9),
                ..binding()
            },
            Binding {
                tenant_id: Uuid::from_u128(9),
                ..binding()
            },
            Binding {
                server_id: Uuid::from_u128(9),
                ..binding()
            },
            Binding {
                action_id: Uuid::from_u128(9),
                ..binding()
            },
            Binding {
                request_digest: "f".repeat(64),
                ..binding()
            },
        ] {
            let replayed = tool_sign_for(&p, "a.b", &other, id);
            assert!(countersigned(Some(&k), id, Some(&replayed)).is_err());
        }
    }
    #[test]
    fn rejects_uppercase_signature() {
        let (p, id) = (pair(7), Uuid::new_v4());
        let upper = tool_sign(&p, "a.b", id).to_uppercase();
        assert!(countersigned(Some(&key(&p, "a.b")), id, Some(&upper)).is_err());
    }
    #[test]
    fn rejects_signature_from_other_key() {
        let id = Uuid::new_v4();
        let forged = tool_sign(&pair(8), "a.b", id);
        let k = key(&pair(7), "a.b");
        assert!(countersigned(Some(&k), id, Some(&forged)).is_err());
        assert!(countersigned(Some(&k), id, Some("zz")).is_err());
    }
    #[test]
    fn rejects_gateway_attestation_key_at_registration() {
        // Key substitution: the gateway cannot countersign for the tool server.
        let signer = crate::action_control::execution_tests::signer();
        let own: [u8; 32] = signer.public_key().try_into().unwrap();
        assert_eq!(refuse_gateway_key(Some(&signer), &own), Err(INVALID));
        assert_eq!(refuse_gateway_key(Some(&signer), &[7; 32]), Ok(()));
        assert_eq!(refuse_gateway_key(None, &own), Ok(()));
    }
    #[test]
    fn rejects_invalid_public_key() {
        let good = format!(r#"{{"public_key":"{}"}}"#, "ab".repeat(32));
        assert_eq!(parse(good.as_bytes()), Ok([0xab; 32]));
        for bad in [
            format!(r#"{{"public_key":"{}"}}"#, "ab".repeat(31)),
            format!(r#"{{"public_key":"{}"}}"#, "AB".repeat(32)),
            format!(r#"{{"public_key":"{}","x":1}}"#, "ab".repeat(32)),
            format!(
                r#"{{"public_key":"{0}","public_key":"{0}"}}"#,
                "ab".repeat(32)
            ),
            r#"{"public_key":7}"#.to_owned(),
            format!(r#"{{"public_key":"01{}"}}"#, "00".repeat(31)),
            // Sign-bit variants of small-order points (ring decodes them).
            format!(r#"{{"public_key":"01{}80"}}"#, "00".repeat(30)),
            format!(r#"{{"public_key":"ec{}"}}"#, "ff".repeat(31)),
            "[]".to_owned(),
        ] {
            assert_eq!(parse(bad.as_bytes()), Err(INVALID), "{bad}");
        }
    }
}
