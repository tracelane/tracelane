//! ACT-17 against real Postgres: registration, countersigned execution, export and verify.
use super::*;
use crate::action_control::receipt_keys::{
    self,
    tests::{pair, tool_sign_for, tool_sign_header},
};
use ring::signature::KeyPair;
use tracelane_audit_verifier::action::bundle;

async fn register(
    f: &Fixture,
    server: Uuid,
    seed: u8,
    resolved: crate::entitlement_cache::ResolvedEntitlements,
) -> std::result::Result<Value, receipt_keys::Refusal> {
    let public: [u8; 32] = pair(seed).public_key().as_ref().try_into().unwrap();
    let actor = crate::control_plane::ControlActor::for_test(f.publisher.tenant_id.clone());
    let timeout = std::time::Duration::from_secs(30);
    receipt_keys::commit(
        &f.pool,
        &f.publisher,
        &actor,
        &resolved,
        timeout,
        server,
        &public,
    )
    .await
    .map(|(out, _)| out)
}
/// Approve and run one protected call. `tool` is what the synthetic tool server answers,
/// given the attestation header it received and the receipt id it minted.
async fn run(f: &Fixture, tool: impl FnOnce(&str, Uuid) -> Outcome) -> Receipt {
    let id = f.pending().await;
    assert_eq!(f.decide(&f.human, id, true).await, None);
    let call = f.call(Uuid::new_v4(), Some(id));
    execute(
        &f.pool,
        &f.agent,
        Some(&grants()),
        &call,
        &f.signer,
        None,
        |h| async move { tool(&h, Uuid::new_v4()) },
    )
    .await
    .unwrap()
    .unwrap()
}
async fn count(f: &Fixture, sql: &str) -> i64 {
    let db = f.pool.get().await.unwrap();
    db.query_one(sql, &[f.agent.tenant_id.as_uuid()])
        .await
        .unwrap()
        .get(0)
}
const LEDGER: &str = "SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1 AND event_type=";
/// The rejected call left durable Unknown state and no success row; the bundle still verifies.
async fn assert_unknown(f: &Fixture, r: &Receipt) {
    assert_eq!((r.state, r.tool_receipt), (State::Unknown, None), "{r:?}");
    assert_eq!(r.countersignature, None);
    let states = "SELECT count(*) FROM action_executions WHERE tenant_id=$1 AND state='unknown'";
    assert_eq!(count(f, states).await, 1);
    assert_eq!(count(f, &format!("{LEDGER}'execution_succeeded'")).await, 0);
    assert_eq!(count(f, &format!("{LEDGER}'execution_unknown'")).await, 1);
    let (zip, pin) = export_pg_tests::exported(f).await;
    let report = bundle::verify(&zip, Some(pin)).unwrap();
    assert_eq!(report.actions.unknown, [r.execution_id]);
    assert_eq!(report.actions.countersigned, 0);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_countersigned_execution_exports_and_verifies() {
    let f = Fixture::new().await;
    let server = f.server;
    register(&f, f.server, 7, grants()).await.unwrap();
    let r = run(&f, |h, id| {
        Outcome::Countersigned(id, tool_sign_header(&pair(7), h, server, id))
    })
    .await;
    assert_eq!(r.state, State::Succeeded, "{r:?}");
    assert!(r.countersignature.is_some(), "{r:?}");
    let (zip, pin) = export_pg_tests::exported(&f).await;
    let report = bundle::verify(&zip, Some(pin)).unwrap();
    let counts = (report.actions.countersigned, report.actions.uncountersigned);
    assert_eq!(counts, (1, 0));
    assert!(report.actions.unknown.is_empty());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_unregistered_server_keeps_uncountersigned_success() {
    let f = Fixture::new().await;
    // No key registered: a signature the tool volunteers is ignored, not recorded.
    let r = run(&f, |_, id| Outcome::Countersigned(id, "junk".into())).await;
    assert_eq!((r.state, &r.countersignature), (State::Succeeded, &None));
    let extended = "SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1 AND (payload LIKE '%receipt_expected%' OR payload LIKE '%countersignature%')";
    assert_eq!(count(&f, extended).await, 0, "ledger shape changed");
    let (zip, pin) = export_pg_tests::exported(&f).await;
    let report = bundle::verify(&zip, Some(pin)).unwrap();
    let counts = (report.actions.countersigned, report.actions.uncountersigned);
    assert_eq!(counts, (0, 1));
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_registration_writes_ledger_and_control_audit() {
    let f = Fixture::new().await;
    let first = register(&f, f.server, 7, grants()).await.unwrap();
    let second = register(&f, f.server, 8, grants()).await.unwrap();
    let key_id = receipt_keys::receipt::key_id(pair(8).public_key().as_ref());
    assert_eq!(second["receipt_key_id"], key_id);
    let db = f.pool.get().await.unwrap();
    let t = f.agent.tenant_id.as_uuid();
    let rows = db
        .query(
            "SELECT receipt_key_id,public_key FROM action_tool_receipt_keys WHERE tenant_id=$1",
            &[t],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "rotation must replace, not add");
    assert_eq!(rows[0].get::<_, String>(0), key_id);
    assert_eq!(rows[0].get::<_, Vec<u8>>(1), pair(8).public_key().as_ref());
    let ledger = format!("{LEDGER}'tool_receipt_key_registered' AND actor='human'");
    assert_eq!(count(&f, &ledger).await, 2);
    let audit = db.query("SELECT before_json,after_json FROM admin_audit_log WHERE actor_workspace_id=$1 AND action='mcp_server.receipt_key.set' ORDER BY id", &[t]).await.unwrap();
    assert_eq!(audit.len(), 2);
    assert_eq!(
        audit[1].get::<_, Option<Value>>(0).unwrap()["receipt_key_id"],
        first["receipt_key_id"]
    );
    assert_eq!(audit[1].get::<_, Option<Value>>(1).unwrap(), second);
    // Migration 0100: a registration row is append-only like every other action row.
    let deleted = db
        .execute(
            "DELETE FROM audit_log_rows WHERE tenant_id=$1 AND event_type='tool_receipt_key_registered'",
            &[t],
        )
        .await;
    assert!(deleted.is_err(), "registration rows must be append-only");
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_bad_countersignature_records_unknown() {
    let f = Fixture::new().await;
    let server = f.server;
    register(&f, f.server, 7, grants()).await.unwrap();
    // Signed by a key that is not the registered one.
    let before = tracelane_shared::degradation::count(
        tracelane_shared::degradation::Degradation::CountersignatureRejected,
    );
    let r = run(&f, |h, id| {
        Outcome::Countersigned(id, tool_sign_header(&pair(8), h, server, id))
    })
    .await;
    assert_unknown(&f, &r).await;
    let after = tracelane_shared::degradation::count(
        tracelane_shared::degradation::Degradation::CountersignatureRejected,
    );
    assert!(
        after > before,
        "rejected countersignature must move the counter"
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_signature_bound_to_other_execution_records_unknown() {
    let f = Fixture::new().await;
    register(&f, f.server, 7, grants()).await.unwrap();
    // A genuine tool signature for the same receipt id, minted for a different execution.
    let server = f.server;
    let r = run(&f, |h, id| {
        let b = receipt_keys::Binding {
            execution_id: Uuid::new_v4(),
            ..receipt_keys::tests::header_binding(h, server)
        };
        Outcome::Countersigned(id, tool_sign_for(&pair(7), h, &b, id))
    })
    .await;
    assert_unknown(&f, &r).await;
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_missing_countersignature_records_unknown() {
    let f = Fixture::new().await;
    register(&f, f.server, 7, grants()).await.unwrap();
    let r = run(&f, |_, id| Outcome::Succeeded(id)).await;
    assert_unknown(&f, &r).await;
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_refuses_foreign_server() {
    let f = Fixture::new().await;
    let other = f.other().await;
    // `other`'s admin names this tenant's server: the tenant comes from the claims, so 404.
    assert_eq!(
        register(&other, f.server, 7, grants()).await,
        Err((404, "mcp_server_not_found"))
    );
    let keys = "SELECT count(*) FROM action_tool_receipt_keys WHERE $1::uuid IS NOT NULL";
    assert_eq!(count(&f, keys).await, 0);
    let ledger = format!("{LEDGER}'tool_receipt_key_registered'");
    assert_eq!(count(&other, &ledger).await, 0);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_refused_when_disabled() {
    let f = Fixture::new().await;
    let off = crate::entitlement_cache::ResolvedEntitlements::deny_all();
    assert_eq!(
        register(&f, f.server, 7, off).await,
        Err((409, "action_control_disabled"))
    );
    let keys = "SELECT count(*) FROM action_tool_receipt_keys WHERE tenant_id=$1";
    assert_eq!(count(&f, keys).await, 0);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_start_refused_when_receipt_key_is_the_attestation_key() {
    let f = Fixture::new().await;
    // Registered while the signer was another key; the signer then rotated to it.
    let own: [u8; 32] = f.signer.public_key().try_into().unwrap();
    let actor = crate::control_plane::ControlActor::for_test(f.publisher.tenant_id.clone());
    let t = std::time::Duration::from_secs(30);
    receipt_keys::commit(&f.pool, &f.publisher, &actor, &grants(), t, f.server, &own)
        .await
        .unwrap();
    let id = f.pending().await;
    assert_eq!(f.decide(&f.human, id, true).await, None);
    let call = f.call(Uuid::new_v4(), Some(id));
    let sent = std::sync::atomic::AtomicBool::new(false);
    let out = execute(
        &f.pool,
        &f.agent,
        Some(&grants()),
        &call,
        &f.signer,
        None,
        |_| {
            sent.store(true, std::sync::atomic::Ordering::SeqCst);
            async { Outcome::Succeeded(Uuid::new_v4()) }
        },
    )
    .await;
    assert!(
        out.is_err(),
        "start must fail closed: {:?}",
        out.map(|r| r.is_some())
    );
    assert!(
        !sent.load(std::sync::atomic::Ordering::SeqCst),
        "nothing may be sent"
    );
    assert_eq!(count(&f, &format!("{LEDGER}'execution_started'")).await, 0);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_signature_over_other_request_digest_records_unknown() {
    let f = Fixture::new().await;
    register(&f, f.server, 7, grants()).await.unwrap();
    let server = f.server;
    let r = run(&f, |h, id| {
        let b = receipt_keys::Binding {
            request_digest: "f".repeat(64),
            ..receipt_keys::tests::header_binding(h, server)
        };
        Outcome::Countersigned(id, tool_sign_for(&pair(7), h, &b, id))
    })
    .await;
    assert_unknown(&f, &r).await;
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_registration_row_carries_no_agent_key() {
    let f = Fixture::new().await;
    // An API-key caller (the agent): the row must still name no agent key.
    let actor = crate::control_plane::ControlActor::for_test(f.agent.tenant_id.clone());
    let public: [u8; 32] = pair(7).public_key().as_ref().try_into().unwrap();
    let t = std::time::Duration::from_secs(30);
    receipt_keys::commit(&f.pool, &f.agent, &actor, &grants(), t, f.server, &public)
        .await
        .unwrap();
    let sql =
        format!("{LEDGER}'tool_receipt_key_registered' AND payload LIKE '%\"agent_key_id\":null%'");
    assert_eq!(count(&f, &sql).await, 1);
}
