//! ACT-10a acceptance: real protected flows, then the routes. Child of `approval_pg_tests` so it
//! reuses that `Fixture` (real contract, policy, agent key, human) without widening its API.
use super::*;
use axum::http::StatusCode;
use tower::ServiceExt;

const RAW_BENEFICIARY: &str = "synthetic-private-account-1234";
const RAW_MEMO: &str = "never retain this raw memo";
static HTTP: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn args(amount: u64) -> String {
    json!({"amount_minor":amount,"currency":"USD","beneficiary":RAW_BENEFICIARY,"memo":RAW_MEMO})
        .to_string()
}
/// Contract v2 adds a tokenized beneficiary and a digest-only memo; policy v2 maps amounts to
/// allow (<= 500000), require_approval (<= 5000000) and deny (above).
async fn timeline_fixture() -> Fixture {
    crate::mcp_security_tests::init_master_for_security_tests();
    let mut f = Fixture::new().await;
    let mut c: Value = serde_json::from_str(&f.contract).unwrap();
    c["version"] = json!(2);
    c["fields"]["beneficiary"] =
        json!({"path":"/beneficiary","kind":"string","required":true,"evidence":"tokenize"});
    c["fields"]["memo"] =
        json!({"path":"/memo","kind":"string","required":true,"evidence":"digest_only"});
    let mut p: Value = serde_json::from_str(&f.policy).unwrap();
    p["version"] = json!(2);
    p["rules"] = json!([
        {"id":"huge","when":[{"field":"amount","op":"gt","value":5000000}],"decision":"deny"},
        {"id":"review","when":[{"field":"amount","op":"gt","value":500000}],"decision":"require_approval"},
        {"id":"small","when":[],"decision":"allow"}]);
    activate(&f, &c, &p).await;
    f.contract = c.to_string();
    f.policy = p.to_string();
    f
}
async fn activate(f: &Fixture, c: &Value, p: &Value) {
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    policy_store::activate_tx(
        &tx,
        &f.publisher,
        Some(&grants()),
        &c.to_string(),
        &p.to_string(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}
async fn call_with(f: &Fixture, amount: u64, approval: Option<Uuid>) -> Result<Option<Receipt>> {
    let a = args(amount);
    let mut c = f.call(Uuid::new_v4(), approval);
    c.args = &a;
    execute(
        &f.pool,
        &f.agent,
        Some(&grants()),
        &c,
        &f.signer,
        None,
        |_| async { Outcome::Succeeded(Uuid::new_v4()) },
    )
    .await
}
async fn last_action(f: &Fixture) -> Uuid {
    let id: String = f.pool.get().await.unwrap().query_one("SELECT payload::jsonb->>'action_id' FROM audit_log_rows WHERE tenant_id=$1 AND event_type='action_proposed' ORDER BY seq DESC LIMIT 1", &[f.agent.tenant_id.as_uuid()]).await.unwrap().get(0);
    id.parse().unwrap()
}
/// allow -> executed
async fn allowed(f: &Fixture) -> Uuid {
    call_with(f, 100_000, None).await.unwrap().unwrap();
    last_action(f).await
}
/// require_approval, still pending: (approval id, action id)
async fn pending(f: &Fixture) -> (Uuid, Uuid) {
    let err = call_with(f, 1_500_000, None).await.unwrap_err();
    (
        err.downcast_ref::<ApprovalRequired>().unwrap().id,
        last_action(f).await,
    )
}
async fn blocked(f: &Fixture) -> Uuid {
    call_with(f, 9_000_000, None).await.unwrap_err();
    last_action(f).await
}
/// require_approval -> approve -> consume -> executed
async fn approved_and_executed(f: &Fixture) -> (Uuid, Uuid) {
    let (approval, action) = pending(f).await;
    assert_eq!(f.decide(&f.human, approval, true).await, None);
    call_with(f, 1_500_000, Some(approval))
        .await
        .unwrap()
        .unwrap();
    (approval, action)
}
async fn ledger_rows(f: &Fixture) -> i64 {
    f.pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1",
            &[f.agent.tenant_id.as_uuid()],
        )
        .await
        .unwrap()
        .get(0)
}

async fn http_raw(
    f: &Fixture,
    who: &crate::auth::Claims,
    resolved: crate::entitlement_cache::ResolvedEntitlements,
    method: &str,
    uri: &str,
    body: Value,
) -> (StatusCode, String) {
    let _lock = HTTP.lock().await;
    let jwks = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(json!({"keys":[protected::session_tests::jwk()]})),
        )
        .mount(&jwks)
        .await;
    let _env = SessionEnv::new(&jwks.uri());
    let token = protected::session_tests::signed_jwt(who, Some("synthetic-verified-session"));
    let _auth = crate::auth::test_claims::Guard::set(who.clone());
    let _access =
        crate::control_plane::test_overrides::Guard::new(Some(Ok(Default::default())), None, None);
    let response = crate::mcp_routes::router(f.http_state(resolved))
        .oneshot(
            axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", format!("Bearer {token}"))
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 << 20)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}
async fn get_as(f: &Fixture, who: &crate::auth::Claims, uri: &str) -> (StatusCode, Value) {
    let (s, t) = http_raw(f, who, grants(), "GET", uri, json!({})).await;
    (s, serde_json::from_str(&t).unwrap_or(Value::Null))
}
async fn get(f: &Fixture, uri: &str) -> (StatusCode, Value) {
    get_as(f, &f.human, uri).await
}
async fn detail(f: &Fixture, action: Uuid) -> Value {
    let (s, b) = get(f, &format!("/v1/actions/{action}")).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    b
}
fn ids(list: &Value) -> Vec<String> {
    list["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["action_id"].as_str().unwrap().to_owned())
        .collect()
}
fn event_types(d: &Value) -> Vec<String> {
    d["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["event_type"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_list_actions_newest_first() {
    let f = timeline_fixture().await;
    let a = allowed(&f).await;
    let (_, p) = pending(&f).await;
    let b = blocked(&f).await;
    let (s, list) = get(&f, "/v1/actions").await;
    assert_eq!(s, StatusCode::OK, "{list}");
    assert_eq!(
        ids(&list),
        vec![b.to_string(), p.to_string(), a.to_string()]
    );
    let states: Vec<_> = list["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["state"].as_str().unwrap())
        .collect();
    assert_eq!(states, ["blocked", "awaiting_approval", "executed"]);
    assert_eq!(list["actions"][0]["tool_name"], "pay");
    assert!(list.get("next_before").is_none());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_list_actions_keyset_pages() {
    let f = timeline_fixture().await;
    let mut all = Vec::new();
    for _ in 0..5 {
        all.push(allowed(&f).await.to_string());
    }
    all.reverse();
    let mut seen = Vec::new();
    let mut uri = "/v1/actions?limit=2".to_owned();
    let mut pages = 0;
    loop {
        let (s, page) = get(&f, &uri).await;
        assert_eq!(s, StatusCode::OK, "{page}");
        pages += 1;
        seen.extend(ids(&page));
        match page.get("next_before") {
            Some(n) => uri = format!("/v1/actions?limit=2&before={n}"),
            None => break,
        }
        assert!(pages < 10, "cursor never terminated");
    }
    assert_eq!(pages, 3);
    assert_eq!(
        seen, all,
        "pages must cover every action once, newest first"
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_allowed_action_state_executed() {
    let f = timeline_fixture().await;
    let a = allowed(&f).await;
    let d = detail(&f, a).await;
    assert_eq!(d["state"], "executed");
    assert!(
        d.get("approval").is_none(),
        "an allowed call has no approval descriptor"
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_action_states_progress() {
    let f = timeline_fixture().await;
    let (approval, action) = pending(&f).await;
    assert_eq!(detail(&f, action).await["state"], "awaiting_approval");
    assert_eq!(f.decide(&f.human, approval, true).await, None);
    assert_eq!(detail(&f, action).await["state"], "approved");
    call_with(&f, 1_500_000, Some(approval))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(detail(&f, action).await["state"], "executed");
    let (_, list) = get(&f, "/v1/actions").await;
    assert_eq!(list["actions"][0]["state"], "executed");
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_denied_action_state_blocked() {
    let f = timeline_fixture().await;
    let b = blocked(&f).await;
    let d = detail(&f, b).await;
    assert_eq!(d["state"], "blocked");
    assert_eq!(
        event_types(&d),
        ["action_proposed", "decision_made", "denied_runtime"]
    );
    let decision = &d["events"][1]["body"];
    assert_eq!(decision["decision"], "deny");
    assert_eq!(decision["rule_id"], "huge");
    assert_eq!(decision["reason_codes"], json!(["policy_denied"]));
    // A human deny of a pending approval is a different state.
    let (approval, action) = pending(&f).await;
    assert_eq!(f.decide(&f.human, approval, false).await, None);
    assert_eq!(detail(&f, action).await["state"], "denied");
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_invalidated_action_state() {
    let f = timeline_fixture().await;
    let (_, action) = pending(&f).await;
    let c: Value = serde_json::from_str(&f.contract).unwrap();
    let mut p: Value = serde_json::from_str(&f.policy).unwrap();
    p["version"] = json!(3);
    activate(&f, &c, &p).await;
    let d = detail(&f, action).await;
    assert_eq!(d["state"], "invalidated");
    assert_eq!(
        d["events"].as_array().unwrap().last().unwrap()["event_type"],
        "approval_invalidated"
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_action_detail_events_in_seq_order() {
    let f = timeline_fixture().await;
    let (_, action) = approved_and_executed(&f).await;
    let d = detail(&f, action).await;
    assert_eq!(
        event_types(&d),
        [
            "action_proposed",
            "decision_made",
            "denied_runtime",
            "approval_requested",
            "approval_granted",
            "approval_consumed",
            "execution_started",
            "execution_succeeded"
        ]
    );
    let seqs: Vec<i64> = d["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["seq"].as_i64().unwrap())
        .collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]), "{seqs:?}");
    // Every body is the stored typed payload body, unchanged.
    let db = f.pool.get().await.unwrap();
    for e in d["events"].as_array().unwrap() {
        let stored: String = db
            .query_one(
                "SELECT payload FROM audit_log_rows WHERE tenant_id=$1 AND seq=$2",
                &[f.agent.tenant_id.as_uuid(), &e["seq"].as_i64().unwrap()],
            )
            .await
            .unwrap()
            .get(0);
        let stored: Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(e["body"], stored["body"], "body must round-trip unchanged");
        assert_eq!(e["occurred_at"], stored["occurred_at"]);
    }
    assert_eq!(d["events"][0]["actor_kind"], "agent_key");
    assert_eq!(d["events"][4]["actor_kind"], "human");
    assert_eq!(
        d["events"][4]["body"]["decider_digest"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        d["events"][7]["body"]["receipt_digest"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_action_detail_descriptor_matches_row() {
    let f = timeline_fixture().await;
    let (approval, action) = pending(&f).await;
    let d = detail(&f, action).await;
    let a = &d["approval"];
    let row: Value = f
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT to_jsonb(a) FROM approvals a WHERE tenant_id=$1 AND id=$2",
            &[f.agent.tenant_id.as_uuid(), &approval],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(a["approval_id"], approval.to_string());
    for (field, column) in [
        ("status", "status"),
        ("tool_name", "subject"),
        ("server_id", "server_id"),
        ("tool_ref", "tool_ref"),
        ("contract_version", "contract_version"),
        ("policy_id", "policy_id"),
        ("policy_version", "policy_version"),
        ("policy_hash", "policy_hash"),
        ("proposer_key_id", "proposer_key_id"),
        ("request_digest", "request_digest"),
    ] {
        assert_eq!(a[field], row[column], "descriptor {field}");
    }
    // Evidence is the stored, signed EvidenceField form: byte-equal to the ledger proposal.
    let preview: Value = serde_json::from_str(row["args_preview"].as_str().unwrap()).unwrap();
    assert_eq!(a["evidence_fields"], preview["evidence_fields"]);
    let proposed = &detail(&f, action).await["events"][0]["body"];
    assert_eq!(a["evidence_fields"], proposed["evidence_fields"]);
    assert_eq!(
        a["evidence_fields"]["amount"],
        json!({"mode":"clear","value":{"MinorUnits":1500000}})
    );
    assert_eq!(
        a["evidence_fields"]["currency"],
        json!({"mode":"clear","value":{"Currency":"USD"}})
    );
    assert_eq!(a["evidence_fields"]["beneficiary"]["mode"], "tokenize");
    assert_eq!(a["evidence_fields"]["beneficiary"]["last4"], "1234");
    assert_eq!(a["evidence_fields"]["memo"]["mode"], "digest_only");
    assert!(a["evidence_fields"]["memo"].get("value").is_none());
    // The list carries the same evidence for the same action.
    let (_, list) = get(&f, "/v1/actions").await;
    assert_eq!(list["actions"][0]["evidence"], a["evidence_fields"]);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_descriptor_digest_is_jcs_sha256() {
    let f = timeline_fixture().await;
    let (_, action) = pending(&f).await;
    let d = detail(&f, action).await;
    let jcs = tracelane_audit_verifier::action::canonical_json(&d["approval"].to_string()).unwrap();
    let expect = hex::encode(ring::digest::digest(&ring::digest::SHA256, jcs.as_bytes()).as_ref());
    assert_eq!(d["descriptor_digest"], expect);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approve_with_matching_descriptor_digest() {
    let f = timeline_fixture().await;
    let (approval, action) = pending(&f).await;
    let digest = detail(&f, action).await["descriptor_digest"].clone();
    let (s, t) = http_raw(
        &f,
        &f.human,
        grants(),
        "POST",
        &format!("/v1/approvals/{approval}/approve"),
        json!({"descriptor_digest":digest}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{t}");
    assert_eq!(f.status(approval).await, "approved");
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_detail_uses_action_index() {
    let f = timeline_fixture().await;
    let (_, action) = approved_and_executed(&f).await;
    let mut db = f.pool.get().await.unwrap();
    db.batch_execute("ANALYZE audit_log_rows").await.unwrap();
    let tx = db.transaction().await.unwrap();
    // Tiny test tables prefer a seq scan whatever the indexes; this asks whether the planner CAN use ours.
    tx.batch_execute("SET LOCAL enable_seqscan=off")
        .await
        .unwrap();
    let plan: Vec<String> = tx
        .query(
            &["EXPLAIN ", timeline::DETAIL_SQL].concat(),
            &[f.agent.tenant_id.as_uuid(), &action.to_string(), &200_i64],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert!(
        plan.iter().any(|l| l.contains("audit_action_id")),
        "{plan:#?}"
    );
}
#[test]
fn action_state_maps_every_terminal_event() {
    use ActionPayload::*;
    let (e, a) = (Uuid::nil(), Uuid::nil());
    let d = || "0".repeat(64);
    let cases: Vec<(ActionPayload, &str)> = vec![
        (
            ExecutionSucceeded {
                execution_id: e,
                receipt_digest: d(),
                countersignature: None,
            },
            "executed",
        ),
        (
            ExecutionFailed {
                execution_id: e,
                receipt_digest: d(),
            },
            "failed",
        ),
        (
            ExecutionUnknown {
                execution_id: e,
                receipt_digest: None,
            },
            "needs_review",
        ),
        (
            ExecutionStarted {
                execution_id: e,
                idempotency_key: e,
                attestation_key_id: "k".into(),
                receipt_expected: None,
            },
            "approved",
        ),
        (
            ApprovalGranted {
                approval_id: a,
                decider_digest: d(),
                note_digest: d(),
                channel: None,
                link_digest: None,
            },
            "approved",
        ),
        (ApprovalConsumed { approval_id: a }, "approved"),
        (
            ApprovalDenied {
                approval_id: a,
                decider_digest: d(),
                note_digest: d(),
                channel: None,
                link_digest: None,
            },
            "denied",
        ),
        (ApprovalExpired { approval_id: a }, "expired"),
        (ApprovalInvalidated { approval_id: a }, "invalidated"),
        (
            ApprovalRequested {
                approval_id: a,
                required_role: "admin".into(),
                expires_at: chrono::Utc::now(),
            },
            "awaiting_approval",
        ),
        (
            DeniedRuntime {
                reason: ReasonCode::PolicyDenied,
            },
            "blocked",
        ),
        (
            DeniedRuntime {
                reason: ReasonCode::WorkspacePaused,
            },
            "refused_paused",
        ),
        (
            DeniedRuntime {
                reason: ReasonCode::ApprovalRequired,
            },
            "awaiting_approval",
        ),
    ];
    for (body, state) in &cases {
        assert_eq!(timeline::action_state(std::iter::once(body)), *state);
    }
    // A rejected attempt after a grant changes nothing; a bare proposal is never "executed".
    let granted = ApprovalGranted {
        approval_id: a,
        decider_digest: d(),
        note_digest: d(),
        channel: None,
        link_digest: None,
    };
    let rejected = ApprovalAttemptRejected {
        approval_id: a,
        decider_digest: d(),
        reason: ReasonCode::Unauthorized,
        channel: None,
        link_digest: None,
    };
    assert_eq!(
        timeline::action_state([&granted, &rejected].into_iter()),
        "approved"
    );
    assert_eq!(timeline::action_state(std::iter::empty()), "needs_review");
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_action_detail_cross_tenant_not_found() {
    let f = timeline_fixture().await;
    let other = f.other().await;
    let a = allowed(&f).await;
    assert_eq!(
        get(&f, &format!("/v1/actions/{a}")).await.0,
        StatusCode::OK,
        "positive control"
    );
    let (s, b) = get_as(&f, &other.human, &format!("/v1/actions/{a}")).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{b}");
    assert_eq!(b["error"], "action_not_found");
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_list_actions_tenant_isolated() {
    let f = timeline_fixture().await;
    let other = f.other().await;
    let mine = [
        allowed(&f).await.to_string(),
        pending(&f).await.1.to_string(),
    ];
    let theirs_action = pending(&other).await.1.to_string();
    let (_, list) = get(&f, "/v1/actions").await;
    let got = ids(&list);
    assert_eq!(got.len(), 2, "{list}");
    assert!(mine.iter().all(|m| got.contains(m)));
    assert!(!got.contains(&theirs_action));
    let (_, list) = get_as(&f, &other.human, "/v1/actions").await;
    assert_eq!(ids(&list), vec![theirs_action]);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_action_detail_unknown_not_found() {
    let f = timeline_fixture().await;
    allowed(&f).await;
    for id in [Uuid::new_v4().to_string(), "not-a-uuid".to_owned()] {
        let (s, b) = get(&f, &format!("/v1/actions/{id}")).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{id}: {b}");
        assert_eq!(b["error"], "action_not_found");
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_responses_never_contain_raw_arguments() {
    let f = timeline_fixture().await;
    let (approval, action) = approved_and_executed(&f).await;
    let (_, list) = http_raw(&f, &f.human, grants(), "GET", "/v1/actions", json!({})).await;
    let (_, one) = http_raw(
        &f,
        &f.human,
        grants(),
        "GET",
        &format!("/v1/actions/{action}"),
        json!({}),
    )
    .await;
    let (_, queue) = http_raw(
        &f,
        &f.human,
        grants(),
        "GET",
        &format!("/v1/approvals/{approval}"),
        json!({}),
    )
    .await;
    for wire in [&list, &one] {
        assert!(
            wire.contains("\"last4\":\"1234\""),
            "positive control: minimized evidence present"
        );
        assert!(
            !wire.contains(RAW_BENEFICIARY) && !wire.contains(RAW_MEMO),
            "raw argument leaked: {wire}"
        );
    }
    assert!(!queue.contains(RAW_MEMO));
}
async fn mismatch_is_refused(verb: &str, approve: bool) {
    let f = timeline_fixture().await;
    let (approval, action) = pending(&f).await;
    let before = ledger_rows(&f).await;
    let (s, t) = http_raw(
        &f,
        &f.human,
        grants(),
        "POST",
        &format!("/v1/approvals/{approval}/{verb}"),
        json!({"descriptor_digest":"0".repeat(64)}),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{t}");
    assert!(t.contains("descriptor_mismatch"), "{t}");
    assert_eq!(f.status(approval).await, "pending");
    // Only the rejected attempt is written; no decision event.
    assert_eq!(ledger_rows(&f).await, before + 1);
    let kinds = event_types(&detail(&f, action).await);
    assert_eq!(kinds.last().unwrap(), "approval_attempt_rejected");
    assert!(
        !kinds
            .iter()
            .any(|k| k == "approval_granted" || k == "approval_denied")
    );
    // Positive control: the same request with the true digest is accepted.
    let digest = detail(&f, action).await["descriptor_digest"].clone();
    let (s, t) = http_raw(
        &f,
        &f.human,
        grants(),
        "POST",
        &format!("/v1/approvals/{approval}/{verb}"),
        json!({"descriptor_digest":digest}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{t}");
    assert_eq!(
        f.status(approval).await,
        if approve { "approved" } else { "denied" }
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approve_with_mismatched_descriptor_digest_conflicts() {
    mismatch_is_refused("approve", true).await;
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_deny_with_mismatched_descriptor_digest_conflicts() {
    mismatch_is_refused("deny", false).await;
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_actions_flag_off_refused() {
    let f = timeline_fixture().await;
    let a = allowed(&f).await;
    for uri in ["/v1/actions".to_owned(), format!("/v1/actions/{a}")] {
        let off = crate::entitlement_cache::ResolvedEntitlements::deny_all();
        let (s, t) = http_raw(&f, &f.human, off, "GET", &uri, json!({})).await;
        assert_eq!(s, StatusCode::CONFLICT, "{uri}: {t}");
        assert!(t.contains("action_control_disabled"));
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_actions_require_approve_capability() {
    let f = timeline_fixture().await;
    let a = allowed(&f).await;
    let mut viewer = f.human.clone();
    viewer.role = Some(crate::auth::Role::Viewer);
    for uri in ["/v1/actions".to_owned(), format!("/v1/actions/{a}")] {
        assert_eq!(
            get(&f, &uri).await.0,
            StatusCode::OK,
            "positive control {uri}"
        );
        assert_eq!(
            get_as(&f, &viewer, &uri).await.0,
            StatusCode::FORBIDDEN,
            "viewer {uri}"
        );
        assert_eq!(
            get_as(&f, &f.agent, &uri).await.0,
            StatusCode::FORBIDDEN,
            "api key {uri}"
        );
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_list_actions_rejects_bad_cursor() {
    let f = timeline_fixture().await;
    allowed(&f).await;
    for q in [
        "before=abc",
        "before=-1",
        "before=99999999999999999999",
        "limit=abc",
        "limit=-3",
    ] {
        let (s, b) = get(&f, &format!("/v1/actions?{q}")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{q}: {b}");
    }
    assert_eq!(
        get(&f, "/v1/actions?before=1").await.1,
        json!({"actions":[]})
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_list_actions_clamps_limit() {
    let f = timeline_fixture().await;
    let max = crate::mcp_policy::settings()
        .unwrap()
        .approvals
        .max_list_page_size;
    let db = f.pool.get().await.unwrap();
    let tenant = f.agent.tenant_id.as_uuid();
    for i in 0..(max + 5) {
        let id = Uuid::new_v4();
        let payload = json!({"schema_version":1,"event_id":id,"action_id":id,"tenant_id":tenant,
            "agent_key_id":null,"occurred_at":"2026-11-09T00:00:00.000Z","request_digest":"a".repeat(64),
            "body":{"event_type":"action_proposed","tool_ref":Uuid::new_v4(),"contract_version":1,
                "args_digest":"b".repeat(64),"evidence_fields":{},"agent_claimed_labels":{}}}).to_string();
        db.execute("INSERT INTO audit_log_rows(tenant_id,seq,event_time,event_type,actor,payload,row_hash) VALUES($1,$2,now(),'action_proposed','synthetic',$3,'synthetic')",
            &[tenant, &(1_000_000 + i64::try_from(i).unwrap()), &payload]).await.unwrap();
    }
    let (s, list) = get(&f, "/v1/actions?limit=100000").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        list["actions"].as_array().unwrap().len(),
        max,
        "limit must clamp to the table cap"
    );
    assert!(list.get("next_before").is_some());
    let (_, one) = get(&f, "/v1/actions?limit=0").await;
    assert_eq!(one["actions"].as_array().unwrap().len(), 1);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_legacy_approvals_not_listed_as_actions() {
    let f = timeline_fixture().await;
    let legacy: Uuid = f.pool.get().await.unwrap().query_one("INSERT INTO approvals(tenant_id,subject_kind,subject,requester_sub,args_fp,args_bytes,expires_at) VALUES($1,'model','synthetic-model','synthetic-requester','synthetic-fp',1,now()+interval '1 hour') RETURNING id", &[f.agent.tenant_id.as_uuid()]).await.unwrap().get(0);
    let (s, list) = get(&f, "/v1/actions").await;
    assert_eq!((s, list), (StatusCode::OK, json!({"actions":[]})));
    assert_eq!(
        get(&f, &format!("/v1/actions/{legacy}")).await.0,
        StatusCode::NOT_FOUND
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_non_action_rows_not_listed() {
    let f = timeline_fixture().await;
    let id = Uuid::new_v4();
    // A chat-shaped ledger row that even carries an action_id must stay invisible.
    let payload = json!({"action_id":id,"model":"synthetic"}).to_string();
    f.pool.get().await.unwrap().execute("INSERT INTO audit_log_rows(tenant_id,seq,event_time,event_type,actor,payload,row_hash) VALUES($1,900000,now(),'chat.completion','synthetic',$2,'synthetic')", &[f.agent.tenant_id.as_uuid(), &payload]).await.unwrap();
    let real = allowed(&f).await;
    let (_, list) = get(&f, "/v1/actions").await;
    assert_eq!(ids(&list), vec![real.to_string()]);
    assert_eq!(
        get(&f, &format!("/v1/actions/{id}")).await.0,
        StatusCode::NOT_FOUND
    );
}

async fn insert_row(f: &Fixture, seq: i64, kind: &str, payload: &Value) {
    f.pool.get().await.unwrap().execute("INSERT INTO audit_log_rows(tenant_id,seq,event_time,event_type,actor,payload,row_hash) VALUES($1,$2,now(),$3,'synthetic',$4,'synthetic')",
        &[f.agent.tenant_id.as_uuid(), &seq, &kind, &payload.to_string()]).await.unwrap();
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_action_detail_after_retention_still_returns_events() {
    let f = timeline_fixture().await;
    let (approval, action) = pending(&f).await;
    let before = detail(&f, action).await;
    assert!(before["approval"].is_object(), "positive control");
    // What the retention sweep does to an old approval.
    f.pool
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE approvals SET args_preview=NULL WHERE tenant_id=$1 AND id=$2",
            &[f.agent.tenant_id.as_uuid(), &approval],
        )
        .await
        .unwrap();
    let d = detail(&f, action).await;
    // Minimal object only: no descriptor fields, no digest.
    let keys: Vec<_> = d["approval"].as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, ["approval_id", "expires_at", "status"]);
    assert_eq!(d["descriptor_digest"], Value::Null);
    assert_eq!(d["approval_expired"], true);
    assert_eq!(d["events"], before["events"]);
    assert_eq!(d["state"], "awaiting_approval");
    // No descriptor, no blind decision: with or without an echo, approve and deny are refused
    // 409 and each refusal is recorded.
    for (verb, body) in [
        (
            "approve",
            json!({"descriptor_digest":before["descriptor_digest"]}),
        ),
        ("deny", json!({})),
        ("approve", json!({})),
    ] {
        let rows = ledger_rows(&f).await;
        let (s, t) = http_raw(
            &f,
            &f.human,
            grants(),
            "POST",
            &format!("/v1/approvals/{approval}/{verb}"),
            body,
        )
        .await;
        assert_eq!(s, StatusCode::CONFLICT, "{t}");
        assert!(t.contains("descriptor_expired"), "{t}");
        assert_eq!(ledger_rows(&f).await, rows + 1);
        assert_eq!(f.status(approval).await, "pending");
    }
    let last = detail(&f, action).await["events"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(
        (&last["event_type"], &last["body"]["reason"]),
        (
            &json!("approval_attempt_rejected"),
            &json!("approval_expired")
        )
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_list_marks_action_with_malformed_terminal_event_needs_review() {
    let f = timeline_fixture().await;
    let bad = allowed(&f).await;
    let good = allowed(&f).await;
    let (_, list) = get(&f, "/v1/actions").await;
    assert!(
        list["actions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["state"] == "executed"),
        "positive control"
    );
    // A later terminal event whose body does not parse as the typed payload.
    insert_row(
        &f,
        2_000_000,
        "execution_failed",
        &json!({"action_id":bad,"body":{"event_type":"execution_failed"}}),
    )
    .await;
    let (_, list) = get(&f, "/v1/actions").await;
    let item = |id: Uuid| {
        list["actions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["action_id"] == id.to_string())
            .unwrap()
            .clone()
    };
    assert_eq!(
        (item(bad)["state"].clone(), item(bad)["malformed"].clone()),
        (json!("needs_review"), json!(true))
    );
    assert_eq!(item(good)["state"], "executed");
    assert!(item(good).get("malformed").is_none());
    assert_eq!(
        get(&f, &format!("/v1/actions/{bad}")).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_action_detail_state_correct_when_events_truncated() {
    let f = timeline_fixture().await;
    let max = crate::mcp_policy::settings()
        .unwrap()
        .approvals
        .max_list_page_size;
    let (approval, action) = pending(&f).await;
    // A gate-denied caller pads the action with rejected attempts BEFORE the outcome lands.
    for _ in 0..(max + 5) {
        assert!(f.decide(&f.agent, approval, true).await.is_some());
    }
    assert_eq!(f.decide(&f.human, approval, true).await, None);
    call_with(&f, 1_500_000, Some(approval))
        .await
        .unwrap()
        .unwrap();
    let d = detail(&f, action).await;
    assert_eq!(d["state"], "executed");
    assert_eq!(d["events_truncated"], true);
    assert_eq!(d["events"].as_array().unwrap().len(), max);
    let kinds = event_types(&d);
    assert_eq!(
        kinds.last().unwrap(),
        "execution_succeeded",
        "newest events are kept"
    );
    let seqs: Vec<i64> = d["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["seq"].as_i64().unwrap())
        .collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]), "still ascending");
    // Phase 2: pad past the cap AFTER the outcome. Every visible event is now a rejected attempt,
    // yet the state must still come from the state-changing events.
    for _ in 0..(max + 5) {
        assert!(f.decide(&f.agent, approval, true).await.is_some());
    }
    let d = detail(&f, action).await;
    assert_eq!(d["state"], "executed");
    assert_eq!(d["events_truncated"], true);
    assert!(
        event_types(&d)
            .iter()
            .all(|k| k == "approval_attempt_rejected"),
        "{:?}",
        event_types(&d)
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_descriptor_mismatch_is_recorded_in_ledger() {
    let f = timeline_fixture().await;
    let (approval, action) = pending(&f).await;
    let (s, _) = http_raw(
        &f,
        &f.human,
        grants(),
        "POST",
        &format!("/v1/approvals/{approval}/approve"),
        json!({"descriptor_digest":"f".repeat(64)}),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    let d = detail(&f, action).await;
    let last = d["events"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(last["event_type"], "approval_attempt_rejected");
    assert_eq!(last["actor_kind"], "human");
    assert_eq!(last["body"]["reason"], "approval_mismatch");
    assert_eq!(last["body"]["approval_id"], approval.to_string());
    assert_eq!(last["body"]["decider_digest"].as_str().unwrap().len(), 64);
    assert_eq!(
        d["state"], "awaiting_approval",
        "a rejected attempt decides nothing"
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_echo_on_unprotected_approval_is_rejected() {
    let f = timeline_fixture().await;
    let legacy: Uuid = f.pool.get().await.unwrap().query_one("INSERT INTO approvals(tenant_id,subject_kind,subject,requester_sub,args_fp,args_bytes,expires_at) VALUES($1,'model','synthetic-model','synthetic-requester','synthetic-fp',1,now()+interval '1 hour') RETURNING id", &[f.agent.tenant_id.as_uuid()]).await.unwrap().get(0);
    let (s, t) = http_raw(
        &f,
        &f.human,
        grants(),
        "POST",
        &format!("/v1/approvals/{legacy}/approve"),
        json!({"descriptor_digest":"0".repeat(64)}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{t}");
    assert!(t.contains("descriptor_unsupported"), "{t}");
    assert_eq!(f.status(legacy).await, "pending");
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approve_with_stale_digest_after_content_change_conflicts() {
    let f = timeline_fixture().await;
    let (approval, action) = pending(&f).await;
    let stale = detail(&f, action).await["descriptor_digest"].clone();
    // The bound evidence changes after the approver fetched the descriptor.
    let n = f.pool.get().await.unwrap().execute("UPDATE approvals SET args_preview=replace(args_preview,'1500000','1500001') WHERE tenant_id=$1 AND id=$2", &[f.agent.tenant_id.as_uuid(), &approval]).await.unwrap();
    assert_eq!(n, 1);
    let fresh = detail(&f, action).await["descriptor_digest"].clone();
    assert_ne!(stale, fresh, "the digest must cover the evidence");
    let (s, t) = http_raw(
        &f,
        &f.human,
        grants(),
        "POST",
        &format!("/v1/approvals/{approval}/approve"),
        json!({"descriptor_digest":stale}),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{t}");
    assert!(t.contains("descriptor_mismatch"));
    assert_eq!(f.status(approval).await, "pending");
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_list_queries_use_indexes() {
    let f = timeline_fixture().await;
    let action = allowed(&f).await;
    // A "can use" check (seq scans off), not a cost proof. Plenty of non-action ledger rows make
    // the partial indexes the cheap path.
    let mut db = f.pool.get().await.unwrap();
    db.execute("INSERT INTO audit_log_rows(tenant_id,seq,event_time,event_type,actor,payload,row_hash) SELECT $1,3000000+g,now(),'chat.completion','synthetic','{}','synthetic' FROM generate_series(1,3000) g", &[f.agent.tenant_id.as_uuid()]).await.unwrap();
    db.batch_execute("ANALYZE audit_log_rows").await.unwrap();
    let tx = db.transaction().await.unwrap();
    tx.batch_execute("SET LOCAL enable_seqscan=off")
        .await
        .unwrap();
    let plan = |rows: Vec<tokio_postgres::Row>| {
        rows.iter()
            .map(|r| r.get::<_, String>(0))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let heads = plan(
        tx.query(
            &["EXPLAIN ", timeline::HEADS_SQL].concat(),
            &[f.agent.tenant_id.as_uuid(), &None::<i64>, &51_i64],
        )
        .await
        .unwrap(),
    );
    assert!(heads.contains("audit_action_heads"), "{heads}");
    let page = plan(
        tx.query(
            &["EXPLAIN ", timeline::PAGE_EVENTS_SQL].concat(),
            &[f.agent.tenant_id.as_uuid(), &vec![action.to_string()]],
        )
        .await
        .unwrap(),
    );
    assert!(page.contains("audit_action_id"), "{page}");
    // The NOT EXISTS subquery is a hashed SubPlan over the partial heads index (measured: the
    // planner picks audit_action_heads there, not audit_action_id); it must not be a table scan.
    let sub = &heads[heads.find("SubPlan").expect(&heads)..];
    assert!(
        sub.contains("Index Scan using audit_action_heads"),
        "{heads}"
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_check_order_hides_digest_result_from_unseparated_requester() {
    let f = timeline_fixture().await;
    let (approval, action) = pending(&f).await;
    let right = detail(&f, action).await["descriptor_digest"].clone();
    // A human with a session who is not separated from the request.
    let mut creator = f.human.clone();
    creator.sub = "synthetic-creator".into();
    let wrong = "0".repeat(64);
    for i in 0..3 {
        if i == 2 {
            f.pool
                .get()
                .await
                .unwrap()
                .execute(
                    "UPDATE approvals SET args_preview=NULL WHERE tenant_id=$1 AND id=$2",
                    &[f.agent.tenant_id.as_uuid(), &approval],
                )
                .await
                .unwrap();
        }
        let body = json!({"descriptor_digest": if i == 0 { right.clone() } else { json!(wrong) }});
        let rows = ledger_rows(&f).await;
        let (s, t) = http_raw(
            &f,
            &creator,
            grants(),
            "POST",
            &format!("/v1/approvals/{approval}/approve"),
            body,
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "case {i}: {t}");
        assert!(t.contains("separation_required"), "case {i}: {t}");
        assert_eq!(
            ledger_rows(&f).await,
            rows + 1,
            "case {i}: refusal must be recorded"
        );
    }
    assert_eq!(f.status(approval).await, "pending");
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_action_detail_non_action_id_not_found() {
    let f = timeline_fixture().await;
    allowed(&f).await;
    // A policy activation carries an action_id of its own but is not an action.
    let id: String = f
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT payload::jsonb->>'action_id' FROM audit_log_rows WHERE tenant_id=$1 AND event_type='policy_activated' LIMIT 1",
            &[f.agent.tenant_id.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    let (s, b) = get(&f, &format!("/v1/actions/{id}")).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{b}");
}

#[path = "act19_pg_tests.rs"]
mod act19_pg_tests;
