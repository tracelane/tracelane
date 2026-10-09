//! rev6 re-review (`240d369d..46485982`, `REVIEW-rev6-reverify.md`) — regression tests for
//! the findings whose proof spans modules. Each test names its finding. The harness is
//! `og_controls_tests`'s (a control plane that resolves every tenant to the given
//! `WorkspaceControls`); every test runs under its own fresh tenant and key ids.

use std::sync::Arc;

use axum::body::Bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::controls::{Pause, WorkspaceControls};
use crate::handler_harness::{authed, body_json};
use crate::og_controls_tests::{
    chat, chat_as, code, fresh_tenant, key_claims, session, state_with,
};

// ── M3 residual: limits.per_model matches provider-facing names ─────────────

/// rev6 M3: a `per_model` limit on `gpt-4o*` binds `azure/gpt-4o` too — the prefix-stripped
/// name the provider sees — through the same helper the deny and block lists use. RED
/// before the fix: plain `glob_match` on the routed name, so `azure/gpt-4o` escaped.
#[tokio::test]
async fn rev6_m3_a_per_model_limit_binds_provider_facing_names() {
    let state = state_with(WorkspaceControls::default());
    let t = fresh_tenant();
    let key = uuid::Uuid::new_v4();
    let c = || {
        key_claims(
            &t,
            key,
            None,
            None,
            Some(json!({"limits": {"per_model": [{"model": "gpt-4o*", "rpm": 1}]}})),
        )
    };
    assert_eq!(
        code(&chat_as(&state, c(), chat("azure/gpt-4o", 5)).await),
        None
    );
    assert_eq!(
        code(&chat_as(&state, c(), chat("azure/gpt-4o", 5)).await),
        Some("rpm_limit_model"),
        "azure/gpt-4o is gpt-4o on the provider's wire — inside the gpt-4o* limit"
    );
    // Not over-matching: an unrelated model keeps its own (absent) limit.
    assert_eq!(
        code(&chat_as(&state, c(), chat("azure/gpt-35-turbo", 5)).await),
        None
    );
}

// ── H2 residual: an eval / experiment run re-validates its starting key ─────

/// rev6 H2 residual: between chunks a run re-validates the key it was started with — a
/// revoked key (revoke-all included) stops it with `key_revoked`; a policy tightened since
/// the start binds the next call; a session has no key to revoke. RED before the fix:
/// `RunContext.caller` was captured once and never re-checked (there was no re-check).
#[tokio::test]
async fn rev6_h2_a_run_revalidates_its_starting_key_between_chunks() {
    let state = state_with(WorkspaceControls::default());
    let t = fresh_tenant();

    // Revoked mid-run → the run stops, naming why.
    let revoked = uuid::Uuid::new_v4();
    let caller = Arc::new(key_claims(&t, revoked, None, None, None));
    assert!(
        crate::offpath::revalidate_caller(&caller, None)
            .await
            .is_ok()
    );
    crate::offpath::test_revoked()
        .lock()
        .insert(revoked.to_string());
    let stop = crate::offpath::revalidate_caller(&caller, None)
        .await
        .expect_err("a revoked key stops the run");
    assert!(stop.starts_with("key_revoked:"), "{stop}");

    // Policy tightened mid-run → the NEXT call is judged under the new policy.
    let tightened = uuid::Uuid::new_v4();
    let caller = Arc::new(key_claims(&t, tightened, None, None, None));
    let req = tracelane_shared::ChatRequest {
        model: "gpt-4o".into(),
        ..Default::default()
    };
    let env = crate::offpath::OffPathEnv::of(&state);
    assert!(crate::offpath::admit(&env, &caller, &req).await.is_ok());
    let deny = tracelane_shared::key_policy::Governance::from_columns(
        None,
        None,
        None,
        Some(&json!({"models": {"deny": ["gpt-4o*"]}})),
    )
    .map(Arc::new);
    crate::offpath::test_policy()
        .lock()
        .insert(tightened.to_string(), deny);
    let current = crate::offpath::revalidate_caller(&caller, None)
        .await
        .expect("still live");
    let refused = crate::offpath::admit(&env, &current, &req).await;
    assert_eq!(
        refused.as_ref().err().map(crate::offpath::code),
        Some("policy_model_denied"),
        "the tightened policy binds the run's next call"
    );

    // A session started the run: nothing to revoke, the principal is unchanged.
    let who = Arc::new(session(&t));
    let same = crate::offpath::revalidate_caller(&who, None).await.unwrap();
    assert!(Arc::ptr_eq(&who, &same));
}

/// rev6 H2 residual: only a `tlane_` bearer is kept for re-validation.
#[test]
fn rev6_h2_only_an_api_key_bearer_is_kept() {
    use secrecy::ExposeSecret as _;
    let mut h = axum::http::HeaderMap::new();
    h.insert("authorization", "Bearer tlane_abc".parse().unwrap());
    let kept = crate::offpath::key_credential(&h);
    assert_eq!(
        kept.as_deref().map(|s| s.expose_secret()),
        Some("Bearer tlane_abc")
    );
    h.insert("authorization", "Bearer eyJhbGciOi.jwt".parse().unwrap());
    assert!(crate::offpath::key_credential(&h).is_none());
    assert!(crate::offpath::key_credential(&axum::http::HeaderMap::new()).is_none());
}

// ── count_tokens companions: pause / blocks / key policy deny ───────────────

fn paused() -> WorkspaceControls {
    WorkspaceControls {
        paused: Some(Pause {
            at: chrono::Utc::now(),
            by: Some("owner".into()),
            reason: None,
        }),
        ..WorkspaceControls::default()
    }
}

async fn anthropic_count(
    state: crate::server::AppState,
    claims: crate::auth::Claims,
) -> (u16, Value) {
    let body = Bytes::from(
        json!({"model": "claude-sonnet-4-5", "messages": [{"role": "user", "content": "hi"}]})
            .to_string(),
    );
    let r =
        crate::anthropic_messages::count_tokens_with_claims(state, authed(), body, claims).await;
    let s = r.status().as_u16();
    (s, body_json(r).await)
}

async fn gemini_count(state: crate::server::AppState, claims: crate::auth::Claims) -> (u16, Value) {
    let body = Bytes::from(json!({"contents": [{"parts": [{"text": "hi"}]}]}).to_string());
    let r = crate::gemini_native::count_tokens_with_claims(state, "gemini-2.5-flash", body, claims)
        .await;
    let s = r.status().as_u16();
    (s, body_json(r).await)
}

/// rev6: Anthropic `count_tokens` forwards the whole prompt with the tenant's key, so a
/// paused workspace, a blocked model / provider and a key policy that denies the model
/// refuse it BEFORE the key is touched. RED before the fix: none was consulted.
#[tokio::test]
async fn rev6_anthropic_count_tokens_runs_pause_blocks_and_key_policy() {
    let t = fresh_tenant();
    let (s, v) = anthropic_count(state_with(paused()), session(&t)).await;
    assert_eq!(
        (s, v["error"]["code"].clone()),
        (423, json!("workspace_paused")),
        "{v}"
    );

    let blocked = WorkspaceControls::from_row(None, None, vec!["claude*".into()], vec![], vec![]);
    let (s, v) = anthropic_count(state_with(blocked), session(&t)).await;
    assert_eq!(
        (s, v["error"]["code"].clone()),
        (403, json!("model_blocked")),
        "{v}"
    );

    let blocked = WorkspaceControls::from_row(None, None, vec![], vec!["anthropic".into()], vec![]);
    let (s, v) = anthropic_count(state_with(blocked), session(&t)).await;
    assert_eq!(
        (s, v["error"]["code"].clone()),
        (403, json!("provider_blocked")),
        "{v}"
    );

    let k = key_claims(
        &t,
        uuid::Uuid::new_v4(),
        None,
        None,
        Some(json!({"models": {"deny": ["claude-sonnet*"]}})),
    );
    let (s, v) = anthropic_count(state_with(WorkspaceControls::default()), k).await;
    assert_eq!(
        (s, v["error"]["code"].clone()),
        (403, json!("policy_model_denied")),
        "{v}"
    );
}

/// rev6: the same for Gemini `countTokens`.
#[tokio::test]
async fn rev6_gemini_count_tokens_runs_pause_blocks_and_key_policy() {
    let t = fresh_tenant();
    let (s, v) = gemini_count(state_with(paused()), session(&t)).await;
    assert_eq!(s, 423, "{v}");
    assert!(v.to_string().contains("workspace_paused"), "{v}");

    let blocked = WorkspaceControls::from_row(None, None, vec!["gemini*".into()], vec![], vec![]);
    let (s, v) = gemini_count(state_with(blocked), session(&t)).await;
    assert_eq!(s, 403, "{v}");
    assert!(v.to_string().contains("model_blocked"), "{v}");

    let k = key_claims(
        &t,
        uuid::Uuid::new_v4(),
        None,
        None,
        Some(json!({"providers": {"deny": ["google"]}})),
    );
    let (s, v) = gemini_count(state_with(WorkspaceControls::default()), k).await;
    assert_eq!(s, 403, "{v}");
    assert!(v.to_string().contains("policy_model_denied"), "{v}");
}

/// rev6: the must-ACCEPT direction, asked of the gate itself (so no test can reach a
/// provider): nothing set, or rules that do not touch this model, admit the companion.
#[test]
fn rev6_companion_gate_admits_what_no_control_refuses() {
    let t = fresh_tenant();
    let none = WorkspaceControls::default();
    assert_eq!(
        crate::controls::companion_refusal(
            &session(&t),
            Some(&none),
            "claude-sonnet-4-5",
            "anthropic"
        ),
        None
    );
    assert_eq!(
        crate::controls::companion_refusal(&session(&t), None, "claude-sonnet-4-5", "anthropic"),
        None,
        "no control plane: nothing can have been set"
    );
    let other = WorkspaceControls::from_row(
        None,
        None,
        vec!["gpt-4o*".into()],
        vec!["openai".into()],
        vec![],
    );
    let k = key_claims(
        &t,
        uuid::Uuid::new_v4(),
        None,
        None,
        Some(json!({"models": {"deny": ["gpt-4o*"]}})),
    );
    assert_eq!(
        crate::controls::companion_refusal(&k, Some(&other), "claude-sonnet-4-5", "anthropic"),
        None
    );
    // A workspace policy's model rule binds the companion too (rev5 M6).
    let ws = WorkspaceControls::from_row(
        Some(&json!({"models": {"deny": ["claude*"]}})),
        None,
        vec![],
        vec![],
        vec![],
    );
    assert_eq!(
        crate::controls::companion_refusal(
            &session(&t),
            Some(&ws),
            "claude-sonnet-4-5",
            "anthropic"
        )
        .map(|r| r.code),
        Some("policy_model_denied")
    );
}

// ── N4: an Invalid stored workspace policy fails CLOSED at authentication ───

/// rev6 N4: a stored workspace policy that does not parse (or carries a rule a workspace
/// may not) cannot be shown to carry no `source_ips` rule, so the auth-time check refuses
/// every API key `policy_invalid` — as admission already refuses inference for it. RED
/// before the fix: `policy()?` returned `None` and the key authenticated.
#[tokio::test]
async fn rev6_n4_an_invalid_workspace_policy_refuses_keys_at_authentication() {
    let invalid = WorkspaceControls::from_row(
        Some(&json!({"max_body_bytes": 1000})),
        None,
        vec![],
        vec![],
        vec![],
    );
    assert!(
        matches!(
            invalid.policy,
            Some(tracelane_shared::key_policy::LayerPolicy::Invalid)
        ),
        "the fixture is an Invalid workspace policy"
    );
    let state = state_with(invalid);
    let t = fresh_tenant();
    let public: std::net::IpAddr = "203.0.113.9".parse().unwrap();
    let d = crate::auth::api_key::workspace_source_refusal(
        state.entitlements.as_ref(),
        &t,
        Some(public),
    )
    .await
    .expect("refused");
    assert_eq!((d.status, d.code), (403, "policy_invalid"));
    assert_eq!(d.origin, tracelane_shared::key_policy::Origin::Workspace);
    // The admission half agreed before the fix and still does.
    assert_eq!(
        code(
            &chat_as(
                &state,
                key_claims(&t, uuid::Uuid::new_v4(), None, None, None),
                chat("gpt-4o", 5)
            )
            .await
        ),
        Some("policy_invalid")
    );
    // A valid policy without `source_ips` still authenticates.
    let fine = state_with(WorkspaceControls::from_row(
        Some(&json!({"models": {"deny": ["gpt-4o*"]}})),
        None,
        vec![],
        vec![],
        vec![],
    ));
    assert!(
        crate::auth::api_key::workspace_source_refusal(
            fine.entitlements.as_ref(),
            &t,
            Some(public)
        )
        .await
        .is_none()
    );
}

// ── N2: /v1/auth/whoami reports the derived client address ─────────────────

/// rev6 N2: the deploy's Proof G asks `/v1/auth/whoami` (through Cloudflare) for the
/// address the gateway derived. Through the REAL B-594 layer: a public peer is reported as
/// itself even when it spoofs every forwarding header; a trusted proxy hop's header decides.
#[tokio::test]
async fn rev6_n2_whoami_reports_the_derived_client_address() {
    use axum::extract::connect_info::MockConnectInfo;
    use tower::ServiceExt as _;
    async fn ask(peer: &str, headers: &[(&str, &str)]) -> Value {
        let app = crate::server::whoami_router()
            .layer(axum::middleware::from_fn_with_state(
                crate::preauth_limiter::PreAuthLimiter::new(60),
                crate::preauth_limiter::layer,
            ))
            .layer(MockConnectInfo(std::net::SocketAddr::new(
                peer.parse().unwrap(),
                4000,
            )));
        let mut req = axum::http::Request::get("/v1/auth/whoami");
        for (k, v) in authed().iter() {
            req = req.header(k, v);
        }
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let r = app
            .oneshot(req.body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        body_json(r).await
    }
    let v = ask(
        "198.51.100.7",
        &[
            ("cf-connecting-ip", "10.9.9.9"),
            ("x-forwarded-for", "10.9.9.9"),
        ],
    )
    .await;
    assert_eq!(v["client_ip"], json!("198.51.100.7"), "{v}");
    let v = ask("10.0.0.2", &[("cf-connecting-ip", "203.0.113.50")]).await;
    assert_eq!(v["client_ip"], json!("203.0.113.50"), "{v}");
}
