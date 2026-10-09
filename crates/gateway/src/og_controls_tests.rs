//! `OG-21` / `OG-22` / `OG-25` — the workspace controls, limits and budgets, proven at the
//! admission steps that enforce them (`specs/OG-21-tpm-rpm-limits.md` §7,
//! `specs/OG-22-budgets-every-level.md` §7, `specs/OG-25-emergency-controls.md` §7).
//!
//! Every test runs under its OWN fresh tenant and key ids: the limit and budget tables
//! are process-wide, and the suite runs in parallel.

use std::sync::Arc;

use axum::http::HeaderMap;
use serde_json::{Value, json};

use crate::admission::{Refusal, Route, admit_with_claims};
use crate::auth::{AuthMethod, Claims};
use crate::controls::{Pause, WorkspaceControls};
use crate::entitlement_cache::{EntitlementCache, ResolvedEntitlements};
use crate::handler_harness::{authed, test_state};
use crate::key_policy_route_tests::{every_route, run_with};
use crate::providers::ProviderRegistry;
use crate::server::AppState;

type Resolved = std::pin::Pin<
    Box<dyn std::future::Future<Output = anyhow::Result<ResolvedEntitlements>> + Send>,
>;

pub(crate) fn fresh_tenant() -> tracelane_shared::TenantId {
    tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::new_v4())
}

/// A test state whose control plane resolves every tenant to `controls`.
pub(crate) fn state_with(controls: WorkspaceControls) -> AppState {
    let mut state = test_state(ProviderRegistry::new().expect("registry"));
    let controls = Arc::new(controls);
    state.entitlements = Some(Arc::new(EntitlementCache::new(Arc::new(move |_t| {
        let controls = Arc::clone(&controls);
        Box::pin(async move {
            Ok(ResolvedEntitlements {
                controls,
                rate_limit_rpm: None,
                ..ResolvedEntitlements::deny_all()
            })
        }) as Resolved
    }))));
    state
}

/// An API key of `tenant`, id `key`, in `project`, with `key_doc` / `project_doc`.
pub(crate) fn key_claims(
    tenant: &tracelane_shared::TenantId,
    key: uuid::Uuid,
    project: Option<uuid::Uuid>,
    project_doc: Option<Value>,
    key_doc: Option<Value>,
) -> Claims {
    Claims {
        tenant_id: tenant.clone(),
        sub: format!("apikey:{key}"),
        governance: tracelane_shared::key_policy::Governance::from_columns(
            project,
            None,
            project_doc.as_ref(),
            key_doc.as_ref(),
        )
        .map(Arc::new),
        ..crate::auth::dev_stub_claims(AuthMethod::ApiKey)
    }
}

pub(crate) fn session(tenant: &tracelane_shared::TenantId) -> Claims {
    Claims {
        tenant_id: tenant.clone(),
        ..crate::auth::dev_stub_claims(AuthMethod::JwtBearer)
    }
}

pub(crate) fn chat(model: &str, max_tokens: u64) -> Value {
    json!({"model": model, "max_tokens": max_tokens,
           "messages": [{"role": "user", "content": "hi"}]})
}

pub(crate) async fn chat_as(state: &AppState, claims: Claims, body: Value) -> Result<(), Refusal> {
    run_with::<crate::admission::Chat>(state, &authed(), body, claims).await
}

pub(crate) async fn chat_as_user(
    state: &AppState,
    claims: Claims,
    body: Value,
    user: &str,
) -> Result<(), Refusal> {
    let mut h: HeaderMap = authed();
    h.insert("x-tracelane-user-id", user.parse().unwrap());
    run_with::<crate::admission::Chat>(state, &h, body, claims).await
}

pub(crate) fn code(r: &Result<(), Refusal>) -> Option<&'static str> {
    match r {
        Ok(()) => None,
        Err(Refusal::Control(c)) => Some(c.code),
        Err(Refusal::Policy(d)) => Some(d.code),
        Err(Refusal::KeyBudgetExceeded { .. }) => Some("key_budget_exceeded"),
        Err(Refusal::RateLimited { .. }) => Some("rate_limited"),
        Err(_) => Some("other"),
    }
}

// ── OG-25 ────────────────────────────────────────────────────────────────────

/// PROOF 1: a paused workspace refuses EVERY inference route `423 workspace_paused`,
/// before any charge, dispatch or ledger row.
#[tokio::test]
async fn og25_a_pause_blocks_every_inference_route() {
    let state = state_with(WorkspaceControls {
        paused: Some(Pause {
            at: chrono::Utc::now(),
            by: Some("owner".into()),
            reason: None,
        }),
        ..WorkspaceControls::default()
    });
    let tenant = fresh_tenant();
    let results = every_route(&state, || session(&tenant)).await;
    assert_eq!(results.len(), 10);
    for (route, r) in &results {
        assert_eq!(code(r), Some("workspace_paused"), "{route}");
    }
    assert_eq!(
        state.audit_chain.in_memory_seq(&tenant),
        0,
        "nothing ledgered"
    );
    // The wire renders 423 with the code.
    let Err(refusal) = chat_as(&state, session(&tenant), chat("gpt-4o", 5)).await else {
        panic!("paused")
    };
    let resp = crate::admission::Chat::refuse(refusal);
    assert_eq!(resp.status().as_u16(), 423);
    let j = crate::handler_harness::body_json(resp).await;
    assert_eq!(j["error"], json!("workspace_paused"));
}

/// PROOF 3: blocked model (through a workspace alias too), provider and end user.
#[tokio::test]
async fn og25_blocked_models_providers_and_end_users_are_refused() {
    let state = state_with(WorkspaceControls::from_row(
        None,
        None,
        vec!["gpt-4o*".into()],
        vec!["anthropic".into()],
        vec!["mallory".into()],
    ));
    let t = fresh_tenant();
    assert_eq!(
        code(&chat_as(&state, session(&t), chat("gpt-4o-mini", 5)).await),
        Some("model_blocked")
    );
    assert_eq!(
        code(&chat_as(&state, session(&t), chat("claude-sonnet-4-5", 5)).await),
        Some("provider_blocked")
    );
    assert_eq!(
        code(&chat_as_user(&state, session(&t), chat("ollama/llama3", 5), "mallory").await),
        Some("end_user_blocked")
    );
    assert_eq!(
        code(&chat_as_user(&state, session(&t), chat("ollama/llama3", 5), "alice").await),
        None,
        "everything else is admitted"
    );
}

// ── OG-21 ────────────────────────────────────────────────────────────────────

/// PROOF 4: a key RPM of 2 refuses the third request `429 rpm_limit_key` with Retry-After.
#[tokio::test]
async fn og21_a_key_rpm_limit_refuses_with_a_named_code_and_retry_after() {
    let state = state_with(WorkspaceControls::default());
    let t = fresh_tenant();
    let key = uuid::Uuid::new_v4();
    let c = || key_claims(&t, key, None, None, Some(json!({"limits": {"rpm": 2}})));
    assert_eq!(
        code(&chat_as(&state, c(), chat("ollama/llama3", 5)).await),
        None
    );
    assert_eq!(
        code(&chat_as(&state, c(), chat("ollama/llama3", 5)).await),
        None
    );
    let r = chat_as(&state, c(), chat("ollama/llama3", 5)).await;
    assert_eq!(code(&r), Some("rpm_limit_key"));
    let resp = crate::admission::Chat::refuse(r.unwrap_err());
    assert_eq!(resp.status().as_u16(), 429);
    let retry: u32 = resp.headers()[axum::http::header::RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=30).contains(&retry), "{retry}");
    let j = crate::handler_harness::body_json(resp).await;
    assert_eq!(j["limit"], json!(2));
    assert_eq!(j["scope"], json!("key"));
}

/// AND semantics across layers: a project RPM of 1 is ONE bucket for every key in it,
/// and a workspace RPM binds sessions too.
#[tokio::test]
async fn og21_project_and_workspace_layers_bind_every_key_and_session() {
    let state = state_with(WorkspaceControls::default());
    let t = fresh_tenant();
    let project = uuid::Uuid::new_v4();
    let doc = json!({"limits": {"rpm": 1}});
    let k1 = key_claims(
        &t,
        uuid::Uuid::new_v4(),
        Some(project),
        Some(doc.clone()),
        None,
    );
    let k2 = key_claims(&t, uuid::Uuid::new_v4(), Some(project), Some(doc), None);
    assert_eq!(
        code(&chat_as(&state, k1, chat("ollama/llama3", 5)).await),
        None
    );
    assert_eq!(
        code(&chat_as(&state, k2, chat("ollama/llama3", 5)).await),
        Some("rpm_limit_project"),
        "a second key in the project shares its bucket"
    );

    let ws = state_with(WorkspaceControls::from_row(
        Some(&json!({"limits": {"rpm": 1}})),
        None,
        vec![],
        vec![],
        vec![],
    ));
    let t = fresh_tenant();
    assert_eq!(
        code(&chat_as(&ws, session(&t), chat("ollama/llama3", 5)).await),
        None
    );
    assert_eq!(
        code(&chat_as(&ws, session(&t), chat("ollama/llama3", 5)).await),
        Some("rpm_limit_workspace")
    );
}

/// Per end user and per model are their own buckets.
#[tokio::test]
async fn og21_end_users_and_models_each_get_their_own_bucket() {
    let state = state_with(WorkspaceControls::default());
    let t = fresh_tenant();
    let key = uuid::Uuid::new_v4();
    let c = || {
        key_claims(
            &t,
            key,
            None,
            None,
            Some(json!({"limits": {
                "per_end_user": {"rpm": 1},
                "per_model": [{"model": "gpt-4o*", "rpm": 1}]
            }})),
        )
    };
    assert_eq!(
        code(&chat_as_user(&state, c(), chat("ollama/llama3", 5), "a").await),
        None
    );
    assert_eq!(
        code(&chat_as_user(&state, c(), chat("ollama/llama3", 5), "a").await),
        Some("rpm_limit_end_user")
    );
    assert_eq!(
        code(&chat_as_user(&state, c(), chat("ollama/llama3", 5), "b").await),
        None
    );
    assert_eq!(code(&chat_as(&state, c(), chat("gpt-4o", 5)).await), None);
    assert_eq!(
        code(&chat_as(&state, c(), chat("gpt-4o-mini", 5)).await),
        Some("rpm_limit_model"),
        "gpt-4o-mini matches gpt-4o* and shares its bucket"
    );
    assert_eq!(
        code(&chat_as(&state, c(), chat("ollama/llama3", 5)).await),
        None
    );
}

/// PROOF 3 (OG-21): a TPM reservation is the declared cap + input estimate, and the span
/// reconciles it — the refund lets the next request in.
#[tokio::test]
async fn og21_tpm_is_reserved_at_admission_and_reconciled_from_actual_usage() {
    let state = state_with(WorkspaceControls::default());
    let t = fresh_tenant();
    let key = uuid::Uuid::new_v4();
    let c = || key_claims(&t, key, None, None, Some(json!({"limits": {"tpm": 1000}})));
    let a = admit_with_claims::<crate::admission::Chat>(
        &state,
        &authed(),
        chat("ollama/llama3", 600),
        c(),
    )
    .await
    .unwrap_or_else(|r| panic!("{r:?}"));
    let trace = a.trace_id;
    let mut a = a;
    a.dispatch_guard.disarm();
    assert_eq!(
        code(&chat_as(&state, c(), chat("ollama/llama3", 600)).await),
        Some("tpm_limit_key"),
        "600 reserved of 1000: another 600 does not fit"
    );
    // The first response used 50 tokens: reconciliation refunds the rest.
    let r = crate::limits::table()
        .take(
            *t.as_uuid(),
            trace,
            Some(&key.to_string()),
            Some("ollama/llama3"),
            None,
        )
        .expect("the reservation was parked");
    crate::limits::table().reconcile(&r, 50);
    assert_eq!(
        code(&chat_as(&state, c(), chat("ollama/llama3", 600)).await),
        None
    );
}

/// A route that cannot estimate its input is refused under a TPM rule (fail-CLOSED).
#[tokio::test]
async fn og21_passthrough_under_a_tpm_rule_is_unenforceable() {
    let state = state_with(WorkspaceControls::default());
    let t = fresh_tenant();
    let mut c = key_claims(
        &t,
        uuid::Uuid::new_v4(),
        None,
        None,
        Some(json!({"limits": {"tpm": 10}})),
    );
    c.key_scope = crate::auth::scope::KeyScope::Scoped(
        [crate::auth::scope::Scope::Passthrough]
            .into_iter()
            .collect(),
    );
    let r = run_with::<crate::passthrough::Passthrough>(
        &state,
        &authed(),
        crate::passthrough::PassthroughInput {
            provider: "openai".into(),
            raw_path: "v1/vector_stores".into(),
            method: axum::http::Method::GET,
        },
        c,
    )
    .await;
    assert_eq!(code(&r), Some("policy_unenforceable"));
}

// ── OG-22 ────────────────────────────────────────────────────────────────────

pub(crate) fn record(
    t: &tracelane_shared::TenantId,
    project: Option<uuid::Uuid>,
    key: Option<uuid::Uuid>,
    user: Option<&str>,
    usd: f64,
) {
    crate::budgets::table().record(
        *t.as_uuid(),
        project,
        key,
        user,
        (usd * 1_000_000.0) as u64,
        chrono::Utc::now(),
        &|_| true,
    );
}

/// PROOF 4: a hard project budget refuses `402 budget_exceeded_project` once spent; the
/// same budget SOFT admits.
#[tokio::test]
async fn og22_a_hard_project_budget_refuses_and_a_soft_one_admits() {
    let state = state_with(WorkspaceControls::default());
    for (mode, want) in [("hard", Some("budget_exceeded_project")), ("soft", None)] {
        let t = fresh_tenant();
        let project = uuid::Uuid::new_v4();
        let doc = json!({"budget": {"usd": 1, "window": "daily", "mode": mode}});
        let c = || {
            key_claims(
                &t,
                uuid::Uuid::new_v4(),
                Some(project),
                Some(doc.clone()),
                None,
            )
        };
        assert_eq!(
            code(&chat_as(&state, c(), chat("gpt-4o", 5)).await),
            None,
            "{mode}: seeded at 0"
        );
        record(&t, Some(project), None, None, 1.5);
        let r = chat_as(&state, c(), chat("gpt-4o", 5)).await;
        assert_eq!(code(&r), want, "{mode}");
        if let Err(refusal) = r {
            let resp = crate::admission::Chat::refuse(refusal);
            assert_eq!(resp.status().as_u16(), 402);
            let j = crate::handler_harness::body_json(resp).await;
            assert_eq!(j["budget_usd"], json!(1.0));
            assert_eq!(j["spent_usd"], json!(1.5));
        }
    }
}

/// PROOF 5: an end-user budget is per end user.
#[tokio::test]
async fn og22_an_end_user_budget_isolates_end_users() {
    let state = state_with(WorkspaceControls::from_row(
        Some(&json!({"end_user_budget": {"usd": 1, "window": "daily"}})),
        None,
        vec![],
        vec![],
        vec![],
    ));
    let t = fresh_tenant();
    assert_eq!(
        code(&chat_as_user(&state, session(&t), chat("gpt-4o", 5), "a").await),
        None
    );
    assert_eq!(
        code(&chat_as_user(&state, session(&t), chat("gpt-4o", 5), "b").await),
        None
    );
    record(&t, None, None, Some("a"), 2.0);
    assert_eq!(
        code(&chat_as_user(&state, session(&t), chat("gpt-4o", 5), "a").await),
        Some("budget_exceeded_end_user")
    );
    assert_eq!(
        code(&chat_as_user(&state, session(&t), chat("gpt-4o", 5), "b").await),
        None
    );
}

/// PROOF 3 — THE ABSORBED DEFECT: a hard cap whose spend cannot be read REFUSES. Both the
/// GWY-43 key budget and an OG-22 budget, ClickHouse pointed at a closed port. A soft
/// budget with unknown spend still admits.
#[tokio::test]
async fn og22_a_hard_cap_with_unknown_spend_refuses() {
    let mut state = state_with(WorkspaceControls::default());
    state.quota_ch_url = Some("http://127.0.0.1:9".into());
    let t = fresh_tenant();

    // GWY-43: the key's own monthly budget.
    let mut c = key_claims(&t, uuid::Uuid::new_v4(), None, None, None);
    c.budget_usd_monthly = Some(5.0);
    let r = chat_as(&state, c.clone(), chat("gpt-4o", 5)).await;
    assert_eq!(code(&r), Some("budget_spend_unknown"));
    let resp = crate::admission::Chat::refuse(r.unwrap_err());
    assert_eq!(resp.status().as_u16(), 503);
    assert!(resp.headers().contains_key(axum::http::header::RETRY_AFTER));
    // Still unknown on the next request (backoff, no per-request re-read).
    assert_eq!(
        code(&chat_as(&state, c, chat("gpt-4o", 5)).await),
        Some("budget_spend_unknown")
    );

    // OG-22: a hard key-policy budget.
    let hard = key_claims(
        &t,
        uuid::Uuid::new_v4(),
        None,
        None,
        Some(json!({"budget": {"usd": 5, "window": "monthly", "mode": "hard"}})),
    );
    assert_eq!(
        code(&chat_as(&state, hard, chat("gpt-4o", 5)).await),
        Some("budget_spend_unknown")
    );

    // A soft one never refuses.
    let soft = key_claims(
        &t,
        uuid::Uuid::new_v4(),
        None,
        None,
        Some(json!({"budget": {"usd": 5, "window": "monthly", "mode": "soft"}})),
    );
    assert_eq!(code(&chat_as(&state, soft, chat("gpt-4o", 5)).await), None);
}

/// The order: every step, including the three new ones, runs in `ORDER`.
#[tokio::test]
async fn og21_og22_og25_the_new_steps_run_in_order() {
    let state = state_with(WorkspaceControls::default());
    let t = fresh_tenant();
    let mut a = admit_with_claims::<crate::admission::Chat>(
        &state,
        &authed(),
        chat("ollama/llama3", 5),
        session(&t),
    )
    .await
    .unwrap_or_else(|r| panic!("{r:?}"));
    a.dispatch_guard.disarm();
    assert_eq!(a.steps, crate::admission::ORDER.to_vec());
}
