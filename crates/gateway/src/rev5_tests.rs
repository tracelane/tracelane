//! rev5 security review (Wave C/D, `c3ca9947..240d369d`) — the regression tests for the
//! findings whose proof spans modules. Each test names its finding. The admission-step
//! harness is `og_controls_tests`'s (a control plane that resolves every tenant to the
//! given `WorkspaceControls`); every test runs under its own fresh tenant and key ids.

use std::sync::Arc;

use serde_json::json;
use tracelane_shared::{Message, MessageContent, Role};

use crate::controls::{Pause, WorkspaceControls};
use crate::og_controls_tests::{fresh_tenant, key_claims, record, session, state_with};
use crate::prompt_eval::{EvalCase, EvalSpanRole, PromptEvalEngine};
use crate::server::AppState;

// ── H2: eval / experiment / online-eval provider calls ───────────────────────

fn engine(state: &AppState) -> Arc<PromptEvalEngine> {
    Arc::new(
        PromptEvalEngine::new(
            crate::clickhouse_query::ch_client("http://127.0.0.1:9"),
            state.providers.clone(),
            Arc::new(crate::prompt_router::PromptRouter::new()),
            None,
        )
        .with_entitlements(state.entitlements.clone()),
    )
}

fn case() -> EvalCase {
    EvalCase {
        name: "c1".into(),
        messages: vec![Message {
            role: Role::User,
            content: MessageContent::Text("hi".into()),
            tool_calls: None,
            tool_call_id: None,
        }],
        expected: None,
        metadata: None,
    }
}

/// Does the off-path gate admit `claims` on `model`? (The must-ACCEPT direction is asked
/// of the gate itself, so no test can reach the BYOK lookup or a provider.)
async fn admitted(state: &AppState, claims: &crate::auth::Claims, model: &str) -> bool {
    let req = tracelane_shared::ChatRequest {
        model: model.into(),
        ..Default::default()
    };
    crate::offpath::admit(&crate::offpath::OffPathEnv::of(state), claims, &req)
        .await
        .is_ok()
}

/// One eval case (or judge — the judge goes through the same `execute_case`) as `claims`
/// on `model`, for a call a control must REFUSE: `Some(code)` when a Wave C/D control
/// refused it BEFORE dispatch; anything else is a failure of the test.
async fn eval_call(
    state: &AppState,
    claims: &crate::auth::Claims,
    model: &str,
) -> Option<&'static str> {
    let r = engine(state)
        .execute_case(
            claims,
            model,
            "",
            &case(),
            uuid::Uuid::new_v4(),
            None,
            EvalSpanRole::Case,
        )
        .await;
    match r {
        Ok(_) => None,
        Err(e) => Some(
            e.downcast_ref::<crate::offpath::OffPathRefused>()
                .map_or("not_refused", |r| r.code),
        ),
    }
}

/// H2: a PAUSED workspace refuses an eval provider call before dispatch.
#[tokio::test]
async fn rev5_h2_a_paused_workspace_refuses_eval_calls() {
    let state = state_with(WorkspaceControls {
        paused: Some(Pause {
            at: chrono::Utc::now(),
            by: Some("owner".into()),
            reason: None,
        }),
        ..WorkspaceControls::default()
    });
    let t = fresh_tenant();
    assert_eq!(
        eval_call(&state, &session(&t), "gpt-4o").await,
        Some("workspace_paused")
    );
    let k = key_claims(&t, uuid::Uuid::new_v4(), None, None, None);
    assert_eq!(
        eval_call(&state, &k, "gpt-4o").await,
        Some("workspace_paused")
    );
}

/// H2: a BLOCKED model / provider refuses; an unblocked one gets past the controls.
#[tokio::test]
async fn rev5_h2_a_blocked_model_or_provider_refuses_eval_calls() {
    let state = state_with(WorkspaceControls::from_row(
        None,
        None,
        vec!["gpt-4o*".into()],
        vec!["anthropic".into()],
        vec![],
    ));
    let t = fresh_tenant();
    let who = session(&t);
    assert_eq!(
        eval_call(&state, &who, "gpt-4o-mini").await,
        Some("model_blocked")
    );
    assert_eq!(
        eval_call(&state, &who, "claude-sonnet-4-5").await,
        Some("provider_blocked")
    );
    assert!(
        admitted(&state, &who, "gpt-3.5-turbo").await,
        "an unblocked model passes the controls"
    );
}

/// H2: a key whose policy DENIES the model cannot reach it through an eval run.
#[tokio::test]
async fn rev5_h2_a_key_model_deny_refuses_eval_calls() {
    let state = state_with(WorkspaceControls::default());
    let t = fresh_tenant();
    let k = key_claims(
        &t,
        uuid::Uuid::new_v4(),
        None,
        None,
        Some(json!({"models": {"deny": ["gpt-4o*"]}})),
    );
    assert_eq!(
        eval_call(&state, &k, "gpt-4o").await,
        Some("policy_model_denied")
    );
    assert!(admitted(&state, &k, "gpt-3.5-turbo").await);
    // A rule an eval call cannot evaluate refuses with a code that names it.
    let tags = key_claims(
        &t,
        uuid::Uuid::new_v4(),
        None,
        None,
        Some(json!({"max_body_bytes": 1000})),
    );
    assert_eq!(
        eval_call(&state, &tags, "gpt-3.5-turbo").await,
        Some("policy_unenforceable")
    );
}

/// H2: a HARD budget that is spent refuses (project, key and the GWY-43 key ceiling); a
/// soft one does not.
#[tokio::test]
async fn rev5_h2_an_exhausted_hard_budget_refuses_eval_calls() {
    let state = state_with(WorkspaceControls::default());
    let t = fresh_tenant();
    let project = uuid::Uuid::new_v4();
    let key = uuid::Uuid::new_v4();
    let k = key_claims(
        &t,
        key,
        Some(project),
        Some(json!({"budget": {"usd": 1, "window": "daily", "mode": "hard"}})),
        None,
    );
    assert!(
        admitted(&state, &k, "gpt-3.5-turbo").await,
        "seeded at zero"
    );
    record(&t, Some(project), None, None, 1.5);
    assert_eq!(
        eval_call(&state, &k, "gpt-3.5-turbo").await,
        Some("budget_exceeded_project")
    );

    // GWY-43: the key's own ceiling.
    let t2 = fresh_tenant();
    let id2 = uuid::Uuid::new_v4();
    let mut capped = key_claims(&t2, id2, None, None, None);
    capped.budget_usd_monthly = Some(1.0);
    assert!(admitted(&state, &capped, "gpt-3.5-turbo").await);
    crate::spend::tracker().record(crate::spend::Subject::Key(id2), Some(2.0));
    assert_eq!(
        eval_call(&state, &capped, "gpt-3.5-turbo").await,
        Some("key_budget_exceeded")
    );
}

/// H2: the off-path RPM limit binds eval calls (the third call in the minute refuses).
#[tokio::test]
async fn rev5_h2_a_key_rpm_limit_binds_eval_calls() {
    let state = state_with(WorkspaceControls::default());
    let t = fresh_tenant();
    let k = key_claims(
        &t,
        uuid::Uuid::new_v4(),
        None,
        None,
        Some(json!({"limits": {"rpm": 2}})),
    );
    assert!(admitted(&state, &k, "gpt-3.5-turbo").await);
    assert!(admitted(&state, &k, "gpt-3.5-turbo").await);
    assert_eq!(
        eval_call(&state, &k, "gpt-3.5-turbo").await,
        Some("rpm_limit_key")
    );
}

/// H2: the online-eval judge is a WORKSPACE call — the workspace's pause and blocks bind it
/// (`offpath::workspace_principal`), and the principal carries no key and no capability.
#[tokio::test]
async fn rev5_h2_the_online_eval_judge_principal_is_bound_by_workspace_controls() {
    let state = state_with(WorkspaceControls::from_row(
        None,
        None,
        vec!["gpt-4o*".into()],
        vec![],
        vec![],
    ));
    let t = fresh_tenant();
    let p = crate::offpath::workspace_principal(&t);
    assert!(p.api_key_id().is_none());
    for c in crate::auth::capability::MATRIX {
        assert!(
            !p.can(c.cap),
            "the background principal holds no capability"
        );
    }
    let env = crate::offpath::OffPathEnv::of(&state);
    let req = |m: &str| tracelane_shared::ChatRequest {
        model: m.into(),
        ..Default::default()
    };
    let r = crate::offpath::admit(&env, &p, &req("gpt-4o")).await;
    assert_eq!(
        r.as_ref().err().map(crate::offpath::code),
        Some("model_blocked")
    );
    assert!(
        crate::offpath::admit(&env, &p, &req("gpt-3.5-turbo"))
            .await
            .is_ok()
    );
}

// ── M3: deny / block matching sees the provider-facing model name ────────────

/// rev5 M3: a routing prefix (`azure/`, `bedrock/`, `vertex/`, an openrouter-style
/// `provider/model` chain, a Bedrock `vendor.` id) no longer dodges a key DENY or a
/// workspace BLOCK — both are matched against the name the provider sees as well as the
/// one the caller typed. An ALLOW list is NOT widened (fail-closed): `allow: [gpt-4o]`
/// still refuses `azure/gpt-4o`.
#[tokio::test]
async fn rev5_m3_a_routing_prefix_cannot_dodge_a_deny_or_a_block() {
    use crate::og_controls_tests::{chat, chat_as, code};
    let state = state_with(WorkspaceControls::default());
    let t = fresh_tenant();
    let deny = |pat: &str| {
        key_claims(
            &t,
            uuid::Uuid::new_v4(),
            None,
            None,
            Some(json!({"models": {"deny": [pat]}})),
        )
    };
    for (pat, model) in [
        ("gpt-4o*", "azure/gpt-4o"),
        ("gemini-2.5-pro", "vertex/gemini-2.5-pro"),
        (
            "claude*",
            "bedrock/anthropic.claude-3-5-sonnet-20240620-v1:0",
        ),
        (
            "claude*",
            "bedrock/us.anthropic.claude-3-5-sonnet-20240620-v1:0",
        ),
        ("gpt-4o", "openrouter/openai/gpt-4o"),
        ("llama-3.3-70b*", "groq/llama-3.3-70b-versatile"),
    ] {
        assert_eq!(
            code(&chat_as(&state, deny(pat), chat(model, 5)).await),
            Some("policy_model_denied"),
            "deny `{pat}` must refuse `{model}`"
        );
    }
    // The workspace block list, the same names.
    let blocked = state_with(WorkspaceControls::from_row(
        None,
        None,
        vec!["gpt-4o*".into()],
        vec![],
        vec![],
    ));
    assert_eq!(
        code(&chat_as(&blocked, session(&t), chat("azure/gpt-4o", 5)).await),
        Some("model_blocked")
    );
    // An allow list is not widened by the stripped name.
    let allow = key_claims(
        &t,
        uuid::Uuid::new_v4(),
        None,
        None,
        Some(json!({"models": {"allow": ["gpt-4o"]}})),
    );
    assert_eq!(
        code(&chat_as(&state, allow, chat("azure/gpt-4o", 5)).await),
        Some("policy_model_denied")
    );
    // A post-admission move (failover, ZDR re-route) is judged the same way.
    let g = tracelane_shared::key_policy::Governance::from_columns(
        None,
        None,
        None,
        Some(&json!({"models": {"deny": ["gpt-4o*"]}})),
    )
    .expect("a policy");
    assert!(!g.allows_dispatch("azure/gpt-4o", "azure"));
    assert!(g.allows_dispatch("azure/gpt-35-turbo", "azure"));
    let c = WorkspaceControls::from_row(None, None, vec!["gpt-4o*".into()], vec![], vec![]);
    assert!(!crate::controls::allows_dispatch(
        &c,
        "azure/gpt-4o",
        "azure"
    ));
    // Not over-matching: a version dot is not a vendor separator.
    assert_eq!(
        tracelane_shared::key_policy::provider_facing_names("gpt-4.1"),
        Vec::<String>::new()
    );
}

// ── M6: a workspace policy binds every key ───────────────────────────────────

/// rev5 M6: the WORKSPACE policy may carry model and provider rules, and they bind every
/// key — including one a developer mints after the policy was set, with no policy of its
/// own — every session, an eval call, and a post-admission move (failover / ZDR).
#[tokio::test]
async fn rev5_m6_a_workspace_model_and_provider_policy_binds_every_key() {
    use crate::og_controls_tests::{chat, chat_as, code};
    let state = state_with(WorkspaceControls::from_row(
        Some(&json!({"models": {"deny": ["gpt-4o*"]}, "providers": {"deny": ["anthropic"]}})),
        None,
        vec![],
        vec![],
        vec![],
    ));
    let t = fresh_tenant();
    // A key minted by a developer: no project, no policy of its own.
    let fresh_key = key_claims(&t, uuid::Uuid::new_v4(), None, None, None);
    let r = chat_as(&state, fresh_key.clone(), chat("gpt-4o-mini", 5)).await;
    assert_eq!(code(&r), Some("policy_model_denied"));
    if let Err(crate::admission::Refusal::Policy(d)) = &r {
        assert_eq!(
            d.origin.as_str(),
            "workspace",
            "the refusal names the layer"
        );
    }
    assert_eq!(
        code(&chat_as(&state, fresh_key.clone(), chat("claude-sonnet-4-5", 5)).await),
        Some("policy_provider_denied")
    );
    assert_eq!(
        code(&chat_as(&state, session(&t), chat("azure/gpt-4o", 5)).await),
        Some("policy_model_denied"),
        "a session and a routing prefix are bound too"
    );
    assert_eq!(
        code(&chat_as(&state, fresh_key.clone(), chat("gpt-3.5-turbo", 5)).await),
        None,
        "everything else is admitted"
    );
    assert_eq!(
        eval_call(&state, &fresh_key, "gpt-4o").await,
        Some("policy_model_denied")
    );
    let c = WorkspaceControls::from_row(
        Some(&json!({"models": {"deny": ["gpt-4o*"]}})),
        None,
        vec![],
        vec![],
        vec![],
    );
    assert!(!crate::controls::allows_dispatch(&c, "gpt-4o", "openai"));
    assert!(crate::controls::allows_dispatch(
        &c,
        "gpt-3.5-turbo",
        "openai"
    ));
}

/// rev5 M6: the workspace's `source_ips` bind every API key (a session is not bound —
/// the admin plane has OG-36's allowlist). At authentication (every route) through the
/// boot-time cache, and again at admission; no derivable address under a rule refuses.
#[tokio::test]
async fn rev5_m6_workspace_source_ips_bind_every_key() {
    use crate::og_controls_tests::{chat, chat_as, code};
    let ws = WorkspaceControls::from_row(
        Some(&json!({"source_ips": ["10.0.0.0/8"]})),
        None,
        vec![],
        vec![],
        vec![],
    );
    let state = state_with(ws);
    let t = fresh_tenant();
    let key = key_claims(&t, uuid::Uuid::new_v4(), None, None, None);
    assert_eq!(
        code(&chat_as(&state, key, chat("gpt-3.5-turbo", 5)).await),
        Some("policy_ip_denied"),
        "the harness derives no address: refused under a CIDR rule"
    );
    assert_eq!(
        code(&chat_as(&state, session(&t), chat("gpt-3.5-turbo", 5)).await),
        None,
        "a session is not bound by a key rule"
    );
    // The authentication-time check every key route runs.
    let cache = state.entitlements.as_ref();
    let inside: std::net::IpAddr = "10.1.2.3".parse().unwrap();
    let outside: std::net::IpAddr = "203.0.113.9".parse().unwrap();
    assert!(
        crate::auth::api_key::workspace_source_refusal(cache, &t, Some(inside))
            .await
            .is_none()
    );
    assert_eq!(
        crate::auth::api_key::workspace_source_refusal(cache, &t, Some(outside))
            .await
            .map(|d| d.code),
        Some("policy_ip_denied")
    );
    assert!(
        crate::auth::api_key::workspace_source_refusal(cache, &t, None)
            .await
            .is_some(),
        "no derivable address under a CIDR rule is refused"
    );
    assert!(
        crate::auth::api_key::workspace_source_refusal(None, &t, None)
            .await
            .is_none(),
        "no control plane: nothing can have been set"
    );
}

// ── L6: caller-asserted end-user ids cannot fill the workspace's capacity ────

/// rev5 L6: where a per-end-user rule applies, one key may introduce at most the table's
/// `end_user_ids_per_key_per_window` DISTINCT end-user ids per window; a further NEW id
/// is `429 end_user_id_cap` with Retry-After, while an id already seen keeps working and
/// another key has its own allowance.
#[tokio::test]
async fn rev5_l6_one_key_cannot_rotate_end_user_ids_without_bound() {
    use crate::og_controls_tests::{chat, chat_as_user, code};
    let state = state_with(WorkspaceControls::from_row(
        Some(&json!({"end_user_budget": {"usd": 1000, "window": "daily", "mode": "soft"}})),
        None,
        vec![],
        vec![],
        vec![],
    ));
    let t = fresh_tenant();
    let key = key_claims(&t, uuid::Uuid::new_v4(), None, None, None);
    let cap = crate::controls::config().end_user_ids_per_key_per_window;
    for i in 0..cap {
        assert_eq!(
            code(
                &chat_as_user(
                    &state,
                    key.clone(),
                    chat("gpt-3.5-turbo", 5),
                    &format!("u{i}")
                )
                .await
            ),
            None,
            "id {i} is within the cap"
        );
    }
    let r = chat_as_user(
        &state,
        key.clone(),
        chat("gpt-3.5-turbo", 5),
        "one-too-many",
    )
    .await;
    assert_eq!(code(&r), Some("end_user_id_cap"));
    if let Err(crate::admission::Refusal::Control(c)) = &r {
        assert_eq!(c.status, 429);
        assert!(c.retry_after_secs.is_some());
    }
    assert_eq!(
        code(&chat_as_user(&state, key, chat("gpt-3.5-turbo", 5), "u0").await),
        None,
        "an id already seen keeps working"
    );
    let other = key_claims(&t, uuid::Uuid::new_v4(), None, None, None);
    assert_eq!(
        code(&chat_as_user(&state, other, chat("gpt-3.5-turbo", 5), "one-too-many").await),
        None,
        "another key has its own allowance"
    );
}

// ── L7: a hard budget has no reservation — the overshoot is bounded, and shown ─

/// rev5 L7 (documented, not reserved): a HARD budget is checked against RECORDED spend, so
/// requests admitted while the spend is under the ceiling all run — the overshoot is at
/// most (requests in flight when the ceiling is crossed) × (cost of one). Once any of their
/// spend is recorded past the ceiling, the very next request is refused: the overshoot
/// never compounds past the in-flight set.
#[tokio::test]
async fn rev5_l7_hard_budget_overshoot_is_bounded_by_the_in_flight_requests() {
    use crate::og_controls_tests::{chat, chat_as, code};
    let state = state_with(WorkspaceControls::default());
    let t = fresh_tenant();
    let project = uuid::Uuid::new_v4();
    let doc = json!({"budget": {"usd": 1, "window": "daily", "mode": "hard"}});
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
        code(&chat_as(&state, c(), chat("gpt-3.5-turbo", 5)).await),
        None
    );
    record(&t, Some(project), None, None, 0.99);
    // Five requests admitted at $0.99 of $1.00 — all run (no reservation).
    let in_flight = 5_u32;
    for _ in 0..in_flight {
        assert_eq!(
            code(&chat_as(&state, c(), chat("gpt-3.5-turbo", 5)).await),
            None
        );
    }
    // Their spend lands ($0.10 each): the overshoot is exactly the in-flight set's.
    let per_request = 0.10;
    for _ in 0..in_flight {
        record(&t, Some(project), None, None, per_request);
    }
    assert_eq!(
        code(&chat_as(&state, c(), chat("gpt-3.5-turbo", 5)).await),
        Some("budget_exceeded_project"),
        "the next request after the crossing is refused"
    );
    let snap = crate::budgets::table().snapshot(*t.as_uuid(), chrono::Utc::now());
    let spent = snap
        .iter()
        .filter_map(|v| v["spent_usd"].as_f64())
        .fold(0.0_f64, f64::max);
    assert!(
        spent <= 0.99 + f64::from(in_flight) * per_request + 1e-9,
        "overshoot bounded by in-flight x per-request: {spent}"
    );
}
