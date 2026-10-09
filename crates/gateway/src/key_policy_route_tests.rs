//! `OG-20` — the per-key policy, proven on EVERY dispatch route at the ONE place it is
//! enforced: admission's `Step::Policy` (`specs/OG-20-per-key-policy.md` §7 proofs 2, 4, 5).
//!
//! Each route's own `impl Route` is driven through `admit_with_claims` with its own body
//! type, so what is proven is the route's `Parsed::policy_request` + the shared step — the
//! two things a new route could get wrong. A refusal from admission means the handler
//! never ran: no BYOK lookup, no upstream request, no ledger row (`Refusal` doc). The
//! handler-level "nothing reached the upstream" proofs live with each route's own fixtures
//! (`passthrough::tests::og20_*`, `files_batches::tests::og20_*`).

use std::sync::Arc;

use axum::http::{HeaderMap, Method};
use bytes::Bytes;
use serde_json::{Value, json};

use crate::admission::{Refusal, Route, admit_with_claims};
use crate::auth::Claims;
use crate::handler_harness::{authed, test_state};
use crate::providers::ProviderRegistry;
use crate::server::AppState;

fn governed(doc: Value) -> Claims {
    Claims {
        governance: tracelane_shared::key_policy::Governance::from_columns(
            None,
            None,
            None,
            Some(&doc),
        )
        .map(Arc::new),
        ..crate::auth::dev_stub_claims(crate::auth::AuthMethod::ApiKey)
    }
}

fn ungoverned() -> Claims {
    crate::auth::dev_stub_claims(crate::auth::AuthMethod::ApiKey)
}

/// Deny every model AND the three providers the fixtures route to. On a route that knows
/// its model the model rule fires first; on one that does not (batch create, passthrough)
/// the provider rule — or, for passthrough, the unenforceable model rule — does.
fn deny_all_doc() -> Value {
    json!({
        "models": { "deny": ["*"] },
        "providers": { "deny": ["openai", "anthropic", "google"] }
    })
}

pub(crate) async fn run<R: Route>(
    state: &AppState,
    body: R::Body,
    claims: Claims,
) -> Result<(), Refusal> {
    run_with::<R>(state, &authed(), body, claims).await
}

pub(crate) async fn run_with<R: Route>(
    state: &AppState,
    headers: &HeaderMap,
    body: R::Body,
    claims: Claims,
) -> Result<(), Refusal> {
    match admit_with_claims::<R>(state, headers, body, claims).await {
        Ok(mut a) => {
            a.dispatch_guard.disarm();
            Ok(())
        }
        Err(r) => Err(r),
    }
}

fn policy_code(r: Result<(), Refusal>) -> Option<&'static str> {
    match r {
        Err(Refusal::Policy(d)) => Some(d.code),
        _ => None,
    }
}

fn state() -> AppState {
    test_state(ProviderRegistry::new().expect("registry"))
}

/// One body per route, each naming a model the deny-all policy refuses.
#[allow(clippy::too_many_lines)]
pub(crate) async fn every_route(
    state: &AppState,
    claims: impl Fn() -> Claims,
) -> Vec<(&'static str, Result<(), Refusal>)> {
    use crate::files_batches::{BatchIntake, BatchesCreate, FileIntake, FilesUpload};
    let mut out = Vec::new();
    out.push((
        "chat",
        run::<crate::admission::Chat>(
            state,
            json!({"model": "gpt-4o", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]}),
            claims(),
        )
        .await,
    ));
    out.push((
        "embeddings",
        run::<crate::admission::Embeddings>(
            state,
            json!({"model": "text-embedding-3-small", "input": "hi"}),
            claims(),
        )
        .await,
    ));
    out.push((
        "messages",
        run::<crate::anthropic_messages::Messages>(
            state,
            Bytes::from_static(
                br#"{"model":"claude-sonnet-4-5","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}"#,
            ),
            claims(),
        )
        .await,
    ));
    out.push((
        "responses",
        run::<crate::openai_responses::Responses>(
            state,
            Bytes::from_static(br#"{"model":"gpt-4o","input":"hi","max_output_tokens":5}"#),
            claims(),
        )
        .await,
    ));
    out.push((
        "gemini",
        run::<crate::gemini_native::Gemini>(
            state,
            crate::gemini_native::GeminiBody {
                model: "gemini-2.5-pro".into(),
                stream: false,
                alt_sse: false,
                raw: Bytes::from_static(
                    br#"{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"generationConfig":{"maxOutputTokens":5}}"#,
                ),
            },
            claims(),
        )
        .await,
    ));
    out.push((
        "moderations",
        run::<crate::media_routes::Moderations>(
            state,
            crate::media_routes::Intake {
                raw: Bytes::from_static(br#"{"model":"omni-moderation-latest","input":"hi"}"#),
                content_type: "application/json".into(),
                form: None,
            },
            claims(),
        )
        .await,
    ));
    let jsonl = Bytes::from_static(
        b"{\"custom_id\":\"a\",\"method\":\"POST\",\"url\":\"/v1/chat/completions\",\"body\":{\"model\":\"gpt-4o-mini\",\"max_tokens\":5,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}}\n",
    );
    let len = jsonl.len();
    out.push((
        "files (batch line)",
        run::<FilesUpload>(
            state,
            FileIntake::Batch {
                raw: jsonl,
                content_type: "multipart/form-data".into(),
                data: 0..len,
                provider_id: "openai",
                limits: crate::providers::translation_policy::media_limits(),
            },
            claims(),
        )
        .await,
    ));
    out.push((
        "batches",
        run::<BatchesCreate>(
            state,
            BatchIntake {
                raw: Bytes::from_static(
                    br#"{"input_file_id":"file-a","endpoint":"/v1/chat/completions","completion_window":"24h"}"#,
                ),
                provider_id: "openai",
            },
            claims(),
        )
        .await,
    ));
    out.push((
        "passthrough",
        run::<crate::passthrough::Passthrough>(
            state,
            crate::passthrough::PassthroughInput {
                provider: "openai".into(),
                raw_path: "v1/vector_stores".into(),
                method: Method::GET,
            },
            {
                let mut c = claims();
                c.key_scope = crate::auth::scope::KeyScope::Scoped(
                    [crate::auth::scope::Scope::Passthrough]
                        .into_iter()
                        .collect(),
                );
                c
            },
        )
        .await,
    ));
    out.push((
        "realtime",
        run::<crate::realtime::Realtime>(
            state,
            crate::realtime::RealtimeInput {
                model: Some("gpt-realtime-2.1".into()),
            },
            claims(),
        )
        .await,
    ));
    out
}

/// PROOF 2: a denied model (or provider) is refused on EVERY dispatch route — a batch-file
/// line included — before anything is charged, dispatched or ledgered.
#[tokio::test]
async fn og20_a_denied_model_is_refused_on_every_dispatch_route() {
    let state = state();
    let results = every_route(&state, || governed(deny_all_doc())).await;
    assert_eq!(results.len(), 10, "every dispatch route is in the matrix");
    for (route, r) in results {
        let want = match route {
            "batches" => "policy_provider_denied",
            "passthrough" => "policy_unenforceable",
            _ => "policy_model_denied",
        };
        assert_eq!(policy_code(r), Some(want), "{route}");
    }
    // Nothing reached the ledger: every refusal is before `Step::Audit`.
    assert_eq!(
        state
            .audit_chain
            .in_memory_seq(&crate::handler_harness::dev_tenant()),
        0
    );
}

/// PROOF 4b: ABSENT policy = today's behaviour. The SAME bodies, with no governance, are
/// never refused by the policy step (whatever else a fixture without upstreams says).
#[tokio::test]
async fn og20_no_policy_means_no_policy_refusal_on_any_route() {
    let state = state();
    for (route, r) in every_route(&state, ungoverned).await {
        assert_eq!(
            policy_code(r),
            None,
            "{route} refused by a policy it does not have"
        );
    }
}

/// PROOF 4a: an unparseable stored policy blocks — at admission as well as at auth.
#[tokio::test]
async fn og20_an_unparseable_policy_blocks_the_request() {
    let state = state();
    let r = run::<crate::admission::Chat>(
        &state,
        json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}),
        governed(json!({"models": {"allow": ["gpt-4o"]}, "rule_from_the_future": 1})),
    )
    .await;
    assert_eq!(policy_code(r), Some("policy_invalid"));
}

/// A batch file is judged LINE BY LINE: the refusal names the first failing line.
#[tokio::test]
async fn og20_the_first_denied_batch_line_is_named() {
    let state = state();
    let line = |m: &str| {
        format!(
            "{{\"custom_id\":\"{m}\",\"method\":\"POST\",\"url\":\"/v1/chat/completions\",\"body\":{{\"model\":\"{m}\",\"max_tokens\":5,\"messages\":[{{\"role\":\"user\",\"content\":\"hi\"}}]}}}}\n"
        )
    };
    let jsonl = Bytes::from(format!("{}\n{}", line("gpt-4o-mini"), line("gpt-4o")));
    let len = jsonl.len();
    let r = run::<crate::files_batches::FilesUpload>(
        &state,
        crate::files_batches::FileIntake::Batch {
            raw: jsonl,
            content_type: "multipart/form-data".into(),
            data: 0..len,
            provider_id: "openai",
            limits: crate::providers::translation_policy::media_limits(),
        },
        governed(json!({"models": {"deny": ["gpt-4o"]}})),
    )
    .await;
    match r {
        Err(Refusal::Policy(d)) => {
            assert_eq!((d.code, d.line), ("policy_model_denied", Some(3)));
            assert!(d.message.contains("line 3"), "{}", d.message);
        }
        other => panic!("expected a policy refusal, got {other:?}"),
    }
}

/// Token caps, body cap and required labels, through the chat route's real facts.
#[tokio::test]
async fn og20_caps_and_required_labels_are_enforced_with_their_codes() {
    let state = state();
    let chat = |max: Option<u64>| {
        let mut b =
            json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "x".repeat(400)}]});
        if let Some(m) = max {
            b["max_tokens"] = json!(m);
        }
        b
    };
    let code = policy_code;
    assert_eq!(
        code(
            run::<crate::admission::Chat>(
                &state,
                chat(Some(50)),
                governed(json!({"max_output_tokens": 10}))
            )
            .await
        ),
        Some("policy_max_output_tokens")
    );
    assert_eq!(
        code(
            run::<crate::admission::Chat>(
                &state,
                chat(None),
                governed(json!({"max_output_tokens": 10}))
            )
            .await
        ),
        Some("policy_max_output_tokens"),
        "an undeclared cap is refused under an output rule"
    );
    assert_eq!(
        code(
            run::<crate::admission::Chat>(
                &state,
                chat(Some(5)),
                governed(json!({"max_input_tokens": 10}))
            )
            .await
        ),
        Some("policy_max_input_tokens")
    );
    match run::<crate::admission::Chat>(
        &state,
        chat(Some(5)),
        governed(json!({"max_body_bytes": 64})),
    )
    .await
    {
        Err(r @ Refusal::Policy(_)) => {
            assert_eq!(r.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
        }
        other => panic!("expected 413, got {other:?}"),
    }
    let tags = governed(json!({"required_tags": ["prod"], "required_metadata_keys": ["team"]}));
    assert_eq!(
        code(run::<crate::admission::Chat>(&state, chat(Some(5)), tags.clone()).await),
        Some("policy_required_tag_missing")
    );
    let mut h = authed();
    h.insert("x-tracelane-tags", "prod".parse().unwrap());
    h.insert(
        "x-tracelane-metadata",
        r#"{"team":"core"}"#.parse().unwrap(),
    );
    assert_eq!(
        code(run_with::<crate::admission::Chat>(&state, &h, chat(Some(5)), tags).await),
        None,
        "present labels pass"
    );
}

/// PROOF 5: a WORKSPACE alias cannot launder a denied model — the resolver hands the
/// policy the alias TARGET.
#[test]
fn og20_a_workspace_alias_resolves_to_its_target_for_the_policy() {
    let ent = crate::entitlement_cache::ResolvedEntitlements {
        model_aliases: Arc::new([("fast".to_string(), "gpt-4o".to_string())].into()),
        ..crate::entitlement_cache::ResolvedEntitlements::deny_all()
    };
    let r = crate::admission::policy_resolve("fast", true, Some(&ent));
    assert_eq!(r.names, vec!["fast".to_string(), "gpt-4o".to_string()]);
    assert_eq!(r.allow_names, vec!["gpt-4o".to_string()]);
    assert_eq!(r.provider.as_deref(), Some("openai"));
    // A route that does not rewrite workspace aliases is judged on the name it dispatches.
    let r = crate::admission::policy_resolve("fast", false, Some(&ent));
    assert_eq!(r.allow_names, vec!["fast".to_string()]);
}

/// The rendered refusal on the OpenAI-shaped wire carries the code, the rule and the layer.
#[tokio::test]
async fn og20_the_refusal_body_names_code_rule_and_layer() {
    let state = state();
    let r = admit_with_claims::<crate::admission::Chat>(
        &state,
        &authed(),
        json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}),
        governed(json!({"models": {"allow": ["claude-*"]}})),
    )
    .await;
    let Err(refusal) = r else {
        panic!("expected a refusal")
    };
    let resp = crate::admission::Chat::refuse(refusal);
    assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
    let j = crate::handler_harness::body_json(resp).await;
    assert_eq!(j["error"], json!("policy_model_denied"));
    assert_eq!(j["rule"], json!("models"));
    assert_eq!(j["policy"], json!("key"));
    assert!(j["message"].as_str().unwrap().contains("gpt-4o"), "{j}");
}
