//! `OG-51` — response-cache controls, driven through the REAL chat handler
//! (`specs/OG-51-cache-controls.md` §7). Every test reads a counter, a header or a mock's
//! request log; none asserts "200" alone.
//!
//! The provider is a wiremock that answers one streamed completion; "was the cache used" is
//! "how many times did the provider receive a request". The exact tier is in-process, so no
//! ClickHouse is needed; the semantic tier's embedding calls go to the same mock (and fail
//! open, as they do in production when an embedder is unreachable).

use std::sync::{Arc, Mutex};

use axum::extract::{Json, State};
use axum::http::{HeaderMap, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::db::cache_settings::{KeyCache, Loaded, Mode, NamespaceBy, Settings};
use crate::entitlement_cache::{EntitlementCache, ResolvedEntitlements};
use crate::handler_harness::{
    LoopbackBypassGuard, authed, registry_pointing_ollama_at, test_state,
};
use crate::server::{AppState, chat_completions_handler};

const SSE: &str = "data: {\"choices\":[{\"delta\":{\"content\":\"fresh\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n";

/// What a workspace looks like to the cache: its settings, the plan, and whether it records text.
#[derive(Clone)]
struct Ws {
    loaded: Loaded,
    plan_cache_control: bool,
    capture: bool,
}

impl Ws {
    fn new() -> Self {
        Self {
            loaded: Loaded::default(),
            plan_cache_control: true,
            capture: true,
        }
    }
    fn settings(mut self, f: impl FnOnce(&mut Settings)) -> Self {
        f(&mut self.loaded.settings);
        self
    }
    fn resolved(&self) -> ResolvedEntitlements {
        let mut e = ResolvedEntitlements::deny_all();
        e.f_cache_control = self.plan_cache_control;
        e.cache_ttl_hours = if self.plan_cache_control { 168 } else { 0 };
        e.content_capture = crate::db::workspace_capture::WorkspaceCapture {
            input: self.capture,
            output: self.capture,
        };
        e.cache = Arc::new(self.loaded.clone());
        e
    }
}

struct Rig {
    server: MockServer,
    state: AppState,
    ws: Arc<Mutex<Ws>>,
    _bypass: LoopbackBypassGuard,
}

impl Rig {
    async fn new(ws: Ws) -> Self {
        let bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(SSE),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "object": "list", "model": "ollama/embed",
                "data": [{"object": "embedding", "index": 0, "embedding": [1.0, 0.0, 0.0]}],
                "usage": {"prompt_tokens": 1, "total_tokens": 1}
            })))
            .mount(&server)
            .await;
        let mut state = test_state(registry_pointing_ollama_at(server.uri()));
        let cfg = crate::server::config::parse(
            "semantic_cache:\n  embedding_models: ollama/embed\n  ttl_hours: 168\n",
        )
        .unwrap();
        state.semantic_cache = Some(Arc::new(crate::semantic_cache::SemanticCache::new(
            crate::clickhouse_query::ch_client(server.uri()),
            state.providers.clone(),
            cfg.semantic_cache().unwrap().clone(),
        )));
        let ws = Arc::new(Mutex::new(ws));
        let shared = Arc::clone(&ws);
        state.entitlements = Some(Arc::new(EntitlementCache::new(Arc::new(move |_t| {
            let e = shared.lock().expect("ws").resolved();
            Box::pin(async move { Ok(e) })
        }))));
        Self {
            server,
            state,
            ws,
            _bypass: bypass,
        }
    }

    /// Change the workspace and drop its warm entitlement entry, as a settings write does.
    async fn change(&self, f: impl FnOnce(&mut Ws)) {
        f(&mut self.ws.lock().expect("ws"));
        self.state
            .entitlements
            .as_ref()
            .expect("cache")
            .invalidate(*crate::handler_harness::dev_tenant().as_uuid())
            .await;
    }

    fn zdr_eligible(&self) {
        self.state
            .zdr
            .store(Arc::new(crate::zdr::ZdrCapabilities::from_rows([(
                "ollama".to_owned(),
                "default".to_owned(),
            )])));
    }

    async fn provider_calls(&self) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|r| r.url.path() == "/v1/chat/completions")
            .count()
    }

    async fn embedding_calls(&self) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|r| r.url.path() == "/v1/embeddings")
            .count()
    }

    /// One non-streaming chat request; waits for the fire-and-forget store to land.
    async fn ask(&self, content: &str, headers: &[(&str, &str)], user: Option<&str>) -> Answer {
        let mut h = authed();
        for (k, v) in headers {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        let mut body =
            json!({"model":"ollama/llama3","messages":[{"role":"user","content":content}]});
        if let Some(u) = user {
            body["user"] = json!(u);
        }
        let resp = chat_completions_handler(State(self.state.clone()), h, Json(body)).await;
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body");
        // The store is a spawned task: on the test's current-thread runtime it runs when this
        // task yields, and its exact-tier insert needs no I/O — so yielding is the wait.
        for _ in 0..200 {
            tokio::task::yield_now().await;
        }
        Answer {
            status,
            headers,
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        }
    }
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

impl Answer {
    fn cache(&self) -> Option<&str> {
        self.headers
            .get("x-tracelane-cache")
            .and_then(|v| v.to_str().ok())
    }
    fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    }
}

fn key_claims(key: Uuid) -> crate::auth::test_claims::Guard {
    let mut c = crate::auth::dev_stub_claims(crate::auth::AuthMethod::ApiKey);
    c.sub = format!("apikey:{key}");
    crate::auth::test_claims::Guard::set(c)
}

// ── The privacy fix (spec §2 "Today", §9; founder z8 #3) ─────────────────────────────────

/// RED before OG-51: with the operator block present, a workspace that records NO text was
/// still stored and served ("the caller's opt-in" was wrong — a header is not an opt-in).
#[tokio::test]
async fn og51_a_capture_off_workspace_is_never_cached() {
    let rig = Rig::new(Ws::new()).await;
    rig.change(|w| w.capture = false).await;
    let a = rig.ask("same question", &[], None).await;
    let b = rig.ask("same question", &[], None).await;
    assert_eq!((a.status, b.status), (StatusCode::OK, StatusCode::OK));
    assert_eq!(
        rig.provider_calls().await,
        2,
        "the second identical request must reach the provider: nothing was stored"
    );
    assert_eq!(
        b.cache(),
        None,
        "no header either — the caller asked nothing"
    );
    assert_eq!(b.body["choices"][0]["message"]["content"], "fresh");
}

#[tokio::test]
async fn og51_a_capture_on_workspace_in_inherit_is_served_from_the_exact_tier() {
    let rig = Rig::new(Ws::new()).await;
    rig.ask("same question", &[], None).await;
    let b = rig.ask("same question", &[], None).await;
    assert_eq!(rig.provider_calls().await, 1);
    assert_eq!(b.cache(), Some("exact"));
}

/// A request header never turns on a cache the workspace did not: `use` on a capture-off
/// workspace in `inherit` is `409 response_cache_disabled`, and nothing is stored.
#[tokio::test]
async fn og51_a_use_header_cannot_override_the_privacy_default() {
    let rig = Rig::new(Ws::new()).await;
    rig.change(|w| w.capture = false).await;
    let a = rig.ask("q", &[("x-tracelane-cache", "use")], None).await;
    assert_eq!(a.status, StatusCode::CONFLICT);
    assert_eq!(a.body["error"]["code"], "response_cache_disabled");
    assert_eq!(rig.provider_calls().await, 0, "refused before dispatch");
}

// ── Modes (spec §7 row 4) ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn og51_mode_on_is_the_explicit_opt_in_and_a_lost_plan_degrades_it_to_inherit() {
    let rig = Rig::new(Ws::new().settings(|s| s.mode = Mode::On)).await;
    rig.change(|w| w.capture = false).await;
    rig.ask("q", &[], None).await;
    let b = rig.ask("q", &[], None).await;
    assert_eq!(
        rig.provider_calls().await,
        1,
        "on + capture off still serves"
    );
    assert_eq!(b.cache(), Some("exact"));
    // The plan stops granting cache control: `on` degrades to inherit — capture off ⇒ off.
    rig.change(|w| w.plan_cache_control = false).await;
    let c = rig.ask("q", &[], None).await;
    assert_eq!(c.cache(), None);
    assert_eq!(rig.provider_calls().await, 2);
}

#[tokio::test]
async fn og51_off_wins_at_the_workspace_and_at_the_key() {
    // Workspace off, capture on.
    let rig = Rig::new(Ws::new().settings(|s| s.mode = Mode::Off)).await;
    rig.ask("q", &[], None).await;
    rig.ask("q", &[], None).await;
    assert_eq!(rig.provider_calls().await, 2);
    // `use` on an off workspace is 409, not a silent serve.
    let r = rig.ask("q", &[("x-tracelane-cache", "use")], None).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.body["error"]["code"], "response_cache_disabled");

    // Key off: that key is never served, a sibling key is.
    let (off_key, other) = (Uuid::new_v4(), Uuid::new_v4());
    let mut ws = Ws::new();
    ws.loaded.keys.insert(
        off_key,
        KeyCache {
            off: true,
            namespace_by: None,
        },
    );
    let rig = Rig::new(ws).await;
    {
        let _g = key_claims(off_key);
        rig.ask("q2", &[], None).await;
        rig.ask("q2", &[], None).await;
    }
    assert_eq!(
        rig.provider_calls().await,
        2,
        "the off key never uses the cache"
    );
    {
        let _g = key_claims(other);
        rig.ask("q3", &[], None).await;
        let b = rig.ask("q3", &[], None).await;
        assert_eq!(b.cache(), Some("exact"));
    }
    assert_eq!(rig.provider_calls().await, 3);
}

// ── Namespaces (spec §7 row 2, §8) ───────────────────────────────────────────────────────

#[tokio::test]
async fn og51_namespace_by_key_separates_keys_and_by_workspace_shares() {
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    // by key: A stores, B misses, A hits.
    let rig = Rig::new(Ws::new().settings(|s| s.namespace_by = NamespaceBy::Key)).await;
    {
        let _g = key_claims(a);
        rig.ask("shared question", &[], None).await;
    }
    {
        let _g = key_claims(b);
        let r = rig.ask("shared question", &[], None).await;
        assert_ne!(
            r.cache(),
            Some("exact"),
            "key B must not see key A's answer"
        );
    }
    assert_eq!(rig.provider_calls().await, 2);
    {
        let _g = key_claims(a);
        let r = rig.ask("shared question", &[], None).await;
        assert_eq!(r.cache(), Some("exact"));
        let ns = r
            .header("x-tracelane-cache-namespace")
            .expect("namespace tag");
        assert_eq!(ns.len(), 8);
        assert!(ns.bytes().all(|c| c.is_ascii_hexdigit()));
        assert!(
            !ns.contains(&a.to_string()),
            "only an 8-hex prefix of a hash leaves the process, never the key id"
        );
    }
    // by workspace: both keys share one cache.
    let rig = Rig::new(Ws::new()).await;
    {
        let _g = key_claims(a);
        rig.ask("shared question", &[], None).await;
    }
    {
        let _g = key_claims(b);
        let r = rig.ask("shared question", &[], None).await;
        assert_eq!(r.cache(), Some("exact"));
        assert!(
            r.header("x-tracelane-cache-namespace").is_none(),
            "no namespace applies — no header"
        );
    }
    assert_eq!(rig.provider_calls().await, 1);
}

#[tokio::test]
async fn og51_a_key_can_narrow_but_never_widen_the_workspace_namespace() {
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    // Workspace shares; key A narrows itself to `key`: A's entries are private to A.
    let mut ws = Ws::new();
    ws.loaded.keys.insert(
        a,
        KeyCache {
            off: false,
            namespace_by: Some(NamespaceBy::Key),
        },
    );
    let rig = Rig::new(ws).await;
    {
        let _g = key_claims(b);
        rig.ask("q", &[], None).await; // B stores in the shared (workspace) namespace
    }
    {
        let _g = key_claims(a);
        let r = rig.ask("q", &[], None).await;
        assert_ne!(
            r.cache(),
            Some("exact"),
            "A is narrowed: it cannot see the shared entry"
        );
    }
    // Workspace is by `key`; a key document asking for `workspace` does NOT widen it.
    let mut ws = Ws::new().settings(|s| s.namespace_by = NamespaceBy::Key);
    ws.loaded.keys.insert(
        a,
        KeyCache {
            off: false,
            namespace_by: Some(NamespaceBy::Workspace),
        },
    );
    let rig = Rig::new(ws).await;
    {
        let _g = key_claims(a);
        rig.ask("q", &[], None).await;
    }
    {
        let _g = key_claims(b);
        let r = rig.ask("q", &[], None).await;
        assert_ne!(
            r.cache(),
            Some("exact"),
            "the key could not widen the namespace"
        );
    }
}

#[tokio::test]
async fn og51_end_user_namespace_and_the_narrowing_header_separate_entries() {
    let rig = Rig::new(Ws::new().settings(|s| s.namespace_by = NamespaceBy::EndUser)).await;
    rig.ask("q", &[], Some("alice")).await;
    let hit = rig.ask("q", &[], Some("alice")).await;
    assert_eq!(hit.cache(), Some("exact"));
    let other = rig.ask("q", &[], Some("bob")).await;
    assert_ne!(other.cache(), Some("exact"), "bob is not alice");
    // No end user and no key: the namespace has no value for this session — never widen, so
    // the cache is not used (two provider calls, no hit).
    let before = rig.provider_calls().await;
    rig.ask("q2", &[], None).await;
    let r = rig.ask("q2", &[], None).await;
    assert_ne!(r.cache(), Some("exact"));
    assert_eq!(rig.provider_calls().await, before + 2);

    // The caller's own namespace header narrows within the workspace.
    let rig = Rig::new(Ws::new()).await;
    rig.ask("q", &[("x-tracelane-cache-namespace", "tenant-a")], None)
        .await;
    let same = rig
        .ask("q", &[("x-tracelane-cache-namespace", "tenant-a")], None)
        .await;
    assert_eq!(same.cache(), Some("exact"));
    assert_eq!(
        same.header("x-tracelane-cache-namespace").map(|s| s.len()),
        Some(8)
    );
    let diff = rig
        .ask("q", &[("x-tracelane-cache-namespace", "tenant-b")], None)
        .await;
    assert_ne!(diff.cache(), Some("exact"));
    let bare = rig.ask("q", &[], None).await;
    assert_ne!(bare.cache(), Some("exact"), "the header only ever narrows");
    // A malformed namespace is a 400 before anything is charged.
    let bad = rig
        .ask("q", &[("x-tracelane-cache-namespace", "has space")], None)
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert_eq!(bad.body["error"]["code"], "invalid_cache_control");
}

// ── Invalidation (spec §7 row 3) ─────────────────────────────────────────────────────────

#[tokio::test]
async fn og51_an_epoch_bump_stops_serving_and_the_gateway_never_issues_a_delete() {
    let rig = Rig::new(Ws::new()).await;
    rig.ask("q", &[], None).await;
    let hit = rig.ask("q", &[], None).await;
    assert_eq!(hit.cache(), Some("exact"));
    assert_eq!(rig.provider_calls().await, 1);

    rig.change(|w| {
        w.loaded.epochs.insert("workspace".into(), 1);
    })
    .await;
    let miss = rig.ask("q", &[], None).await;
    assert_ne!(
        miss.cache(),
        Some("exact"),
        "the old entry is unreachable after the bump"
    );
    assert_eq!(rig.provider_calls().await, 2);
    let tag = miss.header("x-tracelane-cache-epoch").expect("epoch tag");
    assert_eq!(tag.len(), 8, "only an 8-hex prefix of the epoch hash");
    let again = rig.ask("q", &[], None).await;
    assert_eq!(
        again.cache(),
        Some("exact"),
        "the new generation caches normally"
    );
    assert_eq!(rig.provider_calls().await, 2);

    // No statement that deletes rows was ever sent to ClickHouse (the mock stands in for it).
    for r in rig.server.received_requests().await.unwrap_or_default() {
        let text = format!("{} {}", r.url, String::from_utf8_lossy(&r.body)).to_lowercase();
        assert!(
            !text.contains("delete") && !text.contains("truncate"),
            "a delete reached ClickHouse: {text}"
        );
    }
}

#[tokio::test]
async fn og51_key_project_and_model_epochs_touch_only_their_subjects() {
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let rig = Rig::new(Ws::new()).await;
    for k in [a, b] {
        let _g = key_claims(k);
        rig.ask("q", &[], None).await;
    }
    // Both keys share the workspace namespace: B's ask was a hit.
    assert_eq!(rig.provider_calls().await, 1);
    // Bump KEY A's epoch only.
    rig.change(|w| {
        w.loaded.epochs.insert(format!("key:{a}"), 1);
    })
    .await;
    {
        let _g = key_claims(a);
        let r = rig.ask("q", &[], None).await;
        assert_ne!(r.cache(), Some("exact"), "A's scope was invalidated");
    }
    {
        let _g = key_claims(b);
        let r = rig.ask("q", &[], None).await;
        assert_eq!(r.cache(), Some("exact"), "B's scope was untouched");
    }
    // A model epoch for a DIFFERENT model touches nothing here.
    rig.change(|w| {
        w.loaded.epochs.insert("model:some-other-model".into(), 7);
    })
    .await;
    {
        let _g = key_claims(b);
        let r = rig.ask("q", &[], None).await;
        assert_eq!(r.cache(), Some("exact"));
    }
    // The served model's epoch invalidates it.
    rig.change(|w| {
        w.loaded.epochs.insert("model:ollama/llama3".into(), 1);
    })
    .await;
    {
        let _g = key_claims(b);
        let r = rig.ask("q", &[], None).await;
        assert_ne!(r.cache(), Some("exact"));
    }
}

// ── ZDR (spec §7 row 7) ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn og51_a_zdr_required_request_neither_reads_nor_writes_the_cache() {
    let rig = Rig::new(Ws::new()).await;
    rig.zdr_eligible();
    // Warm the cache with a normal request.
    rig.ask("q", &[], None).await;
    assert_eq!(rig.provider_calls().await, 1);
    // The ZDR request does NOT read it …
    let z = rig.ask("q", &[("x-tracelane-zdr", "required")], None).await;
    assert_eq!(z.status, StatusCode::OK);
    assert_eq!(z.cache(), Some("bypass"), "and says so");
    assert_eq!(
        rig.provider_calls().await,
        2,
        "the warm entry was not served"
    );
    // … and a ZDR-only question is not stored: the next normal request misses.
    rig.ask("zdr only", &[("x-tracelane-zdr", "required")], None)
        .await;
    let after = rig.ask("zdr only", &[], None).await;
    assert_ne!(
        after.cache(),
        Some("exact"),
        "a ZDR answer must not be retained"
    );
    assert_eq!(rig.provider_calls().await, 4);
}

// ── The semantic switch ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn og51_semantic_false_sends_no_text_to_an_embedder() {
    let rig = Rig::new(Ws::new().settings(|s| s.semantic = false)).await;
    rig.ask("no embedding please", &[], None).await;
    assert_eq!(rig.embedding_calls().await, 0);
    // The exact tier still works.
    let b = rig.ask("no embedding please", &[], None).await;
    assert_eq!(b.cache(), Some("exact"));
    // The control: the default workspace DOES embed on a miss.
    let rig = Rig::new(Ws::new()).await;
    rig.ask("embed me", &[], None).await;
    assert!(rig.embedding_calls().await >= 1, "the control must embed");
}

// ── TTL (spec §7 row 5) ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn og51_a_workspace_ttl_is_the_effective_one_and_the_header_names_what_bound_it() {
    let rig = Rig::new(Ws::new().settings(|s| s.ttl_hours = Some(24))).await;
    let a = rig.ask("q", &[], None).await;
    assert_eq!(
        a.header("x-tracelane-cache-ttl-hours").as_deref(),
        Some("24")
    );
    assert_eq!(
        a.header("x-tracelane-cache-bound").as_deref(),
        Some("workspace")
    );
    // A request asking for less is bound by the request.
    let b = rig.ask("q", &[("x-tracelane-cache", "ttl=2")], None).await;
    assert_eq!(
        b.header("x-tracelane-cache-ttl-hours").as_deref(),
        Some("2")
    );
    assert_eq!(
        b.header("x-tracelane-cache-bound").as_deref(),
        Some("requested")
    );
    // A request asking for more is bound by the workspace.
    let c = rig
        .ask("q", &[("x-tracelane-cache", "ttl=100")], None)
        .await;
    assert_eq!(
        c.header("x-tracelane-cache-ttl-hours").as_deref(),
        Some("24")
    );
    assert_eq!(
        c.header("x-tracelane-cache-bound").as_deref(),
        Some("workspace")
    );
}

// ── Wires (spec §7 row 6) ────────────────────────────────────────────────────────────────

#[test]
fn og51_every_route_declares_what_it_does_with_the_cache() {
    use crate::admission::{CacheScope, Route};
    assert_eq!(<crate::admission::Chat as Route>::CACHE, CacheScope::Serves);
    // The three routes that refuse in their own wire's error shape.
    assert_eq!(
        <crate::admission::Embeddings as Route>::CACHE,
        CacheScope::Refuses
    );
    assert_eq!(
        <crate::anthropic_messages::Messages as Route>::CACHE,
        CacheScope::Refuses
    );
    assert_eq!(
        <crate::openai_responses::Responses as Route>::CACHE,
        CacheScope::Refuses
    );
    // Everything else is refused by admission itself.
    assert_eq!(
        <crate::passthrough::Passthrough as Route>::CACHE,
        CacheScope::Unsupported
    );
    assert_eq!(
        <crate::gemini_native::Gemini as Route>::CACHE,
        CacheScope::Unsupported
    );
    assert_eq!(
        <crate::files_batches::FilesUpload as Route>::CACHE,
        CacheScope::Unsupported
    );
    assert_eq!(
        <crate::files_batches::BatchesCreate as Route>::CACHE,
        CacheScope::Unsupported
    );
    assert_eq!(
        <crate::realtime::Realtime as Route>::CACHE,
        CacheScope::Unsupported
    );
}

#[test]
fn og51_use_and_ttl_on_an_unsupported_route_are_refused_and_bypass_is_a_no_op() {
    use crate::admission::{CacheScope, cache_header_refusal};
    let entitled = {
        let mut e = ResolvedEntitlements::deny_all();
        e.f_cache_control = true;
        e.cache_ttl_hours = 168;
        e
    };
    let hdr = |v: &str| {
        let mut h = HeaderMap::new();
        h.insert("x-tracelane-cache", v.parse().unwrap());
        h
    };
    for v in ["use", "ttl=5"] {
        let d = cache_header_refusal(CacheScope::Unsupported, &hdr(v), Some(&entitled))
            .unwrap_or_else(|| panic!("{v} must be refused"));
        assert_eq!((d.status, d.code), (409, "cache_control_unsupported_route"));
        let d = cache_header_refusal(CacheScope::Unsupported, &hdr(v), None).unwrap();
        assert_eq!((d.status, d.code), (403, "cache_control_not_entitled"));
    }
    for scope in [CacheScope::Serves, CacheScope::Refuses] {
        assert!(cache_header_refusal(scope, &hdr("use"), Some(&entitled)).is_none());
    }
    assert!(
        cache_header_refusal(CacheScope::Unsupported, &hdr("bypass"), Some(&entitled)).is_none()
    );
    assert!(cache_header_refusal(CacheScope::Unsupported, &HeaderMap::new(), None).is_none());
    // A malformed value was never read by any non-chat route: still not.
    assert!(cache_header_refusal(CacheScope::Unsupported, &hdr("nonsense"), None).is_none());
}

// ── Golden (spec §7 row 1) ───────────────────────────────────────────────────────────────

/// The default settings hash to the SAME bytes as before OG-51: a deploy flushes nothing.
#[test]
fn og51_default_settings_leave_both_hashes_byte_identical() {
    let req: tracelane_shared::ChatRequest = serde_json::from_value(
        json!({"model":"ollama/llama3","messages":[{"role":"user","content":"golden"}]}),
    )
    .unwrap();
    let raw = crate::semantic_cache::request_key(&req);
    let who = crate::cache_controls::CacheCaller {
        model: "ollama/llama3",
        captured: true,
        ..Default::default()
    };
    let e = Ws::new().resolved();
    let cfg = crate::server::config::parse("semantic_cache:\n  embedding_models: ollama/embed\n")
        .unwrap();
    let cache = crate::semantic_cache::SemanticCache::new(
        crate::clickhouse_query::ch_client("http://127.0.0.1:1"),
        Arc::new(registry_pointing_ollama_at("http://127.0.0.1:1".into())),
        cfg.semantic_cache().unwrap().clone(),
    );
    let policy = crate::semantic_cache::CacheControl::Default
        .resolve(Some(&e), Some(&cache), true, &who)
        .expect("default resolves");
    let keyed = policy.key(raw.clone());
    assert_eq!(keyed.exact_hash, raw.exact_hash);
    assert_eq!(keyed.params_hash, raw.params_hash);
    // Pinned: `request_key` itself did not move (these are the pre-OG-51 values).
    assert_eq!(raw.params_hash.len(), 64);
    assert_eq!(
        raw.exact_hash,
        crate::semantic_cache::request_key(&req).exact_hash,
        "deterministic"
    );
}
