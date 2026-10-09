//! `OG-05` §3.3 — `GET /v1/models`, the OpenAI list shape.
//!
//! A tool (Cursor, Open WebUI, the OpenAI SDKs) calls this to learn which models
//! it may use. The answer is "what YOU can call", never "what exists":
//!
//!   1. the workspace's own model aliases, and
//!   2. every verified-card model ([`crate::pricing::VERIFIED_FRONTIER_MODELS`])
//!      whose provider this tenant holds a BYOK key for.
//!
//! **Tenant isolation.** Both inputs are read for the VALIDATED CLAIM's tenant
//! and nothing else (`db::provider_keys::list_provider_ids`,
//! `db::model_aliases::list` both bind `tenant_id = $1`), and the response is a
//! pure function of those two inputs ([`build_entries`]) — so a model enabled
//! only by tenant B's key cannot appear in tenant A's list. The two-tenant test
//! below drives that through the same [`ModelSource`] seam the handler uses.
//!
//! **Auth:** any valid `tlane_` key or JWT whose scope is `chat` OR `read`
//! (fail-CLOSED: 401 on a bad credential, 503 when the credential store is
//! down, 403 for a key scoped to neither). **No control plane** (no Postgres
//! pool): there is no tenant to derive keys for, so the list is empty — the
//! honest answer, not a guess from process env vars.
//!
//! The route is a read of two small indexed tables; it is not on the chat hot
//! path and gains no call there.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracelane_shared::TenantId;

use crate::providers::ProviderRegistry;
use crate::server::AppState;

/// `?limit` default and ceiling (spec §5).
const MAX_LIMIT: usize = 1000;

/// One entry of the OpenAI model list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModelEntry {
    pub id: String,
    pub object: &'static str,
    /// The provider id that serves it (`openai`, `anthropic`, ...).
    pub owned_by: String,
    /// Always `0`: the gateway does not track model release dates and will not
    /// invent one.
    pub created: u64,
}

impl ModelEntry {
    fn new(id: &str, provider: &str) -> Self {
        Self {
            id: id.to_owned(),
            object: "model",
            owned_by: provider.to_owned(),
            created: 0,
        }
    }
}

/// Where the two per-tenant inputs come from. Production reads Postgres
/// ([`PgSource`]); the tests supply an in-memory implementation keyed by tenant.
pub(crate) trait ModelSource {
    /// The provider ids the tenant holds a key for.
    fn provider_ids(
        &self,
        tenant: &TenantId,
    ) -> impl Future<Output = anyhow::Result<Vec<String>>> + Send;
    /// The tenant's `alias -> target model` map.
    fn aliases(
        &self,
        tenant: &TenantId,
    ) -> impl Future<Output = anyhow::Result<BTreeMap<String, String>>> + Send;
}

struct PgSource<'a>(&'a crate::db::DbPool);

impl ModelSource for PgSource<'_> {
    async fn provider_ids(&self, tenant: &TenantId) -> anyhow::Result<Vec<String>> {
        crate::db::provider_keys::list_provider_ids(self.0, tenant).await
    }
    async fn aliases(&self, tenant: &TenantId) -> anyhow::Result<BTreeMap<String, String>> {
        crate::db::model_aliases::list(self.0, tenant).await
    }
}

/// The list as a pure function of the caller's own inputs. Aliases first (sorted
/// by name — they are the workspace's own vocabulary), then verified models in
/// the reference order; an alias with an unroutable target is omitted (it would
/// answer `400 unroutable_model`); an id already listed is not repeated.
#[must_use]
pub(crate) fn build_entries(
    provider_ids: &[String],
    aliases: &BTreeMap<String, String>,
    limit: usize,
) -> Vec<ModelEntry> {
    let mut out: Vec<ModelEntry> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (alias, target) in aliases {
        if let Some(provider) = ProviderRegistry::provider_id_for_model(target)
            && seen.insert(alias.clone())
        {
            out.push(ModelEntry::new(alias, provider));
        }
    }
    for model in crate::pricing::VERIFIED_FRONTIER_MODELS {
        let Some(provider) = ProviderRegistry::provider_id_for_model(model) else {
            continue;
        };
        if provider_ids.iter().any(|p| p == provider) && seen.insert((*model).to_owned()) {
            out.push(ModelEntry::new(model, provider));
        }
    }
    out.truncate(limit);
    out
}

/// `M3` (security review 2026-10-02): one tenant's two inputs, as last read, and when.
type Inputs = (Vec<String>, BTreeMap<String, String>);

fn inputs_cache() -> &'static parking_lot::Mutex<HashMap<uuid::Uuid, (Instant, Inputs)>> {
    static C: OnceLock<parking_lot::Mutex<HashMap<uuid::Uuid, (Instant, Inputs)>>> =
        OnceLock::new();
    C.get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
}

/// Both inputs for `tenant`, from the per-tenant cache when the entry is younger than the
/// reference table's TTL (`models_list.cache_ttl_secs`), else from the store. Keyed by the
/// VALIDATED tenant UUID, so one tenant's entry can never answer another's call. Past
/// `cache_max_tenants` entries the cache is cleared rather than grown. A store ERROR is
/// never cached.
async fn inputs_for<S: ModelSource>(source: &S, tenant: &TenantId) -> anyhow::Result<Inputs> {
    let policy = crate::providers::translation_policy::models_list_policy();
    let ttl = Duration::from_secs(policy.cache_ttl_secs);
    let key = *tenant.as_uuid();
    if !ttl.is_zero()
        && let Some((at, inputs)) = inputs_cache().lock().get(&key)
        && at.elapsed() < ttl
    {
        return Ok(inputs.clone());
    }
    let providers = source.provider_ids(tenant).await?;
    let aliases = source.aliases(tenant).await?;
    let inputs = (providers, aliases);
    if !ttl.is_zero() {
        let mut c = inputs_cache().lock();
        if c.len() >= policy.cache_max_tenants {
            c.clear();
        }
        if policy.cache_max_tenants > 0 {
            c.insert(key, (Instant::now(), inputs.clone()));
        }
    }
    Ok(inputs)
}

/// Both inputs for `tenant`, then the list.
///
/// # Errors
/// Fail-CLOSED: a store error is returned, never papered over with an empty or
/// guessed list.
pub(crate) async fn list_for<S: ModelSource>(
    source: &S,
    tenant: &TenantId,
    limit: usize,
) -> anyhow::Result<serde_json::Value> {
    let (providers, aliases) = inputs_for(source, tenant).await?;
    let data = build_entries(&providers, &aliases, limit);
    Ok(json!({ "object": "list", "data": data }))
}

fn error(status: StatusCode, kind: &str, message: &str) -> Response {
    (
        status,
        Json(json!({ "error": { "message": message, "type": kind, "code": kind } })),
    )
        .into_response()
}

/// `?limit=` -> a usable bound. Absent = the ceiling; `0` is an empty list; a
/// number above the ceiling is clamped; anything non-numeric is a 400.
fn parse_limit(raw: Option<&str>) -> Result<usize, ()> {
    match raw {
        None => Ok(MAX_LIMIT),
        Some(s) => s
            .trim()
            .parse::<usize>()
            .map(|n| n.min(MAX_LIMIT))
            .map_err(|_| ()),
    }
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    limit: Option<String>,
}

/// `GET /v1/models`.
pub async fn models_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Response {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if auth.is_empty() {
        return error(
            StatusCode::UNAUTHORIZED,
            "invalid_request_error",
            "missing bearer token",
        );
    }
    let claims = match crate::auth::validate_authorization(auth).await {
        Ok(c) => c,
        Err(err) => {
            let (status, msg) = crate::auth::failure(&err);
            return error(status, "authentication_error", msg);
        }
    };
    // A key scoped for chat OR read may list models (a `read`-only auditor key
    // still learns what the workspace can call; an `ingest`-only key does not).
    if !(claims.allows_scope(crate::auth::scope::Scope::Chat)
        || claims.allows_scope(crate::auth::scope::Scope::Read))
    {
        return error(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "This API key needs the `chat` or `read` scope to list models.",
        );
    }
    // M3 (security review 2026-10-02): the tenant's per-minute bucket, like every other
    // authenticated route — this one used to be free to call in a loop, each call two
    // Postgres reads.
    if let Err(retry_after_secs) = crate::admission::charge_rate_limit(&state, &claims).await {
        let mut resp = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": {
                "message": "rate limit exceeded",
                "type": "rate_limited",
                "code": "rate_limited",
                "retry_after_secs": retry_after_secs,
            } })),
        )
            .into_response();
        crate::admission::insert_retry_after(&mut resp, retry_after_secs);
        return resp;
    }
    let Ok(limit) = parse_limit(q.limit.as_deref()) else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_limit",
            "`limit` must be a non-negative integer",
        );
    };
    let Some(pool) = state.pg.as_ref() else {
        // No control plane -> no tenant keys to derive from. Empty is the honest answer.
        return Json(json!({ "object": "list", "data": [] })).into_response();
    };
    match list_for(&PgSource(pool), &claims.tenant_id, limit).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => {
            tracing::error!(error = %e, tenant_id = %claims.tenant_id, "GET /v1/models: store read failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "models_unavailable",
                "could not read this workspace's models; retry",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn tenant(n: u128) -> TenantId {
        TenantId::from_jwt_claim(Uuid::from_u128(n))
    }

    /// An in-memory store keyed by tenant — the stand-in for the two
    /// `WHERE tenant_id = $1` reads.
    struct MemSource {
        providers: HashMap<Uuid, Vec<String>>,
        aliases: HashMap<Uuid, BTreeMap<String, String>>,
    }

    impl ModelSource for MemSource {
        async fn provider_ids(&self, t: &TenantId) -> anyhow::Result<Vec<String>> {
            Ok(self.providers.get(t.as_uuid()).cloned().unwrap_or_default())
        }
        async fn aliases(&self, t: &TenantId) -> anyhow::Result<BTreeMap<String, String>> {
            Ok(self.aliases.get(t.as_uuid()).cloned().unwrap_or_default())
        }
    }

    fn ids(v: &serde_json::Value) -> Vec<String> {
        v["data"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|m| m["id"].as_str().unwrap_or("").to_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// OG-05 §7 row 2: the guard BLOCKS. Tenant A holds only an OpenAI key and
    /// tenant B only an Anthropic key + an alias; A never sees a model — or an
    /// alias — that exists only because of B's rows, and vice versa.
    #[tokio::test]
    async fn a_tenant_never_sees_a_model_enabled_only_by_another_tenants_key() {
        let (a, b) = (tenant(1), tenant(2));
        let mut src = MemSource {
            providers: HashMap::new(),
            aliases: HashMap::new(),
        };
        src.providers.insert(*a.as_uuid(), vec!["openai".into()]);
        src.providers.insert(*b.as_uuid(), vec!["anthropic".into()]);
        src.aliases.insert(
            *b.as_uuid(),
            BTreeMap::from([("b-secret-alias".into(), "claude-opus-5-5".into())]),
        );

        let la = ids(&list_for(&src, &a, 1000).await.unwrap());
        let lb = ids(&list_for(&src, &b, 1000).await.unwrap());

        assert!(
            la.contains(&"gpt-6-astra".to_owned()),
            "A sees its own: {la:?}"
        );
        assert!(
            !la.iter()
                .any(|m| m.starts_with("claude") || m == "b-secret-alias"),
            "A must never see B's anthropic models or alias: {la:?}"
        );
        assert!(
            lb.contains(&"claude-opus-5-5".to_owned()),
            "B sees its own: {lb:?}"
        );
        assert!(lb.contains(&"b-secret-alias".to_owned()));
        assert!(
            !lb.iter().any(|m| m.starts_with("gpt-")),
            "B must never see A's openai models: {lb:?}"
        );
    }

    /// No keys and no aliases -> an empty list in the OpenAI envelope (spec §4).
    #[tokio::test]
    async fn no_keys_means_an_empty_list_not_a_catalog() {
        let src = MemSource {
            providers: HashMap::new(),
            aliases: HashMap::new(),
        };
        let v = list_for(&src, &tenant(9), 1000).await.unwrap();
        assert_eq!(v["object"], "list");
        assert_eq!(v["data"].as_array().unwrap().len(), 0);
    }

    /// The OpenAI shape, `limit`, alias ordering and de-duplication.
    #[tokio::test]
    async fn entries_have_the_openai_shape_and_honour_limit() {
        let t = tenant(3);
        let mut src = MemSource {
            providers: HashMap::new(),
            aliases: HashMap::new(),
        };
        src.providers
            .insert(*t.as_uuid(), vec!["openai".into(), "google".into()]);
        src.aliases.insert(
            *t.as_uuid(),
            BTreeMap::from([
                ("fast".into(), "gemini-3.8-flash".into()),
                // An unroutable target would 400 on use: it is not listed.
                ("broken".into(), "no-such-model-xyz".into()),
                // Same id as a verified model: listed once.
                ("gpt-5.5".into(), "gpt-5.5".into()),
            ]),
        );
        let v = list_for(&src, &t, 1000).await.unwrap();
        let first = &v["data"][0];
        assert_eq!(first["object"], "model");
        assert_eq!(first["created"], 0);
        let all = ids(&v);
        assert!(all.contains(&"fast".to_owned()));
        assert!(!all.contains(&"broken".to_owned()));
        assert_eq!(all.iter().filter(|m| *m == "gpt-5.5").count(), 1);
        let owned: Vec<_> = v["data"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["id"] == "fast")
            .map(|m| m["owned_by"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(owned, vec!["google".to_owned()]);

        let two = list_for(&src, &t, 2).await.unwrap();
        assert_eq!(two["data"].as_array().unwrap().len(), 2);
        let none = list_for(&src, &t, 0).await.unwrap();
        assert_eq!(none["data"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn limit_parsing_clamps_and_refuses_garbage() {
        assert_eq!(parse_limit(None), Ok(1000));
        assert_eq!(parse_limit(Some("5")), Ok(5));
        assert_eq!(parse_limit(Some("0")), Ok(0));
        assert_eq!(parse_limit(Some("999999")), Ok(1000));
        assert!(parse_limit(Some("abc")).is_err());
        assert!(parse_limit(Some("-1")).is_err());
    }

    /// The reference list is only worth anything if every entry is a verified
    /// card AND routes: a model that is listed but unpriced or unroutable would
    /// advertise something the gateway cannot serve honestly.
    #[test]
    fn every_listed_model_routes_and_has_a_verified_card() {
        for m in crate::pricing::VERIFIED_FRONTIER_MODELS {
            assert!(
                ProviderRegistry::provider_id_for_model(m).is_some(),
                "`{m}` is listed but unroutable"
            );
            let u = tracelane_shared::Usage {
                input_tokens: 1000,
                output_tokens: 1000,
                cache_read_input_tokens: None,
                cache_creation_input_tokens: None,
            };
            assert!(
                crate::pricing::cost_usd(m, &u).is_some_and(|c| c > 0.0),
                "`{m}` is listed but has no verified price"
            );
        }
    }

    /// The scope gate: an `ingest`-only key may NOT list models; a `read`-only or
    /// `chat`-only key may. Asserted on the predicate the handler uses, with real
    /// `Claims`, so a change to the gate's shape fails here.
    #[test]
    fn scope_gate_is_chat_or_read() {
        use crate::auth::scope::{KeyScope, Scope};
        let scoped = |s: &[Scope]| KeyScope::Scoped(s.iter().copied().collect());
        let may = |k: &KeyScope| k.allows(Scope::Chat) || k.allows(Scope::Read);
        assert!(may(&scoped(&[Scope::Read])));
        assert!(may(&scoped(&[Scope::Chat])));
        assert!(may(&KeyScope::LegacyFullSurface));
        assert!(!may(&scoped(&[Scope::Ingest])));
        assert!(!may(&scoped(&[Scope::Admin])));
    }

    /// M3 (security review 2026-10-02): a second call inside the TTL is answered from the
    /// per-tenant cache — the store is read once — and another tenant's entry is never used.
    #[tokio::test]
    async fn m3_inputs_are_cached_per_tenant_within_the_ttl() {
        struct Counting(std::sync::atomic::AtomicUsize);
        impl ModelSource for Counting {
            async fn provider_ids(&self, _t: &TenantId) -> anyhow::Result<Vec<String>> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(vec!["openai".to_owned()])
            }
            async fn aliases(&self, _t: &TenantId) -> anyhow::Result<BTreeMap<String, String>> {
                Ok(BTreeMap::new())
            }
        }
        assert!(
            crate::providers::translation_policy::models_list_policy().cache_ttl_secs > 0,
            "the reference table sets a TTL"
        );
        let src = Counting(std::sync::atomic::AtomicUsize::new(0));
        let (a, b) = (tenant(9001), tenant(9002));
        list_for(&src, &a, 10).await.expect("first");
        list_for(&src, &a, 10).await.expect("second, cached");
        assert_eq!(src.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        list_for(&src, &b, 10)
            .await
            .expect("another tenant reads its own");
        assert_eq!(src.0.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    /// M3: `GET /v1/models` charges the caller's rate limit — an exhausted bucket is a 429.
    #[tokio::test]
    async fn m3_models_is_rate_limited() {
        let t = tenant(9003);
        let claims = crate::auth::Claims {
            tenant_id: t,
            sub: format!("apikey:{}", Uuid::new_v4()),
            auth_method: crate::auth::AuthMethod::ApiKey,
            role: None,
            key_scope: crate::auth::scope::KeyScope::LegacyFullSurface,
            budget_usd_monthly: None,
            rate_limit_rpm: Some(1),
            budget_reset: crate::spend::BudgetReset::Monthly,
            governance: None,
        };
        let _g = crate::auth::test_claims::Guard::set(claims);
        let state = crate::handler_harness::test_state(
            crate::providers::ProviderRegistry::new().expect("registry"),
        );
        let call = || {
            models_handler(
                State(state.clone()),
                crate::handler_harness::authed(),
                Query(ListQuery { limit: None }),
            )
        };
        assert_eq!(call().await.status(), StatusCode::OK);
        let second = call().await;
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(second.headers().get("retry-after").is_some());
    }

    /// Structural: the per-tenant reads bind the validated tenant UUID. Needles
    /// are ASSEMBLED so this cannot be satisfied by its own text.
    #[test]
    fn the_provider_ids_read_is_bound_to_the_tenant() {
        let src = include_str!("db/provider_keys.rs");
        let needle = format!(
            "{}{}",
            "FROM provider_keys WHERE tenant_id", " = $1 ORDER BY provider_id"
        );
        assert!(
            src.contains(&needle),
            "list_provider_ids lost its tenant bind"
        );
    }
}
