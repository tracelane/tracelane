//! Manual credential checks and span-derived rejection history for provider keys.
//! Only status-level model-probe results are retained; model bodies are never read.
use crate::clickhouse_query::{PlanTier, TenantQuery};
use crate::db::provider_keys::{KeyValidation, ProviderKeyRow};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use tracelane_shared::TenantId;

// A control-plane probe must finish promptly; this is a transport timeout,
// not a product allowance. No retry: one real-key request and one invalid-key control.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Serialize)]
struct ProbeResult {
    status: &'static str,
    reason: &'static str,
}
#[derive(Clone, Copy)]
enum ProbeAuth {
    Bearer,
    Anthropic,
    Google,
    Azure,
}
struct Probe {
    url: String,
    auth: ProbeAuth,
}

/// Every catalog row uses the same API root as its OpenAI-compatible adapter.
/// Differential probes distinguish authenticated endpoints from public catalogs.
fn probe_for(provider: &str) -> Option<Probe> {
    let (base, suffix, auth) = match provider {
        "anthropic" => (
            std::env::var("ANTHROPIC_BASE_URL")
                .unwrap_or_else(|_| "https://api.anthropic.com".into()),
            "/v1/models",
            ProbeAuth::Anthropic,
        ),
        "google" => (
            std::env::var("GOOGLE_AI_BASE_URL")
                .unwrap_or_else(|_| "https://generativelanguage.googleapis.com".into()),
            "/v1beta/models",
            ProbeAuth::Google,
        ),
        "cohere" => (
            std::env::var("COHERE_BASE_URL")
                .unwrap_or_else(|_| "https://api.cohere.com/v2".into())
                .trim_end_matches('/')
                .trim_end_matches("/v2")
                .to_owned(),
            "/v1/models",
            ProbeAuth::Bearer,
        ),
        "azure" => {
            return Some(Probe {
                url: crate::providers::azure::AzureOpenAiProvider::new()
                    .ok()?
                    .models_url()
                    .ok()?,
                auth: ProbeAuth::Azure,
            });
        }
        _ => (
            crate::providers::catalog::by_id(provider)?.base_url(),
            "/v1/models",
            ProbeAuth::Bearer,
        ),
    };
    Some(Probe {
        url: format!("{}{suffix}", base.trim_end_matches('/')),
        auth,
    })
}

#[tracing::instrument(skip(probe, secret, pinned))]
async fn request_probe(
    probe: &Probe,
    secret: &SecretString,
    pinned: crate::ssrf_guard::PinnedTarget,
) -> ProbeResult {
    let client = match pinned
        .pin(crate::ssrf_guard::safe_client_builder())
        .timeout(PROBE_TIMEOUT)
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            return ProbeResult {
                status: "unavailable",
                reason: "transport_failed",
            };
        }
    };
    // Both requests share the same DNS-pinned client and redirect policy.
    let garbage = SecretString::from(format!("tracelane-invalid-{}", uuid::Uuid::new_v4()));
    let (actual, control) = tokio::join!(
        probe_status(&client, probe, secret),
        probe_status(&client, probe, &garbage),
    );
    let result = match (actual, control) {
        (Ok(200), Ok(401 | 403)) => ProbeResult {
            status: "valid",
            reason: "authenticated",
        },
        (Ok(200), Ok(200)) => ProbeResult {
            status: "cannot_validate",
            reason: "public_catalog",
        },
        (Ok(401 | 403), Ok(401 | 403)) => ProbeResult {
            status: "rejected",
            reason: "authentication_rejected",
        },
        (Ok(429), _) | (_, Ok(429)) => ProbeResult {
            status: "unavailable",
            reason: "rate_limited",
        },
        (Err(reason), _) | (_, Err(reason)) => ProbeResult {
            status: "unavailable",
            reason,
        },
        _ => ProbeResult {
            status: "cannot_validate",
            reason: "inconclusive_probe",
        },
    };
    tracing::debug!(
        status = result.status,
        reason = result.reason,
        "provider credential check completed"
    );
    result
}

#[tracing::instrument(skip(client, probe, secret))]
async fn probe_status(
    client: &reqwest::Client,
    probe: &Probe,
    secret: &SecretString,
) -> Result<u16, &'static str> {
    let request = client.get(&probe.url);
    let mut value = reqwest::header::HeaderValue::from_str(secret.expose_secret())
        .map_err(|_| "credential_malformed")?;
    value.set_sensitive(true);
    let request = match probe.auth {
        ProbeAuth::Bearer => request.bearer_auth(secret.expose_secret()),
        ProbeAuth::Anthropic => request
            .header("x-api-key", value)
            .header("anthropic-version", "2023-06-01"),
        ProbeAuth::Google => request.header("x-goog-api-key", value),
        ProbeAuth::Azure => request.header("api-key", value),
    };
    // Bodies and transport errors can echo credentials; never read/format them.
    request
        .send()
        .await
        .map(|response| response.status().as_u16())
        .map_err(|_| "transport_failed")
}

#[tracing::instrument(skip(provider, secret, tenant))]
async fn check(provider: &str, secret: &SecretString, tenant: &TenantId) -> ProbeResult {
    if provider == "bedrock" {
        return ProbeResult {
            status: "cannot_validate",
            reason: "no_tenant_credential",
        };
    }
    let vertex_token;
    let probe = if provider == "vertex" {
        let credentials = async {
            crate::providers::vertex::VertexProvider::new()?
                .models_probe(secret.expose_secret(), tenant)
                .await
        };
        match tokio::time::timeout(PROBE_TIMEOUT, credentials).await {
            Ok(Ok((url, token))) => {
                vertex_token = token;
                Probe {
                    url,
                    auth: ProbeAuth::Bearer,
                }
            }
            Ok(Err(error)) => {
                let rejected = error
                    .downcast_ref::<crate::providers::ProviderHttpError>()
                    .is_some_and(|e| matches!(e.status, 400 | 401 | 403));
                return ProbeResult {
                    status: if rejected {
                        "rejected"
                    } else {
                        "cannot_validate"
                    },
                    reason: "token_exchange_failed",
                };
            }
            Err(_) => {
                return ProbeResult {
                    status: "unavailable",
                    reason: "token_exchange_failed",
                };
            }
        }
    } else {
        vertex_token = SecretString::from("");
        let Some(probe) = probe_for(provider) else {
            return ProbeResult {
                status: "cannot_validate",
                reason: "unknown_provider",
            };
        };
        probe
    };
    let credential = if provider == "vertex" {
        &vertex_token
    } else {
        secret
    };
    if !probe.url.starts_with("https://") {
        return ProbeResult {
            status: "unavailable",
            reason: "target_blocked",
        };
    }
    let target = match tokio::time::timeout(
        PROBE_TIMEOUT,
        crate::ssrf_guard::validate_url_pinned(&probe.url),
    )
    .await
    {
        Ok(Ok(target)) => target,
        _ => {
            return ProbeResult {
                status: "unavailable",
                reason: "target_blocked",
            };
        }
    };
    request_probe(&probe, credential, target).await
}

#[derive(Clone)]
pub struct ValidationState {
    pub pool: deadpool_postgres::Pool,
}
pub fn routes() -> Router<ValidationState> {
    Router::new().route("/v1/provider-keys/{id}/validate", post(validate))
}

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({"error":message}))).into_response()
}

/// Owner-only, tenant-scoped and fail CLOSED on auth, decrypt and storage failures.
#[tracing::instrument(skip(headers, state, id))]
async fn validate(
    headers: HeaderMap,
    State(state): State<ValidationState>,
    Path(id): Path<String>,
) -> Response {
    let auth = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let claims = match crate::auth::validate_authorization(auth).await {
        Ok(claims) => claims,
        Err(e) => {
            let (status, message) = crate::auth::failure(&e);
            return error(status, message);
        }
    };
    if !claims.is_verified_owner() {
        return error(StatusCode::FORBIDDEN, "workspace owner required");
    }
    let source = match crate::db::provider_keys::get(&state.pool, &claims.tenant_id, &id).await {
        Ok(Some(row)) => row,
        Ok(None) => return error(StatusCode::NOT_FOUND, "provider key not found"),
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "provider key unavailable"),
    };
    let Some(master) = crate::byok::master_key() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "key encryption unavailable",
        );
    };
    let aad = crate::byok::provider_key_aad(&claims.tenant_id, &id);
    let secret = match master.decrypt_with_context(&source.ciphertext_b64, &aad) {
        Ok(secret) => secret,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "provider key unavailable"),
    };
    let result = check(&id, &secret, &claims.tenant_id).await;
    let result = KeyValidation {
        status: result.status.into(),
        reason: result.reason.into(),
        checked_at: chrono::Utc::now(),
    };
    match crate::db::provider_keys::record_validation(
        &state.pool,
        &claims.tenant_id,
        &source,
        &claims.sub,
        &result,
    )
    .await
    {
        Ok(true) => (
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(serde_json::json!({
                "status": result.status, "reason": result.reason,
                "checked_at": result.checked_at, "saved_at": source.saved_at,
            })),
        )
            .into_response(),
        Ok(false) => error(
            StatusCode::CONFLICT,
            "provider key changed during validation",
        ),
        Err(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "could not record validation",
        ),
    }
}

#[derive(Deserialize, clickhouse::Row)]
pub struct Rejection {
    pub provider: String,
    pub rejected_at_us: i64,
}

fn rejection_sql() -> &'static str {
    "SELECT JSONExtractString(attributes, 'gen_ai_provider_name') AS provider,
        toUnixTimestamp64Micro(max(start_time)) AS rejected_at_us
     FROM tracelane.spans FINAL
     WHERE tenant_id = ? AND start_time >= fromUnixTimestamp64Micro(?) AND start_time <= now64(6)
       AND status_message = 'provider_key_rejected'
       AND JSONExtractString(attributes, 'gen_ai_provider_name') IN ?
     GROUP BY provider LIMIT ?"
}

/// One capped read over retained spans since the earliest saved key in this list.
///
/// `tier` is the TENANT'S OWN tier, resolved by the caller through
/// [`crate::clickhouse_query::tier_for_tenant`] — never a literal. SRE register
/// #20 is the reason: a hardcoded `PlanTier::Builder` here caps a Team or
/// Business tenant's read at Builder's limits whatever they pay for.
/// # Errors
/// Fail CLOSED as unavailable history; callers must not turn an error into "no rejection".
pub async fn rejections(
    ch: &clickhouse::Client,
    tenant: &TenantId,
    keys: &[ProviderKeyRow],
    tier: PlanTier,
) -> Result<Vec<Rejection>, clickhouse::error::Error> {
    let Some(since) = keys.iter().map(|key| key.saved_at.timestamp_micros()).min() else {
        return Ok(vec![]);
    };
    let providers: Vec<&str> = keys
        .iter()
        .map(|key| telemetry_provider(&key.provider_id))
        .collect();
    let capped = TenantQuery::new(rejection_sql(), tier).sql_with_settings();
    ch.query(&capped)
        .bind(tenant.to_string())
        .bind(since)
        .bind(providers)
        .bind(keys.len() as u64)
        .fetch_all()
        .await
}

fn telemetry_provider(provider: &str) -> &str {
    match provider {
        "vertex" => "gcp_vertex_ai",
        "bedrock" => "aws_bedrock",
        other => other,
    }
}

pub fn last_rejected(
    key: &ProviderKeyRow,
    rejections: &[Rejection],
) -> Option<chrono::DateTime<chrono::Utc>> {
    // Bedrock ignores the tenant's stored value and uses gateway AWS credentials.
    if key.provider_id == "bedrock" {
        return None;
    }
    rejections
        .iter()
        .find(|r| r.provider == telemetry_provider(&key.provider_id))
        .and_then(|r| chrono::DateTime::from_timestamp_micros(r.rejected_at_us))
        .filter(|at| *at >= key.saved_at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing::instrument::WithSubscriber as _;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    #[test]
    fn every_catalog_provider_has_a_models_probe() {
        for provider in crate::providers::catalog::providers() {
            let probe = probe_for(provider.id)
                .unwrap_or_else(|| panic!("{} has no credential probe", provider.id));
            assert!(
                probe.url.ends_with("/models"),
                "{} must probe its models catalog",
                provider.id
            );
        }
    }

    #[tokio::test]
    async fn public_catalog_cannot_validate_a_credential() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let probe = Probe {
            url: format!("http://provider.test:{}/models", server.address().port()),
            auth: ProbeAuth::Bearer,
        };
        let target =
            crate::ssrf_guard::PinnedTarget::for_test("provider.test", vec![*server.address()]);
        let result = request_probe(&probe, &SecretString::from("unit-test-real-key"), target).await;
        assert_eq!(
            result.status, "cannot_validate",
            "two public 200s do not authenticate the saved key"
        );
        assert_eq!(result.reason, "public_catalog");
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn bedrock_has_no_tenant_credential_to_validate() {
        let result = check(
            "bedrock",
            &SecretString::from("ignored-unit-test-key"),
            &TenantId::from_jwt_claim(uuid::Uuid::new_v4()),
        )
        .await;
        assert_eq!(result.status, "cannot_validate");
        assert_eq!(result.reason, "no_tenant_credential");
    }

    #[tokio::test]
    async fn every_catalog_row_runs_real_and_invalid_key_controls() {
        let server = MockServer::start().await;
        let secret = SecretString::from("unit-test-catalog-key");
        for provider in crate::providers::catalog::providers() {
            let original = probe_for(provider.id).unwrap();
            let original_url = reqwest::Url::parse(&original.url).unwrap();
            // Preserve the catalog-derived path while pinning only the destination
            // to the local server. No real provider or credential is contacted.
            let probe = Probe {
                url: format!(
                    "http://provider.test:{}{}",
                    server.address().port(),
                    original_url.path()
                ),
                auth: original.auth,
            };
            for (real, control, expected) in [
                (200, 401, "valid"),
                (200, 403, "valid"),
                (200, 200, "cannot_validate"),
                (401, 401, "rejected"),
                (403, 403, "rejected"),
                (200, 500, "cannot_validate"),
            ] {
                server.reset().await;
                Mock::given(method("GET"))
                    .and(path(original_url.path()))
                    .respond_with(ResponseTemplate::new(control))
                    .with_priority(2)
                    .expect(1)
                    .mount(&server)
                    .await;
                Mock::given(method("GET"))
                    .and(path(original_url.path()))
                    .and(header("authorization", "Bearer unit-test-catalog-key"))
                    .respond_with(ResponseTemplate::new(real))
                    .with_priority(1)
                    .expect(1)
                    .mount(&server)
                    .await;
                let target = crate::ssrf_guard::PinnedTarget::for_test(
                    "provider.test",
                    vec![*server.address()],
                );
                let result = request_probe(&probe, &secret, target).await;
                assert_eq!(
                    result.status, expected,
                    "{} real={real} control={control}",
                    provider.id
                );
                assert_eq!(server.received_requests().await.unwrap().len(), 2);
                server.verify().await;
            }
        }
    }

    #[derive(Clone)]
    struct LogWriter(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for LogWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogWriter {
        type Writer = Self;
        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }

    #[tokio::test]
    async fn provider_validation_classifies_status_without_logging_or_storing_body() {
        let server = MockServer::start().await;
        let secret = SecretString::from("unit_test_provider_secret_DO_NOT_LOG");
        let logs = LogWriter(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(logs.clone())
            .with_ansi(false)
            .finish();
        async {
            for (auth, header_name, header_value) in [
                (
                    ProbeAuth::Bearer,
                    "authorization",
                    "Bearer unit_test_provider_secret_DO_NOT_LOG",
                ),
                (
                    ProbeAuth::Anthropic,
                    "x-api-key",
                    "unit_test_provider_secret_DO_NOT_LOG",
                ),
                (
                    ProbeAuth::Azure,
                    "api-key",
                    "unit_test_provider_secret_DO_NOT_LOG",
                ),
                (
                    ProbeAuth::Google,
                    "x-goog-api-key",
                    "unit_test_provider_secret_DO_NOT_LOG",
                ),
            ] {
                for (code, expected) in [
                    (401, "rejected"),
                    (200, "valid"),
                    (429, "unavailable"),
                    (500, "cannot_validate"),
                    (302, "cannot_validate"),
                ] {
                    server.reset().await;
                    Mock::given(method("GET"))
                        .respond_with(ResponseTemplate::new(401))
                        .with_priority(2)
                        .expect(1)
                        .mount(&server)
                        .await;
                    Mock::given(method("GET"))
                        .and(path("/v1/models"))
                        .and(header(header_name, header_value))
                        .respond_with(
                            ResponseTemplate::new(code)
                                .set_body_string("unit_test_provider_secret_DO_NOT_LOG")
                                .insert_header(
                                    "location",
                                    "http://169.254.169.254/latest/meta-data",
                                ),
                        )
                        .with_priority(1)
                        .expect(1)
                        .mount(&server)
                        .await;
                    let pinned = crate::ssrf_guard::PinnedTarget::for_test(
                        "provider.test",
                        vec![*server.address()],
                    );
                    let probe = Probe {
                        url: format!("http://provider.test:{}/v1/models", server.address().port()),
                        auth,
                    };
                    let result = request_probe(&probe, &secret, pinned).await;
                    assert_eq!(
                        result.status, expected,
                        "HTTP {code} must have an honest credential verdict"
                    );
                    assert!(
                        !serde_json::to_string(&result)
                            .unwrap()
                            .contains(secret.expose_secret())
                    );
                }
            }
        }
        .with_subscriber(subscriber)
        .await;
        assert!(
            !String::from_utf8(logs.0.lock().unwrap().clone())
                .unwrap()
                .contains(secret.expose_secret()),
            "secret appeared in tracing output"
        );
    }
}

#[cfg(test)]
mod rejection_tests {
    use super::*;
    #[test]
    fn bedrock_rejection_is_not_a_tenant_credential_rejection() {
        let now = chrono::Utc::now();
        let key = ProviderKeyRow {
            provider_id: "bedrock".into(),
            ciphertext_b64: "unused-test-ciphertext".into(),
            last4: "test".into(),
            saved_at: now - chrono::Duration::hours(1),
            last_validation: None,
        };
        let history = [Rejection {
            provider: "aws_bedrock".into(),
            rejected_at_us: now.timestamp_micros(),
        }];
        assert!(
            last_rejected(&key, &history).is_none(),
            "Bedrock uses gateway credentials, so a tenant's stored value has no rejection history"
        );
    }

    #[test]
    fn rejection_query_is_tenant_first_capped_and_scoped_to_auth_failures() {
        let sql = TenantQuery::new(rejection_sql(), PlanTier::Builder).sql_with_settings();
        assert!(sql.contains("WHERE tenant_id = ? AND start_time >="));
        assert!(sql.contains("status_message = 'provider_key_rejected'"));
        assert!(sql.contains("LIMIT ?"));
        assert!(sql.contains("max_execution_time"));
    }

    /// SRE register #20: the caller's tier must REACH the settings block. A
    /// hardcoded tier passes the test above and still caps a paying tenant at
    /// Builder, so the discriminating assertion is that two tiers differ.
    #[test]
    fn rejection_query_caps_follow_the_tenants_own_tier() {
        let free = TenantQuery::new(rejection_sql(), PlanTier::Free).sql_with_settings();
        let business = TenantQuery::new(rejection_sql(), PlanTier::Business).sql_with_settings();
        assert_ne!(
            free, business,
            "the tier must change the SETTINGS block, or threading it through is a no-op"
        );
    }

    #[tokio::test]
    #[ignore = "requires isolated ClickHouse"]
    async fn clickhouse_roundtrip_provider_key_rejections_isolate_tenant_and_saved_version() {
        let url = std::env::var("CLICKHOUSE_TEST_URL").expect("isolated ClickHouse required");
        let ch = clickhouse::Client::default().with_url(url);
        ch.query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .unwrap();
        let schema = include_str!("../../../infra/dev/clickhouse/schema.sql");
        let spans = crate::clickhouse_query::split_migration_statements(schema)
            .into_iter()
            .find(|statement| statement.contains("CREATE TABLE IF NOT EXISTS tracelane.spans"))
            .expect("canonical spans DDL");
        ch.query(&spans).execute().await.unwrap();
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let other = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let saved = chrono::Utc::now() - chrono::Duration::hours(1);
        let source = ProviderKeyRow {
            provider_id: "anthropic".into(),
            ciphertext_b64: "unit-test-ciphertext".into(),
            last4: "test".into(),
            saved_at: saved,
            last_validation: None,
        };
        let expected = saved + chrono::Duration::minutes(1);
        for (id, who, at, reason, provider) in [
            (
                "old",
                &tenant,
                saved - chrono::Duration::seconds(1),
                "provider_key_rejected",
                "anthropic",
            ),
            (
                "mine",
                &tenant,
                expected,
                "provider_key_rejected",
                "anthropic",
            ),
            (
                "other",
                &other,
                expected + chrono::Duration::minutes(1),
                "provider_key_rejected",
                "anthropic",
            ),
            (
                "rate",
                &tenant,
                expected + chrono::Duration::minutes(2),
                "provider_rate_limited",
                "anthropic",
            ),
            (
                "provider",
                &tenant,
                expected + chrono::Duration::minutes(3),
                "provider_key_rejected",
                "openai",
            ),
        ] {
            ch.query("INSERT INTO tracelane.spans (tenant_id, trace_id, span_id, start_time, status_message, attributes) VALUES (?, ?, ?, fromUnixTimestamp64Micro(?), ?, ?)")
                .bind(who.to_string()).bind(id).bind(id).bind(at.timestamp_micros()).bind(reason)
                .bind(serde_json::json!({"gen_ai_provider_name":provider}).to_string()).execute().await.unwrap();
        }
        let history = rejections(
            &ch,
            &tenant,
            std::slice::from_ref(&source),
            PlanTier::Business,
        )
        .await
        .unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(
            last_rejected(&source, &history).unwrap().timestamp_micros(),
            expected.timestamp_micros()
        );
        let replaced = ProviderKeyRow {
            saved_at: expected + chrono::Duration::seconds(1),
            ..source
        };
        assert!(last_rejected(&replaced, &history).is_none());
        assert!(
            rejections(&ch, &tenant, &[replaced], PlanTier::Business)
                .await
                .unwrap()
                .is_empty()
        );
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    #[tokio::test]
    async fn validation_route_requires_auth_before_touching_database() {
        use tower::ServiceExt;
        let mut config = deadpool_postgres::Config::new();
        config.host = Some("unused.invalid".into());
        config.dbname = Some("unused".into());
        let pool = config
            .create_pool(
                Some(deadpool_postgres::Runtime::Tokio1),
                tokio_postgres::NoTls,
            )
            .unwrap();
        let response = routes()
            .with_state(ValidationState { pool })
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/provider-keys/anthropic/validate")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    #[tokio::test]
    async fn unknown_provider_cannot_validate_without_network() {
        let result = check(
            "not-a-provider",
            &SecretString::from("unit-test-only"),
            &TenantId::from_jwt_claim(uuid::Uuid::new_v4()),
        )
        .await;
        assert_eq!(result.status, "cannot_validate");
        assert_eq!(result.reason, "unknown_provider");
    }
    #[tokio::test]
    async fn provider_validation_ssrf_refuses_metadata_before_request() {
        assert!(
            crate::ssrf_guard::validate_url_pinned("https://169.254.169.254/latest/meta-data")
                .await
                .is_err()
        );
    }
}
