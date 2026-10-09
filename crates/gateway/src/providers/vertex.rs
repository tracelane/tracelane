//! Google Vertex AI (a.k.a. "Gemini Enterprise Agent Platform") provider adapter.
//!
//! Callers: `server::dispatch_to_provider` for any `vertex/*` model.
//!
//! This is deliberately NOT a second Gemini implementation. Vertex speaks the
//! identical Gemini request/response contract as AI Studio (`google.rs`) —
//! same `contents`/`systemInstruction`/`tools`/`generationConfig` fields, same
//! `usageMetadata` shape — so this module reuses `GeminiRequest::from_universal`
//! and `build_gemini_stream` wholesale, inheriting the `thoughtsTokenCount`
//! fold for free. Only three things differ: host, path, and auth.
//!
//! Auth is the whole reason this is a separate adapter. **Vertex rejects API
//! keys** — `aiplatform.googleapis.com` answers a well-formed key with
//! `401 "API keys are not supported by this API"` (verified against the live
//! endpoint 2026-07-17). The credential is therefore a GCP **service-account
//! JSON**, exchanged for a 1-hour OAuth2 access token via a self-signed RS256
//! JWT bearer grant (RFC 7523). Tokens are cached so the hot path does not sign
//! a JWT or hit Google's token endpoint per request.
//!
//! Why it exists at all: Google Cloud credits are **explicitly barred** from AI
//! Studio — *"The $300 credit can't pay for Gemini API in AI Studio costs"* —
//! but DO cover Vertex first-party Gemini. Vertex is the only path that spends
//! GCP credits on Gemini. (Partner models in Model Garden — Claude/Llama/Mistral
//! — are separately excluded from credits; this adapter is first-party Gemini only.)
//!
//! Invariants:
//!   - The service-account private key is a credential: `SecretString`, never
//!     logged, never in an error body. Provider errors carry status only.
//!   - Every outbound URL passes the SSRF guard before the request.
//!   - Token cache TTL is deliberately shorter than the token lifetime so a
//!     cached token can never be served past expiry.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use reqwest::Client;
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use super::google::{GeminiRequest, build_gemini_stream};
use super::{ProviderHttpError, ProviderStream};
use tracelane_shared::{ChatRequest, TenantId};

/// OAuth2 scope required for Vertex `generateContent`.
const SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// Google's JWT-bearer grant type (RFC 7523 §2.1).
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Access tokens live 3600s. Cache for 55 min so a cached token is never
/// served inside the last 5 minutes of its life — clock skew between us and
/// Google must not be able to produce a 401 on a "valid" cache hit.
const TOKEN_TTL: Duration = Duration::from_secs(55 * 60);

/// The subset of a GCP service-account JSON we need.
///
/// Deserialised from the BYOK plaintext. `private_key` is PEM PKCS#8 and is a
/// credential — it is moved into a `SecretString` immediately on parse.
#[derive(Deserialize)]
struct ServiceAccountJson {
    client_email: String,
    private_key: String,
    project_id: String,
    #[serde(default = "default_token_uri")]
    token_uri: String,
}

/// Google's OAuth2 token endpoint — the ONLY `token_uri` a service account may name
/// (SB, security re-review round 2, 2026-10-05). The field comes from the tenant's JSON,
/// so any other value pointed the gateway's token exchange at a tenant-chosen host (one
/// answering 500 manufactured provider failures). A wire invariant, not a tunable.
const GOOGLE_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

fn default_token_uri() -> String {
    GOOGLE_TOKEN_URI.to_owned()
}

fn token_uri_allowed(uri: &str) -> bool {
    #[cfg(test)]
    if test_host_override().is_some_and(|origin| uri == format!("{origin}/token")) {
        return true;
    }
    uri == GOOGLE_TOKEN_URI
}

/// Parsed service account with the private key contained.
struct ServiceAccount {
    client_email: String,
    private_key: SecretString,
    project_id: String,
    token_uri: String,
}

impl ServiceAccount {
    /// Parse a service-account JSON blob.
    ///
    /// # Errors
    /// Fails when the blob is not JSON or is missing a required field.
    /// Fail-closed: a malformed credential must never fall through to an
    /// unauthenticated request.
    fn parse(sa_json: &str) -> Result<Self> {
        let raw: ServiceAccountJson = serde_json::from_str(sa_json)
            .context("service-account JSON is malformed or missing required fields")?;
        if raw.private_key.is_empty() || raw.client_email.is_empty() || raw.project_id.is_empty() {
            bail!("service-account JSON missing client_email / private_key / project_id");
        }
        if !token_uri_allowed(&raw.token_uri) {
            bail!("service-account token_uri must be {GOOGLE_TOKEN_URI}");
        }
        Ok(Self {
            client_email: raw.client_email,
            private_key: SecretString::from(raw.private_key),
            project_id: raw.project_id,
            token_uri: raw.token_uri,
        })
    }
}

/// Claims for the self-signed assertion we exchange for an access token.
#[derive(Serialize)]
struct Assertion<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    exp: u64,
    iat: u64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

pub struct VertexProvider {
    client: Client,
    /// Vertex location. `global` uses the un-prefixed host and is the default:
    /// its per-token pricing matches AI Studio, whereas regional endpoints
    /// carry a ~10% premium.
    location: String,
    /// Access-token cache keyed by `tenant_id:client_email`. Keyed by tenant
    /// (not just the SA identity) so a token can never be served across a
    /// tenant boundary, even if two tenants upload the same service account.
    tokens: moka::future::Cache<String, Arc<str>>,
}

impl VertexProvider {
    /// `OG-13`: the region the circuit breaker keys this adapter's dispatches on.
    #[must_use]
    pub fn location(&self) -> &str {
        &self.location
    }

    pub fn new() -> Result<Self> {
        Ok(Self {
            client: crate::ssrf_guard::safe_client_builder()
                .timeout(Duration::from_secs(300))
                .build()
                .context("build Vertex reqwest client")?,
            location: std::env::var("TRACELANE_VERTEX_LOCATION")
                .unwrap_or_else(|_| "global".into()),
            tokens: moka::future::Cache::builder()
                .max_capacity(1024)
                .time_to_live(TOKEN_TTL)
                .build(),
        })
    }

    /// Host for the configured location. `global` is un-prefixed; every other
    /// location is `{location}-aiplatform.googleapis.com`.
    fn host(&self) -> String {
        #[cfg(test)]
        if let Some(origin) = test_host_override() {
            return origin;
        }
        if self.location == "global" {
            "https://aiplatform.googleapis.com".to_owned()
        } else {
            format!("https://{}-aiplatform.googleapis.com", self.location)
        }
    }

    /// Mint an OAuth2 access token from the service account, or return a cached one.
    ///
    /// Signs an RS256 JWT assertion and exchanges it at Google's token endpoint
    /// (RFC 7523). Cached for `TOKEN_TTL`, so the steady-state hot path performs
    /// neither a signature nor a network round-trip.
    ///
    /// # Errors
    /// Fails on an unparseable PEM key, a signing failure, or a non-2xx token
    /// response. The token-endpoint body is never surfaced — it can echo the
    /// assertion.
    async fn access_token(&self, sa: &ServiceAccount, tenant_id: &TenantId) -> Result<Arc<str>> {
        let cache_key = format!("{tenant_id}:{}", sa.client_email);
        if let Some(tok) = self.tokens.get(&cache_key).await {
            return Ok(tok);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_secs();
        let claims = Assertion {
            iss: &sa.client_email,
            scope: SCOPE,
            aud: &sa.token_uri,
            exp: now + 3600,
            iat: now,
        };
        let key =
            jsonwebtoken::EncodingKey::from_rsa_pem(sa.private_key.expose_secret().as_bytes())
                .context("service-account private_key is not a valid RSA PEM")?;
        let assertion = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
            &claims,
            &key,
        )
        .context("failed to sign service-account assertion")?;

        // B-472 (REV-3): `token_uri` comes from the CUSTOMER's service-account JSON, so
        // its DNS is customer-controlled — connect to the addresses the guard checked.
        let pinned = crate::ssrf_guard::validate_url_pinned(&sa.token_uri)
            .await
            .context("SSRF guard rejected the token_uri")?;
        let token_client = pinned
            .pin(crate::ssrf_guard::safe_client_builder())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("token-exchange client build failed")?;

        let resp = crate::routing::deadlines::send_auxiliary(
            token_client
                .post(&sa.token_uri)
                .form(&[("grant_type", GRANT_TYPE), ("assertion", &assertion)]),
        )
        .await
        .context("failed to reach Google's OAuth2 token endpoint")?;

        let status = resp.status();
        if !status.is_success() {
            // SECURITY: the token endpoint echoes the assertion (which is signed
            // with the customer's private key) in some error bodies. Status only.
            let retry_after = crate::providers::retry_after_from(resp.headers());
            let _body = crate::routing::deadlines::error_text(resp).await?;
            tracing::warn!(status = %status, "Vertex OAuth2 token exchange failed");
            return Err(ProviderHttpError {
                provider: "vertex",
                status: status.as_u16(),
                reason: crate::providers::reason_from_body(&_body),
                // The token endpoint echoes the signed assertion: never relayed.
                message: None,
                retry_after,
            }
            .into());
        }

        let parsed: TokenResponse = resp
            .json()
            .await
            .map_err(reqwest::Error::without_url)
            .context("token endpoint returned an unparseable body")?;
        let token: Arc<str> = Arc::from(parsed.access_token.as_str());
        self.tokens.insert(cache_key, Arc::clone(&token)).await;
        Ok(token)
    }

    /// Exchange this saved service account and build its project-scoped models list.
    /// Validation constructs a fresh provider so an older cached token cannot mask
    /// a replaced or revoked service-account key.
    ///
    /// # Errors
    /// Fail CLOSED on malformed credentials, token exchange, or URL construction.
    #[instrument(skip(self, sa_json), fields(tenant_id = %tenant_id))]
    pub(crate) async fn models_probe(
        &self,
        sa_json: &str,
        tenant_id: &TenantId,
    ) -> Result<(String, SecretString)> {
        let sa = ServiceAccount::parse(sa_json).map_err(super::credential_derived)?;
        let token = self
            .access_token(&sa, tenant_id)
            .await
            .map_err(super::credential_derived)?;
        let mut url = reqwest::Url::parse(&self.host())?;
        url.path_segments_mut()
            .map_err(|()| anyhow::anyhow!("invalid Vertex models host"))?
            .extend([
                "v1",
                "projects",
                &sa.project_id,
                "locations",
                &self.location,
                "models",
            ]);
        Ok((url.into(), SecretString::from(token.as_ref())))
    }

    /// Dispatch a chat request to Vertex first-party Gemini.
    ///
    /// `sa_json` is the tenant's BYOK service-account JSON (not an API key —
    /// Vertex rejects those). The model string arrives with its `vertex/`
    /// routing prefix already attached; it is stripped here so the wire model
    /// is the bare Gemini ID (`gemini-2.5-pro`), which Vertex shares with
    /// AI Studio.
    ///
    /// # Errors
    /// Returns `ProviderHttpError` for a non-2xx upstream so the handler can
    /// distinguish an auth rejection (401/403) from an outage.
    #[instrument(skip(self, request, sa_json), fields(
        tenant_id = %tenant_id,
        model = %request.model,
        provider = "vertex",
    ))]
    pub async fn chat(
        &self,
        request: ChatRequest,
        sa_json: &str,
        tenant_id: &TenantId,
    ) -> Result<ProviderStream> {
        let sa = ServiceAccount::parse(sa_json).map_err(super::credential_derived)?;
        // OG-02 §3.1: the model is a URL path segment — validated, never interpolated raw.
        let Some(model) = super::google::safe_path_segment(strip_vertex_prefix(&request.model))
            .map(str::to_owned)
        else {
            return Err(super::google::invalid_model_error("vertex"));
        };
        let token = self
            .access_token(&sa, tenant_id)
            .await
            .map_err(super::credential_derived)?;

        // Identical contract to AI Studio — reuse the translation rather than
        // maintaining a second Gemini serialiser that can drift.
        let gemini_request = GeminiRequest::from_universal(request)
            .context("failed to translate to Gemini format")?;

        let url = format!(
            "{}/v1/projects/{}/locations/{}/publishers/google/models/{}:streamGenerateContent?alt=sse",
            self.host(),
            sa.project_id,
            self.location,
            model,
        );
        crate::ssrf_guard::validate_url(&url)
            .await
            .context("SSRF guard rejected the Vertex URL")?;

        let response = crate::routing::deadlines::send(
            self.client
                .post(&url)
                .bearer_auth(token.as_ref())
                .header("content-type", "application/json")
                .json(&gemini_request),
        )
        .await
        .context("failed to send request to Vertex AI")?;

        let status = response.status();
        if !status.is_success() {
            // Status only — never the body (: provider error bodies echo credentials).
            let retry_after = crate::providers::retry_after_from(response.headers());
            let body = crate::routing::deadlines::error_text(response).await?;
            tracing::warn!(status = %status, "Vertex AI API error");
            // OG-03 §3.4. The "key" scrubbed from the message is the OAuth bearer.
            return Err(ProviderHttpError::from_response(
                "vertex",
                status.as_u16(),
                crate::providers::reason_from_body(&body),
                &body,
                token.as_ref(),
            )
            .with_retry_after(retry_after)
            .into());
        }

        Ok(Box::pin(build_gemini_stream(response)))
    }
}

#[cfg(test)]
thread_local! {
    /// `OG-90`. The Vertex host is a fixed Google origin, so a test that dispatches through
    /// the REAL adapter to a mock server needs a way to point it elsewhere. Thread-local, like
    /// the SSRF loopback bypass it is always used with: no process env, no cross-test leak.
    static TEST_HOST_OVERRIDE: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn test_host_override() -> Option<String> {
    TEST_HOST_OVERRIDE.with(|h| h.borrow().clone())
}

/// RAII guard: Vertex requests on this thread go to `origin` until it drops.
#[cfg(test)]
pub(crate) struct HostOverrideGuard;

#[cfg(test)]
impl HostOverrideGuard {
    pub(crate) fn new(origin: impl Into<String>) -> Self {
        TEST_HOST_OVERRIDE.with(|h| *h.borrow_mut() = Some(origin.into()));
        Self
    }
}

#[cfg(test)]
impl Drop for HostOverrideGuard {
    fn drop(&mut self) {
        TEST_HOST_OVERRIDE.with(|h| *h.borrow_mut() = None);
    }
}

/// Strip the `vertex/` routing prefix to recover the wire model ID.
///
/// Vertex and AI Studio share model ID strings (`gemini-2.5-pro`), so the
/// prefix exists only to select the provider, never to reach the wire.
fn strip_vertex_prefix(model: &str) -> &str {
    model.strip_prefix("vertex/").unwrap_or(model)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

    /// A THROWAWAY RSA key, generated in this process and never written to disk.
    ///
    /// The probe signs a real JWT assertion (`EncodingKey::from_rsa_pem`), so the
    /// test needs a structurally valid PKCS#8 PEM — a `NOT-A-REAL-KEY` literal
    /// cannot exercise the signing path. It is generated rather than committed
    /// because `crates/` SHIPS PUBLICLY (`CLAUDE.md` §4a): a committed PEM is a
    /// private key in a public repository, which every downstream secret scanner
    /// reports and which `gitleaks` blocks in this repo's own gate. `aws-lc-rs`
    /// is already in `Cargo.lock` (rustls + jsonwebtoken), so this adds no crate.
    fn throwaway_service_account_pem() -> String {
        use aws_lc_rs::encoding::AsDer as _;
        let key = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
            .expect("generate a test RSA key");
        let der = key.as_der().expect("PKCS#8 DER");
        let b64 = B64.encode(der.as_ref());
        let body: String = b64
            .as_bytes()
            .chunks(64)
            .map(|line| format!("{}\n", std::str::from_utf8(line).expect("base64 is ascii")))
            .collect();
        format!("-----BEGIN PRIVATE KEY-----\n{body}-----END PRIVATE KEY-----\n")
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn models_probe_exchanges_the_saved_service_account_and_surfaces_rejection() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{body_string_contains, method, path},
        };
        struct LoopbackGuard;
        impl Drop for LoopbackGuard {
            fn drop(&mut self) {
                crate::ssrf_guard::set_loopback_bypass_for_tests(false);
            }
        }
        crate::ssrf_guard::set_loopback_bypass_for_tests(true);
        let _guard = LoopbackGuard;
        let server = MockServer::start().await;
        // SB: a token_uri other than Google's is refused unless a test points the
        // adapter at a mock origin.
        let _host = HostOverrideGuard::new(server.uri());
        let secret = serde_json::json!({
            "client_email": "unit-test@example.test",
            "project_id": "unit-test-project",
            "private_key": throwaway_service_account_pem(),
            "token_uri": format!("{}/token", server.uri()),
        })
        .to_string();
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("assertion="))
            .and(body_string_contains("grant_type="))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"access_token": "unit-test-access-token"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let provider = VertexProvider::new().unwrap();
        let (url, token) = provider.models_probe(&secret, &tenant).await.unwrap();
        assert!(url.ends_with("/v1/projects/unit-test-project/locations/global/models"));
        assert_eq!(token.expose_secret(), "unit-test-access-token");
        server.verify().await;
        server.reset().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&server)
            .await;
        // New validation action must exchange again, even for the same SA identity.
        let fresh = VertexProvider::new().unwrap();
        let error = fresh.models_probe(&secret, &tenant).await.err().unwrap();
        assert_eq!(
            error.downcast_ref::<ProviderHttpError>().unwrap().status,
            401
        );
        assert!(fresh.models_probe("not-json", &tenant).await.is_err());
        server.verify().await;
    }

    /// A syntactically valid but obviously fake service account. Never a real
    /// credential — the PEM is not a parseable key, which is fine for the
    /// parse-level assertions here.
    fn fake_sa_json() -> &'static str {
        r#"{
            "type": "service_account",
            "project_id": "unit-test-project",
            "client_email": "unit-test@unit-test-project.iam.gserviceaccount.com",
            "private_key": "-----BEGIN PRIVATE KEY-----\nNOT-A-REAL-KEY-do-not-use\n-----END PRIVATE KEY-----\n"
        }"#
    }

    #[test]
    fn parses_service_account_and_defaults_token_uri() {
        let sa = ServiceAccount::parse(fake_sa_json()).expect("should parse");
        assert_eq!(sa.project_id, "unit-test-project");
        assert_eq!(
            sa.client_email,
            "unit-test@unit-test-project.iam.gserviceaccount.com"
        );
        // token_uri is optional in the wild; default must be Google's endpoint.
        assert_eq!(sa.token_uri, "https://oauth2.googleapis.com/token");
    }

    /// Fail-closed: a malformed credential must error, never fall through to
    /// an unauthenticated request.
    #[test]
    fn rejects_malformed_service_account() {
        assert!(ServiceAccount::parse("not json").is_err());
        assert!(ServiceAccount::parse("{}").is_err());
        // Present-but-empty fields are as bad as absent ones.
        assert!(
            ServiceAccount::parse(r#"{"project_id":"p","client_email":"","private_key":"k"}"#)
                .is_err()
        );
    }

    /// An API key is NOT a service account. Vertex rejects API keys outright,
    /// so a tenant pasting one must fail here with a clear parse error rather
    /// than reaching Google and getting an opaque 401.
    #[test]
    fn api_key_pasted_as_credential_is_rejected() {
        assert!(ServiceAccount::parse("AQ.AbSomeApiKeyNotAServiceAccount").is_err());
        // SB (round 2, 2026-10-05): the tenant's JSON may not redirect the token exchange.
        for uri in [
            "https://attacker.example/token",
            "http://oauth2.googleapis.com/token",
            "https://oauth2.googleapis.com.evil.test/token",
            "https://oauth2.googleapis.com/token?x=1",
        ] {
            let sa = serde_json::json!({
                "client_email": "a@b.test", "private_key": "k", "project_id": "p",
                "token_uri": uri,
            })
            .to_string();
            assert!(ServiceAccount::parse(&sa).is_err(), "{uri} must be refused");
        }
        let google = serde_json::json!({
            "client_email": "a@b.test", "private_key": "k", "project_id": "p",
            "token_uri": "https://oauth2.googleapis.com/token",
        })
        .to_string();
        assert!(ServiceAccount::parse(&google).is_ok());
    }

    #[test]
    fn strips_routing_prefix_to_wire_model() {
        assert_eq!(
            strip_vertex_prefix("vertex/gemini-2.5-pro"),
            "gemini-2.5-pro"
        );
        assert_eq!(
            strip_vertex_prefix("vertex/gemini-3-flash-preview"),
            "gemini-3-flash-preview"
        );
        // Idempotent: an already-bare model passes through untouched.
        assert_eq!(strip_vertex_prefix("gemini-2.5-pro"), "gemini-2.5-pro");
    }

    /// `global` is the default because its pricing matches AI Studio; regional
    /// endpoints carry a ~10% premium and must be opt-in.
    #[test]
    fn global_location_uses_unprefixed_host() {
        let p = VertexProvider {
            client: Client::new(),
            location: "global".into(),
            tokens: moka::future::Cache::builder().max_capacity(4).build(),
        };
        assert_eq!(p.host(), "https://aiplatform.googleapis.com");
    }

    #[test]
    fn regional_location_prefixes_host() {
        let p = VertexProvider {
            client: Client::new(),
            location: "us-central1".into(),
            tokens: moka::future::Cache::builder().max_capacity(4).build(),
        };
        assert_eq!(p.host(), "https://us-central1-aiplatform.googleapis.com");
    }

    /// The token cache must not be able to serve a token past its life. Google
    /// issues 3600s tokens; the TTL is deliberately shorter so clock skew can
    /// never turn a cache hit into a 401.
    #[test]
    fn token_ttl_is_shorter_than_token_lifetime() {
        assert!(
            TOKEN_TTL < Duration::from_secs(3600),
            "cache TTL must expire before the token does"
        );
    }
}
