//! Google Vertex AI (a.k.a. "Gemini Enterprise Agent Platform") provider adapter.
//!
//! Callers: `server::dispatch_to_provider` for any `vertex/*` model.
//!
//! This is deliberately NOT a second Gemini implementation. Vertex speaks the
//! identical Gemini request/response contract as AI Studio (`google.rs`) —
//! same `contents`/`systemInstruction`/`tools`/`generationConfig` fields, same
//! `usageMetadata` shape — so this module reuses `GeminiRequest::from_universal`
//! and `build_gemini_stream` wholesale, inheriting the B-104 `thoughtsTokenCount`
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

fn default_token_uri() -> String {
    "https://oauth2.googleapis.com/token".to_owned()
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

        crate::ssrf_guard::validate_url(&sa.token_uri)
            .await
            .context("SSRF guard rejected the token_uri")?;

        let resp = self
            .client
            .post(&sa.token_uri)
            .form(&[("grant_type", GRANT_TYPE), ("assertion", &assertion)])
            .send()
            .await
            .context("failed to reach Google's OAuth2 token endpoint")?;

        let status = resp.status();
        if !status.is_success() {
            // SECURITY: the token endpoint echoes the assertion (which is signed
            // with the customer's private key) in some error bodies. Status only.
            let _body = resp.text().await.unwrap_or_default();
            tracing::warn!(status = %status, "Vertex OAuth2 token exchange failed");
            return Err(ProviderHttpError {
                provider: "vertex",
                status: status.as_u16(),
                reason: crate::providers::reason_from_body(&_body),
            }
            .into());
        }

        let parsed: TokenResponse = resp
            .json()
            .await
            .context("token endpoint returned an unparseable body")?;
        let token: Arc<str> = Arc::from(parsed.access_token.as_str());
        self.tokens.insert(cache_key, Arc::clone(&token)).await;
        Ok(token)
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
        let sa = ServiceAccount::parse(sa_json)?;
        let model = strip_vertex_prefix(&request.model).to_owned();
        let token = self.access_token(&sa, tenant_id).await?;

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

        let response = self
            .client
            .post(&url)
            .bearer_auth(token.as_ref())
            .header("content-type", "application/json")
            .json(&gemini_request)
            .send()
            .await
            .context("failed to send request to Vertex AI")?;

        let status = response.status();
        if !status.is_success() {
            // Status only — never the body (R2 C-3: provider error bodies echo credentials).
            let _body = response.text().await.unwrap_or_default();
            tracing::warn!(status = %status, "Vertex AI API error");
            return Err(ProviderHttpError {
                provider: "vertex",
                status: status.as_u16(),
                reason: crate::providers::reason_from_body(&_body),
            }
            .into());
        }

        Ok(Box::pin(build_gemini_stream(response)))
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
