//! SPIFFE mTLS authentication for ingest workers.
//!
//! Verifies that an incoming connection presents a valid SPIFFE X.509-SVID
//! and extracts the tenant identity from the SPIFFE ID path. The expected
//! SPIFFE ID format is:
//!
//! ```text
//! spiffe://tracelane.dev/tenant/<uuid>/ingest-worker
//! ```
//!
//! ## Scope
//!
//! This module handles the *application-layer* SVID verification:
//! parsing the X.509 DER, walking SubjectAlternativeName, validating the
//! SPIFFE ID format and trust domain, and checking the certificate's
//! validity window. It exposes both a pure-function entry point
//! (`verify_spiffe_svid`) and an axum middleware (`require_spiffe_auth`).
//!
//! ## Out of scope (tracked as INGEST-002)
//!
//! *Chain* trust — verifying that the SVID was issued by the SPIRE trust
//! bundle — belongs at the rustls layer via a custom `ClientCertVerifier`
//! on the server's `ServerConfig`. That requires a SPIRE Workload API
//! client (`unix:///tmp/spire-agent/public/api.sock`) that fetches and
//! refreshes the trust bundle. Until that lands, this middleware is
//! dormant in prod: it only fires when a TLS layer injects a verified
//! peer-cert DER into the request extensions as `PeerCertDer`.
//!
//! ## Failure mode
//!
//! Fail-closed. Any verification error produces `401 Unauthorized` with a
//! `WWW-Authenticate: SPIFFE-mTLS` header. The original error is logged at
//! `warn` level with redacted SPIFFE URI for forensics; the response body
//! is intentionally generic.

use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use chrono::{DateTime, TimeZone, Utc};
use thiserror::Error;
use tracing::instrument;
use uuid::Uuid;
use x509_parser::prelude::*;

use tracelane_shared::TenantId;

/// The only trust domain Tracelane ingest workers accept.
pub const TRUST_DOMAIN: &str = "tracelane.dev";

/// Expected workload identifier within the SPIFFE path.
/// Full path shape: `/tenant/<uuid>/<WORKLOAD_KIND>`.
const WORKLOAD_KIND: &str = "ingest-worker";

/// Extension key wrapper for the peer's verified X.509-SVID DER bytes.
/// A TLS termination layer (rustls `ClientCertVerifier`) is expected to
/// insert this into request extensions after chain validation.
#[derive(Debug, Clone)]
pub struct PeerCertDer(pub Bytes);

/// A successfully-verified SPIFFE identity.
///
/// Returned from `verify_spiffe_svid` and inserted into request extensions
/// by `require_spiffe_auth` so downstream handlers can reach it via
/// `Extension<SpiffeIdentity>` or `Extension<TenantId>`.
#[derive(Debug, Clone)]
pub struct SpiffeIdentity {
    pub tenant_id: TenantId,
    pub spiffe_uri: String,
    pub expires_at: DateTime<Utc>,
}

/// Five-bucket label used by the `tracelane_ingest_auth_total` counter.
///
/// Collapses the 14 `SpiffeAuthError` variants (plus the TLS-layer
/// "no peer cert" case) into the result set documented in ADR-028 §
/// Observability. Stable strings — these appear in Prometheus scrapes
/// and dashboard queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResult {
    Ok,
    WrongTrustDomain,
    InvalidPath,
    ExpiredSvid,
    NoSvid,
}

impl AuthResult {
    /// Stable Prometheus label string. Do not change without bumping the
    /// metric name — dashboards depend on these literals.
    pub const fn label(self) -> &'static str {
        match self {
            AuthResult::Ok => "ok",
            AuthResult::WrongTrustDomain => "wrong_trust_domain",
            AuthResult::InvalidPath => "invalid_path",
            AuthResult::ExpiredSvid => "expired_svid",
            AuthResult::NoSvid => "no_svid",
        }
    }

    const fn idx(self) -> usize {
        match self {
            AuthResult::Ok => 0,
            AuthResult::WrongTrustDomain => 1,
            AuthResult::InvalidPath => 2,
            AuthResult::ExpiredSvid => 3,
            AuthResult::NoSvid => 4,
        }
    }
}

/// Per-bucket counters for `tracelane_ingest_auth_total`. Process-local;
/// the scraper reads them via [`auth_metric_snapshot`]. Zero-dep: std
/// `AtomicU64` so this is a drop-in for environments where a Prometheus
/// crate has not been wired into the binary yet.
static AUTH_COUNTERS: [AtomicU64; 5] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Increment the `tracelane_ingest_auth_total{result=<label>}` counter
/// and emit a structured `tracing` event for log-based aggregation. Cheap
/// (relaxed atomic add); safe to call on every request.
pub fn record_auth_result(result: AuthResult) {
    AUTH_COUNTERS[result.idx()].fetch_add(1, Ordering::Relaxed);
    tracing::info!(
        metric_name = "tracelane_ingest_auth_total",
        result = result.label(),
        "ingest auth outcome"
    );
}

/// Snapshot of the five `tracelane_ingest_auth_total` buckets. Used by
/// tests and (eventually) the Prometheus exporter to read live counts.
pub fn auth_metric_snapshot() -> [u64; 5] {
    [
        AUTH_COUNTERS[0].load(Ordering::Relaxed),
        AUTH_COUNTERS[1].load(Ordering::Relaxed),
        AUTH_COUNTERS[2].load(Ordering::Relaxed),
        AUTH_COUNTERS[3].load(Ordering::Relaxed),
        AUTH_COUNTERS[4].load(Ordering::Relaxed),
    ]
}

/// All failure modes for SPIFFE SVID verification. Every variant maps to
/// 401 at the HTTP layer — fail-closed is non-negotiable.
#[derive(Debug, Error)]
pub enum SpiffeAuthError {
    #[error("certificate DER could not be parsed")]
    MalformedCertificate,
    #[error("certificate DER exceeds size cap ({MAX_SVID_DER_BYTES} bytes)")]
    OversizeCertificate,
    #[error("certificate has no SubjectAlternativeName extension")]
    MissingSan,
    #[error("certificate SAN contains no SPIFFE URI")]
    NoSpiffeId,
    #[error("certificate SAN contains multiple SPIFFE URIs (SPIFFE spec §4.1 violation)")]
    MultipleSpiffeIds,
    #[error("SPIFFE ID is malformed: {0}")]
    MalformedSpiffeId(&'static str),
    #[error("SPIFFE ID trust domain is not permitted")]
    WrongTrustDomain,
    #[error("SPIFFE ID path is missing /tenant/<uuid>/{WORKLOAD_KIND} segments")]
    MissingTenantPath,
    #[error("SPIFFE ID tenant component is not a valid UUID")]
    MalformedTenantId,
    #[error(
        "certificate is a CA cert — SVID leaves MUST NOT have BasicConstraints::cA=TRUE (SPIFFE X.509-SVID §4.3)"
    )]
    LeafIsCa,
    #[error("certificate lacks KeyUsage::digital_signature (SPIFFE X.509-SVID §4.3)")]
    MissingKeyUsageDigitalSignature,
    #[error("certificate validity window is malformed (not_before >= not_after)")]
    InvertedValidity,
    #[error("certificate is not yet valid")]
    NotYetValid,
    #[error("certificate has expired")]
    Expired,
}

impl SpiffeAuthError {
    /// Map a typed error to the five-bucket metric label per ADR-028 §
    /// Observability. Stable mapping — adding a new error variant must
    /// also extend this match arm (compile-time exhaustiveness check).
    pub const fn as_auth_result(&self) -> AuthResult {
        match self {
            SpiffeAuthError::WrongTrustDomain => AuthResult::WrongTrustDomain,
            SpiffeAuthError::NoSpiffeId => AuthResult::NoSvid,
            SpiffeAuthError::NotYetValid | SpiffeAuthError::Expired => AuthResult::ExpiredSvid,
            // Everything else is structural / shape failure on the cert.
            SpiffeAuthError::MalformedCertificate
            | SpiffeAuthError::OversizeCertificate
            | SpiffeAuthError::MissingSan
            | SpiffeAuthError::MultipleSpiffeIds
            | SpiffeAuthError::MalformedSpiffeId(_)
            | SpiffeAuthError::MissingTenantPath
            | SpiffeAuthError::MalformedTenantId
            | SpiffeAuthError::LeafIsCa
            | SpiffeAuthError::MissingKeyUsageDigitalSignature
            | SpiffeAuthError::InvertedValidity => AuthResult::InvalidPath,
        }
    }
}

/// Upper bound on accepted X.509 DER. Real SVIDs are <2 KB; we cap at 8 KB
/// to defend against attacker-supplied multi-MB certs that would force
/// `x509-parser` to walk the entire structure (DoS hardening).
pub const MAX_SVID_DER_BYTES: usize = 8 * 1024;

/// Verify a peer X.509-SVID and extract the SPIFFE identity.
///
/// Performs:
/// 1. DER parse via `x509-parser`
/// 2. SAN extraction — requires exactly one `URI:spiffe://...` GeneralName
/// 3. SPIFFE URI parse — scheme, trust domain, path validation
/// 4. Validity window — `now ∈ [not_before, not_after]`
/// 5. Tenant UUID extraction from path
///
/// # Errors
///
/// Returns a `SpiffeAuthError` variant for each distinct failure mode.
/// Callers MUST treat any error as authentication failure (401).
///
/// # Trust assumption
///
/// This function does NOT validate the certificate's signature chain
/// against a CA bundle — that is the rustls layer's job. Calling this
/// on an unverified DER would let a self-signed cert pass identity
/// extraction; that is intentional (test ergonomics) but production
/// callers MUST come through a TLS layer that has already verified chain
/// trust against the SPIRE trust bundle.
#[instrument(skip(peer_cert_der), fields(spiffe_uri = tracing::field::Empty))]
pub fn verify_spiffe_svid(peer_cert_der: &[u8]) -> Result<SpiffeIdentity, SpiffeAuthError> {
    verify_spiffe_svid_at(peer_cert_der, Utc::now())
}

/// Same as [`verify_spiffe_svid`] but with an injectable clock for tests.
#[instrument(skip(peer_cert_der, now), fields(spiffe_uri = tracing::field::Empty))]
pub fn verify_spiffe_svid_at(
    peer_cert_der: &[u8],
    now: DateTime<Utc>,
) -> Result<SpiffeIdentity, SpiffeAuthError> {
    if peer_cert_der.len() > MAX_SVID_DER_BYTES {
        return Err(SpiffeAuthError::OversizeCertificate);
    }

    let (_, cert) = X509Certificate::from_der(peer_cert_der)
        .map_err(|_| SpiffeAuthError::MalformedCertificate)?;

    let validity = cert.validity();
    let not_before = unix_seconds_to_utc(validity.not_before.timestamp())
        .ok_or(SpiffeAuthError::MalformedCertificate)?;
    let not_after = unix_seconds_to_utc(validity.not_after.timestamp())
        .ok_or(SpiffeAuthError::MalformedCertificate)?;

    if not_before >= not_after {
        return Err(SpiffeAuthError::InvertedValidity);
    }
    if now < not_before {
        return Err(SpiffeAuthError::NotYetValid);
    }
    if now > not_after {
        return Err(SpiffeAuthError::Expired);
    }

    // SPIFFE X.509-SVID spec §4.3: SVID leaves MUST NOT be CA certs and
    // MUST have KeyUsage::digital_signature. Without these checks, a
    // CA-issued intermediate cert whose SAN happens to contain the right
    // SPIFFE URI would authenticate as a workload.
    if let Ok(Some(bc)) = cert.basic_constraints() {
        if bc.value.ca {
            return Err(SpiffeAuthError::LeafIsCa);
        }
    }
    let key_usage = cert
        .key_usage()
        .map_err(|_| SpiffeAuthError::MalformedCertificate)?;
    if let Some(ku) = key_usage {
        if !ku.value.digital_signature() {
            return Err(SpiffeAuthError::MissingKeyUsageDigitalSignature);
        }
    } else {
        // KeyUsage extension is OPTIONAL per RFC 5280, but SPIFFE SVID §4.3
        // makes it mandatory for the leaf. Reject if absent.
        return Err(SpiffeAuthError::MissingKeyUsageDigitalSignature);
    }

    let san_ext = cert
        .extensions()
        .iter()
        .find(|ext| ext.oid == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
        .ok_or(SpiffeAuthError::MissingSan)?;

    let san = match san_ext.parsed_extension() {
        ParsedExtension::SubjectAlternativeName(san) => san,
        _ => return Err(SpiffeAuthError::MissingSan),
    };

    let spiffe_uris: Vec<&str> = san
        .general_names
        .iter()
        .filter_map(|gn| match gn {
            GeneralName::URI(uri) if uri.starts_with("spiffe://") => Some(*uri),
            _ => None,
        })
        .collect();

    match spiffe_uris.len() {
        0 => return Err(SpiffeAuthError::NoSpiffeId),
        1 => {}
        _ => return Err(SpiffeAuthError::MultipleSpiffeIds),
    }
    let spiffe_uri = spiffe_uris[0];
    // Truncate before logging to bound log size when the cert carries a
    // pathologically long URI. Real SPIFFE IDs are <256 chars.
    let log_uri: &str = &spiffe_uri[..spiffe_uri.len().min(256)];
    tracing::Span::current().record("spiffe_uri", log_uri);

    let tenant_id = parse_spiffe_id(spiffe_uri)?;

    Ok(SpiffeIdentity {
        tenant_id,
        spiffe_uri: spiffe_uri.to_string(),
        expires_at: not_after,
    })
}

/// Parse a SPIFFE URI string and validate against the Tracelane format.
///
/// Accepts only `spiffe://tracelane.dev/tenant/<uuid>/ingest-worker`.
/// Trust domain compare is ASCII-case-insensitive per SPIFFE spec §2.1;
/// non-ASCII authority characters are rejected outright to block IDN /
/// unicode-confusable trust domains.
fn parse_spiffe_id(uri: &str) -> Result<TenantId, SpiffeAuthError> {
    let rest = uri
        .strip_prefix("spiffe://")
        .ok_or(SpiffeAuthError::MalformedSpiffeId(
            "missing spiffe:// scheme",
        ))?;

    let (authority, path) = rest
        .split_once('/')
        .ok_or(SpiffeAuthError::MalformedSpiffeId("missing path component"))?;

    if authority.is_empty() {
        return Err(SpiffeAuthError::MalformedSpiffeId("empty trust domain"));
    }
    if !authority.is_ascii() {
        return Err(SpiffeAuthError::MalformedSpiffeId(
            "non-ASCII trust domain (IDN / confusables banned)",
        ));
    }
    if !authority.eq_ignore_ascii_case(TRUST_DOMAIN) {
        return Err(SpiffeAuthError::WrongTrustDomain);
    }

    let segments: Vec<&str> = path.split('/').collect();
    // Expected: ["tenant", "<uuid>", "ingest-worker"]
    if segments.len() != 3 || segments[0] != "tenant" || segments[2] != WORKLOAD_KIND {
        return Err(SpiffeAuthError::MissingTenantPath);
    }
    // Reject empty UUID segment explicitly (Uuid::parse_str would catch this
    // too, but the explicit check makes the intent visible).
    if segments[1].is_empty() {
        return Err(SpiffeAuthError::MalformedTenantId);
    }

    let tenant_uuid =
        Uuid::parse_str(segments[1]).map_err(|_| SpiffeAuthError::MalformedTenantId)?;
    Ok(TenantId::from_spiffe_svid(tenant_uuid))
}

fn unix_seconds_to_utc(secs: i64) -> Option<DateTime<Utc>> {
    Utc.timestamp_opt(secs, 0).single()
}

/// Axum middleware enforcing SPIFFE mTLS authentication.
///
/// Reads a [`PeerCertDer`] from request extensions (placed there by the
/// future rustls `ClientCertVerifier` layer), verifies the SVID, and on
/// success inserts both [`SpiffeIdentity`] and [`TenantId`] into request
/// extensions for downstream handlers. On any failure returns
/// `401 Unauthorized` with `WWW-Authenticate: SPIFFE-mTLS`.
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
pub async fn require_spiffe_auth(mut req: Request<Body>, next: Next) -> Response {
    let peer_der = match req.extensions().get::<PeerCertDer>() {
        Some(p) => p.0.clone(),
        None => {
            tracing::warn!("ingest request without PeerCertDer extension; rejecting");
            record_auth_result(AuthResult::NoSvid);
            return spiffe_unauthorized();
        }
    };

    let identity = match verify_spiffe_svid(&peer_der) {
        Ok(id) => id,
        Err(e) => {
            let bucket = e.as_auth_result();
            tracing::warn!(error = %e, result = bucket.label(), "SPIFFE SVID verification failed");
            record_auth_result(bucket);
            return spiffe_unauthorized();
        }
    };

    tracing::Span::current().record("tenant_id", tracing::field::display(&identity.tenant_id));
    record_auth_result(AuthResult::Ok);

    req.extensions_mut().insert(identity.tenant_id.clone());
    req.extensions_mut().insert(identity);

    next.run(req).await
}

fn spiffe_unauthorized() -> Response {
    let mut resp = (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    resp.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("SPIFFE-mTLS"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::{Request as HttpRequest, StatusCode},
        middleware,
        routing::get,
    };
    use chrono::Duration as ChronoDuration;
    use http_body_util::BodyExt as _;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, Ia5String, IsCa, KeyPair, KeyUsagePurpose,
        SanType, date_time_ymd,
    };
    use tower::ServiceExt;

    /// Mint a self-signed test SVID with the given SAN URIs and validity window.
    /// KeyUsage::DigitalSignature set per SPIFFE X.509-SVID §4.3.
    fn mint_svid(
        san_uris: &[&str],
        not_before: (i32, u8, u8),
        not_after: (i32, u8, u8),
    ) -> Vec<u8> {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "test");
        params.not_before = date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = date_time_ymd(not_after.0, not_after.1, not_after.2);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.subject_alt_names = san_uris
            .iter()
            .map(|u| SanType::URI(Ia5String::try_from(u.to_string()).unwrap()))
            .collect();

        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.der().to_vec()
    }

    /// Mint a self-signed CA cert with the right SAN — used to exercise the
    /// BasicConstraints::cA=TRUE rejection path.
    fn mint_ca_with_spiffe_san(uri: &str) -> Vec<u8> {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "ca");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
        ];
        params.subject_alt_names =
            vec![SanType::URI(Ia5String::try_from(uri.to_string()).unwrap())];
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    /// Mint a leaf SVID that LACKS KeyUsage::DigitalSignature — used to
    /// exercise the MissingKeyUsageDigitalSignature rejection.
    fn mint_leaf_no_key_usage(uri: &str) -> Vec<u8> {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "no-ku");
        params.subject_alt_names =
            vec![SanType::URI(Ia5String::try_from(uri.to_string()).unwrap())];
        // Deliberately no key_usages — KeyUsage extension is absent in DER.
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    fn valid_svid(tenant: &str) -> Vec<u8> {
        let uri = format!("spiffe://tracelane.dev/tenant/{tenant}/ingest-worker");
        mint_svid(&[&uri], (2025, 1, 1), (2099, 1, 1))
    }

    #[test]
    fn accepts_well_formed_svid() {
        let tenant_uuid = Uuid::new_v4();
        let der = valid_svid(&tenant_uuid.to_string());

        let id = verify_spiffe_svid(&der).expect("should accept valid SVID");
        assert_eq!(id.tenant_id.as_uuid(), &tenant_uuid);
        assert!(id.spiffe_uri.contains(&tenant_uuid.to_string()));
        assert!(id.expires_at > Utc::now());
    }

    #[test]
    fn rejects_expired_svid() {
        let uri = format!(
            "spiffe://tracelane.dev/tenant/{}/ingest-worker",
            Uuid::new_v4()
        );
        let der = mint_svid(&[&uri], (2020, 1, 1), (2021, 1, 1));
        // Injectable clock (testing.md discipline) — provably time-independent,
        let now = Utc.with_ymd_and_hms(2026, 5, 21, 0, 0, 0).unwrap();

        match verify_spiffe_svid_at(&der, now) {
            Err(SpiffeAuthError::Expired) => {}
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[test]
    fn rejects_not_yet_valid_svid() {
        let uri = format!(
            "spiffe://tracelane.dev/tenant/{}/ingest-worker",
            Uuid::new_v4()
        );
        let der = mint_svid(&[&uri], (2090, 1, 1), (2099, 1, 1));
        let now = Utc.with_ymd_and_hms(2026, 5, 21, 0, 0, 0).unwrap();

        match verify_spiffe_svid_at(&der, now) {
            Err(SpiffeAuthError::NotYetValid) => {}
            other => panic!("expected NotYetValid, got {other:?}"),
        }
    }

    #[test]
    fn rejects_wrong_trust_domain() {
        let uri = format!(
            "spiffe://evil.example.com/tenant/{}/ingest-worker",
            Uuid::new_v4()
        );
        let der = mint_svid(&[&uri], (2025, 1, 1), (2099, 1, 1));

        match verify_spiffe_svid(&der) {
            Err(SpiffeAuthError::WrongTrustDomain) => {}
            other => panic!("expected WrongTrustDomain, got {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_tenant_path() {
        let uri = "spiffe://tracelane.dev/gateway";
        let der = mint_svid(&[uri], (2025, 1, 1), (2099, 1, 1));

        match verify_spiffe_svid(&der) {
            Err(SpiffeAuthError::MissingTenantPath) => {}
            other => panic!("expected MissingTenantPath, got {other:?}"),
        }
    }

    #[test]
    fn rejects_wrong_workload_kind() {
        let uri = format!("spiffe://tracelane.dev/tenant/{}/gateway", Uuid::new_v4());
        let der = mint_svid(&[&uri], (2025, 1, 1), (2099, 1, 1));

        match verify_spiffe_svid(&der) {
            Err(SpiffeAuthError::MissingTenantPath) => {}
            other => panic!("expected MissingTenantPath, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_uuid_tenant_component() {
        let uri = "spiffe://tracelane.dev/tenant/not-a-uuid/ingest-worker";
        let der = mint_svid(&[uri], (2025, 1, 1), (2099, 1, 1));

        match verify_spiffe_svid(&der) {
            Err(SpiffeAuthError::MalformedTenantId) => {}
            other => panic!("expected MalformedTenantId, got {other:?}"),
        }
    }

    #[test]
    fn rejects_multiple_spiffe_ids() {
        let u1 = format!(
            "spiffe://tracelane.dev/tenant/{}/ingest-worker",
            Uuid::new_v4()
        );
        let u2 = format!(
            "spiffe://tracelane.dev/tenant/{}/ingest-worker",
            Uuid::new_v4()
        );
        let der = mint_svid(&[&u1, &u2], (2025, 1, 1), (2099, 1, 1));

        match verify_spiffe_svid(&der) {
            Err(SpiffeAuthError::MultipleSpiffeIds) => {}
            other => panic!("expected MultipleSpiffeIds, got {other:?}"),
        }
    }

    #[test]
    fn rejects_no_spiffe_id() {
        let der = mint_svid(
            &["https://example.com/not-spiffe"],
            (2025, 1, 1),
            (2099, 1, 1),
        );

        match verify_spiffe_svid(&der) {
            Err(SpiffeAuthError::NoSpiffeId) => {}
            other => panic!("expected NoSpiffeId, got {other:?}"),
        }
    }

    #[test]
    fn rejects_malformed_certificate_bytes() {
        let der = b"definitely not a certificate";
        match verify_spiffe_svid(der) {
            Err(SpiffeAuthError::MalformedCertificate) => {}
            other => panic!("expected MalformedCertificate, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_trust_domain() {
        // Construct SPIFFE URI with empty authority: "spiffe:///tenant/<uuid>/ingest-worker"
        // x509-parser SAN URI may not let us inject this via rcgen easily, so test the
        // string parser directly.
        match parse_spiffe_id("spiffe:///tenant/abc/ingest-worker") {
            Err(SpiffeAuthError::MalformedSpiffeId(_)) => {}
            other => panic!("expected MalformedSpiffeId, got {other:?}"),
        }
    }

    #[test]
    fn parse_spiffe_id_rejects_missing_scheme() {
        match parse_spiffe_id("http://tracelane.dev/tenant/abc/ingest-worker") {
            Err(SpiffeAuthError::MalformedSpiffeId(_)) => {}
            other => panic!("expected MalformedSpiffeId, got {other:?}"),
        }
    }

    // ---- post-review hardening tests (security-reviewer findings) ----

    #[test]
    fn rejects_ca_certificate_with_spiffe_san() {
        // SPIFFE X.509-SVID §4.3 violation: a CA cert MUST NOT pass as a workload.
        let der = mint_ca_with_spiffe_san(
            "spiffe://tracelane.dev/tenant/00000000-0000-0000-0000-00000000000a/ingest-worker",
        );
        match verify_spiffe_svid(&der) {
            Err(SpiffeAuthError::LeafIsCa) => {}
            other => panic!("expected LeafIsCa, got {other:?}"),
        }
    }

    #[test]
    fn rejects_leaf_without_key_usage_digital_signature() {
        let der = mint_leaf_no_key_usage(
            "spiffe://tracelane.dev/tenant/00000000-0000-0000-0000-00000000000b/ingest-worker",
        );
        match verify_spiffe_svid(&der) {
            Err(SpiffeAuthError::MissingKeyUsageDigitalSignature) => {}
            other => panic!("expected MissingKeyUsageDigitalSignature, got {other:?}"),
        }
    }

    #[test]
    fn rejects_oversize_certificate() {
        let mut buf = vec![0u8; MAX_SVID_DER_BYTES + 1];
        buf[0] = 0x30; // make it superficially look ASN.1-ish
        match verify_spiffe_svid(&buf) {
            Err(SpiffeAuthError::OversizeCertificate) => {}
            other => panic!("expected OversizeCertificate, got {other:?}"),
        }
    }

    #[test]
    fn trust_domain_compare_is_case_insensitive() {
        // Upper-case authority must still be accepted per SPIFFE §2.1.
        let tenant_uuid = Uuid::new_v4();
        let uri = format!("spiffe://Tracelane.DEV/tenant/{tenant_uuid}/ingest-worker");
        let der = mint_svid(&[&uri], (2025, 1, 1), (2099, 1, 1));
        let id = verify_spiffe_svid(&der).expect("ASCII-case variant accepted");
        assert_eq!(id.tenant_id.as_uuid(), &tenant_uuid);
    }

    #[test]
    fn rejects_non_ascii_trust_domain() {
        // IDN / unicode-confusable trust domain banned outright.
        match parse_spiffe_id("spiffe://trac\u{0435}lane.dev/tenant/abc/ingest-worker") {
            Err(SpiffeAuthError::MalformedSpiffeId(_)) => {}
            other => panic!("expected MalformedSpiffeId for non-ASCII authority, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_path_segment() {
        // /tenant//ingest-worker — empty UUID segment.
        match parse_spiffe_id("spiffe://tracelane.dev/tenant//ingest-worker") {
            Err(SpiffeAuthError::MalformedTenantId) => {}
            other => panic!("expected MalformedTenantId, got {other:?}"),
        }
    }

    #[test]
    fn accepts_dns_san_alongside_spiffe_uri() {
        // SAN may carry multiple GeneralNames of different types. We pick
        // the SPIFFE URI; DNS entries should be ignored without contamination.
        let tenant_uuid = Uuid::new_v4();
        let spiffe = format!("spiffe://tracelane.dev/tenant/{tenant_uuid}/ingest-worker");

        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "test");
        params.not_before = date_time_ymd(2025, 1, 1);
        params.not_after = date_time_ymd(2099, 1, 1);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.subject_alt_names = vec![
            SanType::DnsName(Ia5String::try_from("example.com".to_string()).unwrap()),
            SanType::URI(Ia5String::try_from(spiffe.clone()).unwrap()),
        ];
        let key = KeyPair::generate().unwrap();
        let der = params.self_signed(&key).unwrap().der().to_vec();

        let id = verify_spiffe_svid(&der).expect("DNS sibling does not contaminate");
        assert_eq!(id.tenant_id.as_uuid(), &tenant_uuid);
        assert_eq!(id.spiffe_uri, spiffe);
    }

    #[test]
    fn injectable_clock_passes_inside_validity_window() {
        let uri = format!(
            "spiffe://tracelane.dev/tenant/{}/ingest-worker",
            Uuid::new_v4()
        );
        let der = mint_svid(&[&uri], (2026, 1, 1), (2026, 12, 31));
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();

        let id = verify_spiffe_svid_at(&der, now).expect("inside window");
        assert!(id.expires_at - now > ChronoDuration::days(180));
    }

    // ---- middleware integration ----

    async fn handler_echoes_tenant(req: Request<Body>) -> String {
        match req.extensions().get::<TenantId>() {
            Some(t) => t.to_string(),
            None => "no-tenant".to_string(),
        }
    }

    fn router() -> Router {
        Router::new()
            .route("/v1/traces", get(handler_echoes_tenant))
            .layer(middleware::from_fn(require_spiffe_auth))
    }

    #[tokio::test]
    async fn middleware_rejects_request_without_peer_cert() {
        let app = router();
        let req = HttpRequest::builder()
            .uri("/v1/traces")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "SPIFFE-mTLS"
        );
    }

    #[tokio::test]
    async fn middleware_rejects_request_with_bad_peer_cert() {
        let app = router();
        let mut req = HttpRequest::builder()
            .uri("/v1/traces")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(PeerCertDer(Bytes::from_static(b"garbage")));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn middleware_accepts_valid_peer_cert_and_injects_tenant() {
        let tenant_uuid = Uuid::new_v4();
        let der = valid_svid(&tenant_uuid.to_string());

        let app = router();
        let mut req = HttpRequest::builder()
            .uri("/v1/traces")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(PeerCertDer(Bytes::from(der)));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = std::str::from_utf8(&body).unwrap();
        assert_eq!(body_str, tenant_uuid.to_string());
    }

    // ---- mock SPIRE issuer integration test ----
    //
    // Acceptance criterion #8: integration test using a mock SPIRE issuer.
    // The real SPIRE Workload API hands out SVIDs over `unix:///tmp/spire-agent/
    // public/api.sock`. For an in-process test we model the issuer as a
    // function that mints SVIDs from a CA-style parameter set. This exercises
    // the full middleware path end-to-end with a freshly-minted cert.

    struct MockSpireIssuer;

    impl MockSpireIssuer {
        fn issue(tenant: Uuid, ttl_hours: i64) -> Vec<u8> {
            let uri = format!("spiffe://tracelane.dev/tenant/{tenant}/ingest-worker");
            let now = Utc::now();
            let exp = now + ChronoDuration::hours(ttl_hours);
            mint_svid(
                &[&uri],
                (
                    now.format("%Y").to_string().parse().unwrap(),
                    now.format("%m").to_string().parse().unwrap(),
                    now.format("%d").to_string().parse().unwrap(),
                ),
                (
                    exp.format("%Y").to_string().parse().unwrap(),
                    exp.format("%m").to_string().parse().unwrap(),
                    exp.format("%d").to_string().parse().unwrap(),
                ),
            )
        }
    }

    // ---- metric counter (ADR-028 §Observability) ----

    #[test]
    fn auth_result_label_strings_are_stable() {
        // These literals are read by Prometheus / Grafana queries — bumping
        // them silently would break dashboards.
        assert_eq!(AuthResult::Ok.label(), "ok");
        assert_eq!(AuthResult::WrongTrustDomain.label(), "wrong_trust_domain");
        assert_eq!(AuthResult::InvalidPath.label(), "invalid_path");
        assert_eq!(AuthResult::ExpiredSvid.label(), "expired_svid");
        assert_eq!(AuthResult::NoSvid.label(), "no_svid");
    }

    #[test]
    fn error_variants_map_to_metric_buckets() {
        use SpiffeAuthError::*;
        assert_eq!(
            WrongTrustDomain.as_auth_result(),
            AuthResult::WrongTrustDomain
        );
        assert_eq!(NoSpiffeId.as_auth_result(), AuthResult::NoSvid);
        assert_eq!(Expired.as_auth_result(), AuthResult::ExpiredSvid);
        assert_eq!(NotYetValid.as_auth_result(), AuthResult::ExpiredSvid);
        assert_eq!(MissingTenantPath.as_auth_result(), AuthResult::InvalidPath);
        assert_eq!(MalformedTenantId.as_auth_result(), AuthResult::InvalidPath);
        assert_eq!(LeafIsCa.as_auth_result(), AuthResult::InvalidPath);
        assert_eq!(
            MissingKeyUsageDigitalSignature.as_auth_result(),
            AuthResult::InvalidPath
        );
        assert_eq!(
            MalformedCertificate.as_auth_result(),
            AuthResult::InvalidPath
        );
        assert_eq!(
            OversizeCertificate.as_auth_result(),
            AuthResult::InvalidPath
        );
        assert_eq!(MissingSan.as_auth_result(), AuthResult::InvalidPath);
        assert_eq!(MultipleSpiffeIds.as_auth_result(), AuthResult::InvalidPath);
        assert_eq!(InvertedValidity.as_auth_result(), AuthResult::InvalidPath);
        assert_eq!(
            MalformedSpiffeId("test").as_auth_result(),
            AuthResult::InvalidPath
        );
    }

    #[tokio::test]
    async fn middleware_increments_no_svid_when_peer_cert_missing() {
        let before = auth_metric_snapshot()[AuthResult::NoSvid.idx()];
        let app = router();
        let req = HttpRequest::builder()
            .uri("/v1/traces")
            .body(Body::empty())
            .unwrap();
        let _ = app.oneshot(req).await.unwrap();
        let after = auth_metric_snapshot()[AuthResult::NoSvid.idx()];
        assert!(
            after > before,
            "no_svid counter should advance on missing PeerCertDer (before={before}, after={after})"
        );
    }

    #[tokio::test]
    async fn middleware_increments_ok_on_valid_svid() {
        let before = auth_metric_snapshot()[AuthResult::Ok.idx()];
        let tenant_uuid = Uuid::new_v4();
        let der = valid_svid(&tenant_uuid.to_string());
        let app = router();
        let mut req = HttpRequest::builder()
            .uri("/v1/traces")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(PeerCertDer(Bytes::from(der)));
        let _ = app.oneshot(req).await.unwrap();
        let after = auth_metric_snapshot()[AuthResult::Ok.idx()];
        assert!(after > before, "ok counter should advance on valid SVID");
    }

    #[tokio::test]
    async fn mock_spire_issuer_end_to_end() {
        let tenant_uuid = Uuid::new_v4();
        let der = MockSpireIssuer::issue(tenant_uuid, 24);

        let app = router();
        let mut req = HttpRequest::builder()
            .uri("/v1/traces")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(PeerCertDer(Bytes::from(der)));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(std::str::from_utf8(&body).unwrap(), tenant_uuid.to_string());
    }


    /// A handler that decodes an OTLP body using the tenant the middleware
    /// injected (`Extension<TenantId>` from the verified SVID) and echoes the
    /// resolved span's tenant — the downstream shape of the real ingest path.
    async fn decode_and_echo_resolved_tenant(
        axum::Extension(peer_tenant): axum::Extension<TenantId>,
        body: Bytes,
    ) -> String {
        match crate::otlp_decode::decode_otlp_protobuf(&body, Some(&peer_tenant)) {
            Ok(spans) => spans
                .first()
                .map(|s| s.tenant_id.to_string())
                .unwrap_or_else(|| "no-spans".to_string()),
            Err(e) => format!("decode-error: {e}"),
        }
    }

    fn decode_router() -> Router {
        Router::new()
            .route(
                "/v1/traces",
                axum::routing::post(decode_and_echo_resolved_tenant),
            )
            .layer(middleware::from_fn(require_spiffe_auth))
    }

    /// Build an OTLP protobuf body whose resource carries
    /// `tracelane.tenant_id = <tenant_uuid_str>` and one well-formed span.
    fn otlp_body_with_resource_tenant(tenant_uuid_str: &str) -> Vec<u8> {
        use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
        use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value::Value};
        use opentelemetry_proto::tonic::resource::v1::Resource;
        use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
        use prost::Message as _;

        let span = Span {
            trace_id: vec![7u8; 16],
            span_id: vec![9u8; 8],
            name: "chat".into(),
            start_time_unix_nano: 1_700_000_000_000_000_000,
            end_time_unix_nano: 1_700_000_001_000_000_000,
            ..Default::default()
        };
        let req = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: crate::otlp_decode::TRACELANE_TENANT_ID_ATTR.into(),
                        value: Some(AnyValue {
                            value: Some(Value::StringValue(tenant_uuid_str.to_string())),
                        }),
                    }],
                    ..Default::default()
                }),
                scope_spans: vec![ScopeSpans {
                    spans: vec![span],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        req.encode_to_vec()
    }

    /// `require_spiffe_auth` seam.
    ///
    /// A valid tenant-A mTLS peer sends a body that stuffs `tracelane.tenant_id`
    /// = tenant B. The span MUST be attributed to A (the authenticated SVID
    /// peer), never B (the body). Until now this was covered only at two
    /// *separate* lower layers — `otlp_decode::peer_tenant_wins_over_resource_attribute`
    /// (decode, called directly with a peer) and
    /// `middleware_accepts_valid_peer_cert_and_injects_tenant` (middleware only)
    /// — with no test proving they compose: that the middleware-injected
    /// `Extension<TenantId>` is the one the decoder uses, so a body-supplied
    /// tenant can never win end-to-end. Profile-agnostic: the peer path returns
    /// before `resolve_tenant`'s cfg branches, so it holds in debug AND release.
    #[tokio::test]
    async fn peer_svid_wins_over_body_supplied_tenant_through_middleware() {
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();
        assert_ne!(
            tenant_a, tenant_b,
            "A and B must differ for the test to mean anything"
        );

        let der = valid_svid(&tenant_a.to_string());
        // The body tries to smuggle tenant B via the resource attribute.
        let body = otlp_body_with_resource_tenant(&tenant_b.to_string());

        let app = decode_router();
        let mut req = HttpRequest::builder()
            .method("POST")
            .uri("/v1/traces")
            .body(Body::from(body))
            .unwrap();
        // The TLS layer would insert this after chain-verifying the peer SVID.
        req.extensions_mut().insert(PeerCertDer(Bytes::from(der)));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a valid peer must be admitted"
        );

        let out = resp.into_body().collect().await.unwrap().to_bytes();
        let resolved = std::str::from_utf8(&out).unwrap();
        assert_eq!(
            resolved,
            tenant_a.to_string(),
            "span must be attributed to the mTLS PEER (A), never the body-supplied tenant"
        );
        assert_ne!(
            resolved,
            tenant_b.to_string(),
            "body-supplied tracelane.tenant_id must NOT override the SPIFFE peer identity"
        );
    }

    /// body-supplied tenant is rejected at the middleware (401) and never
    /// reaches the decoder — a body tenant cannot self-authorize.
    #[tokio::test]
    async fn body_supplied_tenant_without_peer_is_rejected_at_middleware() {
        let tenant_b = Uuid::new_v4();
        let body = otlp_body_with_resource_tenant(&tenant_b.to_string());

        let app = decode_router();
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/v1/traces")
            .body(Body::from(body))
            .unwrap();
        // No PeerCertDer inserted → middleware must 401 before the handler runs.
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "SPIFFE-mTLS"
        );
    }
}
