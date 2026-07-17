//! mTLS termination for the ingest receiver.
//!
//! Wires together three pieces:
//!
//! * `SpireClientCertVerifier` — implements `rustls::server::danger::ClientCertVerifier`.
//!   Validates a presented client SVID chain against an `ArcSwap`-installed
//!   trust bundle. The trust bundle can be swapped at any time without
//!   tearing down existing connections (per-connection cache policy).
//! * `build_server_config` — assembles a `rustls::ServerConfig` from the
//!   workload's own SVID, the private key, and the verifier. Enforces
//!   TLS 1.3 only; client auth is **mandatory** (no `_optional` variant).
//! * `BundleRefresher` — owns the SPIRE Workload API stream and
//!   `ArcSwap::store`s each new bundle into the shared cell that the
//!   verifier reads on every handshake.
//!
//! ## Why per-connection cache (CLAUDE-INTERNAL doctrine)
//!
//! When SPIRE rotates the trust bundle (default 1h), in-flight
//! connections that already finished the TLS handshake keep working —
//! they don't reach the verifier again. New handshakes pick up the
//! updated bundle via `ArcSwap::load`. This matches the pattern used by
//! Envoy / Linkerd / Istio. Maximum staleness equals the SVID TTL (1h

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use arc_swap::ArcSwap;
use futures::StreamExt as _;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{CryptoProvider, ring as ring_crypto, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig, SignatureScheme,
};
use secrecy::ExposeSecret as _;
use tracing::instrument;
use zeroize::Zeroizing;

use crate::spire_client::{SpireClient, SvidMaterial};

/// Shared, atomically-swappable trust bundle. Cloning the `Arc` is cheap;
/// `load()` on each handshake is wait-free.
pub type SharedTrustBundle = Arc<ArcSwap<RootCertStore>>;

/// rustls `ClientCertVerifier` backed by a hot-swappable SPIRE trust
/// bundle.
///
/// Internally delegates to `WebPkiClientVerifier` rebuilt against the
/// snapshot of `RootCertStore` captured at handshake time. Allocating a
/// new verifier per handshake is fine — `webpki` parses the roots lazily
/// and the cost is amortised against the TLS handshake itself.
#[derive(Debug)]
pub struct SpireClientCertVerifier {
    bundle: SharedTrustBundle,
    provider: Arc<CryptoProvider>,
}

impl SpireClientCertVerifier {
    pub fn new(bundle: SharedTrustBundle, provider: Arc<CryptoProvider>) -> Self {
        Self { bundle, provider }
    }

    fn delegate(&self) -> Result<Arc<dyn ClientCertVerifier>, rustls::Error> {
        let snapshot = self.bundle.load_full();
        // `WebPkiClientVerifier::builder` consumes the roots Arc; clone
        // the underlying store cheaply via `RootCertStore::clone`.
        let roots = (*snapshot).clone();
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), self.provider.clone())
            .build()
            .map_err(|e| rustls::Error::General(format!("build webpki verifier: {e}")))
    }
}

impl ClientCertVerifier for SpireClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // Empty hint list — SPIRE workloads know their own trust domain.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.delegate()?
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // TLS 1.3 only — reject any TLS 1.2 signature verification attempt.
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOfferedOrEnabled,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a `RootCertStore` from a SPIRE-provided trust bundle.
///
/// SPIRE bundles arrive as a flat `Vec<CertificateDer>`; the rustls
/// `RootCertStore` rejects any cert that can't be parsed as a valid
/// X.509 trust anchor — those are surfaced as a `rustls::Error`.
pub fn root_store_from_bundle(bundle: &[CertificateDer<'static>]) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    for cert in bundle {
        store
            .add(cert.clone())
            .with_context(|| "add cert to trust bundle")?;
    }
    Ok(store)
}

/// Assemble a complete `ServerConfig` for the ingest receiver.
///
/// * Loads `aws_lc_rs` or `ring` crypto provider (we pin to `ring` for
///   parity with rcgen / async-nats / reqwest).
/// * Restricts to TLS 1.3 only.
/// * Installs the SPIRE-backed client cert verifier.
/// * Loads the workload's own SVID chain + private key for the server
///   side of the handshake.
pub fn build_server_config(svid: &SvidMaterial, bundle: SharedTrustBundle) -> Result<ServerConfig> {
    let provider = Arc::new(ring_crypto::default_provider());

    // Note: we do NOT call CryptoProvider::install_default here. Every
    // SpireClientCertVerifier carries its own Arc<CryptoProvider>, so the
    // process default is irrelevant and installing it would only invite the
    // appearance of a TOCTOU race with other crates.

    // Clone the SVID private key into a Zeroizing<Vec<u8>> so the
    // intermediate buffer is wiped on drop. rustls's internal copy after
    // PrivateKeyDer::try_from is NOT zeroizable (upstream limitation), so
    // there is a residual plaintext key in process memory for the binary's
    // lifetime — track upstream issue rustls/rustls#1971.
    let key_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(svid.private_key.expose_secret().clone());
    let private_key = PrivateKeyDer::try_from(key_bytes.to_vec())
        .map_err(|e| anyhow::anyhow!("parse SVID private key: {e}"))?;

    let verifier = Arc::new(SpireClientCertVerifier::new(bundle, provider.clone()));

    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("rustls protocol versions")?
        .with_client_cert_verifier(verifier)
        .with_single_cert(svid.cert_chain.clone(), private_key)
        .context("install workload SVID into ServerConfig")?;

    Ok(config)
}

/// Background task that streams trust-bundle updates from SPIRE and
/// installs each one into the shared `ArcSwap`. Exits when the SPIRE
/// stream ends or errors irrecoverably — caller decides retry policy.
pub struct BundleRefresher {
    client: SpireClient,
    bundle: SharedTrustBundle,
    /// Trust domain name the refresher filters bundle updates to. Other
    /// federated bundles are ignored silently.
    trust_domain: String,
    /// Retry policy. Defaults to the module consts in `new`; FT-09 shrinks
    /// these via `with_retry_policy` so the bail path can be exercised in
    /// milliseconds instead of the ~3.5-minute production budget.
    initial_backoff: Duration,
    max_backoff: Duration,
    max_failures: u32,
}

/// Max consecutive stream-failure backoff before the refresher gives up
/// and exits with `Err`. Caller (main.rs) decides shutdown policy.
const MAX_REFRESH_BACKOFF: Duration = Duration::from_secs(60);
/// Initial backoff before first retry. Doubles on each failure.
const INITIAL_REFRESH_BACKOFF: Duration = Duration::from_millis(500);
/// Maximum total consecutive failures before the refresher exits with Err.
/// At INITIAL=500ms doubling with cap at 60s, 8 attempts ≈ 3.5 minutes — well
/// under the 1h SVID TTL, so a new trust bundle still arrives before client
/// certs expire if any retry succeeds.
const MAX_REFRESH_FAILURES: u32 = 8;

impl BundleRefresher {
    pub fn new(client: SpireClient, bundle: SharedTrustBundle, trust_domain: String) -> Self {
        Self {
            client,
            bundle,
            trust_domain,
            initial_backoff: INITIAL_REFRESH_BACKOFF,
            max_backoff: MAX_REFRESH_BACKOFF,
            max_failures: MAX_REFRESH_FAILURES,
        }
    }

    /// Test-only: shrink the retry policy so FT-09 can drive the
    /// give-up-and-`Err` path without waiting out the production backoff.
    #[cfg(test)]
    fn with_retry_policy(mut self, initial: Duration, max: Duration, max_failures: u32) -> Self {
        self.initial_backoff = initial;
        self.max_backoff = max;
        self.max_failures = max_failures;
        self
    }

    /// Run with bounded retry-with-exponential-backoff on stream failure.
    ///
    /// Each fresh `stream_bundles()` opens a new long-lived gRPC stream
    /// against SPIRE. Within a single stream we process every bundle
    /// update; on transport / decode error we close the stream, sleep,
    /// and re-open. After [`MAX_REFRESH_FAILURES`] consecutive failures
    /// we return `Err` so `main.rs::try_join!` can react.
    #[instrument(skip(self), fields(trust_domain = %self.trust_domain))]
    pub async fn run(self) -> Result<()> {
        let mut failures: u32 = 0;
        let mut backoff = self.initial_backoff;

        loop {
            match self.run_one_stream().await {
                Ok(()) => {
                    // Stream ended cleanly — SPIRE closed the connection.
                    // Reset failure counter and try again immediately; this
                    // is normal during SPIRE agent restarts.
                    tracing::warn!("SPIRE bundle stream ended cleanly; reconnecting");
                    failures = 0;
                    backoff = self.initial_backoff;
                }
                Err(e) => {
                    failures += 1;
                    tracing::warn!(
                        error = %e,
                        failures,
                        backoff_ms = backoff.as_millis() as u64,
                        "SPIRE bundle stream errored; backing off",
                    );
                    if failures >= self.max_failures {
                        anyhow::bail!(
                            "SPIRE bundle refresher gave up after {failures} consecutive failures; last error: {e}"
                        );
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(backoff * 2, self.max_backoff);
                }
            }
        }
    }

    /// Process one open SPIRE bundle stream. Returns `Ok(())` when the
    /// stream ends cleanly, `Err` on any transport / decode failure.
    async fn run_one_stream(&self) -> Result<()> {
        let stream = self
            .client
            .stream_bundles()
            .await
            .context("open FetchX509Bundles stream")?;
        tokio::pin!(stream);

        while let Some(update) = stream.next().await {
            let updates = update.context("stream recv")?;
            for u in updates {
                // Case-insensitive to match parse_spiffe_id's trust-domain
                // must not silently stop bundle rotation.
                if u.trust_domain.eq_ignore_ascii_case(&self.trust_domain) {
                    let store = root_store_from_bundle(&u.bundle)
                        .context("rebuild RootCertStore from updated bundle")?;
                    self.bundle.store(Arc::new(store));
                    tracing::info!(
                        trust_domain = %u.trust_domain,
                        cert_count = u.bundle.len(),
                        "trust bundle rotated",
                    );
                } else {
                    tracing::debug!(
                        federated_domain = %u.trust_domain,
                        "ignoring federated bundle update (not our trust domain)",
                    );
                }
            }
        }
        Ok(())
    }
}

/// Convenience: do an initial SVID fetch and return everything needed to
/// boot the receiver and the refresher.
#[instrument(skip(client), fields(trust_domain = %trust_domain))]
pub async fn bootstrap_from_spire(
    client: &SpireClient,
    trust_domain: &str,
) -> Result<(ServerConfig, SharedTrustBundle)> {
    let svid = client
        .fetch_initial()
        .await
        .context("initial FetchX509SVID")?;

    // Sanity: the workload's own SPIFFE ID must be in our trust domain.
    // Cheap guard against pointing at the wrong SPIRE agent.
    let expected_prefix = format!("spiffe://{trust_domain}/");
    if !svid.spiffe_id.starts_with(&expected_prefix) {
        anyhow::bail!(
            "SPIRE-issued SVID has wrong trust domain: got `{}`, expected prefix `{}`",
            svid.spiffe_id,
            expected_prefix,
        );
    }

    let store = root_store_from_bundle(&svid.bundle)?;
    let bundle: SharedTrustBundle = Arc::new(ArcSwap::from_pointee(store));
    let config = build_server_config(&svid, bundle.clone())?;
    Ok((config, bundle))
}

/// Read-side helper for the accept loop: how long to wait for the TLS
/// handshake to complete before dropping the TCP connection. Defends
/// against slowloris-style handshake-stalling attacks.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, Ia5String, IsCa, KeyPair, KeyUsagePurpose,
        SanType,
    };
    use rustls::pki_types::CertificateDer;

    #[test]
    fn root_store_from_empty_bundle_is_empty_store() {
        let store = root_store_from_bundle(&[]).unwrap();
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn root_store_from_garbage_errors() {
        let bogus = CertificateDer::from(vec![0u8; 16]);
        let res = root_store_from_bundle(&[bogus]);
        assert!(res.is_err(), "garbage cert must be rejected");
    }

    /// Mint a self-signed CA + a leaf cert signed by it. Returns the
    /// CA's DER (for the trust bundle) and the leaf's DER.
    fn mint_ca_and_leaf(leaf_uri: &str) -> (Vec<u8>, Vec<u8>) {
        // CA
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Tracelane Test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();

        // Leaf
        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "leaf");
        leaf_params.subject_alt_names = vec![SanType::URI(
            Ia5String::try_from(leaf_uri.to_string()).unwrap(),
        )];
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();

        (ca.der().to_vec(), leaf.der().to_vec())
    }

    fn shared_bundle_with(ca_der: &[u8]) -> SharedTrustBundle {
        let bundle = vec![CertificateDer::from(ca_der.to_vec())];
        let store = root_store_from_bundle(&bundle).unwrap();
        Arc::new(ArcSwap::from_pointee(store))
    }

    #[test]
    fn verifier_accepts_leaf_chained_to_bundle_ca() {
        let (ca_der, leaf_der) = mint_ca_and_leaf(
            "spiffe://tracelane.dev/tenant/00000000-0000-0000-0000-000000000003/ingest-worker",
        );
        let bundle = shared_bundle_with(&ca_der);
        let provider = Arc::new(ring_crypto::default_provider());
        let verifier = SpireClientCertVerifier::new(bundle, provider);

        let leaf = CertificateDer::from(leaf_der);
        let res = verifier.verify_client_cert(&leaf, &[], UnixTime::now());
        assert!(
            res.is_ok(),
            "leaf chained to bundle CA must verify: {res:?}"
        );
    }

    #[test]
    fn verifier_rejects_leaf_signed_by_unknown_ca() {
        // Two independent CAs. Bundle trusts ca1, leaf is signed by ca2.
        let (ca1_der, _leaf1) = mint_ca_and_leaf("spiffe://tracelane.dev/tenant/a/ingest-worker");
        let (_ca2_der, leaf2_der) =
            mint_ca_and_leaf("spiffe://tracelane.dev/tenant/b/ingest-worker");
        let bundle = shared_bundle_with(&ca1_der);
        let provider = Arc::new(ring_crypto::default_provider());
        let verifier = SpireClientCertVerifier::new(bundle, provider);

        let leaf = CertificateDer::from(leaf2_der);
        let res = verifier.verify_client_cert(&leaf, &[], UnixTime::now());
        assert!(
            res.is_err(),
            "leaf signed by a CA not in the bundle MUST be rejected"
        );
    }

    #[test]
    fn verifier_client_auth_is_mandatory() {
        let (ca_der, _leaf) = mint_ca_and_leaf("spiffe://tracelane.dev/tenant/c/ingest-worker");
        let bundle = shared_bundle_with(&ca_der);
        let provider = Arc::new(ring_crypto::default_provider());
        let verifier = SpireClientCertVerifier::new(bundle, provider);
        assert!(verifier.client_auth_mandatory());
        assert!(verifier.offer_client_auth());
    }

    #[test]
    fn verifier_supported_schemes_include_tls13_set() {
        let (ca_der, _leaf) = mint_ca_and_leaf("spiffe://tracelane.dev/tenant/d/ingest-worker");
        let bundle = shared_bundle_with(&ca_der);
        let provider = Arc::new(ring_crypto::default_provider());
        let verifier = SpireClientCertVerifier::new(bundle, provider);
        let schemes = verifier.supported_verify_schemes();
        assert!(
            !schemes.is_empty(),
            "ring provider must offer at least one signature scheme"
        );
    }

    #[test]
    fn bundle_rotation_picks_up_new_ca_on_next_verify() {
        // Initial bundle has CA1. Verify a leaf chained to CA1 → ok.
        // Swap bundle to CA2. Verify the same leaf → rejected.
        let (ca1_der, leaf1_der) =
            mint_ca_and_leaf("spiffe://tracelane.dev/tenant/rotate/ingest-worker");
        let (ca2_der, _leaf2) =
            mint_ca_and_leaf("spiffe://tracelane.dev/tenant/other/ingest-worker");

        let bundle = shared_bundle_with(&ca1_der);
        let provider = Arc::new(ring_crypto::default_provider());
        let verifier = SpireClientCertVerifier::new(bundle.clone(), provider);

        let leaf = CertificateDer::from(leaf1_der);
        assert!(
            verifier
                .verify_client_cert(&leaf, &[], UnixTime::now())
                .is_ok(),
            "pre-rotation: leaf chained to CA1 should verify"
        );

        // Rotate: replace bundle with one that trusts only CA2.
        let new_store = root_store_from_bundle(&[CertificateDer::from(ca2_der)]).unwrap();
        bundle.store(Arc::new(new_store));

        assert!(
            verifier
                .verify_client_cert(&leaf, &[], UnixTime::now())
                .is_err(),
            "post-rotation: leaf chained to old CA must be rejected"
        );
    }

    /// FT-09 chaos: the SPIRE agent goes down mid-flight. The
    /// `BundleRefresher` must NOT hang silently — after its bounded retries
    /// it returns `Err` so `main.rs::try_join!` propagates the failure and
    /// the supervisor restarts the process (fail-closed: a frozen trust
    /// bundle is worse than a controlled outage, ADR-028 §Risks).
    ///
    /// We spawn a real mock SPIRE (so `connect()` succeeds), then drop the
    /// handle so the agent disappears. The retry policy is shrunk via
    /// `with_retry_policy` so the give-up path runs in milliseconds rather
    /// resolved, so this now runs in the normal suite.
    #[tokio::test]
    async fn ft09_refresher_exits_with_err_when_spire_agent_down() {
        use crate::spire_mock::{MockSpireMaterial, spawn_mock_spire};

        let dir = tempfile::tempdir().unwrap();
        // Dummy material — the FT-09 path only opens the bundle stream, which
        // fails once the agent is gone, so the SVID/bundle bytes are unused.
        let material = MockSpireMaterial {
            spiffe_id: "spiffe://tracelane.dev/ingest-worker".into(),
            x509_svid_der: vec![],
            x509_svid_key_pkcs8_der: vec![],
            bundle_der: vec![],
            trust_domain: "tracelane.dev".into(),
        };
        let handle = spawn_mock_spire(dir.path(), material).await;
        let client = SpireClient::connect(handle.socket_path.clone())
            .await
            .expect("connect to the running mock SPIRE");

        // Agent goes down mid-flight.
        drop(handle);

        let bundle: SharedTrustBundle = Arc::new(ArcSwap::from_pointee(RootCertStore::empty()));
        let refresher = BundleRefresher::new(client, bundle, "tracelane.dev".into())
            .with_retry_policy(Duration::from_millis(1), Duration::from_millis(5), 3);

        let res = tokio::time::timeout(Duration::from_secs(5), refresher.run())
            .await
            .expect("refresher must give up within budget, not hang");
        assert!(
            res.is_err(),
            "refresher must return Err after the SPIRE agent stays down",
        );
    }
}
