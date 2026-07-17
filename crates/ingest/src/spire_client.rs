//! SPIRE Workload API client over a Unix Domain Socket.
//!
//! Connects to the SPIRE agent socket (default
//! `unix:///tmp/spire-agent/public/api.sock`) and exposes:
//!
//! * `fetch_initial()` — one-shot fetch of the workload's X.509-SVID
//!   (cert chain + private key) AND the trust bundle. Used at startup to
//!   build the initial rustls `ServerConfig`.
//! * `stream_bundles()` — long-lived stream of trust-bundle updates. Each
//!   update is `arc_swap`-installed into the running verifier without
//!   tearing down in-flight connections.
//!
//! The SVID private key is wrapped in `secrecy::SecretBox<Vec<u8>>` and
//! zeroized on drop (CLAUDE.md non-negotiable). The trust bundle is a
//! plain `Vec<CertificateDer>` — public material, no secrecy needed.
//!
//! The Workload API spec requires `workload.spiffe.io: true` metadata on
//! every request — we attach it via a tonic interceptor.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow};
use futures::Stream;
use futures::StreamExt as _;
use hyper_util::rt::TokioIo;
use rustls_pki_types::CertificateDer;
use secrecy::SecretBox;
use tokio::net::UnixStream;
use tonic::Request;
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::transport::{Channel, Endpoint, Uri};
use tower_service::Service;
use x509_parser::prelude::FromDer as _;

use crate::spire_proto::spiffe_workload_api_client::SpiffeWorkloadApiClient;
use crate::spire_proto::{X509BundlesRequest, X509svidRequest};

/// Header SPIRE requires on every Workload API call. Without it the agent
/// rejects the request with `PERMISSION_DENIED`.
const SPIFFE_SECURITY_HEADER: &str = "workload.spiffe.io";

/// Default SPIRE agent socket path (per the SPIFFE spec).
pub const DEFAULT_SPIRE_SOCKET: &str = "/tmp/spire-agent/public/api.sock";

/// One snapshot of trust material for a single trust domain.
///
/// The private key is `SecretBox` so that any accidental `Debug`-print
/// or panic-payload capture redacts it; on drop the bytes are zeroized.
pub struct SvidMaterial {
    /// SPIFFE ID asserted by the leaf cert. Verified by the caller to
    /// match `spiffe://tracelane.dev/...`.
    pub spiffe_id: String,
    /// Leaf-first ASN.1 DER certificate chain.
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// PKCS#8 DER-encoded private key. Wrapped in `SecretBox` so the
    /// bytes are zeroized on drop and never appear in `Debug` output.
    pub private_key: SecretBox<Vec<u8>>,
    /// Trust bundle for our own trust domain (separate certificates,
    /// already split on cert boundaries).
    pub bundle: Vec<CertificateDer<'static>>,
}

impl std::fmt::Debug for SvidMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SvidMaterial")
            .field("spiffe_id", &self.spiffe_id)
            .field("cert_chain.len", &self.cert_chain.len())
            .field("private_key", &"<redacted>")
            .field("bundle.len", &self.bundle.len())
            .finish()
    }
}

/// Trust-bundle-only update streamed from `FetchX509Bundles`.
#[derive(Debug, Clone)]
pub struct BundleUpdate {
    pub trust_domain: String,
    pub bundle: Vec<CertificateDer<'static>>,
}

/// Interceptor that injects the mandatory `workload.spiffe.io: true`
/// metadata on every gRPC request.
#[derive(Clone, Copy)]
struct WorkloadHeader;

impl Interceptor for WorkloadHeader {
    fn call(&mut self, mut req: Request<()>) -> std::result::Result<Request<()>, tonic::Status> {
        req.metadata_mut()
            .insert(SPIFFE_SECURITY_HEADER, MetadataValue::from_static("true"));
        Ok(req)
    }
}

/// Build a tonic `Channel` that dials a Unix Domain Socket.
///
/// tonic's `Endpoint` only knows how to dial TCP/IP by default; we
/// substitute a custom connector that opens a `UnixStream` regardless of
/// the URI's authority. The URI itself is a synthetic `http://localhost`
/// because tonic requires a parseable URI.
async fn connect_uds(socket_path: PathBuf) -> Result<Channel> {
    // `connect_timeout` applies only to the initial TCP/UDS dial.
    // We deliberately do NOT set `Endpoint::timeout` because tonic
    // applies that to total RPC duration — which would kill the
    // long-lived `FetchX509Bundles` stream every N seconds.
    let endpoint = Endpoint::try_from("http://[::]:50051")
        .context("synthetic tonic URI failed to parse")?
        .connect_timeout(Duration::from_secs(5));

    let channel = endpoint
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let path = socket_path.clone();
            async move {
                let stream = UnixStream::connect(path)
                    .await
                    .map_err(|e| anyhow!("connect SPIRE socket: {e}"))?;
                Ok::<_, anyhow::Error>(TokioIo::new(stream))
            }
        }))
        .await
        .context("dial SPIRE Workload API socket")?;

    Ok(channel)
}

/// Public handle on the SPIRE Workload API. Cheap to clone.
#[derive(Clone)]
pub struct SpireClient {
    inner: Arc<SpireClientInner>,
}

struct SpireClientInner {
    channel: Channel,
}

impl SpireClient {
    /// Connect to the SPIRE agent at the default socket path.
    #[tracing::instrument]
    pub async fn connect_default() -> Result<Self> {
        Self::connect(PathBuf::from(DEFAULT_SPIRE_SOCKET)).await
    }

    /// Connect to a specific SPIRE agent socket path. Use in tests with a
    /// `tempfile::tempdir()`-rooted socket.
    #[tracing::instrument]
    pub async fn connect(socket_path: PathBuf) -> Result<Self> {
        let channel = connect_uds(socket_path).await?;
        Ok(Self {
            inner: Arc::new(SpireClientInner { channel }),
        })
    }

    fn stub(
        &self,
    ) -> SpiffeWorkloadApiClient<
        tonic::service::interceptor::InterceptedService<Channel, WorkloadHeader>,
    > {
        SpiffeWorkloadApiClient::with_interceptor(self.inner.channel.clone(), WorkloadHeader)
    }

    /// One-shot initial fetch — consumes the first message from the
    /// streaming `FetchX509SVID` RPC and returns the workload's SVID +
    /// trust bundle.
    ///
    /// # Errors
    /// Returns `Err` if the stream closes without producing a message,
    /// the response has no SVIDs, or the embedded cert / bundle bytes
    /// fail X.509 DER parse.
    #[tracing::instrument(skip(self))]
    pub async fn fetch_initial(&self) -> Result<SvidMaterial> {
        let mut stream = self
            .stub()
            .fetch_x509svid(Request::new(X509svidRequest {}))
            .await
            .context("FetchX509SVID call")?
            .into_inner();

        let msg = stream
            .message()
            .await
            .context("FetchX509SVID stream recv")?
            .ok_or_else(|| anyhow!("FetchX509SVID stream closed with no messages"))?;

        let svid = msg
            .svids
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("FetchX509SVID response had no SVIDs"))?;

        let cert_chain = split_cert_chain(&svid.x509_svid)?;
        let bundle = split_cert_chain(&svid.bundle)?;

        Ok(SvidMaterial {
            spiffe_id: svid.spiffe_id,
            cert_chain,
            private_key: SecretBox::new(Box::new(svid.x509_svid_key)),
            bundle,
        })
    }

    /// Long-lived stream of trust-bundle updates. The refresher task
    /// installs the matching `BundleUpdate` into the rustls verifier via
    /// `ArcSwap::store`. Emits a `Vec<BundleUpdate>` per server message
    /// because `X509BundlesResponse` carries a map keyed by trust-domain
    /// name (Tracelane's own + any federated peers) — emitting only
    /// `.next()` would silently drop our own bundle if HashMap iteration
    /// happened to start with a federated entry.
    #[tracing::instrument(skip(self))]
    pub async fn stream_bundles(
        &self,
    ) -> Result<impl Stream<Item = Result<Vec<BundleUpdate>>> + Send + 'static> {
        let stream = self
            .stub()
            .fetch_x509_bundles(Request::new(X509BundlesRequest {}))
            .await
            .context("FetchX509Bundles call")?
            .into_inner();

        Ok(stream.map(|res| -> Result<Vec<BundleUpdate>> {
            let msg = res.context("FetchX509Bundles stream recv")?;
            if msg.bundles.is_empty() {
                return Err(anyhow!("X509BundlesResponse had no bundles"));
            }
            let mut out = Vec::with_capacity(msg.bundles.len());
            for (trust_domain, bytes) in msg.bundles {
                let bundle = split_cert_chain(&bytes)?;
                out.push(BundleUpdate {
                    trust_domain,
                    bundle,
                });
            }
            Ok(out)
        }))
    }
}

/// Split a SPIFFE bundle / SVID byte stream (ASN.1 DER, concatenated
/// certificates) into individual `CertificateDer` entries.
///
/// SPIRE concatenates DER certificates without explicit length prefixes;
/// we walk the buffer using `x509-parser::FromDer::from_der` which
/// reports how many bytes it consumed, then advance.
fn split_cert_chain(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut out = Vec::new();
    let mut remaining = bytes;
    while !remaining.is_empty() {
        let (rest, _cert) = x509_parser::certificate::X509Certificate::from_der(remaining)
            .map_err(|e| anyhow!("split DER chain: {e}"))?;
        let consumed = remaining.len() - rest.len();
        if consumed == 0 {
            return Err(anyhow!("split DER chain: zero-length cert (malformed)"));
        }
        out.push(CertificateDer::from(remaining[..consumed].to_vec()));
        remaining = rest;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spire_mock::{MockSpireMaterial, spawn_mock_spire};
    use rcgen::{CertificateParams, DnType, Ia5String, KeyPair, SanType};

    #[test]
    fn split_cert_chain_empty_buffer_returns_empty() {
        let v = split_cert_chain(&[]).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn split_cert_chain_rejects_garbage() {
        let res = split_cert_chain(b"definitely not asn1");
        assert!(res.is_err());
    }

    /// End-to-end: mint a self-signed cert, stand up the mock SPIRE
    /// server on a tempdir UDS, connect the client, fetch the initial
    /// material, and verify every field round-trips.
    #[tokio::test]
    async fn fetch_initial_against_mock_spire_server() {
        let spiffe_id =
            "spiffe://tracelane.dev/tenant/00000000-0000-0000-0000-000000000001/ingest-worker";

        // Mint a leaf cert with the SPIFFE ID as SAN URI. Self-signed
        // (acts as both CA and leaf for this test — the SPIRE bundle
        // contains it as the trust anchor).
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "test");
        params.subject_alt_names = vec![SanType::URI(
            Ia5String::try_from(spiffe_id.to_string()).unwrap(),
        )];
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();

        let leaf_der = cert.der().to_vec();
        let key_pkcs8 = key.serialize_der();

        let material = MockSpireMaterial {
            spiffe_id: spiffe_id.to_string(),
            x509_svid_der: leaf_der.clone(),
            x509_svid_key_pkcs8_der: key_pkcs8.clone(),
            bundle_der: leaf_der.clone(),
            trust_domain: "tracelane.dev".to_string(),
        };

        let dir = tempfile::tempdir().unwrap();
        let handle = spawn_mock_spire(dir.path(), material).await;
        // Give tonic a moment to start serving.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = SpireClient::connect(handle.socket_path.clone())
            .await
            .expect("connect to mock spire");

        let svid = client.fetch_initial().await.expect("fetch_initial");
        assert_eq!(svid.spiffe_id, spiffe_id);
        assert_eq!(svid.cert_chain.len(), 1);
        assert_eq!(svid.bundle.len(), 1);
        assert_eq!(
            secrecy::ExposeSecret::expose_secret(&svid.private_key),
            &key_pkcs8
        );

        // Drop the handle which cancels the server task.
        drop(handle);
    }

    #[tokio::test]
    async fn stream_bundles_against_mock_spire_yields_initial_update() {
        let spiffe_id =
            "spiffe://tracelane.dev/tenant/00000000-0000-0000-0000-000000000002/ingest-worker";
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "test2");
        params.subject_alt_names = vec![SanType::URI(
            Ia5String::try_from(spiffe_id.to_string()).unwrap(),
        )];
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();

        let material = MockSpireMaterial {
            spiffe_id: spiffe_id.to_string(),
            x509_svid_der: cert.der().to_vec(),
            x509_svid_key_pkcs8_der: key.serialize_der(),
            bundle_der: cert.der().to_vec(),
            trust_domain: "tracelane.dev".to_string(),
        };

        let dir = tempfile::tempdir().unwrap();
        let handle = spawn_mock_spire(dir.path(), material).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = SpireClient::connect(handle.socket_path.clone())
            .await
            .unwrap();
        let mut stream = Box::pin(client.stream_bundles().await.unwrap());
        let first_batch = futures::StreamExt::next(&mut stream)
            .await
            .expect("at least one bundle update")
            .expect("Ok update");
        assert!(
            !first_batch.is_empty(),
            "batch must include at least one bundle"
        );
        let our = first_batch
            .iter()
            .find(|u| u.trust_domain == "tracelane.dev")
            .expect("our trust domain present in batch");
        assert_eq!(our.bundle.len(), 1);

        drop(handle);
    }
}
