//! In-process mock SPIRE Workload API server.
//!
//! Test-only — gated behind `#[cfg(test)]` so the server stub isn't
//! pulled into prod binaries. Spawns a tonic gRPC server bound to a
//! tempdir Unix Domain Socket and serves a fixed `X509SVIDResponse`
//! (and an idle bundle stream). Used by the `spire_client` and `tls`
//! test modules to exercise the wire integration without depending on
//! a real SPIRE agent.

#![cfg(test)]

use std::path::{Path, PathBuf};
use std::pin::Pin;

use futures::Stream;
use tokio::sync::oneshot;
use tonic::{Request, Response, Status};

use crate::spire_proto::spiffe_workload_api_server::{SpiffeWorkloadApi, SpiffeWorkloadApiServer};
use crate::spire_proto::{
    X509BundlesRequest, X509BundlesResponse, X509svid, X509svidRequest, X509svidResponse,
};

/// Materials handed to the mock server at construction time.
#[derive(Clone)]
pub struct MockSpireMaterial {
    pub spiffe_id: String,
    pub x509_svid_der: Vec<u8>,
    pub x509_svid_key_pkcs8_der: Vec<u8>,
    pub bundle_der: Vec<u8>,
    pub trust_domain: String,
}

struct MockService {
    material: MockSpireMaterial,
}

#[tonic::async_trait]
impl SpiffeWorkloadApi for MockService {
    type FetchX509SVIDStream =
        Pin<Box<dyn Stream<Item = Result<X509svidResponse, Status>> + Send + 'static>>;
    type FetchX509BundlesStream =
        Pin<Box<dyn Stream<Item = Result<X509BundlesResponse, Status>> + Send + 'static>>;

    async fn fetch_x509svid(
        &self,
        _req: Request<X509svidRequest>,
    ) -> Result<Response<Self::FetchX509SVIDStream>, Status> {
        let svid = X509svid {
            spiffe_id: self.material.spiffe_id.clone(),
            x509_svid: self.material.x509_svid_der.clone(),
            x509_svid_key: self.material.x509_svid_key_pkcs8_der.clone(),
            bundle: self.material.bundle_der.clone(),
            hint: vec![],
        };
        let resp = X509svidResponse {
            svids: vec![svid],
            crl: vec![],
            federated_bundles: Default::default(),
        };
        let s = futures::stream::iter(vec![Ok(resp)]);
        Ok(Response::new(Box::pin(s)))
    }

    async fn fetch_x509_bundles(
        &self,
        _req: Request<X509BundlesRequest>,
    ) -> Result<Response<Self::FetchX509BundlesStream>, Status> {
        let mut bundles = std::collections::HashMap::new();
        bundles.insert(
            self.material.trust_domain.clone(),
            self.material.bundle_der.clone(),
        );
        let resp = X509BundlesResponse {
            crl: vec![],
            bundles,
        };
        let s = futures::stream::iter(vec![Ok(resp)]);
        Ok(Response::new(Box::pin(s)))
    }
}

/// Handle on a running mock server. Drop to shut it down (the oneshot
/// inside cancels the tonic serve future).
pub struct MockSpireHandle {
    pub socket_path: PathBuf,
    _shutdown: oneshot::Sender<()>,
    pub join: tokio::task::JoinHandle<()>,
}

/// Spawn the mock server on a Unix Domain Socket inside `dir`. Returns
/// the socket path so the client can connect.
pub async fn spawn_mock_spire(dir: &Path, material: MockSpireMaterial) -> MockSpireHandle {
    let socket_path = dir.join("api.sock");
    let _ = std::fs::remove_file(&socket_path);

    let uds = tokio::net::UnixListener::bind(&socket_path).expect("bind uds");
    let stream = tokio_stream::wrappers::UnixListenerStream::new(uds);

    let (tx, rx) = oneshot::channel::<()>();
    let svc = SpiffeWorkloadApiServer::new(MockService { material });

    let join = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(stream, async {
                let _ = rx.await;
            })
            .await;
    });

    MockSpireHandle {
        socket_path,
        _shutdown: tx,
        join,
    }
}
