//! Best-effort RFC 3161 acquisition. Only this background task makes TSA requests.
use anyhow::{Context, Result, ensure};
use std::time::Duration;
use tracelane_shared::degradation::{self, Degradation};
// Reference: Neon suspend timeout; acquisition must leave an idle interval longer than this.
const NEON_SUSPEND_SECS: u64 = 300;
#[derive(Clone)]
pub(crate) struct Config {
    url: String,
    timeout: Duration,
    poll: Duration,
    batch: i64,
    max_bytes: usize,
    pins: Vec<Vec<u8>>,
}
impl Config {
    /// Fail CLOSED for acquisition configuration; requests/exports remain independent.
    fn validate(&self) -> Result<()> {
        let url = reqwest::Url::parse(&self.url).context("invalid TSA URL")?;
        let https = url.scheme() == "https";
        #[cfg(test)]
        let https = https
            || (url.scheme() == "http"
                && url.host_str().is_some_and(|h| {
                    h.parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
                }));
        ensure!(
            https
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "TSA requires HTTPS without credentials, query or fragment"
        );
        ensure!(
            !self.timeout.is_zero()
                && self.poll > Duration::from_secs(NEON_SUSPEND_SECS)
                && self.batch > 0
                && self.max_bytes > 0
                && !self.pins.is_empty(),
            "invalid TSA bounds or missing certificate pins"
        );
        ensure!(
            std::time::Instant::now()
                .checked_add(self.timeout)
                .is_some()
                && std::time::Instant::now().checked_add(self.poll).is_some(),
            "TSA duration overflow"
        );
        Ok(())
    }
    fn from_env() -> Result<Option<Self>> {
        let Some(url) = std::env::var_os("TRACELANE_TSA_URL") else {
            return Ok(None);
        };
        fn number(name: &str) -> Result<u64> {
            std::env::var(name)
                .with_context(|| format!("missing {name}"))?
                .parse()
                .with_context(|| format!("invalid {name}"))
        }
        let config = Self {
            url: url
                .into_string()
                .map_err(|_| anyhow::anyhow!("invalid TSA URL encoding"))?,
            timeout: Duration::from_millis(number("TRACELANE_TSA_TIMEOUT_MS")?),
            poll: Duration::from_secs(number("TRACELANE_TSA_POLL_SECS")?),
            batch: i64::try_from(number("TRACELANE_TSA_BATCH")?)?,
            max_bytes: usize::try_from(number("TRACELANE_TSA_MAX_BYTES")?)?,
            pins: load_pins()?,
        };
        config.validate()?;
        Ok(Some(config))
    }
}
/// Pins remain available to export when acquisition is disabled. Errors on an unreadable OR
/// unparsable pin (review M-A): the caller then exports with no pins, so tokens report
/// `tsa_unpinned` instead of failing every export.
pub(crate) fn load_pins() -> Result<Vec<Vec<u8>>> {
    pins_from(std::env::var_os("TRACELANE_TSA_CERTS"))
}
fn pins_from(paths: Option<std::ffi::OsString>) -> Result<Vec<Vec<u8>>> {
    paths.map_or_else(
        || Ok(Vec::new()),
        |paths| {
            std::env::split_paths(&paths)
                .map(|path| {
                    let raw = std::fs::read(path).context("cannot read TSA certificate pin")?;
                    tracelane_audit_verifier::action::timestamp::validate_pin(&raw)
                        .context("TSA certificate pin is not PEM or DER X.509")?;
                    Ok(raw)
                })
                .collect()
        },
    )
}
/// Fail CLOSED on transport, size or proof errors. Caller counts degradation and retries later.
async fn fetch(config: &Config, statement: &[u8]) -> Result<Vec<u8>> {
    config.validate()?;
    tokio::time::timeout(config.timeout, async {
        // DNS pinning uses the same validated addresses for the actual connection (B-472).
        let target = crate::ssrf_guard::validate_url_pinned(&config.url).await?;
        let client = target
            .pin(crate::ssrf_guard::safe_client_builder().no_proxy())
            .timeout(config.timeout)
            .build()?;
        let mut response = client
            .post(&config.url)
            .header("Content-Type", "application/timestamp-query")
            .header("Accept", "application/timestamp-reply")
            .body(tracelane_audit_verifier::action::timestamp::request(
                statement,
            )?)
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        ensure!(
            response.status().is_success(),
            "TSA returned unsuccessful status"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(reqwest::Error::without_url)?
        {
            ensure!(
                chunk.len() <= config.max_bytes.saturating_sub(bytes.len()),
                "TSA response size exceeded"
            );
            bytes.extend_from_slice(&chunk);
        }
        tracelane_audit_verifier::action::timestamp::verify_optional(
            Some(&bytes),
            statement,
            &config.pins,
        )?
        .context("TSA response signer is not pinned")?;
        Ok(bytes)
    })
    .await
    .context("TSA timeout")?
}
/// Background inventory scan, not request-selected tenant scope. Every mutation binds both IDs.
/// Fail OPEN for request/export availability: no network or worker wait on either path.
async fn poll_once(pool: &deadpool_postgres::Pool, config: &Config) -> Result<bool> {
    let mut degraded = false;
    let rows=pool.get().await?.query("SELECT tenant_id,checkpoint_id,statement FROM audit_head_checkpoints WHERE timestamp_response IS NULL ORDER BY timestamp_attempted_at NULLS FIRST,checkpoint_order LIMIT $1", &[&config.batch]).await?;
    for row in rows {
        let tenant: uuid::Uuid = row.get(0);
        let checkpoint: uuid::Uuid = row.get(1);
        let statement: String = row.get(2);
        pool.get().await?.execute("UPDATE audit_head_checkpoints SET timestamp_attempted_at=clock_timestamp() WHERE tenant_id=$1 AND checkpoint_id=$2 AND timestamp_response IS NULL", &[&tenant,&checkpoint]).await?;
        // No pool client or transaction survives across outbound HTTP.
        match fetch(config, statement.as_bytes()).await {
            Ok(token) => {
                pool.get().await?.execute("UPDATE audit_head_checkpoints SET timestamp_response=$3 WHERE tenant_id=$1 AND checkpoint_id=$2 AND timestamp_response IS NULL", &[&tenant,&checkpoint,&token]).await?;
            }
            Err(_) => {
                degraded = true;
                degradation::note(Degradation::CheckpointTimestampFailed);
            }
        }
    }
    Ok(degraded)
}
/// One sequential bounded worker; disabled config makes no outbound requests.
pub(crate) fn spawn(pool: deadpool_postgres::Pool) {
    let config = match Config::from_env() {
        Ok(Some(config)) => config,
        Ok(None) => return,
        Err(_) => {
            degradation::note(Degradation::CheckpointTimestampFailed);
            tracing::warn!(
                error_kind = "configuration",
                "checkpoint timestamp acquisition degraded"
            );
            return;
        }
    };
    tokio::spawn(async move {
        let mut degraded = false;
        loop {
            let error_kind = match poll_once(&pool, &config).await {
                Ok(false) => None,
                Ok(true) => Some("acquisition"),
                Err(_) => {
                    degradation::note(Degradation::CheckpointTimestampFailed);
                    Some("storage")
                }
            };
            if let Some(error_kind) = error_kind {
                if enter_degraded(&mut degraded) {
                    tracing::warn!(error_kind, "checkpoint timestamp acquisition degraded");
                }
            } else if recover(&mut degraded) {
                tracing::warn!("checkpoint timestamp acquisition recovered");
            }
            tokio::time::sleep(config.poll).await;
        }
    });
}
fn recover(state: &mut bool) -> bool {
    if std::mem::take(state) {
        degradation::resolve(Degradation::CheckpointTimestampFailed);
        true
    } else {
        false
    }
}
fn enter_degraded(state: &mut bool) -> bool {
    !std::mem::replace(state, true)
}
#[cfg(test)]
mod pg_tests;
#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_bytes, method, path},
    };
    fn config(url: String) -> Config {
        Config {
            url,
            timeout: Duration::from_secs(2),
            poll: Duration::from_secs(301),
            batch: 2,
            max_bytes: 65536,
            pins: vec![
                include_bytes!("../../../packages/verifier-rust/tests/fixtures/timestamp/good.der")
                    .to_vec(),
            ],
        }
    }
    #[test]
    fn poll_at_suspend_timeout_refused() {
        let mut c = config("https://example.com".into());
        c.poll = Duration::from_secs(300);
        assert!(c.validate().is_err());
    }
    #[test]
    fn poll_above_suspend_timeout_accepted() {
        let mut c = config("https://example.com".into());
        c.poll = Duration::from_secs(301);
        assert!(c.validate().is_ok());
    }
    #[test]
    fn degradation_diagnostic_only_on_entry() {
        let mut state = false;
        assert!(enter_degraded(&mut state));
        assert!(!enter_degraded(&mut state));
        state = false;
        assert!(enter_degraded(&mut state));
    }
    #[test]
    fn recovery_closes_shared_degradation() {
        let kind = Degradation::CheckpointTimestampFailed;
        degradation::note(kind);
        let mut state = true;
        assert!(recover(&mut state));
        assert!(!state);
        let stat = degradation::snapshot()
            .into_iter()
            .find(|s| s.kind == kind.as_str())
            .unwrap();
        assert!(!stat.open);
        assert!(!recover(&mut state));
    }
    #[test]
    fn credentials_in_url_refused() {
        assert!(
            config("https://user:secret@example.com".into())
                .validate()
                .is_err()
        );
    }
    #[test]
    fn query_in_url_refused() {
        assert!(
            config("https://example.com?token=test".into())
                .validate()
                .is_err()
        );
    }
    #[test]
    fn non_https_refused() {
        assert!(config("http://example.com".into()).validate().is_err());
    }
    #[test]
    fn zero_timeout_refused() {
        let mut c = config("https://example.com".into());
        c.timeout = Duration::ZERO;
        assert!(c.validate().is_err());
    }
    #[test]
    fn zero_batch_refused() {
        let mut c = config("https://example.com".into());
        c.batch = 0;
        assert!(c.validate().is_err());
    }
    #[test]
    fn missing_pin_refused() {
        let mut c = config("https://example.com".into());
        c.pins.clear();
        assert!(c.validate().is_err());
    }
    #[tokio::test]
    async fn exact_request_and_response() {
        let _bypass = crate::handler_harness::LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        let cp = include_bytes!(
            "../../../packages/verifier-rust/tests/fixtures/timestamp/checkpoint.json"
        );
        let token =
            include_bytes!("../../../packages/verifier-rust/tests/fixtures/timestamp/good.tsr");
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_bytes(
                tracelane_audit_verifier::action::timestamp::request(cp).unwrap(),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(token.to_vec())
                    .insert_header("content-type", "application/timestamp-reply"),
            )
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(fetch(&config(server.uri()), cp).await.unwrap(), token);
    }
    #[tokio::test]
    async fn tsa_failure_is_error() {
        let _bypass = crate::handler_harness::LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        assert!(fetch(&config(server.uri()), b"checkpoint").await.is_err());
    }
    #[tokio::test]
    async fn oversized_response_refused() {
        let _bypass = crate::handler_harness::LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0; 32]))
            .mount(&server)
            .await;
        let mut c = config(server.uri());
        c.max_bytes = 8;
        assert!(
            fetch(&c, b"checkpoint")
                .await
                .unwrap_err()
                .to_string()
                .contains("size")
        );
    }
    #[tokio::test]
    async fn tsa_timeout_is_bounded() {
        let _bypass = crate::handler_harness::LoopbackBypassGuard::new();
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
            .mount(&mock)
            .await;
        let mut cfg = config(mock.uri());
        cfg.timeout = Duration::from_millis(20);
        let start = std::time::Instant::now();
        assert!(fetch(&cfg, b"checkpoint").await.is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
    }
    #[tokio::test]
    async fn tsa_ignores_system_proxy() {
        assert_proxy_isolation().await;
    }

    async fn assert_proxy_isolation() {
        let proxy = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&proxy)
            .await;
        let mut child = tokio::process::Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "checkpoint_timestamp::tests::proxy_child",
                "--ignored",
                "--nocapture",
            ])
            .env("AUD12_PROXY_CHILD", "1")
            .env("NO_PROXY", "")
            .env("no_proxy", "");
        for name in [
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            child.env(name, proxy.uri());
        }
        let output = child.output().await.unwrap();
        assert!(
            output.status.success(),
            "child: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(proxy.received_requests().await.unwrap().is_empty());
    }
    /// Review M-A: a malformed pin file is refused at load, so the server falls back to no
    /// pins (tokens report `tsa_unpinned`) instead of failing every export later.
    #[test]
    fn malformed_pin_refused_at_load() {
        struct Dir(std::path::PathBuf);
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let dir = Dir(std::env::temp_dir().join(format!("tsa-pins-{}", uuid::Uuid::new_v4())));
        std::fs::create_dir_all(&dir.0).unwrap();
        let bad = dir.0.join("bad.pem");
        std::fs::write(&bad, b"Certificate:\n    Data:\n").unwrap();
        let good = dir.0.join("good.der");
        std::fs::write(
            &good,
            include_bytes!("../../../packages/verifier-rust/tests/fixtures/timestamp/good.der"),
        )
        .unwrap();
        assert!(pins_from(Some(bad.clone().into_os_string())).is_err());
        assert_eq!(pins_from(Some(good.into_os_string())).unwrap().len(), 1);
        assert!(pins_from(None).unwrap().is_empty());
    }
    #[tokio::test]
    #[ignore = "proxy isolation; direct invocation runs the parent isolation check"]
    async fn proxy_child() {
        match std::env::var("AUD12_PROXY_CHILD") {
            Err(std::env::VarError::NotPresent) => {
                assert_proxy_isolation().await;
                return;
            }
            Ok(marker) => assert_eq!(marker, "1", "invalid proxy child marker"),
            Err(error) => panic!("invalid proxy child marker: {error}"),
        }
        let _bypass = crate::handler_harness::LoopbackBypassGuard::new();
        let mock = MockServer::start().await;
        let cp = include_bytes!(
            "../../../packages/verifier-rust/tests/fixtures/timestamp/checkpoint.json"
        );
        let token =
            include_bytes!("../../../packages/verifier-rust/tests/fixtures/timestamp/good.tsr");
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(token.to_vec()))
            .mount(&mock)
            .await;
        assert_eq!(fetch(&config(mock.uri()), cp).await.unwrap(), token);
    }
}
