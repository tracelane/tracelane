//! `--health-probe`: the container HEALTHCHECK, run by the binary itself.
//!
//! SRE register #45. The runtime image is distroless (`chainguard/glibc-dynamic`:
//! no shell, no curl, no wget), so Docker's HEALTHCHECK can only exec THIS binary.
//! Invoked as `<binary> --health-probe`, it GETs its own local endpoint and exits
//! 0 on any 2xx, non-zero otherwise (a refused connection, a timeout, a 5xx).
//! It reads only the ONE env var that names the port — never the full config —
//! so a probe cannot fail for a reason unrelated to "is the server answering".
//!
//! Deliberately duplicated in gateway and ingest rather than placed in
//! `tracelane_shared`: shared carries no HTTP client, and a healthcheck is not a
//! reason to give it one.

use std::time::Duration;

/// GET `url`; `Ok(())` on 2xx. Bounded at 3 s so a wedged server reads as
/// UNHEALTHY instead of hanging the healthcheck past Docker's own timeout.
pub async fn run(url: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .no_proxy()
        .build()?;
    let resp = client.get(url).send().await?;
    let status = resp.status();
    anyhow::ensure!(
        status.is_success(),
        "health probe: {url} answered {status} (not 2xx)"
    );
    Ok(())
}
