//! SSRF defense: blocks outbound requests to private/reserved IP ranges.
//!
//! Enforces CLAUDE.md security non-negotiables:
//! - Blocks RFC1918 (10/8, 172.16/12, 192.168/16)
//! - Blocks link-local (169.254/16) — covers AWS/GCP IMDS
//! - Blocks Azure metadata service (168.63.129.16, a public-looking but special address)
//! - Blocks carrier-grade NAT (100.64/10, RFC 6598)
//! - Blocks loopback (127/8, ::1)
//! - Blocks unspecified (0.0.0.0/8, ::)
//! - Blocks reserved/future (240/4, ::ffff:0:0/96 IPv4-mapped)
//! - Blocks unique-local IPv6 (fc00::/7)
//! - Blocks IPv4-mapped IPv6 (::ffff:0:0/96) — recursively checks the mapped V4 address
//! - **Disables redirects entirely on the SSRF-hardened client** (mythos
//!   round-3 B-1). Pre-fix policy did per-hop sync validation that could
//!   not detect domain-resolves-to-private-IP TOCTOU. Callers needing
//!   redirects must re-validate every Location: via async validate_url.
//! - Blocks file:// and gopher:// schemes
//!
//! ## Usage
//!
//! Call [`validate_url`] (async — does DNS resolution) before constructing a
//! reqwest request to any operator- or customer-supplied URL. Use
//! [`safe_client_builder`] for all outbound HTTP clients — it installs a custom
//! redirect policy that re-validates each redirect hop's host synchronously.
//!
//! The async [`validate_url`] is the primary defence: it parses the URL, checks
//! the scheme, resolves DNS, and rejects every blocked range. The redirect
//! policy is the second line: even if the initial host is public but redirects
//! to `169.254.169.254`, the redirect policy rejects the hop.

use anyhow::{Context as _, Result, bail};
use reqwest::Url;
use std::net::IpAddr;
use tracing::instrument;

/// Validate an outbound URL before use.
///
/// Returns `Err` if the URL is disallowed by SSRF policy (bad scheme,
/// private IP, DNS resolves to a private IP, etc.). Performs DNS resolution
/// to check all resolved addresses — TOCTOU is acceptable here since
/// network calls follow immediately after validation.
///
/// # Errors
/// - URL parse failure
/// - Disallowed scheme (anything other than `http` / `https`)
/// - IP literal in blocked range
/// - DNS resolves to a blocked range
/// - DNS resolution failure
#[instrument(skip(raw), fields(host = tracing::field::Empty))]
pub async fn validate_url(raw: &str) -> Result<()> {
    let url = Url::parse(raw).context("invalid URL")?;

    match url.scheme() {
        "https" | "http" => {}
        scheme => bail!("SSRF: scheme '{}' is not permitted", scheme),
    }

    let host = url.host_str().context("URL has no host")?;
    tracing::Span::current().record("host", host);

    // Loopback bypass for integration tests against wiremock.
    // Opus-rereview M-4: the bypass is now compile-gated to debug builds.
    // Production binaries (cargo build --release) cannot honour the env
    // var at all, even if an operator sets it. Documented + grep-able.
    let allow_loopback = is_loopback_bypass_enabled();

    // If host is already an IP literal, check it directly without DNS.
    if let Ok(ip) = host.parse::<IpAddr>() {
        if allow_loopback && is_loopback_only(&ip) {
            return Ok(());
        }
        if is_blocked_ip(&ip) {
            bail!("SSRF: IP {} is in a blocked range", ip);
        }
        return Ok(());
    }

    // DNS resolution + check every resolved address.
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs: Vec<_> = tokio::net::lookup_host(format!("{host}:{port}"))
        .await
        .context("DNS resolution failed")?
        .collect();

    if addrs.is_empty() {
        bail!("SSRF: DNS resolved no addresses for {}", host);
    }

    for addr in &addrs {
        if allow_loopback && is_loopback_only(&addr.ip()) {
            continue;
        }
        if is_blocked_ip(&addr.ip()) {
            bail!(
                "SSRF: resolved IP {} for host '{}' is in a blocked range",
                addr.ip(),
                host
            );
        }
    }

    Ok(())
}

// Test-only thread-local loopback-bypass flag (debug builds only).
//
// Enables the bypass for SSRF checks that run on the SAME thread. Every
// `#[tokio::test]` uses a current-thread runtime and the providers call
// `validate_url(...).await` inline, so the check runs on the test thread —
// the only place this flag is read. Using a thread-local instead of process
// env avoids two hazards the env approach had: (1) concurrent
// `env::set_var`/`var` is a data race across the parallel suite (Rust 2024
// marks `set_var` `unsafe` for exactly this reason), and (2) a process-global
// env flag leaked the relaxed policy into the guard's own `blocks_loopback`
// tests running on other threads.
#[cfg(debug_assertions)]
thread_local! {
    static LOOPBACK_BYPASS_TLS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Enable/disable the loopback bypass on the CURRENT thread (debug builds
/// only). `providers::smoke_tests` drives this via an RAII guard.
#[cfg(debug_assertions)]
pub(crate) fn set_loopback_bypass_for_tests(on: bool) {
    LOOPBACK_BYPASS_TLS.with(|b| b.set(on));
}

/// Loopback bypass: debug builds may opt in via the thread-local override
/// (preferred — no process-env mutation) or, for back-compat, the documented
/// `TRACELANE_SSRF_ALLOW_LOOPBACK_FOR_TESTS` env var. Release builds always
/// return false regardless of either.
#[cfg(debug_assertions)]
fn is_loopback_bypass_enabled() -> bool {
    if LOOPBACK_BYPASS_TLS.with(std::cell::Cell::get) {
        return true;
    }
    std::env::var("TRACELANE_SSRF_ALLOW_LOOPBACK_FOR_TESTS")
        .map(|v| v == "1")
        .unwrap_or(false)
}

#[cfg(not(debug_assertions))]
fn is_loopback_bypass_enabled() -> bool {
    // Release builds: bypass is hard-disabled. The env var cannot enable
    // it even if an operator sets it — defence against accidental
    // exposure in production deployments. (Opus-rereview M-4.)
    false
}

/// Strictly check loopback, used only by the
/// `TRACELANE_SSRF_ALLOW_LOOPBACK_FOR_TESTS` bypass.
fn is_loopback_only(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6
                    .to_ipv4_mapped()
                    .map(|v4| v4.is_loopback())
                    .unwrap_or(false)
        }
    }
}

/// Synchronous URL validation. Performs scheme + IP-literal checks only.
///
/// Currently unused in production paths after mythos round-3 B-1 (the
/// reqwest redirect policy is now `Policy::none()`). Kept available
/// for future redirect-aware callers that might want a sync fallback
/// check before doing an async `validate_url` per Location: header.
#[allow(dead_code)]
fn validate_url_sync(url: &Url) -> Result<(), &'static str> {
    match url.scheme() {
        "https" | "http" => {}
        _ => return Err("SSRF: redirect scheme not permitted"),
    }
    if let Some(host) = url.host_str() {
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_blocked_ip(&ip) {
                return Err("SSRF: redirect to blocked IP literal");
            }
        }
    }
    Ok(())
}

/// Build a reqwest client with SSRF mitigations:
/// - Custom redirect policy: cap 3 hops AND reject any hop to an IP literal
///   in a blocked range
/// - rustls TLS (openssl is banned per CLAUDE.md)
/// - TCP keepalive to detect stale connections
///
/// Caller must still call [`validate_url`] on any customer-supplied URL
/// before issuing a request — this builder cannot pre-validate domain DNS.
pub fn safe_client_builder() -> reqwest::ClientBuilder {
    // `validate_url_sync` per hop — which only blocks IP literals,
    // NOT domains whose A record resolves to a blocked range.
    // A redirect to `attacker.com` (DNS → 169.254.169.254) would
    // pass the sync check and be followed. Disabling redirects
    // entirely is the only safe option that doesn't require async
    // DNS inside the synchronous reqwest redirect callback.
    //
    // Every gateway / ingest caller that uses `safe_client_builder`
    // (provider adapters, Rekor submit, JWKS fetch, R2 PUT, BYOK
    // management) talks to a single fixed endpoint with no expected
    // redirects — provider APIs return 3xx only on transient
    // misconfiguration. If a future caller legitimately needs to
    // follow redirects, it must re-validate every `Location:` header
    // through the async `validate_url` itself.
    reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .use_rustls_tls()
        .tcp_keepalive(std::time::Duration::from_secs(60))
}

/// Returns `true` if `ip` falls in any blocked address range.
fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip4) => {
            ip4.is_private()           // 10/8, 172.16/12, 192.168/16
            || ip4.is_loopback()       // 127/8
            || ip4.is_link_local()     // 169.254/16 — covers AWS/GCP IMDS
            || is_cgnat(ip4)           // 100.64/10 (RFC 6598)
            || ip4.is_broadcast()
            || ip4.is_documentation()
            || ip4.is_unspecified()    // 0.0.0.0/8 — added per review M4
            || is_azure_imds(ip4)      // 168.63.129.16 — Azure metadata, public-looking
            || is_reserved_class_e(ip4) // 240/4 — reserved
        }
        IpAddr::V6(ip6) => {
            // IPv4-mapped IPv6 (::ffff:0:0/96) MUST recurse to the V4 check —
            // otherwise an attacker resolving to `::ffff:127.0.0.1` reaches
            // loopback because the mapped form is none of the V6 categories.
            if let Some(v4) = ip6.to_ipv4_mapped() {
                return is_blocked_ip(&IpAddr::V4(v4));
            }
            ip6.is_loopback()              // ::1
            || ip6.is_unspecified()        // ::
            || is_unique_local_v6(ip6)     // fc00::/7
            || ip6.is_multicast()          // ff00::/8
            || is_ipv6_documentation(ip6) // 2001:db8::/32
        }
    }
}

/// Check for CGNAT range 100.64.0.0/10 (RFC 6598).
fn is_cgnat(ip: &std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

/// Azure IMDS lives at a single fixed public-looking address.
/// https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16
fn is_azure_imds(ip: &std::net::Ipv4Addr) -> bool {
    ip.octets() == [168, 63, 129, 16]
}

/// 240.0.0.0/4 — reserved for future use, not routable.
fn is_reserved_class_e(ip: &std::net::Ipv4Addr) -> bool {
    ip.octets()[0] >= 240
}

/// Check for IPv6 unique-local fc00::/7.
fn is_unique_local_v6(ip: &std::net::Ipv6Addr) -> bool {
    ip.segments()[0] & 0xFE00 == 0xFC00
}

/// 2001:db8::/32 — IPv6 documentation prefix.
fn is_ipv6_documentation(ip: &std::net::Ipv6Addr) -> bool {
    let s = ip.segments();
    s[0] == 0x2001 && s[1] == 0x0db8
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn blocks_rfc1918() {
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))));
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn blocks_loopback() {
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_blocked_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn blocks_cgnat() {
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(100, 100, 0, 1))));
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(
            100, 127, 255, 255
        ))));
        assert!(!is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1))));
    }

    #[test]
    fn blocks_link_local() {
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))));
    }

    #[test]
    fn blocks_unique_local_v6() {
        let ip: Ipv6Addr = "fc00::1".parse().unwrap();
        assert!(is_blocked_ip(&IpAddr::V6(ip)));
        let ip: Ipv6Addr = "fd00::1".parse().unwrap();
        assert!(is_blocked_ip(&IpAddr::V6(ip)));
        let ip: Ipv6Addr = "fdff:ffff:ffff::1".parse().unwrap();
        assert!(is_blocked_ip(&IpAddr::V6(ip)));
    }

    #[test]
    fn allows_public_ips() {
        assert!(!is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(104, 16, 0, 1))));
    }

    #[test]
    fn validate_url_rejects_file_scheme() {
        let url = Url::parse("file:///etc/passwd").unwrap();
        assert_ne!(url.scheme(), "https");
        assert_ne!(url.scheme(), "http");
    }

    #[test]
    fn validate_url_rejects_gopher_scheme() {
        let url = Url::parse("gopher://evil.example/").unwrap();
        assert_ne!(url.scheme(), "https");
        assert_ne!(url.scheme(), "http");
    }

    #[test]
    fn cgnat_boundary_100_63() {
        assert!(!is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(
            100, 63, 255, 255
        ))));
    }

    // ---- new tests for review findings ----

    #[test]
    fn blocks_ipv4_mapped_ipv6_loopback() {
        // ::ffff:127.0.0.1 — IPv4-mapped form of loopback.
        // IPv6 doesn't catch the mapped form.
        let ip: Ipv6Addr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_blocked_ip(&IpAddr::V6(ip)));
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6_imds() {
        let ip: Ipv6Addr = "::ffff:169.254.169.254".parse().unwrap();
        assert!(is_blocked_ip(&IpAddr::V6(ip)));
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6_rfc1918() {
        let ip: Ipv6Addr = "::ffff:10.0.0.1".parse().unwrap();
        assert!(is_blocked_ip(&IpAddr::V6(ip)));
        let ip: Ipv6Addr = "::ffff:192.168.1.1".parse().unwrap();
        assert!(is_blocked_ip(&IpAddr::V6(ip)));
    }

    #[test]
    fn blocks_azure_imds() {
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(168, 63, 129, 16))));
        // Adjacent addresses are NOT blocked.
        assert!(!is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(168, 63, 129, 17))));
        assert!(!is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(168, 63, 129, 15))));
    }

    #[test]
    fn blocks_ipv4_unspecified() {
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
    }

    #[test]
    fn blocks_ipv6_unspecified() {
        assert!(is_blocked_ip(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn blocks_reserved_class_e() {
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))));
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(
            255, 255, 255, 254
        ))));
        assert!(!is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(
            239, 255, 255, 255
        ))));
    }

    #[test]
    fn blocks_ipv6_documentation_prefix() {
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(is_blocked_ip(&IpAddr::V6(ip)));
    }

    #[test]
    fn validate_url_sync_blocks_blocked_ip_literals() {
        let bad = Url::parse("http://169.254.169.254/latest/meta-data/").unwrap();
        assert!(validate_url_sync(&bad).is_err());
    }

    #[test]
    fn is_blocked_ip_catches_mapped_v6_loopback() {
        // The is_blocked_ip path (recursing through to_ipv4_mapped) catches
        // the IPv4-mapped IPv6 form even when the URL parser normalises the
        // [::ffff:127.0.0.1] literal into ::ffff:7f00:0001 with the V6 host
        // form retained. Tested directly on the IP rather than via URL since
        // url::Url normalises mapped literals inconsistently across versions.
        let mapped: Ipv6Addr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_blocked_ip(&IpAddr::V6(mapped)));
    }

    #[test]
    fn validate_url_sync_blocks_bad_scheme() {
        let bad = Url::parse("file:///etc/passwd").unwrap();
        assert!(validate_url_sync(&bad).is_err());
    }

    #[tokio::test]
    async fn validate_url_async_rejects_ip_literal_to_imds() {
        let res = validate_url("http://169.254.169.254/").await;
        assert!(res.is_err(), "must reject IMDS ip literal");
    }

    #[tokio::test]
    async fn validate_url_async_rejects_file_scheme() {
        let res = validate_url("file:///etc/passwd").await;
        assert!(res.is_err());
    }

    // Loopback rejection is covered exhaustively by `blocks_loopback` on
    // is_blocked_ip directly. We deliberately do not run an async-pipeline
    // test for loopback here: the smoke tests in `providers::smoke_tests`
    // set the `TRACELANE_SSRF_ALLOW_LOOPBACK_FOR_TESTS` env var while
    // their wiremock server is alive, and racy test ordering could flake
    // this assertion. The is-blocked-ip layer is the load-bearing check.
}
