//! Build the NATS `ConnectOptions` from a `NATS_URL` that may carry credentials.
//!
//! B-383 (b), 2026-09-12. The prod server now requires a user/password
//! (`infra/prod/nats/nats.conf`), and the natural way to hand one to a process is
//! the URL form every NATS tool accepts — `nats://gateway:<pw>@nats:4222`. **The
//! Rust client does not honour it.** async-nats 0.42 parses the userinfo
//! (`ServerAddr::username()` / `password()` exist) but `connector.rs` builds the
//! CONNECT frame from `options.auth` only, so a URL-embedded credential is
//! silently dropped and the server answers `Authorization Violation`. Found by
//! the live proof (`scripts/ci/check-nats-auth.sh`) — the `nats` CLI authenticates
//! with the same URL, so a hand-written probe would have passed while the gateway
//! retried forever and dropped every span.
//!
//! So: credentials are lifted OUT of the URL here, applied with
//! `user_and_password`, and the URL that reaches the client — and every log line —
//! is the credential-free one. A password in a URL is a password in `tracing::info!(%url)`.
//!
//! `NATS_USER` / `NATS_PASSWORD` are honoured too, for a deployment that prefers
//! not to put a secret in a URL at all. The URL wins when both are present.
//! Passwords must be URL-safe (the prod ones are `openssl rand -hex`); this does
//! not percent-decode, and says so rather than half-implementing it.

use secrecy::{ExposeSecret as _, SecretString};

/// A `NATS_URL` split into what the client dials and how it authenticates.
pub struct NatsConnect {
    /// The URL with any `user:pass@` removed — safe to log, safe to dial.
    pub url: String,
    user: Option<String>,
    password: Option<SecretString>,
}

impl NatsConnect {
    /// Parse `raw` (`scheme://[user[:pass]@]host[:port][/…]`), then fall back to
    /// `NATS_USER` / `NATS_PASSWORD` from the environment when the URL carries none.
    #[must_use]
    pub fn from_url(raw: &str) -> Self {
        let mut me = Self::split(raw);
        if me.user.is_none()
            && let (Ok(u), Ok(p)) = (std::env::var("NATS_USER"), std::env::var("NATS_PASSWORD"))
            && !u.is_empty()
        {
            me.user = Some(u);
            me.password = Some(SecretString::from(p));
        }
        me
    }

    /// The pure split — no environment.
    #[must_use]
    pub fn split(raw: &str) -> Self {
        let Some(scheme_end) = raw.find("://") else {
            return Self {
                url: raw.to_owned(),
                user: None,
                password: None,
            };
        };
        let rest = &raw[scheme_end + 3..];
        // Userinfo ends at the LAST `@` before the first `/` (a password may
        // itself contain `@` only if it is not URL-safe, which we do not support).
        let authority_end = rest.find('/').unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        let Some(at) = authority.rfind('@') else {
            return Self {
                url: raw.to_owned(),
                user: None,
                password: None,
            };
        };
        let userinfo = &authority[..at];
        let (user, pass) = match userinfo.split_once(':') {
            Some((u, p)) => (u, Some(p)),
            None => (userinfo, None),
        };
        let url = format!("{}{}", &raw[..scheme_end + 3], &rest[at + 1..]);
        Self {
            url,
            user: (!user.is_empty()).then(|| user.to_owned()),
            password: pass.map(|p| SecretString::from(p.to_owned())),
        }
    }

    /// Whether a credential will be sent.
    #[must_use]
    pub fn authenticates(&self) -> bool {
        self.user.is_some()
    }

    /// The `ConnectOptions` with the credential applied (if any). Callers chain
    /// their own `retry_on_initial_connect()` etc. on the result.
    #[must_use]
    pub fn options(&self) -> async_nats::ConnectOptions {
        let o = async_nats::ConnectOptions::new();
        match (&self.user, &self.password) {
            // async-nats 0.42's `user_and_password(String, String)` owns the
            // password for the connection's lifetime (it re-sends CONNECT on
            // every reconnect); there is no borrowed or SecretString form. This is
            // the wire boundary — the one place the copy is unavoidable — and the
            // marker says so where the guard can read it.
            (Some(u), Some(p)) => o.user_and_password(u.clone(), p.expose_secret().to_owned()), // banned-pattern-allow: async-nats 0.42 user_and_password takes an owned String; this is the wire boundary
            (Some(u), None) => o.user_and_password(u.clone(), String::new()),
            _ => o,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_lifted_out_of_the_url_and_the_dial_url_is_clean() {
        let c = NatsConnect::split("nats://gateway:s3cr3t@nats:4222");
        assert_eq!(c.url, "nats://nats:4222");
        assert_eq!(c.user.as_deref(), Some("gateway"));
        assert_eq!(
            c.password.as_ref().map(|p| p.expose_secret()),
            Some("s3cr3t")
        );
        assert!(c.authenticates());
    }

    #[test]
    fn a_bare_url_is_untouched_and_does_not_authenticate() {
        let c = NatsConnect::split("nats://nats:4222");
        assert_eq!(c.url, "nats://nats:4222");
        assert!(!c.authenticates());
        let c = NatsConnect::split("nats://127.0.0.1:4222/path?x=1");
        assert_eq!(c.url, "nats://127.0.0.1:4222/path?x=1");
        assert!(!c.authenticates());
    }

    #[test]
    fn user_without_password_and_a_path_after_the_authority() {
        let c = NatsConnect::split("nats://ops@nats:4222/x");
        assert_eq!(c.url, "nats://nats:4222/x");
        assert_eq!(c.user.as_deref(), Some("ops"));
        assert!(c.password.is_none());
    }

    #[test]
    fn the_secret_never_appears_in_debug_or_the_url() {
        let c = NatsConnect::split("nats://gateway:hunter2@nats:4222");
        assert!(!c.url.contains("hunter2"));
        assert!(!format!("{:?}", c.password).contains("hunter2"));
    }
}
