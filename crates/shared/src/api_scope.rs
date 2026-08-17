//! API-key scopes (A13 / SET-20) — what a key is allowed to do.
//!
//! **Lives in `shared`, not in the gateway's `auth`, for a concrete reason.**
//! `crates/gateway/tests/postgres_tenant_integration.rs` `#[path]`-includes
//! `src/db/mod.rs` into a SEPARATE test crate, and its own comment states the
//! invariant that makes that work: *"db::api_keys + db::tenants don't reach for
//! crate::predictive or other gateway-internal paths."* Resolving this type
//! through `crate::auth::` broke exactly that, and it failed to compile ONLY
//! under `--all-targets`. It is pure data with no gateway dependency, so `shared`
//! is both the fix and the better home; the gateway re-exports it as
//! `crate::auth::scope`.
//!
//! **Why this exists.** Until now every `tlane_` key was all-or-nothing: it
//! inherited the entire API surface of the workspace, forever. That is why PL-9b
//! demoted API keys to non-admin wholesale — a blanket deny standing in for the
//! per-capability answer nobody could express. The wedge makes it worse rather
//! than better: the flight-recorder story asks a customer to hand a key to a
//! third-party auditor, and the only key we could hand over granted everything.
//!
//! **The vocabulary is CLOSED and deliberately small** — `chat`, `read`, `ingest`,
//! `admin`.
//! A closed set is the whole point: an unrecognised scope grants nothing. That is
//! the same lesson as `Role::from_slug` (PL-9), where an unknown role slug had to
//! deny rather than fall through to a default, and it is why this parses into an
//! enum instead of comparing strings at each call site.
//!
//! **NULL is not empty.** A `NULL` scope column means "legacy key, full surface"
//! and is the backwards-compatibility path for the keys minted before A13. An
//! EMPTY array would be ambiguous — "no permissions" or "all permissions"? — so
//! the database refuses it outright (`api_keys_scope_not_empty_chk`, falsified
//! against prod 2026-08-12). There is exactly one unscoped representation.
//!
//! **Fails CLOSED, in every direction except the one compatibility case:**
//! unknown scope string → denied · unreadable column → denied · empty set →
//! impossible by constraint, and denied here too if one ever appears · `NULL` →
//! full surface, which is the documented legacy behaviour and the only open
//! direction.

use std::collections::BTreeSet;

/// A single capability a key may carry. Closed set — see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// Send completions — `POST /v1/chat/completions` and the other dispatch
    /// routes. The expensive one: it spends the tenant's provider budget.
    Chat,
    /// Read recorded data — traces, sessions, audit, metrics. The scope an
    /// external auditor should be given, and nothing else.
    Read,
    /// Send telemetry IN — `POST /v1/traces`, the authenticated OTLP write path
    /// (`GWY-41`).
    ///
    /// **Why this is not folded into `chat` or `read`.** `chat` spends the
    /// tenant's provider budget and `read` is the auditor's scope; a span export
    /// is neither. Keeping it separate buys a real property: an agent that
    /// REPORTS telemetry does not need to READ it, so an SDK key leaked from a
    /// container image can add data and cannot exfiltrate the customer's traces.
    /// That is the same argument the module docs make for the auditor case, in
    /// the other direction.
    ///
    /// Keys minted BEFORE `GWY-41` do not carry it and are correctly refused —
    /// nobody has been granted this capability yet. Legacy `NULL`-scope keys
    /// allow it, which is the documented compatibility direction and the only
    /// open one.
    Ingest,
    /// Manage the workspace — mint/revoke keys, provider keys, settings.
    Admin,
}

impl Scope {
    /// Parse one scope slug. **Unknown slugs return `None` and MUST deny** —
    /// never fall through to a permissive default.
    #[must_use]
    pub fn from_slug(slug: &str) -> Option<Self> {
        match slug.trim().to_ascii_lowercase().as_str() {
            "chat" => Some(Self::Chat),
            "read" => Some(Self::Read),
            "ingest" => Some(Self::Ingest),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_slug(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Read => "read",
            Self::Ingest => "ingest",
            Self::Admin => "admin",
        }
    }

    /// Every scope a mint request may ask for. Used by the API surface to
    /// validate input and by the UI to render checkboxes.
    ///
    /// **This is the VOCABULARY, not the DEFAULT.** For what an omitted `scope`
    /// resolves to, use [`Scope::default_mint_set`] — the two are deliberately
    /// different and conflating them is the defect below.
    #[must_use]
    pub fn all() -> [Scope; 4] {
        [Scope::Chat, Scope::Read, Scope::Ingest, Scope::Admin]
    }

    /// What an **omitted** `scope` on a mint request resolves to.
    ///
    /// **`Admin` is deliberately absent, and that is a security ruling, not a
    /// UI preference** (founder, 2026-08-14). Until then `with_default_scope`
    /// used [`Scope::all`], so every key minted without an explicit scope —
    /// which is every key the dashboard dialog could produce, because the
    /// deployed dialog had no scope field at all — silently carried `Admin`:
    /// *"Manage the workspace — mint/revoke keys, provider keys, settings."*
    ///
    /// That is precisely the escalation [`crate::api_scope`]'s owner gate exists
    /// provider credential*), reachable **by key instead of by JWT** and with no
    /// disclosure to the person clicking Create.
    ///
    /// **`Admin` is opt-in and explicit, always.** A caller who wants it asks
    /// for it by name; omission can never grant it. The gate lives HERE rather
    /// than in the dialog because the dialog is not the only caller — the API
    /// and the web proxy both reach the same mint path.
    #[must_use]
    pub fn default_mint_set() -> [Scope; 3] {
        [Scope::Chat, Scope::Read, Scope::Ingest]
    }
}

/// The resolved capability of a key.
///
/// Deliberately a two-variant enum rather than an `Option<Set>`: the "legacy,
/// unscoped" case is a *different kind of thing* from "scoped to these", and
/// making that explicit stops a call site from treating an absent scope as an
/// empty one — which would silently deny every legacy key and take the product
/// down for every existing customer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyScope {
    /// `scope IS NULL` — a key minted before A13. Full API surface, unchanged.
    LegacyFullSurface,
    /// An explicit, non-empty set of recognised scopes.
    Scoped(BTreeSet<Scope>),
}

impl KeyScope {
    /// Resolve the raw `text[]` column into a capability.
    ///
    /// - `None` (SQL NULL) → [`KeyScope::LegacyFullSurface`]
    /// - a set containing ANY unrecognised slug → `Scoped` **without** it. The
    ///   unknown slug contributes nothing; it never widens and never errors the
    ///   request. If that leaves the set empty, the key can do nothing, which is
    ///   the correct reading of "this key was granted only things we do not
    ///   recognise".
    #[must_use]
    pub fn from_column(raw: Option<&[String]>) -> Self {
        match raw {
            None => Self::LegacyFullSurface,
            Some(slugs) => Self::Scoped(slugs.iter().filter_map(|s| Scope::from_slug(s)).collect()),
        }
    }

    /// Does this key carry `needed`?
    ///
    /// `LegacyFullSurface` allows everything — the compatibility case. A scoped
    /// key allows exactly what it lists; `admin` does **not** imply `chat` or
    /// `read`, because an implication hierarchy is how a narrow grant quietly
    /// becomes a wide one. A key that needs two capabilities lists two.
    #[must_use]
    pub fn allows(&self, needed: Scope) -> bool {
        match self {
            Self::LegacyFullSurface => true,
            Self::Scoped(s) => s.contains(&needed),
        }
    }

    /// Slugs, sorted, for display and for `GET /v1/keys`. `None` = legacy.
    #[must_use]
    pub fn slugs(&self) -> Option<Vec<&'static str>> {
        match self {
            Self::LegacyFullSurface => None,
            Self::Scoped(s) => Some(s.iter().map(|x| x.as_slug()).collect()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_slugs_parse_and_round_trip() {
        for s in Scope::all() {
            assert_eq!(Scope::from_slug(s.as_slug()), Some(s));
        }
        assert_eq!(Scope::from_slug("  ChAt "), Some(Scope::Chat));
    }

    /// The PL-9 lesson: an unrecognised slug must grant NOTHING. If this ever
    /// returns Some, a typo in a mint request silently becomes a capability.
    #[test]
    fn unknown_slugs_grant_nothing() {
        for bad in [
            "",
            "owner",
            "write",
            "chat:read",
            "*",
            "ADMIN ALL",
            "reads",
            "ingests",
            "traces",
            "otlp",
        ] {
            assert_eq!(Scope::from_slug(bad), None, "{bad:?} must not parse");
        }
    }

    /// The compatibility case, and the ONLY open direction. If this breaks,
    /// every key minted before A13 stops working.
    #[test]
    fn null_column_is_legacy_full_surface() {
        let k = KeyScope::from_column(None);
        assert_eq!(k, KeyScope::LegacyFullSurface);
        for s in Scope::all() {
            assert!(k.allows(s), "legacy key must retain {s:?}");
        }
        assert_eq!(k.slugs(), None);
    }

    #[test]
    fn a_scoped_key_allows_only_what_it_lists() {
        let k = KeyScope::from_column(Some(&["read".to_string()]));
        assert!(k.allows(Scope::Read));
        assert!(!k.allows(Scope::Chat), "read-only key must not send chat");
        assert!(!k.allows(Scope::Admin));
        assert!(
            !k.allows(Scope::Ingest),
            "the auditor key must not be able to WRITE spans into the workspace \
             it was handed to read"
        );
        assert_eq!(k.slugs(), Some(vec!["read"]));
    }

    /// `admin` deliberately does NOT imply the others. A hierarchy is how a
    /// narrow grant widens without anyone deciding it should.
    #[test]
    fn admin_does_not_imply_chat_or_read() {
        let k = KeyScope::from_column(Some(&["admin".to_string()]));
        assert!(k.allows(Scope::Admin));
        assert!(!k.allows(Scope::Chat));
        assert!(!k.allows(Scope::Read));
        assert!(!k.allows(Scope::Ingest));
    }

    /// GWY-41 / B-227. The keys that exist TODAY are `{chat}`, `{chat,read}`,
    /// `{read}` and legacy `NULL`. None of the scoped ones may reach the new OTLP
    /// write path — an existing key silently gaining a new write capability
    /// because a variant was added is exactly the widening this enum's closed
    /// vocabulary exists to prevent.
    #[test]
    fn no_pre_existing_scoped_key_gains_ingest() {
        for existing in [
            vec!["chat".to_string()],
            vec!["read".to_string()],
            vec!["chat".to_string(), "read".to_string()],
            vec!["admin".to_string()],
        ] {
            let k = KeyScope::from_column(Some(&existing));
            assert!(
                !k.allows(Scope::Ingest),
                "{existing:?} must not gain `ingest` by the variant being added"
            );
        }
        // The ONE open direction, unchanged: a legacy key allows everything.
        assert!(KeyScope::from_column(None).allows(Scope::Ingest));
    }

    /// An `ingest` key is the SDK key: it writes spans and can read nothing.
    #[test]
    fn an_ingest_key_writes_spans_and_reads_nothing() {
        let k = KeyScope::from_column(Some(&["ingest".to_string()]));
        assert!(k.allows(Scope::Ingest));
        assert!(
            !k.allows(Scope::Read),
            "a leaked SDK key must not exfiltrate"
        );
        assert!(!k.allows(Scope::Chat));
        assert!(!k.allows(Scope::Admin));
        assert_eq!(k.slugs(), Some(vec!["ingest"]));
    }

    /// An unknown slug beside a known one must not widen the key, and must not
    /// error it either — it simply is not there.
    #[test]
    fn unknown_slug_beside_a_known_one_neither_widens_nor_errors() {
        let k = KeyScope::from_column(Some(&["read".to_string(), "superuser".to_string()]));
        assert!(k.allows(Scope::Read));
        assert!(!k.allows(Scope::Chat));
        assert!(!k.allows(Scope::Admin));
        assert_eq!(k.slugs(), Some(vec!["read"]));
    }

    /// A set of ONLY unrecognised slugs grants nothing — it must NOT collapse
    /// into the legacy full-surface case. This is the assertion that separates
    /// "absent" from "empty", and getting it wrong is a privilege escalation.
    #[test]
    fn only_unknown_slugs_grants_nothing_and_is_not_legacy() {
        let k = KeyScope::from_column(Some(&["superuser".to_string()]));
        assert_ne!(k, KeyScope::LegacyFullSurface);
        for s in Scope::all() {
            assert!(!k.allows(s), "must not grant {s:?}");
        }
        assert_eq!(k.slugs(), Some(vec![]));
    }

    /// The DB forbids `{}` via `api_keys_scope_not_empty_chk`, but if one ever
    /// reaches us it denies rather than defaulting open.
    #[test]
    fn empty_array_denies_rather_than_defaulting_open() {
        let k = KeyScope::from_column(Some(&[]));
        assert_ne!(k, KeyScope::LegacyFullSurface);
        for s in Scope::all() {
            assert!(!k.allows(s));
        }
    }
}
