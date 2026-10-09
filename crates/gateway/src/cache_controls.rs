//! `OG-51` — the pure half of the response-cache controls: the reference table, who is
//! asking ([`CacheCaller`]), whether the workspace's cache is on for this request
//! ([`Enabled`]), what a cache entry is private to ([`namespace`]) and the digest folded
//! into both cache hashes ([`fold`]). Spec: `specs/OG-51-cache-controls.md`.
//!
//! Everything here is a pure function of values the hot path already holds (the warm
//! entitlement read, the validated claims, the request): no I/O, no allocation unless a
//! namespace or an epoch actually applies. `semantic_cache.rs` calls it from
//! `CacheControl::resolve`.
//!
//! **The privacy default.** Previously the
//! response cache was ON for every workspace whenever the operator block existed, and it
//! stored answers even for workspaces with content capture OFF. Earlier guidance called that
//! "the caller's opt-in", which was wrong: a header is not an opt-in, and a workspace that
//! told the gateway not to record its text had never agreed to have it remembered. Now a
//! workspace in mode `inherit` is cached ONLY while it records both prompt and response
//! text (`response_cache.inherit_requires_capture`); mode `on` is the workspace's explicit
//! opt-in; mode `off` and a key's `off` always win.

use std::sync::OnceLock;

use serde_json::Value;
use uuid::Uuid;

use crate::db::cache_settings::{KeyCache, Loaded, Mode, NamespaceBy};

// ── Reference table ──────────────────────────────────────────────────────────

/// The `response_cache` block of `crates/gateway/translation_policy.v1.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResponseCacheConfig {
    /// The longest a stored answer is served — the `semantic_cache` table's own TTL.
    pub ttl_ceiling_hours: u32,
    pub namespace_header_max_bytes: usize,
    pub max_epoch_rows_per_tenant: usize,
    pub stats_window_hours: u32,
    /// `true` = a workspace in mode `inherit` is cached only while its content capture is ON.
    pub inherit_requires_capture: bool,
}

/// Used ONLY when the shipped block does not parse (`the_shipped_block_parses` makes that
/// unreachable in a tested build): the documented values — and the PRIVATE reading of the
/// one flag that matters, never the permissive one.
const FALLBACK: ResponseCacheConfig = ResponseCacheConfig {
    ttl_ceiling_hours: 168,
    namespace_header_max_bytes: 64,
    max_epoch_rows_per_tenant: 256,
    stats_window_hours: 24,
    inherit_requires_capture: true,
};

fn parse_table(raw: &str) -> Option<ResponseCacheConfig> {
    let v: Value = serde_json::from_str(raw).ok()?;
    let v = v.get("response_cache")?;
    let n = |k: &str| v.get(k).and_then(Value::as_u64).filter(|n| *n >= 1);
    Some(ResponseCacheConfig {
        ttl_ceiling_hours: u32::try_from(n("ttl_ceiling_hours")?).ok()?,
        namespace_header_max_bytes: usize::try_from(n("namespace_header_max_bytes")?).ok()?,
        max_epoch_rows_per_tenant: usize::try_from(n("max_epoch_rows_per_tenant")?).ok()?,
        stats_window_hours: u32::try_from(n("stats_window_hours")?).ok()?,
        inherit_requires_capture: v.get("inherit_requires_capture")?.as_bool()?,
    })
}

/// The bounds, parsed once.
pub(crate) fn config() -> ResponseCacheConfig {
    static C: OnceLock<ResponseCacheConfig> = OnceLock::new();
    *C.get_or_init(|| {
        parse_table(include_str!("../translation_policy.v1.json")).unwrap_or_else(|| {
            tracing::warn!(
                "translation_policy.v1.json response_cache block did not parse — using the documented defaults"
            );
            FALLBACK
        })
    })
}

// ── Who is asking ────────────────────────────────────────────────────────────

/// What `CacheControl::resolve` needs to know about the request beyond its header. Every
/// field comes from the validated claims, the admitted request or the capture decision —
/// never from a request body the caller controls beyond what the route already bounded.
#[derive(Debug, Clone, Copy, Default)]
pub struct CacheCaller<'a> {
    /// The model the cache key will hash (after a WORKSPACE alias, before the operator one).
    pub model: &'a str,
    pub key_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub end_user: Option<&'a str>,
    /// `capture.judge_may_read()`: BOTH prompt and response text are recorded for this
    /// workspace (the operator allowlist counts). The privacy default reads this.
    pub captured: bool,
    /// `x-tracelane-cache-namespace`, already validated by [`namespace_header`].
    pub namespace_header: Option<&'a str>,
}

/// The workspace's stored settings, the key's narrowing and what applies to this request,
/// resolved once.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Enabled {
    /// Is the response cache usable for this request at all (before any request header)?
    pub on: bool,
    /// Why it is off, for `GET /v1/cache` and the 409 body — a stable code.
    pub why_off: Option<&'static str>,
}

/// Is the cache on for this caller? Pure. `operator_block` = the operator configured a
/// `semantic_cache:` block; `plan_entitled` = the plan's `f_cache_control` and a non-zero
/// `cache_ttl_hours`.
///
/// **Fail-CLOSED** (`.claude/rules/tenancy.md`): no entitlement read (`loaded` is `None`)
/// means no control plane, which is the unprivileged state — `inherit`, and the caller's
/// `captured` is already false for it (the workspace half of `capture_decision` is OFF), so
/// the cache is off unless the operator allowlisted the tenant for capture.
pub(crate) fn enabled(
    operator_block: bool,
    loaded: Option<&Loaded>,
    key: Option<&KeyCache>,
    plan_entitled: bool,
    captured: bool,
) -> Enabled {
    let off = |why| Enabled {
        on: false,
        why_off: Some(why),
    };
    if !operator_block {
        return off("operator_cache_not_configured");
    }
    if key.is_some_and(|k| k.off) {
        return off("key_cache_off");
    }
    let mode = loaded.map_or(Mode::Inherit, |l| l.settings.mode);
    let inherit_on = !config().inherit_requires_capture || captured;
    match mode {
        Mode::Off => off("workspace_cache_off"),
        // An explicit opt-in — but only while the plan still grants it; a lost entitlement
        // degrades `on` to `inherit`, never keeps serving a feature the plan stopped paying for.
        Mode::On if plan_entitled => Enabled {
            on: true,
            why_off: None,
        },
        Mode::On | Mode::Inherit => {
            if inherit_on {
                Enabled {
                    on: true,
                    why_off: None,
                }
            } else {
                off("content_capture_off")
            }
        }
    }
}

// ── Namespace ────────────────────────────────────────────────────────────────

/// The namespace a request's cache entries are private to: the NARROWER of the workspace's
/// choice and the key's (a key can only narrow).
pub(crate) fn effective_namespace(workspace: NamespaceBy, key: Option<NamespaceBy>) -> NamespaceBy {
    key.map_or(workspace, |k| workspace.max(k))
}

/// The resolved namespace value: the tag (which kind of namespace) and the caller's id for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Namespace {
    pub kind: NamespaceBy,
    pub value: String,
}

/// What a request's namespace resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NamespaceValue {
    /// `workspace`: no namespace — one cache per workspace.
    None,
    Value(Namespace),
    /// The chosen namespace (and every narrower one) has no value for this request — a
    /// session with no key and no end user under `project`, say. **Never widen**: the
    /// request does not use the cache.
    Unavailable,
}

/// Resolve `by` for `who`. A missing value falls back to the NARROWER choice, never the
/// wider: `project` → the key's project, else the end user, else the key; `end_user` → the
/// end user, else the key; `key` → the key. Nothing available = [`NamespaceValue::Unavailable`].
pub(crate) fn namespace(by: NamespaceBy, who: &CacheCaller<'_>) -> NamespaceValue {
    if by == NamespaceBy::Workspace {
        return NamespaceValue::None;
    }
    let candidates = [
        (NamespaceBy::Project, who.project_id.map(|p| p.to_string())),
        (
            NamespaceBy::EndUser,
            who.end_user.filter(|u| !u.is_empty()).map(str::to_owned),
        ),
        (NamespaceBy::Key, who.key_id.map(|k| k.to_string())),
    ];
    for (kind, value) in candidates {
        if kind >= by
            && let Some(value) = value
        {
            return NamespaceValue::Value(Namespace { kind, value });
        }
    }
    NamespaceValue::Unavailable
}

/// Validate the optional `x-tracelane-cache-namespace` header: at most
/// `namespace_header_max_bytes`, `[A-Za-z0-9._:-]`, sent once. It only ever NARROWS — it is
/// folded in beside the workspace namespace, never instead of it.
///
/// # Errors
/// `Err(())` = `400 invalid_cache_control`.
pub(crate) fn namespace_header(headers: &axum::http::HeaderMap) -> Result<Option<String>, ()> {
    let mut values = headers.get_all("x-tracelane-cache-namespace").iter();
    let Some(v) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    let v = v.to_str().map_err(|_| ())?;
    if v.is_empty()
        || v.len() > config().namespace_header_max_bytes
        || !v
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
    {
        return Err(());
    }
    Ok(Some(v.to_owned()))
}

// ── The fold ─────────────────────────────────────────────────────────────────

/// What gets folded into BOTH cache hashes, and the short tags the response headers carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Fold {
    /// The digest `CachePolicy::key` hashes into the exact and the params hash.
    pub digest: [u8; 32],
    /// 8 hex characters of the namespace — the only form of it that leaves the process.
    pub namespace_tag: Option<[u8; 8]>,
    /// 8 hex characters of the applicable epochs.
    pub epoch_tag: Option<[u8; 8]>,
}

fn hash_field(h: &mut blake3::Hasher, bytes: &[u8]) {
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(bytes);
}

fn tag8(h: &blake3::Hasher) -> [u8; 8] {
    let hex = h.finalize().to_hex();
    let mut out = [0u8; 8];
    out.copy_from_slice(&hex.as_bytes()[..8]);
    out
}

/// The fold for a request, or `None` when nothing applies — no namespace, no header, no
/// non-zero epoch — in which case the hashed bytes are IDENTICAL to what they were before
/// OG-51 (a deploy flushes nothing).
pub(crate) fn fold(
    ns: &NamespaceValue,
    header: Option<&str>,
    epochs: &[(String, i64)],
) -> Option<Fold> {
    let ns_value = match ns {
        NamespaceValue::Value(n) => Some(n),
        NamespaceValue::None | NamespaceValue::Unavailable => None,
    };
    if ns_value.is_none() && header.is_none() && epochs.is_empty() {
        return None;
    }
    let mut all = blake3::Hasher::new();
    hash_field(&mut all, b"tracelane.cache.scope.v1");
    let mut ns_h = blake3::Hasher::new();
    let namespace_tag = if ns_value.is_some() || header.is_some() {
        if let Some(n) = ns_value {
            hash_field(&mut all, b"ns");
            hash_field(&mut all, n.kind.as_str().as_bytes());
            hash_field(&mut all, n.value.as_bytes());
            hash_field(&mut ns_h, n.kind.as_str().as_bytes());
            hash_field(&mut ns_h, n.value.as_bytes());
        }
        if let Some(h) = header {
            hash_field(&mut all, b"hdr");
            hash_field(&mut all, h.as_bytes());
            hash_field(&mut ns_h, b"hdr");
            hash_field(&mut ns_h, h.as_bytes());
        }
        Some(tag8(&ns_h))
    } else {
        None
    };
    let mut ep_h = blake3::Hasher::new();
    let epoch_tag = if epochs.is_empty() {
        None
    } else {
        for (scope, epoch) in epochs {
            hash_field(&mut all, b"epoch");
            hash_field(&mut all, scope.as_bytes());
            hash_field(&mut all, &epoch.to_le_bytes());
            hash_field(&mut ep_h, scope.as_bytes());
            hash_field(&mut ep_h, &epoch.to_le_bytes());
        }
        Some(tag8(&ep_h))
    };
    Some(Fold {
        digest: *all.finalize().as_bytes(),
        namespace_tag,
        epoch_tag,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::cache_settings::Settings;

    fn who<'a>() -> CacheCaller<'a> {
        CacheCaller {
            model: "gpt-4o",
            key_id: Some(Uuid::new_v4()),
            project_id: Some(Uuid::new_v4()),
            end_user: Some("user-1"),
            captured: false,
            namespace_header: None,
        }
    }

    #[test]
    fn og51_the_shipped_block_parses_and_the_ceiling_is_the_tables_ttl() {
        let c = parse_table(include_str!("../translation_policy.v1.json")).expect("parses");
        assert_eq!(c, config());
        // The ceiling must equal the semantic_cache table's TTL, or a 30-day plan promise is
        // silently capped by a 7-day delete (spec §7 row 5).
        let ddl = include_str!("../../../infra/dev/clickhouse/migrations/17_semantic_cache.sql");
        let days: u32 = ddl
            .lines()
            .find_map(|l| {
                l.trim()
                    .strip_prefix("TTL toDateTime(created_at) + INTERVAL ")?
                    .strip_suffix(" DAY;")?
                    .parse()
                    .ok()
            })
            .expect("migration 17 carries a day TTL");
        assert_eq!(c.ttl_ceiling_hours, days * 24);
        assert!(
            c.inherit_requires_capture,
            "founder ruling 2026-10-05: private by default"
        );
        assert_eq!(
            FALLBACK, c,
            "the documented fallback equals the shipped table"
        );
        assert!(parse_table(r#"{"response_cache":{"ttl_ceiling_hours":0}}"#).is_none());
    }

    #[test]
    fn og51_inherit_follows_capture_on_follows_the_plan_off_always_wins() {
        let ws = |mode| Loaded {
            settings: Settings {
                mode,
                ..Settings::default()
            },
            ..Loaded::default()
        };
        let key_off = KeyCache {
            off: true,
            namespace_by: None,
        };
        // inherit: only while content is captured (the privacy default).
        assert!(!enabled(true, Some(&ws(Mode::Inherit)), None, true, false).on);
        assert_eq!(
            enabled(true, Some(&ws(Mode::Inherit)), None, true, false).why_off,
            Some("content_capture_off")
        );
        assert!(enabled(true, Some(&ws(Mode::Inherit)), None, true, true).on);
        // no control plane (no entitlement read): the unprivileged reading.
        assert!(!enabled(true, None, None, false, false).on);
        // on: the explicit opt-in, capture or not — while the plan grants it.
        assert!(enabled(true, Some(&ws(Mode::On)), None, true, false).on);
        assert!(
            !enabled(true, Some(&ws(Mode::On)), None, false, false).on,
            "a lost entitlement degrades `on` to `inherit`"
        );
        assert!(enabled(true, Some(&ws(Mode::On)), None, false, true).on);
        // off wins over everything; a key's off wins over an `on` workspace.
        assert!(!enabled(true, Some(&ws(Mode::Off)), None, true, true).on);
        assert!(!enabled(true, Some(&ws(Mode::On)), Some(&key_off), true, true).on);
        // no operator block: nothing to enable.
        assert_eq!(
            enabled(false, Some(&ws(Mode::On)), None, true, true).why_off,
            Some("operator_cache_not_configured")
        );
    }

    #[test]
    fn og51_a_key_can_only_narrow_the_namespace() {
        use NamespaceBy::{EndUser, Key, Project, Workspace};
        assert_eq!(effective_namespace(Workspace, Some(Key)), Key);
        assert_eq!(
            effective_namespace(Key, Some(Workspace)),
            Key,
            "never widens"
        );
        assert_eq!(effective_namespace(Project, Some(EndUser)), EndUser);
        assert_eq!(effective_namespace(Project, None), Project);
    }

    #[test]
    fn og51_a_missing_namespace_value_falls_back_narrower_never_wider() {
        let w = who();
        assert_eq!(namespace(NamespaceBy::Workspace, &w), NamespaceValue::None);
        let NamespaceValue::Value(n) = namespace(NamespaceBy::Project, &w) else {
            panic!("a project value exists")
        };
        assert_eq!(n.kind, NamespaceBy::Project);
        // No project: the end user (narrower); no end user either: the key.
        let no_project = CacheCaller {
            project_id: None,
            ..who()
        };
        assert!(matches!(
            namespace(NamespaceBy::Project, &no_project),
            NamespaceValue::Value(Namespace {
                kind: NamespaceBy::EndUser,
                ..
            })
        ));
        let no_end_user = CacheCaller {
            end_user: None,
            ..no_project
        };
        assert!(matches!(
            namespace(NamespaceBy::EndUser, &no_end_user),
            NamespaceValue::Value(Namespace {
                kind: NamespaceBy::Key,
                ..
            })
        ));
        // A session with nothing narrower to name: the cache is NOT used (never widen).
        let nothing = CacheCaller {
            key_id: None,
            ..no_end_user
        };
        assert_eq!(
            namespace(NamespaceBy::Project, &nothing),
            NamespaceValue::Unavailable
        );
        // `key` never falls back to a WIDER value even when a project exists.
        let only_project = CacheCaller {
            key_id: None,
            end_user: None,
            ..who()
        };
        assert_eq!(
            namespace(NamespaceBy::Key, &only_project),
            NamespaceValue::Unavailable
        );
    }

    #[test]
    fn og51_the_namespace_header_is_bounded_and_charset_checked() {
        let mut h = axum::http::HeaderMap::new();
        assert_eq!(namespace_header(&h), Ok(None));
        h.insert(
            "x-tracelane-cache-namespace",
            "customer-42:v1".parse().unwrap(),
        );
        assert_eq!(namespace_header(&h), Ok(Some("customer-42:v1".to_owned())));
        for bad in ["", "has space", "slash/ed", "ünï", &"a".repeat(65)] {
            h.insert(
                "x-tracelane-cache-namespace",
                bad.parse().unwrap_or_else(|_| "x y".parse().unwrap()),
            );
            assert!(namespace_header(&h).is_err(), "{bad:?}");
        }
        h.insert("x-tracelane-cache-namespace", "ok".parse().unwrap());
        h.append("x-tracelane-cache-namespace", "twice".parse().unwrap());
        assert!(namespace_header(&h).is_err(), "sent twice");
    }

    #[test]
    fn og51_nothing_applying_folds_nothing_and_different_scopes_fold_differently() {
        assert_eq!(fold(&NamespaceValue::None, None, &[]), None);
        assert_eq!(fold(&NamespaceValue::Unavailable, None, &[]), None);
        let a = NamespaceValue::Value(Namespace {
            kind: NamespaceBy::Key,
            value: "key-a".into(),
        });
        let b = NamespaceValue::Value(Namespace {
            kind: NamespaceBy::Key,
            value: "key-b".into(),
        });
        let fa = fold(&a, None, &[]).unwrap();
        assert_ne!(fa.digest, fold(&b, None, &[]).unwrap().digest);
        assert_ne!(fa.digest, fold(&a, Some("x"), &[]).unwrap().digest);
        let e1 = vec![("workspace".to_owned(), 1)];
        let e2 = vec![("workspace".to_owned(), 2)];
        assert_ne!(
            fold(&NamespaceValue::None, None, &e1).unwrap().digest,
            fold(&NamespaceValue::None, None, &e2).unwrap().digest
        );
        // The tags are 8 hex characters and never the raw value.
        let t = fa.namespace_tag.unwrap();
        assert!(t.iter().all(u8::is_ascii_hexdigit));
        assert!(
            fold(&NamespaceValue::None, None, &e1)
                .unwrap()
                .namespace_tag
                .is_none()
        );
        assert!(fa.epoch_tag.is_none());
    }
}
