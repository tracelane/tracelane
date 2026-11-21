//! `OG-61a` — the configuration section registry, EXPORT half
//! (`specs/OG-61-config-as-code.md` §10).
//!
//! A [`Section`] names one family of workspace controls, the capability that reads it, the
//! natural key its list is sorted by, and an `export` function. **The `export` function calls
//! the same store read that the section's own `GET` route calls** — never a second query shape
//! (`db::controls::get`, `db::projects::list`, … ; the three routes that mixed their read into
//! the handler body now share a named statement with it). Import (`OG-61b`) adds the other
//! three functions to the same registry.
//!
//! **No secret leaves through here.** Every `export` builds a typed `*Out` struct that has no
//! secret field, from a row that is allowed to hold one (a spend-alert channel's target is
//! sealed). A secret is recorded only as a `secret_refs` entry such as
//! `spend_alert_channel:<name>.target`, so a re-import knows what it must be handed.
//!
//! **No partial document.** [`export_sections`] returns the first section's error; the route
//! turns it into one `503`, so a document that looks whole is always whole.

use std::future::Future;
use std::pin::Pin;

use anyhow::{Context, Result, anyhow};
use serde::Serialize;
use serde_json::{Map, Value, json};
use tracelane_shared::TenantId;
use uuid::Uuid;

use crate::auth::capability::Capability;
use crate::db::DbPool as Pool;

/// The document's `schema` field. A change to the shape bumps this, never edits it in place.
pub(crate) const SCHEMA: &str = "tracelane.config/v1";

/// What one section's export produced.
pub(crate) struct SectionExport {
    pub value: Value,
    /// References to secrets this section's rows hold but the document never carries.
    pub secret_refs: Vec<String>,
}

type ExportFuture<'a> = Pin<Box<dyn Future<Output = Result<SectionExport>> + Send + 'a>>;

/// One section of the document.
pub(crate) struct Section {
    /// The key under `sections` (and the name `?sections=` takes).
    pub name: &'static str,
    /// The capability that reads this family of controls through its own route. The export
    /// route requires `manage_config` AND this, so it can never show more than the routes do.
    pub capability: Capability,
    /// Field names, in order, that a list section is sorted by (case-folded). Empty for a
    /// singleton section. A git diff of two exports is then the real diff.
    pub sort_key: &'static [&'static str],
    /// The section's read — the same store call its `GET` route makes.
    export: for<'a, 'tx> fn(&'a tokio_postgres::Transaction<'tx>, &'a TenantId) -> ExportFuture<'a>,
}

/// Every section this gateway can export, in document order is irrelevant (keys are sorted).
pub(crate) const SECTIONS: &[Section] = &[
    Section {
        name: "workspace_policy",
        capability: Capability::ViewSettings,
        sort_key: &[],
        export: |p, t| Box::pin(workspace_policy(p, t)),
    },
    Section {
        name: "blocks",
        capability: Capability::ViewSettings,
        sort_key: &[],
        export: |p, t| Box::pin(blocks(p, t)),
    },
    Section {
        name: "capture",
        capability: Capability::ViewSettings,
        sort_key: &[],
        export: |p, t| Box::pin(capture(p, t)),
    },
    Section {
        name: "model_aliases",
        capability: Capability::ViewPolicies,
        sort_key: &["alias"],
        export: |p, t| Box::pin(model_aliases(p, t)),
    },
    Section {
        name: "failover",
        capability: Capability::ViewPolicies,
        sort_key: &[],
        export: |p, t| Box::pin(failover(p, t)),
    },
    Section {
        name: "routing",
        capability: Capability::ViewPolicies,
        sort_key: &[],
        export: |p, t| Box::pin(routing(p, t)),
    },
    Section {
        name: "projects",
        capability: Capability::ViewSettings,
        sort_key: &["name"],
        export: |p, t| Box::pin(projects(p, t)),
    },
    Section {
        name: "spend_alert_channels",
        capability: Capability::ViewSettings,
        sort_key: &["name", "kind"],
        export: |p, t| Box::pin(spend_alert_channels(p, t)),
    },
    Section {
        name: "tool_pins",
        capability: Capability::ViewPolicies,
        sort_key: &["tool_name"],
        export: |p, t| Box::pin(tool_pins(p, t)),
    },
    Section {
        name: "mcp_tool_rules",
        capability: Capability::ViewPolicies,
        sort_key: &["tool_glob", "server_id", "key_id", "action"],
        export: |p, t| Box::pin(mcp_tool_rules(p, t)),
    },
    Section {
        name: "data_controls",
        capability: Capability::ViewSettings,
        sort_key: &[],
        export: |p, t| Box::pin(data_controls(p, t)),
    },
    Section {
        name: "guardrail_policy",
        capability: Capability::ViewPolicies,
        sort_key: &[],
        export: |p, t| Box::pin(guardrail_policy(p, t)),
    },
];

/// What the document says it leaves out, and why. A section whose store has no read
/// function stays out and is listed here (spec §10) — an absence is never silent.
pub(crate) const EXCLUDED: &[(&str, &str)] = &[
    ("pause state", "an action, not configuration"),
    (
        "key policies",
        "no gateway read lists a workspace's keys with their policy; keys are read one at a time",
    ),
    (
        "budgets",
        "a live spend snapshot, not stored configuration; the limits are fields of the workspace and project policy",
    ),
    (
        "mcp servers",
        "read through the entitlement snapshot, which needs the KMS vault; a server's credential is never exported",
    ),
    (
        "mcp policy and approval settings",
        "read through the same entitlement snapshot as mcp servers",
    ),
    (
        "admin access",
        "its lock-out check belongs to import, which ships separately",
    ),
    (
        "guardrail policy of a project or key",
        "keyed by internal id; only the workspace policy is exported",
    ),
    ("provider keys", "credentials are never exported"),
    ("api keys", "credentials are never exported"),
];

/// The section called `name`, or `None` for a name this gateway does not know.
pub(crate) fn find(name: &str) -> Option<&'static Section> {
    SECTIONS.iter().find(|s| s.name == name)
}

/// Run authorised sections for `tenant` in one read-only, repeatable-read snapshot.
///
/// # Errors
/// The first section whose read fails — **fail-CLOSED**: the caller returns no document at
/// all, never the sections that did read.
pub(crate) async fn export_sections(
    pool: &Pool,
    tenant: &TenantId,
    sections: &[&'static Section],
) -> Result<Vec<(&'static str, SectionExport)>> {
    let mut client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let tx = client
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await
        .context("begin configuration snapshot failed")?;
    let mut out = Vec::with_capacity(sections.len());
    for section in sections {
        let mut exported = (section.export)(&tx, tenant)
            .await
            .with_context(|| format!("config section {} could not be read", section.name))?;
        sort_list(&mut exported.value, section.sort_key);
        out.push((section.name, exported));
    }
    tx.commit()
        .await
        .context("commit configuration snapshot failed")?;
    Ok(out)
}

/// Why a document was not built.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DocumentError {
    /// The serialised document is larger than the reference table allows.
    TooLarge { bytes: usize, max: usize },
    /// The document could not be serialised. Unreachable for a `Value`, but the export is
    /// fail-closed, so it is a refusal and never an empty 200 (security review L1).
    Serialise,
}

/// Assemble the document: `{schema, version, exported_at, sections, secret_refs, excluded}`.
/// `version` is the blake3 of the RFC 8785 canonical `sections` object, so it moves only when
/// a section does (`exported_at` is outside the hash). Returns the pretty-printed bytes.
///
/// # Errors
/// [`DocumentError::TooLarge`] when the bytes exceed `max_bytes`.
pub(crate) fn build_document(
    parts: Vec<(&'static str, SectionExport)>,
    exported_at: chrono::DateTime<chrono::Utc>,
    max_bytes: usize,
) -> Result<Vec<u8>, DocumentError> {
    let mut sections = Map::new();
    let mut secret_refs: Vec<String> = Vec::new();
    for (name, exported) in parts {
        sections.insert(name.to_owned(), exported.value);
        secret_refs.extend(exported.secret_refs);
    }
    secret_refs.sort();
    secret_refs.dedup();
    let sections = Value::Object(sections);
    let version = blake3::hash(crate::audit_format::canonical_payload(&sections).as_bytes())
        .to_hex()
        .to_string();
    let excluded: Vec<Value> = EXCLUDED
        .iter()
        .map(|(what, why)| json!({ "what": what, "why": why }))
        .collect();
    let document = json!({
        "schema": SCHEMA,
        "version": version,
        "exported_at": exported_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "sections": sections,
        "secret_refs": secret_refs,
        "excluded": excluded,
    });
    // serde_json's map is ordered by key here, so the pretty output is the canonical key
    // order a diff needs.
    let mut bytes = serde_json::to_vec_pretty(&document).map_err(|_| DocumentError::Serialise)?;
    bytes.push(b'\n');
    if bytes.len() > max_bytes {
        return Err(DocumentError::TooLarge {
            bytes: bytes.len(),
            max: max_bytes,
        });
    }
    Ok(bytes)
}

/// Sort a list section by its natural key: each key field case-folded, then the whole
/// item's canonical form as the tie-break, so the order never depends on the store's.
fn sort_list(value: &mut Value, key: &[&str]) {
    let Value::Array(items) = value else { return };
    items.sort_by_cached_key(|item| {
        let mut k: Vec<String> = key
            .iter()
            .map(|f| match item.get(*f) {
                Some(Value::String(s)) => s.to_lowercase(),
                Some(Value::Null) | None => String::new(),
                Some(other) => other.to_string(),
            })
            .collect();
        k.push(crate::audit_format::canonical_payload(item));
        k
    });
}

fn typed<T: Serialize>(item: &T) -> Result<Value> {
    serde_json::to_value(item).context("section did not serialise")
}

fn plain(value: Value) -> SectionExport {
    SectionExport {
        value,
        secret_refs: Vec::new(),
    }
}

/// Sorted, de-duplicated: a set of labels, not a sequence.
fn set(mut items: Vec<String>) -> Vec<String> {
    items.sort();
    items.dedup();
    items
}

// ── The sections. Each calls the store function its GET route calls. ────────────────────

#[derive(Serialize)]
struct WorkspacePolicyOut {
    policy: Option<Value>,
}

/// `GET /v1/controls` → `db::controls::get`. The pause fields are not read into the output.
async fn workspace_policy(
    client: &tokio_postgres::Transaction<'_>,
    tenant: &TenantId,
) -> Result<SectionExport> {
    let row = crate::db::controls::read_with(client, tenant.as_uuid())
        .await?
        .unwrap_or_default();
    Ok(plain(typed(&WorkspacePolicyOut { policy: row.policy })?))
}

#[derive(Serialize)]
struct BlocksOut {
    models: Vec<String>,
    providers: Vec<String>,
    end_users: Vec<String>,
}

/// `GET /v1/controls` → `db::controls::get`.
async fn blocks(
    client: &tokio_postgres::Transaction<'_>,
    tenant: &TenantId,
) -> Result<SectionExport> {
    let row = crate::db::controls::read_with(client, tenant.as_uuid())
        .await?
        .unwrap_or_default();
    Ok(plain(typed(&BlocksOut {
        models: set(row.blocked_models),
        providers: set(row.blocked_providers),
        end_users: set(row.blocked_end_users),
    })?))
}

#[derive(Serialize)]
struct CaptureOut {
    input: bool,
    output: bool,
}

/// `GET /v1/workspace/capture` → `db::workspace_capture::get`.
async fn capture(
    client: &tokio_postgres::Transaction<'_>,
    tenant: &TenantId,
) -> Result<SectionExport> {
    let stored = crate::db::workspace_capture::get_with(client, tenant.as_uuid())
        .await?
        .unwrap_or_default();
    Ok(plain(typed(&CaptureOut {
        input: stored.input,
        output: stored.output,
    })?))
}

#[derive(Serialize)]
struct AliasOut {
    alias: String,
    target_model: String,
}

/// `GET /v1/model-aliases` → `db::model_aliases::list`.
async fn model_aliases(
    client: &tokio_postgres::Transaction<'_>,
    tenant: &TenantId,
) -> Result<SectionExport> {
    let aliases = crate::db::model_aliases::list_all_with(client, tenant.as_uuid()).await?;
    let items: Vec<AliasOut> = aliases
        .into_iter()
        .map(|(alias, target_model)| AliasOut {
            alias,
            target_model,
        })
        .collect();
    Ok(plain(typed(&items)?))
}

#[derive(Serialize)]
struct FailoverOut {
    enabled: bool,
    /// The order IS the meaning (first fallback first), so it is not sorted.
    models: Vec<String>,
}

/// `GET /v1/gateway/failover` → `db::workspace_failover::get`.
async fn failover(
    client: &tokio_postgres::Transaction<'_>,
    tenant: &TenantId,
) -> Result<SectionExport> {
    let settings = crate::db::workspace_failover::get_with(client, tenant.as_uuid())
        .await?
        .unwrap_or_default();
    Ok(plain(typed(&FailoverOut {
        enabled: settings.enabled,
        models: settings.models,
    })?))
}

#[derive(Serialize)]
struct RoutingOut {
    doc: Value,
}

/// `GET /v1/routing` → `db::routing::get`. The row's `version` counter is the store's own
/// edit count, not configuration, so it stays out and the document hash stays meaningful.
async fn routing(
    client: &tokio_postgres::Transaction<'_>,
    tenant: &TenantId,
) -> Result<SectionExport> {
    let stored = crate::db::routing::get_with(client, tenant.as_uuid()).await?;
    // The route answers `{}` for a workspace that never saved a document.
    let doc = stored.map_or_else(|| json!({}), |r| r.doc);
    Ok(plain(typed(&RoutingOut { doc })?))
}

#[derive(Serialize)]
struct ProjectOut {
    name: String,
    environments: Vec<String>,
    policy: Option<Value>,
}

/// `GET /v1/projects` → `db::projects::list`. Ids and timestamps are the store's, not the
/// workspace's configuration.
async fn projects(
    client: &tokio_postgres::Transaction<'_>,
    tenant: &TenantId,
) -> Result<SectionExport> {
    let list = crate::db::projects::list_with(client, tenant).await?;
    let items: Vec<ProjectOut> = list
        .into_iter()
        .map(|p| ProjectOut {
            name: p.name,
            environments: set(p.environments),
            policy: p.policy,
        })
        .collect();
    Ok(plain(typed(&items)?))
}

#[derive(Serialize)]
struct ChannelOut {
    name: String,
    kind: String,
}

/// `GET /v1/controls/alert-channels` → `db::spend_alerts::list_channels`. The target (an
/// address, or a webhook URL whose path can carry the receiver's token) is NOT exported:
/// the channel is listed by name and a `secret_refs` entry says what a re-import must supply.
async fn spend_alert_channels(
    client: &tokio_postgres::Transaction<'_>,
    tenant: &TenantId,
) -> Result<SectionExport> {
    let list = crate::db::spend_alerts::list_channels_with(client, tenant).await?;
    let secret_refs = list
        .iter()
        .map(|c| format!("spend_alert_channel:{}.target", c.name))
        .collect();
    let items: Vec<ChannelOut> = list
        .into_iter()
        .map(|c| ChannelOut {
            name: c.name,
            kind: c.kind,
        })
        .collect();
    Ok(SectionExport {
        value: typed(&items)?,
        secret_refs,
    })
}

#[derive(Serialize)]
struct ToolPinOut {
    tool_name: String,
    caps: i16,
    def_hash: Option<String>,
}

/// `GET /v1/guardrails/tool-pins` → `db::tool_capabilities::list`.
async fn tool_pins(
    client: &tokio_postgres::Transaction<'_>,
    tenant: &TenantId,
) -> Result<SectionExport> {
    let pins = crate::db::tool_capabilities::list_with(client, tenant).await?;
    let items: Vec<ToolPinOut> = pins
        .into_iter()
        .map(|p| ToolPinOut {
            tool_name: p.tool_name,
            caps: p.caps,
            def_hash: p.def_hash,
        })
        .collect();
    Ok(plain(typed(&items)?))
}

#[derive(serde::Deserialize, Serialize)]
struct ToolRuleOut {
    server_id: Option<Uuid>,
    key_id: Option<Uuid>,
    tool_glob: String,
    action: String,
    reason: String,
}

/// `GET /v1/mcp-tool-rules` → the statement in `mcp_routes::TOOL_RULES_SQL`. The row's own
/// id, creator and timestamps are dropped by the typed struct.
async fn mcp_tool_rules(
    client: &tokio_postgres::Transaction<'_>,
    tenant: &TenantId,
) -> Result<SectionExport> {
    let rows = client
        .query(crate::mcp_routes::TOOL_RULES_SQL, &[tenant.as_uuid()])
        .await
        .context("SELECT mcp_tool_rules failed")?;
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        let rule: ToolRuleOut = serde_json::from_value(row.get::<_, Value>(0))
            .context("a stored MCP tool rule did not decode")?;
        items.push(rule);
    }
    Ok(plain(typed(&items)?))
}

#[derive(Serialize)]
struct DataControlsOut {
    /// `None` = the plan's default window.
    retention_days: Option<i32>,
}

/// `GET /v1/data-controls` → `data_controls_routes::stored_retention_days` (the route's
/// own statement).
async fn data_controls(
    client: &tokio_postgres::Transaction<'_>,
    tenant: &TenantId,
) -> Result<SectionExport> {
    let days = crate::data_controls_routes::stored_retention_days(client, tenant.as_uuid()).await?;
    Ok(plain(typed(&DataControlsOut {
        retention_days: days,
    })?))
}

#[derive(Serialize)]
struct GuardrailPolicyOut {
    policy: Option<Value>,
}

/// `GET /v1/guardrails/policy` (workspace scope) → `guardrail::policy_store::load_scoped`.
/// The hooks (sealed secrets) are never loaded.
async fn guardrail_policy(
    client: &tokio_postgres::Transaction<'_>,
    tenant: &TenantId,
) -> Result<SectionExport> {
    let policies = crate::guardrail::policy_store::load_scoped(client, tenant.as_uuid()).await?;
    Ok(plain(typed(&GuardrailPolicyOut {
        policy: policies.workspace,
    })?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires real local Postgres"]
    async fn config_export_transaction_refuses_writes() {
        let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
        let client = pool.get().await.unwrap();
        let id: uuid::Uuid = client.query_one("INSERT INTO tenants (workos_org_id, name) VALUES ('org_readonly_fixture', 'before') RETURNING id", &[]).await.unwrap().get(0);
        let tenant = TenantId::from_jwt_claim(id);
        static WRITE_PROBE: Section = Section {
            name: "readonly_fixture",
            capability: Capability::ViewSettings,
            sort_key: &[],
            export: |tx, tenant| {
                Box::pin(async move {
                    tx.execute(
                        "UPDATE tenants SET name = 'after' WHERE id = $1",
                        &[tenant.as_uuid()],
                    )
                    .await?;
                    Ok(plain(json!({})))
                })
            },
        };
        let error = match export_sections(&pool, &tenant, &[&WRITE_PROBE]).await {
            Ok(_) => panic!("the actual export transaction accepted a write"),
            Err(error) => error,
        };
        assert_eq!(
            error
                .downcast_ref::<tokio_postgres::Error>()
                .and_then(|e| e.code()),
            Some(&tokio_postgres::error::SqlState::READ_ONLY_SQL_TRANSACTION)
        );
        let name: String = client
            .query_one("SELECT name FROM tenants WHERE id = $1", &[&id])
            .await
            .unwrap()
            .get(0);
        assert_eq!(name, "before");
    }

    fn part(name: &'static str, value: Value) -> (&'static str, SectionExport) {
        (name, plain(value))
    }

    fn at() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_800_000_000, 0).expect("fixed instant")
    }

    #[test]
    fn section_names_are_unique_and_every_one_is_findable() {
        let mut seen = std::collections::HashSet::new();
        for s in SECTIONS {
            assert!(seen.insert(s.name), "duplicate section {}", s.name);
            assert!(find(s.name).is_some());
        }
        assert!(
            find("budgets").is_none(),
            "an excluded family is not a section"
        );
        assert!(find("").is_none());
    }

    #[test]
    fn version_ignores_exported_at_and_follows_the_sections() {
        let doc = |when, value: Value| {
            let bytes = build_document(vec![part("blocks", value)], when, 1 << 20).unwrap();
            serde_json::from_slice::<Value>(&bytes).unwrap()
        };
        let a = doc(at(), json!({"models": ["m"]}));
        let b = doc(at() + chrono::Duration::hours(3), json!({"models": ["m"]}));
        let c = doc(at(), json!({"models": ["m", "n"]}));
        assert_ne!(a["exported_at"], b["exported_at"]);
        assert_eq!(a["version"], b["version"]);
        assert_ne!(a["version"], c["version"]);
    }

    #[test]
    fn a_document_over_the_cap_is_refused_not_truncated() {
        let big = json!({"models": vec!["x".repeat(100); 50]});
        let err = build_document(vec![part("blocks", big.clone())], at(), 1024).unwrap_err();
        assert!(matches!(err, DocumentError::TooLarge { max: 1024, .. }));
        assert!(build_document(vec![part("blocks", big)], at(), 1 << 20).is_ok());
    }

    #[test]
    fn secret_refs_are_sorted_and_unique() {
        let refs = |names: &[&str]| SectionExport {
            value: json!([]),
            secret_refs: names.iter().map(|n| (*n).to_owned()).collect(),
        };
        let bytes = build_document(
            vec![(
                "spend_alert_channels",
                refs(&["b.target", "a.target", "b.target"]),
            )],
            at(),
            1 << 20,
        )
        .unwrap();
        let doc: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(doc["secret_refs"], json!(["a.target", "b.target"]));
    }

    #[test]
    fn lists_sort_case_folded_with_a_stable_tiebreak() {
        let mut v = json!([
            {"name": "Zulu", "kind": "email"},
            {"name": "alpha", "kind": "slack"},
            {"name": "alpha", "kind": "email"},
        ]);
        sort_list(&mut v, &["name", "kind"]);
        assert_eq!(
            v,
            json!([
                {"name": "alpha", "kind": "email"},
                {"name": "alpha", "kind": "slack"},
                {"name": "Zulu", "kind": "email"},
            ])
        );
        // A singleton (object) and an empty key list are left alone.
        let mut obj = json!({"b": 1, "a": 2});
        sort_list(&mut obj, &[]);
        assert_eq!(obj, json!({"a": 2, "b": 1}));
    }

    #[test]
    fn the_output_structs_have_no_field_that_could_hold_a_secret() {
        // The names a credential column goes by in this codebase; a typed export struct that
        // grows one must be a deliberate, reviewed change to this list.
        let src = include_str!("config_sections.rs");
        let production = src.split("#[cfg(test)]").next().expect("production half");
        for banned in [
            "credential",
            "ciphertext",
            "secret_enc",
            "key_hash",
            "target:",
        ] {
            let hits = production
                .lines()
                .filter(|l| {
                    l.trim_start().starts_with(|c: char| c.is_alphanumeric()) && l.contains(banned)
                })
                .filter(|l| l.trim_end().ends_with(','))
                .filter(|l| !l.trim_start().starts_with("//"))
                .count();
            assert_eq!(hits, 0, "a typed export field mentions `{banned}`");
        }
    }
}
