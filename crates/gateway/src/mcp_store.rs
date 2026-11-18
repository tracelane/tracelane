//! MCP control state, loaded through the entitlement refresh, never from caller tenant IDs.
use crate::mcp_policy::{Policy, Rule};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Server {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub url: String,
    pub transport: String,
    pub auth_mode: String,
    pub credential_kind: String,
    // secret-field-ok: header NAME metadata only; the secret value is sealed in credential_ct below
    pub credential_header: Option<String>,
    #[serde(skip_serializing)]
    pub credential_ct: Option<String>,
    pub credential_last4: Option<String>,
    pub enabled: bool,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ModelRule {
    pub id: Uuid,
    pub model_glob: String,
    pub key_id: Option<Uuid>,
    pub ttl_secs: Option<i32>,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ApprovalSettings {
    pub require_second_approver: bool,
    pub default_ttl_secs: i32,
}
#[derive(Clone)]
pub struct Snapshot {
    pub kms: Option<Arc<crate::kms::vault::Configuration>>,
    pub kms_revision: u64,
    pub servers: Vec<Server>,
    pub policy: Policy,
    pub rules: Vec<Rule>,
    pub model_rules: Vec<ModelRule>,
    pub approval_settings: ApprovalSettings,
    pub approved: std::collections::HashMap<(Uuid, String), String>,
}

/// Fail CLOSED: SQL or typed-policy decode errors fail the entire entitlement resolve.
pub async fn load(client: &tokio_postgres::Client, tenant: &Uuid) -> Result<Arc<Snapshot>> {
    let limits = crate::mcp_policy::settings()?;
    let servers:Vec<Server>=client.query("SELECT id,slug,name,url,transport,auth_mode,credential_kind,credential_header,credential_ct,credential_last4,enabled FROM mcp_servers WHERE tenant_id=$1 AND archived_at IS NULL ORDER BY name", &[tenant]).await?.iter().map(|r|Server {
        id:r.get(0),slug:r.get(1),name:r.get(2),url:r.get(3),transport:r.get(4),auth_mode:r.get(5),credential_kind:r.get(6),credential_header:r.get(7),credential_ct:r.get(8),credential_last4:r.get(9),enabled:r.get(10)
    }).collect();
    let row=client.query_opt("SELECT rules_mode,pins_mode,injection_mode,default_action FROM mcp_policy WHERE tenant_id=$1", &[tenant]).await?;
    let policy=match row {
        None=>Policy::default(),
        Some(r)=>serde_json::from_value(serde_json::json!({"rules_mode":r.get::<_,String>(0),"pins_mode":r.get::<_,String>(1),"injection_mode":r.get::<_,String>(2),"default_action":r.get::<_,String>(3)})).context("invalid MCP policy")?
    };
    let mut rules = Vec::new();
    for r in client.query("SELECT id,server_id,key_id,tool_glob,action,reason FROM mcp_tool_rules WHERE tenant_id=$1 ORDER BY created_at,id", &[tenant]).await? {
        rules.push(serde_json::from_value(serde_json::json!({"id":r.get::<_,Uuid>(0),"server_id":r.get::<_,Option<Uuid>>(1),"key_id":r.get::<_,Option<Uuid>>(2),"tool_glob":r.get::<_,String>(3),"action":r.get::<_,String>(4),"reason":r.get::<_,String>(5)})).context("invalid MCP rule")?);
    }
    let model_rules=client.query("SELECT id,model_glob,key_id,ttl_secs FROM approval_rules WHERE tenant_id=$1 ORDER BY created_at,id", &[tenant]).await?.iter().map(|r|ModelRule{id:r.get(0),model_glob:r.get(1),key_id:r.get(2),ttl_secs:r.get(3)}).collect();
    let approval_settings=client.query_opt("SELECT require_second_approver,default_ttl_secs FROM approval_settings WHERE tenant_id=$1", &[tenant]).await?.map_or(ApprovalSettings{require_second_approver:false,default_ttl_secs:limits.approvals.default_ttl_secs},|r|ApprovalSettings{require_second_approver:r.get(0),default_ttl_secs:r.get(1)});
    let approved=client.query("SELECT server_id,tool_name,def_hash FROM mcp_tool_defs WHERE tenant_id=$1 AND status='approved'", &[tenant]).await?.iter().map(|r|((r.get(0),r.get(1)),r.get(2))).collect();
    let tenant_id = tracelane_shared::TenantId::from_jwt_claim(*tenant);
    let vault = crate::kms::KeyVault::global()?;
    let kms_revision = vault.revision(&tenant_id);
    let kms = if servers.iter().any(|s| s.auth_mode == "gateway_held") {
        let master = crate::byok::master_key()
            .ok_or_else(|| anyhow::anyhow!("MCP master key unavailable"))?;
        crate::kms::vault::load(client, &tenant_id, master)
            .await?
            .map(Arc::new)
    } else {
        None
    };
    vault.check_revision(&tenant_id, kms_revision)?;
    Ok(Arc::new(Snapshot {
        kms,
        kms_revision,
        servers,
        policy,
        rules,
        model_rules,
        approval_settings,
        approved,
    }))
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpSnapshot")
            .field("servers", &self.servers.len())
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl PartialEq for Snapshot {
    fn eq(&self, other: &Self) -> bool {
        self.servers == other.servers
            && self.policy == other.policy
            && self.rules == other.rules
            && self.model_rules == other.model_rules
            && self.approval_settings == other.approval_settings
            && self.approved == other.approved
            && self.kms_revision == other.kms_revision
            && match (&self.kms, &other.kms) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            }
    }
}
impl Eq for Snapshot {}

pub const SCHEMA_COLUMNS: &[(&str, &str)] = &[
    ("mcp_servers", "id"),
    ("mcp_servers", "tenant_id"),
    ("mcp_servers", "slug"),
    ("mcp_servers", "name"),
    ("mcp_servers", "url"),
    ("mcp_servers", "transport"),
    ("mcp_servers", "auth_mode"),
    ("mcp_servers", "credential_kind"),
    ("mcp_servers", "credential_header"),
    ("mcp_servers", "credential_ct"),
    ("mcp_servers", "credential_last4"),
    ("mcp_servers", "enabled"),
    ("mcp_servers", "created_at"),
    ("mcp_servers", "updated_at"),
    ("mcp_servers", "archived_at"),
    ("mcp_policy", "tenant_id"),
    ("mcp_policy", "rules_mode"),
    ("mcp_policy", "pins_mode"),
    ("mcp_policy", "injection_mode"),
    ("mcp_policy", "default_action"),
    ("mcp_policy", "updated_at"),
    ("mcp_policy", "updated_by"),
    ("mcp_tool_rules", "id"),
    ("mcp_tool_rules", "tenant_id"),
    ("mcp_tool_rules", "server_id"),
    ("mcp_tool_rules", "key_id"),
    ("mcp_tool_rules", "tool_glob"),
    ("mcp_tool_rules", "action"),
    ("mcp_tool_rules", "reason"),
    ("mcp_tool_rules", "created_at"),
    ("mcp_tool_rules", "created_by"),
    ("mcp_tool_defs", "tenant_id"),
    ("mcp_tool_defs", "server_id"),
    ("mcp_tool_defs", "tool_name"),
    ("mcp_tool_defs", "def_hash"),
    ("mcp_tool_defs", "status"),
    ("mcp_tool_defs", "first_seen"),
    ("mcp_tool_defs", "last_seen"),
    ("mcp_tool_defs", "seen_count"),
    ("mcp_tool_defs", "approved_by"),
    ("mcp_tool_defs", "approved_at"),
    ("approval_settings", "tenant_id"),
    ("approval_settings", "require_second_approver"),
    ("approval_settings", "default_ttl_secs"),
    ("approval_settings", "updated_at"),
    ("approval_settings", "updated_by"),
    ("approval_rules", "id"),
    ("approval_rules", "tenant_id"),
    ("approval_rules", "model_glob"),
    ("approval_rules", "key_id"),
    ("approval_rules", "ttl_secs"),
    ("approval_rules", "created_at"),
    ("approval_rules", "created_by"),
    ("approvals", "id"),
    ("approvals", "tenant_id"),
    ("approvals", "subject_kind"),
    ("approvals", "server_id"),
    ("approvals", "subject"),
    ("approvals", "key_id"),
    ("approvals", "project_id"),
    ("approvals", "requester_sub"),
    ("approvals", "requester_creator"),
    ("approvals", "args_fp"),
    ("approvals", "args_bytes"),
    ("approvals", "args_preview"),
    ("approvals", "rule_id"),
    ("approvals", "status"),
    ("approvals", "decided_by"),
    ("approvals", "decided_at"),
    ("approvals", "decision_note"),
    ("approvals", "created_at"),
    ("approvals", "expires_at"),
    ("approvals", "grant_expires_at"),
    ("approvals", "consumed_at"),
    ("approvals", "trace_id"),
];

#[cfg(test)]
mod serialization_tests {
    use super::*;

    #[test]
    fn server_read_serializes_header_name_but_never_sealed_credential() {
        let server = Server {
            id: Uuid::nil(),
            slug: "fixture".into(),
            name: "Fixture".into(),
            url: "https://example.test/mcp".into(),
            transport: "streamable_http".into(),
            auth_mode: "gateway_held".into(),
            credential_kind: "header".into(),
            credential_header: Some("x-api-key".into()),
            credential_ct: Some("sealed-secret-sentinel".into()),
            credential_last4: Some("1234".into()),
            enabled: true,
        };
        let value = serde_json::to_value(server).unwrap();
        assert_eq!(value["credential_header"], "x-api-key");
        assert!(!value.as_object().unwrap().contains_key("credential_ct"));
        assert!(!value.to_string().contains("sealed-secret-sentinel"));
    }
}
