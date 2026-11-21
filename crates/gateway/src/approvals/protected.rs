//! Protected bindings on the existing approvals table. Candidate writes never commit here.
use crate::{
    action_control::{self as ac, policy_store::ActivePolicy, *},
    auth::Claims,
    db::audit_chain_state::AtomicBatchAppend,
};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use tokio_postgres::Transaction;
use uuid::Uuid;
#[derive(Deserialize)]
pub(crate) struct Grant {
    pub id: Uuid,
    pub action_id: Uuid,
    pub decision_id: Uuid,
    pub request_digest: String,
    pub args_fp: String,
    pub policy_id: Uuid,
    pub policy_version: i32,
    pub policy_hash: String,
    pub tool_ref: Uuid,
    pub contract_version: i32,
    pub proposer_key_id: Uuid,
    pub requester_creator: Option<String>,
    pub policy_publisher_sub: String,
    pub qualified_human_sub: Option<String>,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    pub server_id: Uuid,
    pub subject: String,
}
fn human_creator(subject: &str) -> bool {
    !subject.is_empty()
        && !subject.starts_with("apikey:")
        && !matches!(subject, "self-host" | "dev-stub")
}
impl Grant {
    pub(crate) fn refusal(&self, now: DateTime<Utc>) -> Option<&'static str> {
        if self.status == "denied" {
            Some("approval_denied")
        } else if self.expires_at <= now {
            Some("approval_expired")
        } else {
            None
        }
    }
    pub(crate) fn renewable(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now && matches!(self.status.as_str(), "pending" | "approved" | "expired")
    }
    pub fn matches(
        &self,
        active: &ActivePolicy,
        digest: &str,
        key: Uuid,
        context: Option<&str>,
    ) -> Result<()> {
        ensure!(
            self.requester_creator.as_deref().is_some_and(human_creator),
            "separation_required"
        );
        let p = active.policy.as_ref().context("approval_mismatch")?;
        ensure!(
            context.is_none_or(|c| ac::canonical(&(digest, &active.hash, c))
                .is_ok_and(|b| self.args_fp == ac::sha(b.as_bytes())))
                && self.request_digest == digest
                && self.proposer_key_id == key
                && self.policy_id == p.policy_id
                && self.policy_version == i32::try_from(p.version)?
                && Some(&self.policy_hash) == active.hash.as_ref()
                && self.tool_ref == active.contract.tool_ref
                && self.contract_version == i32::try_from(active.contract.version)?
                && self.server_id == active.contract.server_id
                && self.subject == active.contract.tool_name,
            "approval_mismatch"
        );
        Ok(())
    }
}
/// Errors fail CLOSED. Workspace/key/policy prefix must already be held by reservation.
#[tracing::instrument(skip_all,fields(tenant_id=%claims.tenant_id))]
pub(crate) async fn find_tx(
    tx: &Transaction<'_>,
    claims: &Claims,
    active: &ActivePolicy,
    digest: &str,
    selector: Option<Uuid>,
) -> Result<(Option<Grant>, Vec<AtomicBatchAppend>)> {
    let t = claims.tenant_id.as_uuid();
    let row = if let Some(id) = selector {
        tx.query_opt("SELECT to_jsonb(a) FROM approvals a WHERE tenant_id=$1 AND id=$2 AND requester_sub=$3 AND action_id IS NOT NULL FOR UPDATE", &[t,&id,&claims.sub]).await?.context("approval_mismatch").map(Some)?
    } else {
        tx.query_opt("SELECT to_jsonb(a) FROM approvals a WHERE tenant_id=$1 AND requester_sub=$2 AND request_digest=$3 AND policy_hash=$4 AND action_id IS NOT NULL AND status NOT IN ('expired','consumed') ORDER BY created_at DESC,id DESC LIMIT 1 FOR UPDATE", &[t,&claims.sub,&digest,&active.hash]).await?
    };
    let grant: Option<Grant> = row
        .map(|r| serde_json::from_value(r.get(0)).context("approval_mismatch"))
        .transpose()?;
    if selector.is_none()
        && let Some(g) = &grant
        && g.renewable(ac::db_now(tx).await?)
    {
        let rows = expire_tx(tx, &claims.tenant_id, g.id)
            .await?
            .context("approval_expired")?;
        return Ok((None, vec![rows]));
    }
    Ok((grant, vec![]))
}
async fn evidence(
    tx: &Transaction<'_>,
    claims: &Claims,
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    g: &Grant,
    body: ActionPayload,
) -> Result<AtomicBatchAppend> {
    let e = lifecycle_event(g, body);
    let rows = append_actions_tx(tx, claims, resolved, &[e])
        .await?
        .context("evidence_unavailable")?;
    ensure!(rows.kept.len() == 1, "evidence_unavailable");
    Ok(rows)
}
/// The outbox payload for a waiting protected approval. Named fields only: the webhook channel
/// forwards it whole, so no evidence, digest, policy id or preview may ever be added here.
pub(crate) fn protected_approval_notice(g: &Grant, server_name: Option<&str>) -> serde_json::Value {
    let mut p = json!({"type":"approval.requested","approval_id":g.id,"subject":g.subject,"subject_kind":"tool",
        "protected":true,"expires_at":g.expires_at.to_rfc3339(),"queue_path":"/settings/gateway/approvals",
        // The version of the active action policy, not an internal id (GWY-81).
        "rule":format!("action policy v{}",g.policy_version)});
    if let Some(s) = server_name {
        p["server_name"] = json!(s);
    }
    p
}
/// Errors fail CLOSED; row and evidence share the caller's reservation transaction.
///
/// # Errors
/// The notification outbox insert is fail-CLOSED: if it fails, the whole transaction (approval
/// row and evidence) rolls back and the call is refused. `mcp_protected::refusal` maps that error
/// to 503 `protected_execution_unavailable`.
#[allow(clippy::too_many_arguments)] // Complete existing decision binding, no body-supplied authority.
#[tracing::instrument(skip_all,fields(tenant_id=%claims.tenant_id))]
pub(crate) async fn request_tx(
    tx: &Transaction<'_>,
    claims: &Claims,
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    active: &ActivePolicy,
    digest: &str,
    action: Uuid,
    decision: Uuid,
    args_bytes: usize,
    context: &str,
    evidence_fields: &BTreeMap<String, EvidenceField>,
) -> Result<(Grant, AtomicBatchAppend)> {
    ensure!(enabled(resolved), "action_control_disabled");
    let p = active.policy.as_ref().context("contract_invalid")?;
    // A policy carries its own TTL only when one of ITS rules requires approval
    // (`policy::parse_policy`). In Enforce mode a legacy `require_approval` rule can lift
    // an `allow` to RequireApproval (`policy::evaluate`), so that case takes the legacy
    // queue's TTL exactly as `mcp_store` resolves it — the tenant's `approval_settings`
    // row, else the reference-table default — bounded by the table maximum, instead of
    // failing every call 503. Fail-CLOSED if neither yields a valid TTL.
    let ttl = match p.approval_ttl_secs {
        Some(ttl) => ttl,
        None => {
            let limits = &crate::mcp_policy::settings()?.approvals;
            let tenant_ttl: Option<i32> = tx
                .query_opt(
                    "SELECT default_ttl_secs FROM approval_settings WHERE tenant_id=$1",
                    &[claims.tenant_id.as_uuid()],
                )
                .await?
                .map(|r| r.get(0));
            let ttl = tenant_ttl.unwrap_or(limits.default_ttl_secs);
            u32::try_from(ttl)
                .ok()
                .filter(|t| *t > 0 && i64::from(*t) <= i64::from(limits.max_ttl_secs))
                .context("approval_policy_invalid")?
        }
    };
    let key = Uuid::parse_str(claims.api_key_id().context("unauthorized")?)?;
    let t = claims.tenant_id.as_uuid();
    let creator: Option<String> = key_tx(tx, claims, key, false)
        .await?
        .context("separation_required")?
        .get(0);
    ensure!(
        creator.as_deref().is_some_and(human_creator),
        "separation_required"
    );
    let publisher = publisher_tx(tx, claims, p.policy_id, i32::try_from(p.version)?).await?;

    ensure!(!publisher.is_empty(), "separation_required");
    // reserve_tx holds the legacy shared tenant-cap lock before key/ledger locks.
    let cap = i64::try_from(
        crate::mcp_policy::settings()?
            .approvals
            .max_pending_per_workspace,
    )?;
    let count = pending_count_tx(tx, claims).await?;
    ensure!(count < cap, "approval_capacity");
    let fp = ac::sha(ac::canonical(&(digest, &active.hash, context))?.as_bytes());
    // Reuse the exact minimized proposal, never rebuild a preview from raw args.
    let preview = ac::canonical(&json!({"evidence_fields":evidence_fields,
        "policy_id":p.policy_id,"policy_version":p.version}))?;
    let row=tx.query_one("INSERT INTO approvals(tenant_id,subject_kind,server_id,subject,key_id,requester_sub,requester_creator,args_fp,args_bytes,trace_id,expires_at,action_id,decision_id,request_digest,policy_id,policy_version,policy_hash,tool_ref,contract_version,proposer_key_id,policy_publisher_sub,args_preview) VALUES($1,'tool',$2,$3,$4,$5,$6,$7,$18,NULL,clock_timestamp()+$9::bigint*interval '1 second',$8,$10,$11,$12,$13,$14,$15,$16,$4,$17,$19) RETURNING to_jsonb(approvals)", &[t,&active.contract.server_id,&active.contract.tool_name,&key,&claims.sub,&creator,&fp,&action,&i64::from(ttl),&decision,&digest,&p.policy_id,&i32::try_from(p.version)?,&active.hash,&active.contract.tool_ref,&i32::try_from(active.contract.version)?,&publisher,&i64::try_from(args_bytes)?,&preview]).await?;
    let g: Grant = serde_json::from_value(row.get(0))?;
    let rows = evidence(
        tx,
        claims,
        resolved,
        &g,
        ActionPayload::ApprovalRequested {
            approval_id: g.id,
            required_role: "admin".into(),
            expires_at: g.expires_at,
        },
    )
    .await?;
    ensure!(
        record_request_tx(tx, claims, g.id, i64::try_from(rows.first_seq)?).await? == 1,
        "approval_not_found"
    );
    // Same txn as the row: a notice never points at a rolled-back approval. Coalesced to one
    // notice per channel per window per tenant (DB clock), so a burst of approvals cannot flood
    // the shared OG-24 worker; the payload describes the first approval of the window.
    let window = crate::mcp_policy::settings()?
        .approvals
        .approval_notice_window_secs;
    ensure!(window > 0, "approval_policy_invalid");
    let bucket = ac::db_now(tx).await?.timestamp().div_euclid(window);
    let server_name = tx
        .query_opt(
            "SELECT name FROM mcp_servers WHERE tenant_id=$1 AND id=$2",
            &[t, &g.server_id],
        )
        .await?
        .map(|r| r.get::<_, String>(0));
    crate::db::spend_alerts::enqueue_with(
        tx,
        *t,
        &format!("approval-waiting:{bucket}"),
        &protected_approval_notice(&g, server_name.as_deref()),
    )
    .await?;
    Ok((g, rows))
}
/// Gate-denied callers can record a bound refusal only. No grant mutation or
/// human-decision authorization is performed, even for an otherwise capable admin.
#[tracing::instrument(skip_all,fields(tenant_id=%claims.tenant_id))]
pub(crate) async fn reject_attempt_tx(
    tx: &Transaction<'_>,
    claims: &Claims,
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    id: Uuid,
) -> Result<AtomicBatchAppend> {
    let g = grant_tx(tx, claims, id, false)
        .await?
        .context("approval_not_found")?;
    evidence(
        tx,
        claims,
        resolved,
        &g,
        ActionPayload::ApprovalAttemptRejected {
            approval_id: id,
            decider_digest: ac::sha(ac::canonical(&claims.sub)?.as_bytes()),
            reason: ReasonCode::Unauthorized,
            channel: None,
            link_digest: None,
        },
    )
    .await
}
fn human_decider(claims: &Claims, session_id: Option<&str>) -> bool {
    session_id.is_some_and(|sid| !sid.is_empty())
        && claims.auth_method == crate::auth::AuthMethod::JwtBearer
        && claims.api_key_id().is_none()
        && !claims.sub.is_empty()
        && claims.can(crate::auth::capability::Capability::ApproveToolCalls)
}
/// Refusals return a code + evidence candidate, leaving the grant unchanged.
/// `session_id` must come from auth::verified_session on the request header.
/// Errors fail CLOSED and require rollback. Commit refusals before returning their code.
/// Test-only convenience: production decides through `decide_echo_tx`.
#[cfg(test)]
#[tracing::instrument(skip_all,fields(tenant_id=%claims.tenant_id))]
pub(crate) async fn decide_tx(
    tx: &Transaction<'_>,
    claims: &Claims,
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    id: Uuid,
    approve: bool,
    note: &str,
    session_id: Option<&str>,
) -> Result<(Option<&'static str>, AtomicBatchAppend)> {
    decide_echo_tx(tx, claims, resolved, id, approve, note, session_id, None).await
}
/// `decide_tx` plus the ACT-10a descriptor echo: a digest that no longer matches the LOCKED
/// row is recorded as a rejected attempt (`descriptor_mismatch`) and nothing is decided.
#[allow(clippy::too_many_arguments)] // decide_tx's seven, plus the optional echo.
#[tracing::instrument(skip_all,fields(tenant_id=%claims.tenant_id))]
pub(crate) async fn decide_echo_tx(
    tx: &Transaction<'_>,
    claims: &Claims,
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    id: Uuid,
    approve: bool,
    note: &str,
    session_id: Option<&str>,
    echo: Option<&str>,
) -> Result<(Option<&'static str>, AtomicBatchAppend)> {
    ensure!(enabled(resolved), "action_control_disabled");
    ensure!(
        note.chars().count() <= crate::mcp_policy::settings()?.approvals.note_max_chars,
        "approval_note_invalid"
    );
    let initial = grant_tx(tx, claims, id, false)
        .await?
        .context("approval_not_found")?;
    let active =
        ac::policy_store::protected_tx(tx, claims, resolved, initial.server_id, &initial.subject)
            .await?;
    // Consistent workspace -> key -> approval -> chain ordering.
    let key = key_tx(tx, claims, initial.proposer_key_id, true).await?;
    let g = grant_tx(tx, claims, id, true)
        .await?
        .context("approval_not_found")?;
    let human = human_decider(claims, session_id);
    let now = ac::db_now(tx).await?;
    let separated = key.as_ref().is_some_and(|k| {
        k.get::<_, Option<String>>(0).as_ref() == g.requester_creator.as_ref()
            && (1..3).all(|i| k.get::<_, Option<DateTime<Utc>>>(i).is_none_or(|d| d > now))
    }) && g
        .requester_creator
        .as_ref()
        .is_some_and(|s| human_creator(s) && s != &claims.sub)
        && !g.policy_publisher_sub.is_empty()
        && g.policy_publisher_sub != claims.sub;
    let separated = separated
        && (!human
            || !ac::principal::same_approver_tx(
                tx,
                claims,
                resolved,
                g.action_id,
                &g.request_digest,
            )
            .await?);
    let current = active.as_ref().is_some_and(|a| {
        g.matches(a, &g.request_digest, g.proposer_key_id, None)
            .is_ok()
    });
    // The descriptor is read only for an authorized, separated decider: an unauthorized caller
    // learns nothing about it. `None` = retention cleared the preview.
    let digest = if human && separated {
        ac::timeline::approval_digest(tx, claims.tenant_id.as_uuid(), id)
            .await
            .map_err(|(_, c)| anyhow::anyhow!(c))?
    } else {
        None
    };
    let code = if !human {
        Some("unauthorized")
    } else if !separated {
        Some("separation_required")
    } else if digest.is_none() {
        Some("descriptor_expired") // no descriptor, no blind decision; recorded as ApprovalExpired
    } else if echo.is_some_and(|sent| digest.as_deref() != Some(sent)) {
        Some("descriptor_mismatch") // recorded below as ApprovalMismatch
    } else if g.status == "denied" {
        Some("approval_denied")
    } else if !current {
        Some("approval_mismatch")
    } else if g.expires_at <= now {
        Some("approval_expired")
    } else if g.status != "pending" {
        Some("approval_not_pending")
    } else {
        None
    };
    let decider_digest = ac::sha(ac::canonical(&claims.sub)?.as_bytes());
    let note_digest = ac::sha(ac::canonical(&note)?.as_bytes());
    let body = if let Some(code) = code {
        ActionPayload::ApprovalAttemptRejected {
            approval_id: id,
            decider_digest,
            reason: match code {
                "unauthorized" => ReasonCode::Unauthorized,
                "separation_required" => ReasonCode::SeparationRequired,
                "approval_expired" | "descriptor_expired" => ReasonCode::ApprovalExpired,
                "approval_denied" => ReasonCode::ApprovalDenied,
                _ => ReasonCode::ApprovalMismatch,
            },
            channel: None,
            link_digest: None,
        }
    } else if approve {
        ActionPayload::ApprovalGranted {
            approval_id: id,
            decider_digest,
            note_digest,
            channel: None,
            link_digest: None,
        }
    } else {
        ActionPayload::ApprovalDenied {
            approval_id: id,
            decider_digest,
            note_digest,
            channel: None,
            link_digest: None,
        }
    };
    let rows = evidence(tx, claims, resolved, &g, body).await?;
    if code.is_none() {
        ensure!(
            record_decision_tx(tx, claims, id, approve, i64::try_from(rows.first_seq)?).await? == 1,
            "approval_expired"
        );
    }
    Ok((code, rows))
}
/// Called under the reservation lock prefix. Errors fail CLOSED; caller rolls back.
#[tracing::instrument(skip_all,fields(tenant_id=%claims.tenant_id))]
pub(crate) async fn consume_tx(
    tx: &Transaction<'_>,
    claims: &Claims,
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    g: &Grant,
) -> Result<AtomicBatchAppend> {
    ensure!(
        g.requester_creator.as_deref().is_some_and(human_creator),
        "separation_required"
    );
    ensure!(
        g.status == "approved"
            && g.qualified_human_sub.as_ref().is_some_and(|s| !s.is_empty()
                && Some(s) != g.requester_creator.as_ref()
                && s != &g.policy_publisher_sub),
        "approval_not_approved"
    );
    ensure!(g.expires_at > ac::db_now(tx).await?, "approval_expired");
    let rows = evidence(
        tx,
        claims,
        resolved,
        g,
        ActionPayload::ApprovalConsumed { approval_id: g.id },
    )
    .await?;
    ensure!(tx.execute("UPDATE approvals SET status='consumed',consumed_at=clock_timestamp(),consumed_ledger_seq=$3 WHERE tenant_id=$1 AND id=$2 AND status='approved' AND expires_at>clock_timestamp()", &[claims.tenant_id.as_uuid(),&g.id,&i64::try_from(rows.first_seq)?]).await?==1,"approval_expired");
    Ok(rows)
}

pub(crate) async fn grant_tx(
    tx: &Transaction<'_>,
    claims: &Claims,
    id: Uuid,
    locked: bool,
) -> Result<Option<Grant>> {
    let sql = if locked {
        "SELECT to_jsonb(a) FROM approvals a WHERE tenant_id=$1 AND id=$2 AND action_id IS NOT NULL FOR UPDATE"
    } else {
        "SELECT to_jsonb(a) FROM approvals a WHERE tenant_id=$1 AND id=$2 AND action_id IS NOT NULL"
    };
    tx.query_opt(sql, &[claims.tenant_id.as_uuid(), &id])
        .await?
        .map(|r| serde_json::from_value(r.get(0)).context("approval_mismatch"))
        .transpose()
}
pub(crate) async fn key_tx(
    tx: &Transaction<'_>,
    claims: &Claims,
    key: Uuid,
    locked: bool,
) -> Result<Option<tokio_postgres::Row>> {
    let sql = if locked {
        "SELECT minted_by,revoked_at,expires_at FROM api_keys WHERE tenant_id=$1 AND id=$2 FOR UPDATE"
    } else {
        "SELECT minted_by,revoked_at,expires_at FROM api_keys WHERE tenant_id=$1 AND id=$2"
    };
    Ok(tx
        .query_opt(sql, &[claims.tenant_id.as_uuid(), &key])
        .await?)
}
pub(crate) async fn publisher_tx(
    tx: &Transaction<'_>,
    claims: &Claims,
    policy: Uuid,
    version: i32,
) -> Result<String> {
    Ok(tx.query_one("SELECT publisher_sub FROM action_policies WHERE tenant_id=$1 AND policy_id=$2 AND version=$3", &[claims.tenant_id.as_uuid(),&policy,&version]).await?.get(0))
}
pub(crate) async fn pending_count_tx(tx: &Transaction<'_>, claims: &Claims) -> Result<i64> {
    Ok(tx.query_one("SELECT count(*) FROM approvals WHERE tenant_id=$1 AND status='pending' AND expires_at>clock_timestamp()", &[claims.tenant_id.as_uuid()]).await?.get(0))
}
pub(crate) async fn record_request_tx(
    tx: &Transaction<'_>,
    claims: &Claims,
    id: Uuid,
    seq: i64,
) -> Result<u64> {
    Ok(tx
        .execute(
            "UPDATE approvals SET requested_ledger_seq=$3 WHERE tenant_id=$1 AND id=$2",
            &[claims.tenant_id.as_uuid(), &id, &seq],
        )
        .await?)
}
pub(crate) async fn record_decision_tx(
    tx: &Transaction<'_>,
    claims: &Claims,
    id: Uuid,
    approve: bool,
    seq: i64,
) -> Result<u64> {
    let status = if approve { "approved" } else { "denied" };
    Ok(tx.execute("UPDATE approvals SET status=$3,qualified_human_sub=$4,decided_by=$4,decided_at=clock_timestamp(),grant_expires_at=expires_at,decided_ledger_seq=$5 WHERE tenant_id=$1 AND id=$2 AND status='pending' AND expires_at>clock_timestamp()", &[claims.tenant_id.as_uuid(),&id,&status,&claims.sub,&seq]).await?)
}
pub(crate) fn lifecycle_event(g: &Grant, body: ActionPayload) -> ActionEvent {
    ActionEvent {
        event_id: Uuid::new_v4(),
        action_id: g.action_id,
        request_digest: g.request_digest.clone(),
        occurred_at: Utc::now(),
        body,
    }
}
/// Conditional state + canonical lifecycle evidence share the caller's transaction.
/// Existing grants expire even after the action-control flag is turned OFF.
pub(crate) async fn expire_tx(
    tx: &Transaction<'_>,
    tenant: &tracelane_shared::TenantId,
    id: Uuid,
) -> Result<Option<AtomicBatchAppend>> {
    let row = tx.query_opt("UPDATE approvals SET status='expired' WHERE tenant_id=$1 AND id=$2 AND action_id IS NOT NULL AND status IN ('pending','approved') AND expires_at<=clock_timestamp() RETURNING to_jsonb(approvals)", &[tenant.as_uuid(),&id]).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let g: Grant = serde_json::from_value(row.get(0))?;
    let e = lifecycle_event(&g, ActionPayload::ApprovalExpired { approval_id: id });
    Ok(Some(
        ac::append_lifecycle_tx(tx, tenant, &[e])
            .await?
            .context("evidence_unavailable")?,
    ))
}

#[cfg(test)]
mod fix_tests {
    use super::*;
    use axum::http::{HeaderMap, Method};
    use serde_json::json;
    #[test]
    fn denied_is_not_expired() {
        let (mut g, _, _, _) = fixture();
        g.status = "denied".into();
        assert_eq!(
            g.refusal(g.expires_at + chrono::Duration::seconds(1)),
            Some("approval_denied")
        );
    }
    fn fixture() -> (
        Grant,
        ActivePolicy,
        crate::mcp_proxy::McpRequest,
        crate::mcp_store::Server,
    ) {
        let server: crate::mcp_store::Server = serde_json::from_value(json!({"id":Uuid::new_v4(),"slug":"fixture","name":"Fixture","url":"https://example.invalid/mcp","transport":"streamable_http","auth_mode":"passthrough","credential_kind":"bearer","enabled":true})).unwrap();
        let mcp = crate::mcp_proxy::McpRequest {
            raw_body: None,
            protected: Default::default(),
            slug: "fixture".into(),
            method: "tools/call".into(),
            http_method: Method::POST,
            envelope: json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":{"amount_minor":1500000,"currency":"USD"}}}),
        };
        let contract = policy::parse_contract(&json!({"tool_ref":Uuid::new_v4(),"server_id":server.id,"tool_name":"pay","version":1,"protected":true,"fields":{}}).to_string()).unwrap();
        let policy = policy::parse_policy(&json!({"policy_id":Uuid::new_v4(),"version":1,"agents":null,"approval_ttl_secs":900,"rules":[{"id":"review","when":[],"decision":"require_approval"}]}).to_string(),&contract).unwrap();
        let active = ActivePolicy {
            contract,
            policy: Some(policy),
            hash: Some("b".repeat(64)),
        };
        let context = crate::mcp_policy::execution_binding(
            &mcp,
            &server,
            &HeaderMap::new(),
            &[7; 32],
        )["execution_context"]
            .as_str()
            .unwrap()
            .to_owned();
        let digest = "a".repeat(64);
        let g = serde_json::from_value(json!({"id":Uuid::new_v4(),"action_id":Uuid::new_v4(),"decision_id":Uuid::new_v4(),"request_digest":digest,"args_fp":ac::sha(ac::canonical(&(&digest,&active.hash,&context)).unwrap().as_bytes()),"policy_id":active.policy.as_ref().unwrap().policy_id,"policy_version":1,"policy_hash":active.hash,"tool_ref":active.contract.tool_ref,"contract_version":1,"proposer_key_id":Uuid::new_v4(),"requester_creator":"creator","policy_publisher_sub":"publisher","qualified_human_sub":"human","status":"approved","expires_at":Utc::now()+chrono::Duration::hours(1),"server_id":server.id,"subject":"pay"})).unwrap();
        (g, active, mcp, server)
    }
    fn changed_context(header: Option<(&str, &str)>, change_server: bool) {
        let (g, a, mcp, mut server) = fixture();
        let context = crate::mcp_policy::execution_binding(
            &mcp,
            &server,
            &HeaderMap::new(),
            &[7; 32],
        )["execution_context"]
            .as_str()
            .unwrap()
            .to_owned();
        g.matches(&a, &g.request_digest, g.proposer_key_id, Some(&context))
            .unwrap();
        let mut headers = HeaderMap::new();
        if let Some((name, value)) = header {
            headers.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        if change_server {
            server.url = "https://changed.invalid/mcp".into();
        }
        let changed=crate::mcp_policy::execution_binding(&mcp,&server,&headers,&[7;32])["execution_context"].as_str().unwrap().to_owned();
        assert_ne!(context, changed);
        assert!(
            g.matches(&a, &g.request_digest, g.proposer_key_id, Some(&changed))
                .is_err(),
            "changed execution context consumed the original approval"
        );
    }
    #[test]
    fn binding_rejects_changed_account() {
        changed_context(
            Some(("x-tracelane-upstream-authorization", "Bearer other-account")),
            false,
        );
    }
    #[test]
    fn binding_rejects_changed_session() {
        changed_context(Some(("mcp-session-id", "other-session")), false);
    }
    #[test]
    fn binding_rejects_changed_server_configuration() {
        changed_context(None, true);
    }
    #[test]
    fn fix_pass_binding_rejects_nonhuman_creator_provenance() {
        let (mut g, active, _, _) = fixture();
        for creator in ["apikey:synthetic-key", "self-host", "dev-stub", ""] {
            g.requester_creator = Some(creator.into());
            let result = g.matches(&active, &g.request_digest, g.proposer_key_id, None);
            assert!(result.is_err(), "nonhuman creator {creator} accepted");
            assert_eq!(result.unwrap_err().to_string(), "separation_required");
        }
    }
    #[test]
    fn automatic_expiry_permits_renewal_but_never_consumed_replay() {
        let (mut g, _, _, _) = fixture();
        let now = Utc::now();
        g.expires_at = now;
        for status in ["pending", "approved", "expired"] {
            g.status = status.into();
            assert!(g.renewable(now), "expired {status} cannot renew");
        }
        for status in ["consumed", "denied", "invalidated"] {
            g.status = status.into();
            assert!(!g.renewable(now), "terminal {status} lost replay fence");
        }
    }
}

#[cfg(test)]
pub(crate) mod session_tests {
    use super::*;
    use base64::Engine as _;
    // Synthetic EC keypair, shared with the existing asymmetric auth regression.
    const PRIVATE: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgoQQxRjGx1D6cUiiJJQKdasGYEjTskAb3d4xYidfE7HGhRANCAASFXnV/lOagsDqcuUURHWfsDIENCqa8lx3MNOPxvXqYkFkdER1RM4rJWG94NLIrP1cs591Yq1VigsIBuG4tUNJn";
    pub(crate) fn jwk() -> serde_json::Value {
        json!({"kty":"EC","crv":"P-256","x":"hV51f5TmoLA6nLlFER1n7AyBDQqmvJcdzDTj8b16mJA",
            "y":"WR0RHVEzislYb3g0sis_Vyzn3VirVWKCwgG4bi1Q0mc","use":"sig","alg":"ES256","kid":"synthetic-c1-4"})
    }
    pub(crate) fn signed_jwt(claims: &Claims, sid: Option<&str>) -> String {
        signed_jwt_at(claims, sid, Some(Utc::now().timestamp()))
    }
    /// ACT-41: `signed_jwt` with a chosen `auth_time` claim (`None` omits it).
    pub(crate) fn signed_jwt_at(
        claims: &Claims,
        sid: Option<&str>,
        auth_time: Option<i64>,
    ) -> String {
        let mut body = json!({"sub":claims.sub,"role":claims.role.map(|r| r.product_name()),
            "tenant_id":claims.tenant_id.as_uuid(), "iss":"synthetic-c1-4", "aud":"synthetic-c1-4",
            "exp":Utc::now().timestamp()+3600});
        if let Some(at) = auth_time {
            body["auth_time"] = json!(at);
        }
        if let Some(sid) = sid {
            body["sid"] = json!(sid);
        }
        let key = base64::engine::general_purpose::STANDARD
            .decode(PRIVATE)
            .unwrap();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some("synthetic-c1-4".into());
        jsonwebtoken::encode(
            &header,
            &body,
            &jsonwebtoken::EncodingKey::from_ec_der(&key),
        )
        .unwrap()
    }
    #[test]
    fn signed_owner_jwt_without_sid_cannot_decide() {
        let claims = crate::auth::dev_stub_claims(crate::auth::AuthMethod::JwtBearer);
        assert_eq!(claims.role, Some(crate::auth::Role::Owner));
        assert!(claims.can(crate::auth::capability::Capability::ApproveToolCalls));
        let token = signed_jwt(&claims, None);
        let key =
            jsonwebtoken::DecodingKey::from_jwk(&serde_json::from_value(jwk()).unwrap()).unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_issuer(&["synthetic-c1-4"]);
        validation.set_audience(&["synthetic-c1-4"]);
        let verified = jsonwebtoken::decode::<serde_json::Value>(&token, &key, &validation)
            .unwrap()
            .claims;
        assert_eq!(verified["role"], "admin");
        assert_eq!(verified["sub"], claims.sub);
        assert!(
            !human_decider(
                &claims,
                verified.get("sid").and_then(serde_json::Value::as_str)
            ),
            "validly signed owner JWT without sid authorized a human decision"
        );
    }
    #[test]
    fn human_decider_requires_capability_and_nonempty_session() {
        let mut claims = crate::auth::dev_stub_claims(crate::auth::AuthMethod::JwtBearer);
        assert!(human_decider(&claims, Some("synthetic-session")));
        assert!(!human_decider(&claims, Some("")));
        claims.role = Some(crate::auth::Role::Viewer);
        assert!(!human_decider(&claims, Some("synthetic-session")));
        claims.auth_method = crate::auth::AuthMethod::SelfHostMasterKey;
        claims.role = Some(crate::auth::Role::Owner);
        assert!(!human_decider(&claims, Some("synthetic-session")));
    }
}

#[cfg(test)]
mod notice_tests {
    use super::*;
    #[test]
    fn protected_notice_has_exactly_the_declared_keys() {
        let g: Grant = serde_json::from_value(json!({"id":Uuid::nil(),"action_id":Uuid::nil(),
            "decision_id":Uuid::nil(),"request_digest":"d","args_fp":"f","policy_id":Uuid::nil(),
            "policy_version":1,"policy_hash":"h","tool_ref":Uuid::nil(),"contract_version":1,
            "proposer_key_id":Uuid::nil(),"requester_creator":null,"policy_publisher_sub":"p",
            "qualified_human_sub":null,"status":"pending","expires_at":"2026-11-09T14:05:33Z",
            "server_id":Uuid::nil(),"subject":"pay"}))
        .unwrap();
        let n = protected_approval_notice(&g, Some("srv"));
        let mut keys: Vec<_> = n.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "approval_id",
                "expires_at",
                "protected",
                "queue_path",
                "rule",
                "server_name",
                "subject",
                "subject_kind",
                "type"
            ]
        );
    }
    #[test]
    fn notice_without_a_server_name_omits_the_key() {
        let g: Grant = serde_json::from_value(serde_json::json!({"id":Uuid::nil(),"action_id":Uuid::nil(),"decision_id":Uuid::nil(),"request_digest":"d","args_fp":"f","policy_id":Uuid::nil(),
            "policy_version":3,"policy_hash":"h","tool_ref":Uuid::nil(),"contract_version":1,
            "proposer_key_id":Uuid::nil(),"requester_creator":null,"policy_publisher_sub":"p",
            "qualified_human_sub":null,"status":"pending","expires_at":"2026-11-09T14:05:33Z",
            "server_id":Uuid::nil(),"subject":"pay"}))
        .unwrap();
        let n = protected_approval_notice(&g, None);
        assert!(n.get("server_name").is_none());
        assert_eq!(n["rule"], "action policy v3");
    }
}
