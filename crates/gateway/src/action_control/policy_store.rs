//! Transactional policy service; later admission integration owns forwarding authority.
use super::{policy::*, *};
use crate::db::audit_chain_state::AtomicBatchAppend;
use crate::mcp_policy::{Action, Mode};
pub struct ActivePolicy {
    pub contract: Contract,
    pub policy: Option<Policy>,
    pub hash: Option<String>,
}
/// Flag checked before SQL; tenant is already resolved by auth::resolve_tenant_id.
/// Errors fail CLOSED. Callers serialize with activation using the workspace lock.
#[tracing::instrument(skip_all)]
pub async fn load_tx(
    tx: &Transaction<'_>,
    claims: &crate::auth::Claims,
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    server: Uuid,
    tool: &str,
) -> Result<Option<ActivePolicy>> {
    if !enabled(resolved) {
        return Ok(None);
    }
    let row=tx.query_opt("SELECT c.body_jcs,c.contract_hash,c.tool_ref,c.version,p.body_jcs,p.policy_hash FROM action_tool_contracts c LEFT JOIN action_policy_active a ON a.tenant_id=c.tenant_id AND a.tool_ref=c.tool_ref LEFT JOIN action_policies p ON p.tenant_id=a.tenant_id AND p.tool_ref=a.tool_ref AND p.policy_id=a.policy_id AND p.version=a.version AND p.contract_version=c.version WHERE c.tenant_id=$1 AND c.server_id=$2 AND c.tool_name=$3 ORDER BY c.version DESC LIMIT 1", &[claims.tenant_id.as_uuid(),&server,&tool]).await.context("evidence_unavailable")?;
    let Some(row) = row else {
        // Unknown aliases must not escape to legacy on a protected server.
        let protected = tx.query_opt("SELECT 1 FROM action_tool_contracts WHERE tenant_id=$1 AND server_id=$2 AND protected LIMIT 1", &[claims.tenant_id.as_uuid(), &server]).await?;
        ensure!(protected.is_none(), "contract_invalid");
        return Ok(None);
    };
    let body: String = row.get(0);
    let c = parse_contract(&body)?;
    ensure!(
        sha(canonical_json(&body)?.as_bytes()) == row.get::<_, String>(1)
            && c.server_id == server
            && c.tool_name == tool
            && c.tool_ref == row.get::<_, Uuid>(2)
            && i32::try_from(c.version)? == row.get::<_, i32>(3),
        "contract_invalid"
    );
    let (policy, hash) = match (
        row.get::<_, Option<String>>(4),
        row.get::<_, Option<String>>(5),
    ) {
        (Some(body), Some(hash)) => {
            ensure!(
                sha(canonical_json(&body)?.as_bytes()) == hash,
                "contract_invalid"
            );
            (Some(parse_policy(&body, &c)?), Some(hash))
        }
        (None, None) => (None, None),
        _ => anyhow::bail!("contract_invalid"),
    };
    Ok(Some(ActivePolicy {
        contract: c,
        policy,
        hash,
    }))
}
// Shared lookup lock closes first-activation races without serializing ordinary calls.
// All callers acquire this BEFORE workspace controls, including activation.
async fn server_lock(
    tx: &Transaction<'_>,
    claims: &crate::auth::Claims,
    server: Uuid,
    exclusive: bool,
) -> Result<()> {
    let digest = ring::digest::digest(
        &ring::digest::SHA256,
        canonical(&(claims.tenant_id.to_string(), server))?.as_bytes(),
    );
    let lock = i64::from_be_bytes(digest.as_ref()[..8].try_into()?);
    let sql = if exclusive {
        "SELECT pg_advisory_xact_lock($1)"
    } else {
        "SELECT pg_advisory_xact_lock_shared($1)"
    };
    tx.query_one(sql, &[&lock])
        .await
        .context("evidence_unavailable")?;
    Ok(())
}
/// Errors fail CLOSED. Reload after workspace lock; activation uses the same prefix.
#[tracing::instrument(skip_all, fields(tenant_id=%claims.tenant_id))]
pub async fn protected_tx(
    tx: &Transaction<'_>,
    claims: &crate::auth::Claims,
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    server: Uuid,
    tool: &str,
) -> Result<Option<ActivePolicy>> {
    if !enabled(resolved) {
        return Ok(None);
    }
    server_lock(tx, claims, server, false).await?;
    let Some(active) = load_tx(tx, claims, resolved, server, tool).await? else {
        return Ok(None);
    };
    if !active.contract.protected {
        return Ok(None);
    }
    workspace_lock(tx, claims).await?;
    load_tx(tx, claims, resolved, server, tool).await
}
async fn workspace_lock(tx: &Transaction<'_>, claims: &crate::auth::Claims) -> Result<()> {
    // Fresh workspaces have no controls row; concurrent initializers share this lock.
    tx.execute(
        "INSERT INTO workspace_controls(tenant_id) VALUES ($1) ON CONFLICT (tenant_id) DO NOTHING",
        &[claims.tenant_id.as_uuid()],
    )
    .await
    .context("evidence_unavailable")?;
    tx.query_one(
        "SELECT tenant_id FROM workspace_controls WHERE tenant_id=$1 FOR UPDATE",
        &[claims.tenant_id.as_uuid()],
    )
    .await
    .context("evidence_unavailable")?;
    Ok(())
}
/// Errors fail CLOSED; caller MUST roll back, commit before hook/forwarding.
#[tracing::instrument(skip_all)]
pub async fn activate_tx(
    tx: &Transaction<'_>,
    claims: &crate::auth::Claims,
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    contract_raw: &str,
    policy_raw: &str,
) -> Result<AtomicBatchAppend> {
    require_enabled(resolved)?;
    ensure!(
        claims.auth_method == crate::auth::AuthMethod::JwtBearer
            && claims.is_verified_owner()
            && !claims.sub.is_empty(),
        "unauthorized"
    );
    let c = parse_contract(contract_raw)?;
    let p = parse_policy(policy_raw, &c)?;
    ensure!(
        !c.fields.contains_key("principal.roles"),
        "contract_invalid"
    );
    let cb = canonical_json(contract_raw)?;
    let pb = canonical_json(policy_raw)?;
    let ch = sha(cb.as_bytes());
    let ph = sha(pb.as_bytes());
    server_lock(tx, claims, c.server_id, true).await?;
    workspace_lock(tx, claims).await?;
    // B-640 (second review, M2): never protect an archived (or absent) registration.
    ensure!(
        tx.query_opt(
            "SELECT 1 FROM mcp_servers WHERE tenant_id=$1 AND id=$2 AND archived_at IS NULL",
            &[claims.tenant_id.as_uuid(), &c.server_id],
        )
        .await?
        .is_some(),
        "contract_invalid"
    );
    let t = claims.tenant_id.as_uuid();
    // Check BOTH directions of immutable tool identity, across all historical versions.
    let history=tx.query_one("SELECT bool_and(tool_ref=$2 AND server_id=$3 AND tool_name=$4),max(version) FROM action_tool_contracts WHERE tenant_id=$1 AND (tool_ref=$2 OR (server_id=$3 AND tool_name=$4))", &[t,&c.tool_ref,&c.server_id,&c.tool_name]).await.context("evidence_unavailable")?;
    if let Some(consistent) = history.get::<_, Option<bool>>(0) {
        ensure!(consistent, "contract_invalid");
    }
    if let Some(version) = history.get::<_, Option<i32>>(1) {
        ensure!(i32::try_from(c.version)? >= version, "contract_invalid");
    }
    let old = tx
        .query_one(
            "SELECT max(version) FROM action_policies WHERE tenant_id=$1 AND tool_ref=$2",
            &[t, &c.tool_ref],
        )
        .await
        .context("evidence_unavailable")?;
    if let Some(version) = old.get::<_, Option<i32>>(0) {
        ensure!(
            i32::try_from(p.version)? > version,
            "policy_version_must_increase"
        );
    }
    tx.execute("INSERT INTO action_tool_contracts(tenant_id,tool_ref,version,server_id,tool_name,protected,body_jcs,contract_hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (tenant_id,tool_ref,version) DO NOTHING", &[t,&c.tool_ref,&i32::try_from(c.version)?,&c.server_id,&c.tool_name,&c.protected,&cb,&ch]).await.context("evidence_unavailable")?;
    let stored=tx.query_one("SELECT body_jcs FROM action_tool_contracts WHERE tenant_id=$1 AND tool_ref=$2 AND version=$3", &[t,&c.tool_ref,&i32::try_from(c.version)?]).await.context("evidence_unavailable")?;
    ensure!(stored.get::<_, String>(0) == cb, "contract_invalid");
    tx.execute("INSERT INTO action_policies(tenant_id,policy_id,version,tool_ref,contract_version,body_jcs,policy_hash,publisher_sub) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)", &[t,&p.policy_id,&i32::try_from(p.version)?,&c.tool_ref,&i32::try_from(c.version)?,&pb,&ph,&claims.sub]).await.context("evidence_unavailable")?;
    tx.execute("INSERT INTO action_policy_active(tenant_id,tool_ref,policy_id,version) VALUES ($1,$2,$3,$4) ON CONFLICT (tenant_id,tool_ref) DO UPDATE SET policy_id=EXCLUDED.policy_id,version=EXCLUDED.version", &[t,&c.tool_ref,&p.policy_id,&i32::try_from(p.version)?]).await.context("evidence_unavailable")?;
    // The policy activation event and invalidated grants commit atomically.
    let invalidated = tx.query("UPDATE approvals SET status='invalidated' WHERE tenant_id=$1 AND tool_ref=$2 AND action_id IS NOT NULL AND status IN ('pending','approved') AND (policy_id<>$3 OR policy_version<>$4) RETURNING to_jsonb(approvals)", &[t,&c.tool_ref,&p.policy_id,&i32::try_from(p.version)?]).await.context("evidence_unavailable")?;
    let event = ActionEvent {
        event_id: Uuid::new_v4(),
        action_id: p.policy_id,
        occurred_at: Utc::now(),
        request_digest: ph.clone(),
        body: ActionPayload::PolicyActivated {
            policy_id: p.policy_id,
            version: p.version,
            policy_hash: ph,
            publisher_digest: sha(canonical(&claims.sub)?.as_bytes()),
            tool_ref: c.tool_ref,
            contract_version: c.version,
            contract_hash: ch,
            protected: c.protected,
        },
    };
    let mut events = vec![event];
    for row in invalidated {
        let g: crate::approvals::protected::Grant = serde_json::from_value(row.get(0))?;
        events.push(crate::approvals::protected::lifecycle_event(
            &g,
            ActionPayload::ApprovalInvalidated { approval_id: g.id },
        ));
    }
    append_actions_tx(tx, claims, resolved, &events)
        .await
        .context("evidence_unavailable")?
        .context("evidence_unavailable")
}
/// Callers supply stable IDs across retries.
pub struct Request<'a> {
    pub principal: Option<&'a tracelane_audit_verifier::action::Principal>,
    pub server: Uuid,
    pub tool: &'a str,
    pub args: &'a [u8],
    pub action_id: Uuid,
    pub decision_id: Uuid,
    pub denial_id: Uuid,
}
pub struct Verdict {
    pub decision: Action,
    pub request_digest: String,
}
/// Atomic decision evidence; partial dedup refuses. Ranges are not commit acknowledgments.
/// Errors fail CLOSED. This is policy permission, never execution authorization.
#[tracing::instrument(skip_all)]
pub async fn decide_tx(
    tx: &Transaction<'_>,
    claims: &crate::auth::Claims,
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    request: &Request<'_>,
    legacy: Action,
    mode: Mode,
) -> Result<Option<(Verdict, AtomicBatchAppend)>> {
    if !enabled(resolved) {
        return Ok(None);
    }
    let Some(active) = protected_tx(tx, claims, resolved, request.server, request.tool).await?
    else {
        return Ok(None);
    };
    if !active.contract.protected {
        return Ok(None);
    }
    ensure!(request.decision_id != request.denial_id, "contract_invalid");
    let key =
        Uuid::parse_str(claims.api_key_id().context("unauthorized")?).context("unauthorized")?;
    let raw = std::str::from_utf8(request.args).context("contract_invalid")?;
    let args = bounded_json(raw)?;
    let typed = fields(&active.contract, &serde_json::from_str(&args)?)?;
    let version = active.policy.as_ref().map(|p| p.version);
    let principal_digest = request
        .principal
        .map(|p| canonical(p).map(|s| sha(s.as_bytes())))
        .transpose()?;
    let request_digest = intent_digest_bound(
        &claims.tenant_id,
        key,
        &active.contract,
        version,
        raw,
        principal_digest.as_deref(),
    )?;
    let (decision, rule_id) = evaluate_with_principal(
        active.policy.as_ref(),
        key,
        &typed,
        legacy,
        mode,
        request.principal,
    );
    let reason = match decision {
        Action::Allow => vec![],
        Action::RequireApproval => vec![ReasonCode::ApprovalRequired],
        Action::Deny => vec![ReasonCode::PolicyDenied],
    };
    let mut events = Vec::new();
    if let (Some(p), Some(hash)) = (&active.policy, active.hash) {
        events.push(ActionEvent {
            event_id: request.decision_id,
            action_id: request.action_id,
            occurred_at: Utc::now(),
            request_digest: request_digest.clone(),
            body: ActionPayload::DecisionMade {
                decision: match decision {
                    Action::Allow => Decision::Allow,
                    Action::Deny => Decision::Deny,
                    Action::RequireApproval => Decision::RequireApproval,
                },
                rule_id,
                reason_codes: reason,
                policy_id: p.policy_id,
                policy_version: p.version,
                policy_hash: hash,
            },
        });
    }
    if decision != Action::Allow {
        events.push(ActionEvent {
            event_id: request.denial_id,
            action_id: request.action_id,
            occurred_at: Utc::now(),
            request_digest: request_digest.clone(),
            body: ActionPayload::DeniedRuntime {
                reason: if decision == Action::RequireApproval {
                    ReasonCode::ApprovalRequired
                } else {
                    ReasonCode::PolicyDenied
                },
            },
        });
    }
    // An empty batch also returns None from the append; never let it pass as a replay.
    ensure!(!events.is_empty(), "evidence_unavailable");
    let evidence = match append_actions_tx(tx, claims, resolved, &events)
        .await
        .context("evidence_unavailable")?
    {
        Some(evidence) => evidence,
        // `enabled` was checked above, so None is a complete dedup: replay below.
        None => AtomicBatchAppend {
            first_seq: 0,
            prev_hash: [0; 32],
            row_hashes: Vec::new(),
            kept: Vec::new(),
            rows: Vec::new(),
        },
    };
    if evidence.kept.is_empty() && !events.is_empty() {
        // Full retries return the committed verdict; partial batches still fail closed.
        let ids: Vec<String> = events.iter().map(|e| e.event_id.to_string()).collect();
        let rows = tx.query("SELECT actor,payload::text FROM audit_log_rows WHERE tenant_id=$1 AND event_type IN ('decision_made','denied_runtime') AND payload::jsonb->>'event_id'=ANY($2)", &[claims.tenant_id.as_uuid(), &ids]).await?;
        ensure!(rows.len() == events.len(), "evidence_unavailable");
        let mut original = None;
        for row in rows {
            let payload: Value = serde_json::from_str(&row.get::<_, String>(1))?;
            ensure!(
                row.get::<_, String>(0) == key.to_string()
                    && payload["action_id"] == request.action_id.to_string()
                    && payload["request_digest"] == request_digest,
                "evidence_unavailable"
            );
            original = Some(match serde_json::from_value(payload["body"].clone())? {
                ActionPayload::DecisionMade {
                    decision: Decision::Allow,
                    ..
                } => Action::Allow,
                ActionPayload::DecisionMade {
                    decision: Decision::Deny,
                    ..
                }
                | ActionPayload::DeniedRuntime {
                    reason: ReasonCode::PolicyDenied,
                } => Action::Deny,
                ActionPayload::DecisionMade {
                    decision: Decision::RequireApproval,
                    ..
                }
                | ActionPayload::DeniedRuntime {
                    reason: ReasonCode::ApprovalRequired,
                } => Action::RequireApproval,
                _ => anyhow::bail!("evidence_unavailable"),
            });
        }
        return Ok(Some((
            Verdict {
                decision: original.context("evidence_unavailable")?,
                request_digest,
            },
            evidence,
        )));
    }
    ensure!(evidence.kept.len() == events.len(), "evidence_unavailable");
    Ok(Some((
        Verdict {
            decision,
            request_digest,
        },
        evidence,
    )))
}

/// B-640: the identity of an upstream MCP endpoint: lower-case host (trailing `.` trimmed) and
/// effective port. Scheme, path, query, fragment and userinfo are NOT part of it: one upstream
/// commonly serves the same tools on `/mcp` (streamable) and `/sse` (legacy), so a path-aware
/// identity let `/sse` reach a tool protected on `/mcp` (second review, H1). Residual (spec §5):
/// an IP literal or a second DNS name for the same host is a different identity.
pub(crate) fn upstream_identity(raw: &str) -> Option<String> {
    let url = reqwest::Url::parse(raw).ok()?;
    let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    let port = url.port_or_known_default()?;
    (!host.is_empty()).then(|| format!("{host}:{port}"))
}

/// B-640: does `server` CURRENTLY protect `tool`? A known tool: its latest contract version is
/// protected. An unknown tool, or `None`: the server has any currently protected tool.
async fn currently_protects_tx(
    tx: &Transaction<'_>,
    tenant: &Uuid,
    server: &Uuid,
    tool: Option<&str>,
) -> Result<bool> {
    Ok(tx
        .query_one(
            "WITH latest AS (SELECT DISTINCT ON (tool_name) tool_name, protected \
               FROM action_tool_contracts WHERE tenant_id=$1 AND server_id=$2 \
               ORDER BY tool_name, version DESC) \
             SELECT CASE WHEN EXISTS(SELECT 1 FROM latest WHERE tool_name=$3) \
                         THEN EXISTS(SELECT 1 FROM latest WHERE tool_name=$3 AND protected) \
                         ELSE EXISTS(SELECT 1 FROM latest WHERE protected) END",
            &[tenant, server, &tool],
        )
        .await?
        .get(0))
}

/// B-640: the latest contract version of exactly `tool` on `server` is protected. Used across
/// sibling registrations: an unknown tool there must not expand to "anything protected", or one
/// protected payments app would refuse every tool of an unrelated app on the same host.
async fn protects_exact_tool_tx(
    tx: &Transaction<'_>,
    tenant: &Uuid,
    server: &Uuid,
    tool: &str,
) -> Result<bool> {
    Ok(tx
        .query_opt(
            "SELECT protected FROM action_tool_contracts WHERE tenant_id=$1 AND server_id=$2 \
             AND tool_name=$3 ORDER BY version DESC LIMIT 1",
            &[tenant, server, &tool],
        )
        .await?
        .is_some_and(|r| r.get::<_, bool>(0)))
}

/// B-640 (audit H1): another live registration of the SAME upstream currently protects `tool`,
/// so calling it through this registration would skip decision, approval and evidence.
/// Checked at call time, so duplicates that predate the protection are covered. It takes no
/// lock: a call classified while an activation is still uncommitted sees the old state, the
/// same window the protected server's own path has between classify and dispatch.
pub(crate) async fn protected_elsewhere_tx(
    tx: &Transaction<'_>,
    claims: &crate::auth::Claims,
    server: Uuid,
    url: &str,
    tool: &str,
) -> Result<bool> {
    let tenant = claims.tenant_id.as_uuid();
    let Some(me) = upstream_identity(url) else {
        return Ok(true); // fail-CLOSED: identity unknown on a security path
    };
    let rows = tx
        .query(
            "SELECT id, url FROM mcp_servers WHERE tenant_id=$1 AND id<>$2 AND archived_at IS NULL",
            &[tenant, &server],
        )
        .await?;
    for row in rows {
        let (id, other): (Uuid, String) = (row.get(0), row.get(1));
        if upstream_identity(&other).as_deref() == Some(me.as_str())
            && protects_exact_tool_tx(tx, tenant, &id, tool).await?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// B-640 (second review, M2): the advisory lock `activate_tx` takes on a server, exclusive, so a
/// move or archive cannot interleave with an activation on the same server.
pub(crate) async fn lock_server_for_write_tx(
    tx: &Transaction<'_>,
    tenant: &tracelane_shared::TenantId,
    server: Uuid,
) -> Result<()> {
    let digest = ring::digest::digest(
        &ring::digest::SHA256,
        canonical(&(tenant.to_string(), server))?.as_bytes(),
    );
    let lock = i64::from_be_bytes(digest.as_ref()[..8].try_into()?);
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&lock])
        .await?;
    Ok(())
}

/// B-640 (audit H1): a server that currently protects any tool may not change which upstream
/// it points at, nor be archived, while that protection is active (moving it away would free
/// the URL for an unprotected registration).
pub(crate) async fn server_currently_protected_tx(
    tx: &Transaction<'_>,
    tenant: &Uuid,
    server: &Uuid,
) -> Result<bool> {
    currently_protects_tx(tx, tenant, server, None).await
}

/// Monotone count of immutable protected activations. Registered unprotected tools
/// are isolated from other tools; an unknown alias observes the whole server.
/// Caller holds only a short transaction, never a network request.
pub(crate) async fn legacy_epoch_tx(
    tx: &Transaction<'_>,
    claims: &crate::auth::Claims,
    server: Uuid,
    tool: &str,
) -> Result<i64> {
    server_lock(tx, claims, server, false).await?;
    Ok(tx.query_one("SELECT count(*) FROM action_policies p JOIN action_tool_contracts c ON c.tenant_id=p.tenant_id AND c.tool_ref=p.tool_ref AND c.version=p.contract_version WHERE c.tenant_id=$1 AND c.server_id=$2 AND c.protected AND (c.tool_name=$3 OR NOT EXISTS (SELECT 1 FROM action_tool_contracts known WHERE known.tenant_id=$1 AND known.server_id=$2 AND known.tool_name=$3))", &[claims.tenant_id.as_uuid(),&server,&tool]).await?.get(0))
}
