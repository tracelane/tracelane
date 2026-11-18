//! ACT-15 agent authority register: one read-only answer to "what may each agent key do".
//! Every statement is bound to the tenant taken from validated claims. Credential columns
//! (`lookup_hash`, `argon2id_phc`, `key_hash`) are never named, so they cannot be returned.
use super::{ActionPayload, canonical, canonical_json, db_now, policy::Policy, sha};
use crate::db::ledger::decode_hash_hex;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tokio_postgres::{Row, Transaction};
use tracelane_shared::TenantId;
use uuid::Uuid;

/// Separation rules enforced by `approvals/protected.rs` `separation_required`; constants, not config.
const SEPARATION: [&str; 2] = ["approver != key minter", "approver != policy publisher"];

const TOOLS_SQL: &str = "SELECT a.tool_ref, c.server_id, c.tool_name, a.policy_id, a.version, \
    p.policy_hash, p.publisher_sub, p.body_jcs, s.slug \
    FROM action_policy_active a \
    JOIN action_policies p ON p.tenant_id=a.tenant_id AND p.policy_id=a.policy_id \
        AND p.version=a.version AND p.tool_ref=a.tool_ref \
    JOIN action_tool_contracts c ON c.tenant_id=p.tenant_id AND c.tool_ref=p.tool_ref \
        AND c.version=p.contract_version \
    LEFT JOIN mcp_servers s ON s.tenant_id=c.tenant_id AND s.id=c.server_id AND s.archived_at IS NULL \
    WHERE a.tenant_id=$1 AND c.protected ORDER BY c.tool_name, a.tool_ref";

// Configured (enabled or not) servers with no CURRENTLY protected tool: a tool's newest contract
// decides, so a server whose tools were downgraded is observed-only. Flag off: nothing is protected.
const OBSERVED_SQL: &str = "SELECT s.id, s.slug FROM mcp_servers s \
    WHERE s.tenant_id=$1 AND s.archived_at IS NULL AND ($2::bool = false OR NOT EXISTS \
        (SELECT 1 FROM action_tool_contracts c WHERE c.tenant_id=s.tenant_id \
         AND c.server_id=s.id AND c.protected AND c.version=(SELECT max(m.version) \
         FROM action_tool_contracts m WHERE m.tenant_id=c.tenant_id AND m.tool_ref=c.tool_ref))) \
    ORDER BY s.slug, s.id";

// Tools whose NEWEST contract is protected=false (never protected, or downgraded). They still run
// on the ungated legacy path, so the register must say so.
const UNPROTECTED_SQL: &str = "SELECT c.tool_ref, c.server_id, s.slug, c.tool_name, c.version \
    FROM action_tool_contracts c \
    LEFT JOIN mcp_servers s ON s.tenant_id=c.tenant_id AND s.id=c.server_id AND s.archived_at IS NULL \
    WHERE c.tenant_id=$1 AND NOT c.protected AND c.version=(SELECT max(m.version) \
        FROM action_tool_contracts m WHERE m.tenant_id=c.tenant_id AND m.tool_ref=c.tool_ref) \
    ORDER BY c.tool_name, c.tool_ref";

// Columns are named explicitly: no `SELECT *`, no `to_jsonb(row)` on `api_keys`.
const AGENTS_SQL: &str = "SELECT id, name, key_prefix, minted_by, created_at, expires_at, \
    last_used_at, scope, budget_usd_monthly::text, rate_limit_rpm \
    FROM api_keys WHERE tenant_id=$1 AND (revoked_at IS NULL OR revoked_at > $2) \
    AND ($4::timestamptz IS NULL OR (created_at <= $4 AND (expires_at IS NULL OR expires_at > $4))) \
    ORDER BY created_at, id LIMIT $3";

// ACT-15b: the ledger, not the mutable pointer, says what was active at T. Rows arrive in `seq`
// order, so the last one per `tool_ref` wins (ties and clock skew resolve by `seq`, never by time).
// The register is the policy-activation chain prefix up to S = the greatest `seq` of a
// `policy_activated` row with `event_time <= T`; it never scans other event types (0091 index).
const LEDGER_SQL: &str = "SELECT payload, actor, prev_hash, row_hash, seq FROM audit_log_rows WHERE tenant_id=$1 \
    AND event_type='policy_activated' AND seq <= $2 ORDER BY seq";
const SEQ_SQL: &str = "SELECT max(seq) FROM audit_log_rows WHERE tenant_id=$1 \
    AND event_type='policy_activated' AND event_time <= $2";
// Same columns as TOOLS_SQL (so `entry` reads both), joined by the ledger's (policy, contract) ids.
const AS_OF_SQL: &str = "SELECT p.tool_ref, c.server_id, c.tool_name, p.policy_id, p.version, \
    p.policy_hash, p.publisher_sub, p.body_jcs, s.slug, c.contract_hash, c.body_jcs, c.protected FROM action_policies p \
    JOIN action_tool_contracts c ON c.tenant_id=p.tenant_id AND c.tool_ref=p.tool_ref \
        AND c.version=p.contract_version \
    LEFT JOIN mcp_servers s ON s.tenant_id=c.tenant_id AND s.id=c.server_id \
        AND (s.archived_at IS NULL OR s.archived_at > $6) \
    WHERE p.tenant_id=$1 AND p.policy_id=$2 AND p.version=$3 AND p.tool_ref=$4 \
        AND p.contract_version=$5";
const SERVERS_SQL: &str = "SELECT id, slug FROM mcp_servers WHERE tenant_id=$1 \
    AND created_at <= $2 AND (archived_at IS NULL OR archived_at > $2) ORDER BY slug, id";

/// `as_of` is in the future or too recent; the route maps the code to a 400.
#[derive(Debug, thiserror::Error)]
#[error("as_of rejected: {0}")]
pub struct AsOfRejected(pub &'static str);

/// Tool-side state at T: (protected tools, their agent lists, unprotected, observed servers, max seq).
type AsOf = (
    Vec<(Uuid, Value)>,
    Vec<Option<Vec<Uuid>>>,
    Vec<Value>,
    Vec<Value>,
    Option<i64>,
);

/// One protected-tool entry from a TOOLS_SQL / AS_OF_SQL row. A body that does not match its
/// hash is not evidence (same check as `load_tx`).
fn entry(r: &Row) -> Result<(Value, Option<Vec<Uuid>>)> {
    let body: String = r.get(7);
    anyhow::ensure!(
        sha(canonical_json(&body)?.as_bytes()) == r.get::<_, String>(5),
        "stored policy hash mismatch"
    );
    let policy: Policy = serde_json::from_str(&body).context("stored policy unparsable")?;
    let rules: Vec<Value> = policy
        .rules
        .iter()
        .map(|x| json!({"id": x.id, "decision": x.decision}))
        .collect();
    let agents = policy.agents.as_ref().map_or(json!("all"), |a| json!(a));
    Ok((
        json!({"tool_ref": r.get::<_, Uuid>(0), "server_id": r.get::<_, Uuid>(1),
            "server_slug": r.get::<_, Option<String>>(8), "tool_name": r.get::<_, String>(2),
            "policy_id": r.get::<_, Uuid>(3), "policy_version": r.get::<_, i32>(4),
            "policy_hash": r.get::<_, String>(5), "publisher_sub": r.get::<_, String>(6),
            "rules": rules, "default": "deny", "agents": agents}),
        policy.agents,
    ))
}

/// Reports what the ledger recorded even if the flag is off today (spec edge 6). Fail-CLOSED:
/// an unparsable or foreign ledger row, a missing body or any policy/contract mismatch aborts.
/// Entries are ordered by `tool_ref` (deterministic; restoring tool_name order cost >5 lines).
async fn as_of_state(tx: &Transaction<'_>, tenant: &TenantId, at: DateTime<Utc>) -> Result<AsOf> {
    let t = tenant.as_uuid();
    let seq: Option<i64> = tx.query_one(SEQ_SQL, &[t, &at]).await?.get(0);
    let mut active = BTreeMap::new();
    for r in tx.query(LEDGER_SQL, &[t, &seq.unwrap_or(-1)]).await? {
        let mut v: Value = serde_json::from_str(r.get(0)).context("ledger payload unparsable")?;
        // The same function the ledger writer and offline verifier use.
        let (prev, seq) = (decode_hash_hex(r.get(2))?, r.get::<_, i64>(4));
        let hash = crate::audit_format::row_hash_v2(
            &prev,
            tenant,
            u64::try_from(seq)?,
            "policy_activated",
            r.get(1),
            r.get(0),
        );
        anyhow::ensure!(
            hash == decode_hash_hex(r.get(3))?,
            "ledger row hash mismatch"
        );
        anyhow::ensure!(
            v.get("tenant_id") == Some(&json!(t.to_string())),
            "ledger row names another tenant"
        );
        let body = v
            .get_mut("body")
            .map(Value::take)
            .context("ledger payload has no body")?;
        let ActionPayload::PolicyActivated {
            policy_id,
            version,
            policy_hash,
            tool_ref,
            contract_version,
            contract_hash,
            protected,
            ..
        } = serde_json::from_value(body).context("ledger payload unparsable")?
        else {
            anyhow::bail!("ledger event is not policy_activated");
        };
        active.insert(
            tool_ref,
            (
                policy_id,
                version,
                policy_hash,
                contract_version,
                contract_hash,
                protected,
            ),
        );
    }
    let (mut tools, mut agents, mut unprotected, mut held) = (vec![], vec![], vec![], vec![]);
    for (tool_ref, (policy_id, version, hash, cv, chash, protected)) in active {
        let p: [&(dyn tokio_postgres::types::ToSql + Sync); 6] = [
            t,
            &policy_id,
            &i32::try_from(version)?,
            &tool_ref,
            &i32::try_from(cv)?,
            &at,
        ];
        let r = tx
            .query_opt(AS_OF_SQL, &p)
            .await?
            .context("ledger policy body missing")?;
        let (e, a) = entry(&r)?;
        let cbody: String = r.get(10);
        anyhow::ensure!(r.get::<_, String>(5) == hash, "ledger policy hash mismatch");
        anyhow::ensure!(
            sha(canonical_json(&cbody)?.as_bytes()) == chash && r.get::<_, String>(9) == chash,
            "contract hash mismatch"
        );
        anyhow::ensure!(
            r.get::<_, bool>(11) == protected,
            "contract protection mismatch"
        );
        if protected {
            held.push(r.get::<_, Uuid>(1));
            tools.push((tool_ref, e));
            agents.push(a);
        } else {
            unprotected.push(
                json!({"tool_ref": tool_ref, "server_id": r.get::<_, Uuid>(1),
                "server_slug": r.get::<_, Option<String>>(8), "tool_name": r.get::<_, String>(2),
                "contract_version": cv}),
            );
        }
    }
    let observed = tx
        .query(SERVERS_SQL, &[t, &at])
        .await?
        .iter()
        .filter(|r| !held.contains(&r.get::<_, Uuid>(0)))
        .map(|r| json!({"server_id": r.get::<_, Uuid>(0), "server_slug": r.get::<_, String>(1)}))
        .collect();
    Ok((tools, agents, unprotected, observed, seq))
}

/// With `as_of`, `as_of_seq` is the reproducible key: the register is a pure function of the
/// activation chain prefix up to it (plus key lifecycle), so re-ask by comparing `as_of_seq`.
/// Build the register for `tenant`. `action_control` is the resolved entitlement (absent cache = off).
///
/// # Errors
/// Fail-CLOSED: any query or parse failure aborts; the route maps it to 503 `register_unavailable`.
#[tracing::instrument(skip_all, fields(tenant_id = %tenant))]
pub async fn register(
    pool: &deadpool_postgres::Pool,
    tenant: &TenantId,
    action_control: bool,
    as_of: Option<DateTime<Utc>>,
) -> Result<Value> {
    let max_agents = crate::mcp_policy::settings()?.approvals.max_list_page_size;
    let mut client = pool.get().await?;
    // One snapshot so tools, agents and the clock agree.
    let tx = client
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await?;
    let t = tenant.as_uuid();
    let timeout = std::time::Duration::from_secs(
        crate::mcp_policy::settings()?
            .approvals
            .register_read_timeout_secs,
    );
    super::execution::deadline_tx(&tx, timeout).await?;
    let now = db_now(&tx).await?;
    let min_age = chrono::Duration::seconds(
        crate::mcp_policy::settings()?
            .approvals
            .register_as_of_min_age_secs,
    );
    match as_of {
        Some(a) if a > now => return Err(AsOfRejected("as_of_in_future").into()),
        Some(a) if a > now - min_age => return Err(AsOfRejected("as_of_too_recent").into()),
        _ => {}
    }
    let hist = match as_of {
        Some(a) => Some(as_of_state(&tx, tenant, a).await?),
        None => None,
    };
    let paused_at: Option<chrono::DateTime<chrono::Utc>> = tx
        .query_opt(
            "SELECT paused_at FROM workspace_controls WHERE tenant_id=$1",
            &[t],
        )
        .await?
        .and_then(|r| r.get(0));

    let mut tools: Vec<(Uuid, Value)> = Vec::new(); // (tool_ref, entry) in tool order
    let mut all_agents: Vec<Option<Vec<Uuid>>> = Vec::new(); // parallel to `tools`
    if action_control && hist.is_none() {
        for r in tx.query(TOOLS_SQL, &[t]).await? {
            let (e, agents) = entry(&r)?;
            tools.push((r.get(0), e));
            all_agents.push(agents);
        }
    }
    let mut unprotected: Vec<Value> = if action_control && hist.is_none() {
        tx.query(UNPROTECTED_SQL, &[t])
            .await?
            .iter()
            .map(|r| {
                json!({"tool_ref": r.get::<_, Uuid>(0), "server_id": r.get::<_, Uuid>(1),
                    "server_slug": r.get::<_, Option<String>>(2), "tool_name": r.get::<_, String>(3),
                    "contract_version": r.get::<_, i32>(4)})
            })
            .collect()
    } else {
        Vec::new()
    };
    let mut observed: Vec<Value> = if hist.is_none() {
        tx.query(OBSERVED_SQL, &[t, &action_control])
            .await?
            .iter()
            .map(
                |r| json!({"server_id": r.get::<_, Uuid>(0), "server_slug": r.get::<_, String>(1)}),
            )
            .collect()
    } else {
        Vec::new()
    };
    let mut as_of_seq = None;
    if let Some(h) = hist {
        (tools, all_agents, unprotected, observed, as_of_seq) = h;
    }

    let limit = i64::try_from(max_agents)?
        .checked_add(1)
        .context("agent cap overflow")?;
    let rows = tx
        .query(AGENTS_SQL, &[t, &as_of.unwrap_or(now), &limit, &as_of])
        .await?;
    let truncated = rows.len() > max_agents;
    // `last_used_at` moves with traffic, so it is attached after hashing (like `generated_at`).
    let last_used: Vec<Option<chrono::DateTime<chrono::Utc>>> =
        rows.iter().take(max_agents).map(|r| r.get(6)).collect();
    let agents: Vec<Value> = rows
        .iter()
        .take(max_agents)
        .map(|r| {
            let key_id: Uuid = r.get(0);
            // UPPER BOUND, not a permission inventory: the tools whose active policy names this key
            // (or all keys). Expiry, key scope, rule outcomes, legacy rules, a disabled server, pause,
            // budget and rate limit can each still refuse a call (ACT-15 spec §2a). Flag off: unknown,
            // not "none". As of T they come from the ledger's tools, whatever today's flag says (the
            // flag is in `current`, outside the digest).
            let permitted = (action_control || as_of.is_some()).then(|| tools
                .iter()
                .zip(&all_agents)
                .filter(|(_, a)| a.as_ref().is_none_or(|ids| ids.contains(&key_id)))
                .map(|((tool_ref, _), _)| *tool_ref)
                .collect::<Vec<Uuid>>());
            json!({"key_id": key_id, "name": r.get::<_, String>(1), "key_prefix": r.get::<_, String>(2),
                "minted_by": r.get::<_, Option<String>>(3), "created_at": r.get::<_, chrono::DateTime<chrono::Utc>>(4),
                "expires_at": r.get::<_, Option<chrono::DateTime<chrono::Utc>>>(5),
                "scope": r.get::<_, Option<Vec<String>>>(7), "budget_usd_monthly": r.get::<_, Option<String>>(8),
                "rate_limit_rpm": r.get::<_, Option<i32>>(9), "protected_tools_in_policy_scope": permitted})
        })
        .collect();
    tx.commit().await?;

    let mut doc = json!({
        "workspace": {"tenant_id": t, "paused_at": paused_at, "action_control": action_control},
        "protected_tools": tools.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
        "unprotected_tools": unprotected,
        "observed_only_servers": observed,
        "agents": agents,
        "agents_truncated": truncated,
        "approval": {"capability": "approve_tool_calls", "separation": SEPARATION},
    });
    // Values with no history are not part of an as-of register: they move to `current`, which
    // sits outside the digest (like `generated_at`). Key attributes stay, labelled "current".
    let mut slugs = serde_json::Map::new();
    if let Some(a) = as_of {
        doc["as_of"] = json!(a);
        doc["as_of_seq"] = json!(as_of_seq);
        doc["key_attributes"] = json!("current");
        doc["enforcement_at_as_of"] = json!("not_recorded");
        // Key lifecycle is not in the ledger: membership uses today's (editable) `expires_at`.
        doc["key_membership"] = json!("current_expires_at");
        doc["workspace"] = json!({"tenant_id": t});
        for k in [
            "protected_tools",
            "unprotected_tools",
            "observed_only_servers",
        ] {
            for e in doc[k].as_array_mut().into_iter().flatten() {
                if let Some(s) = e.as_object_mut().and_then(|o| o.remove("server_slug")) {
                    slugs.insert(e["server_id"].as_str().context("server id")?.to_owned(), s);
                }
            }
        }
    }
    // The digest covers the state, not the read time: equal state gives an equal digest.
    let digest = sha(canonical(&doc)?.as_bytes());
    doc["generated_at"] = json!(now);
    let mut used_at = serde_json::Map::new();
    for (a, used) in doc["agents"]
        .as_array_mut()
        .into_iter()
        .flatten()
        .zip(last_used)
    {
        if as_of.is_some() {
            used_at.insert(
                a["key_id"].as_str().context("key id")?.to_owned(),
                json!(used),
            );
        } else {
            a["last_used_at"] = json!(used);
        }
    }
    if as_of.is_some() {
        doc["current"] = json!({"paused_at": paused_at, "action_control": action_control,
            "server_slugs": slugs, "last_used_at": used_at});
    }
    doc["register_digest"] = json!(digest);
    Ok(doc)
}
