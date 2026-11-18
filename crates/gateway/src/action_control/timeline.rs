//! Read API for protected actions (ACT-10a): list, per-action timeline, approval descriptor.
//! Reads the canonical `audit_log_rows`; every query binds the tenant of the validated claims.
//! Refusals are `(status, code)` from a closed vocabulary; anything unlisted fails CLOSED as 503.
use super::{ActionPayload, Decision, EvidenceField, ReasonCode};
use crate::{control_plane::ControlActor, server::AppState};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use tracelane_audit_verifier::action::Envelope;
use uuid::Uuid;

pub type Refusal = (u16, &'static str);
const UNAVAILABLE: Refusal = (503, "evidence_unavailable");
const BAD_REQUEST: Refusal = (400, "invalid_request");
const NOT_FOUND: Refusal = (404, "action_not_found");

fn unavailable<E>(_: E) -> Refusal {
    UNAVAILABLE
}
// The literal list must equal the partial-index predicate of migration 0090 or the planner
// cannot use the index; `concat!` keeps it one static string (no runtime SQL building).
macro_rules! action_types {
    () => {
        "'action_proposed','decision_made','approval_requested','approval_granted','approval_denied','approval_attempt_rejected','approval_consumed','approval_expired','approval_invalidated','legacy_forward_attempted','execution_started','execution_succeeded','execution_failed','execution_unknown','denied_runtime','policy_activated'"
    };
}
/// Action heads: every proposal, plus a runtime denial that has no proposal of its own.
// The events that can change an action's state: every action type except rejected attempts
// (any gate-denied caller can append those) and legacy forwards. A subset of the index predicate.
macro_rules! state_types {
    () => {
        "'action_proposed','decision_made','approval_requested','approval_granted','approval_denied','approval_consumed','approval_expired','approval_invalidated','execution_started','execution_succeeded','execution_failed','execution_unknown','denied_runtime','policy_activated'"
    };
}
pub(crate) const HEADS_SQL: &str = "SELECT r.seq,r.payload FROM audit_log_rows r WHERE r.tenant_id=$1 AND r.event_type IN ('action_proposed','denied_runtime') AND ($2::bigint IS NULL OR r.seq<$2) AND (r.event_type='action_proposed' OR NOT EXISTS (SELECT 1 FROM audit_log_rows p WHERE p.tenant_id=r.tenant_id AND p.event_type='action_proposed' AND (p.payload::jsonb)->>'action_id'=(r.payload::jsonb)->>'action_id')) ORDER BY r.seq DESC LIMIT $3";
pub(crate) const PAGE_EVENTS_SQL: &str = concat!(
    "SELECT seq,payload,(payload::jsonb)->>'action_id' FROM audit_log_rows WHERE tenant_id=$1 AND (payload::jsonb)->>'action_id'=ANY($2) AND event_type IN (",
    state_types!(),
    ") ORDER BY seq"
);
pub(crate) const DETAIL_SQL: &str = concat!(
    "SELECT seq,event_type,actor,payload,row_hash,signature FROM audit_log_rows WHERE tenant_id=$1 AND (payload::jsonb)->>'action_id'=$2 AND event_type IN (",
    action_types!(),
    ") ORDER BY seq DESC LIMIT $3"
);
macro_rules! approval_cols {
    () => {
        "SELECT id,status,expires_at,subject,server_id,tool_ref,contract_version,policy_id,policy_version,policy_hash,proposer_key_id,request_digest,args_preview FROM approvals WHERE tenant_id=$1 AND action_id IS NOT NULL AND "
    };
}
const APPROVAL_BY_ACTION: &str = concat!(approval_cols!(), "action_id=$2");
const APPROVAL_BY_ID: &str = concat!(approval_cols!(), "id=$2");

/// Status of an action, from its last state-changing event. Pure.
pub(crate) fn action_state<'a>(
    bodies: impl DoubleEndedIterator<Item = &'a ActionPayload>,
) -> &'static str {
    use ActionPayload::*;
    bodies
        .rev()
        .find_map(|b| match b {
            ExecutionSucceeded { .. } => Some("executed"),
            ExecutionFailed { .. } => Some("failed"),
            ExecutionUnknown { .. } => Some("needs_review"),
            ExecutionStarted { .. } | ApprovalGranted { .. } | ApprovalConsumed { .. } => {
                Some("approved")
            }
            ApprovalDenied { .. } => Some("denied"),
            ApprovalExpired { .. } => Some("expired"),
            ApprovalInvalidated { .. } => Some("invalidated"),
            ApprovalRequested { .. } => Some("awaiting_approval"),
            DecisionMade { decision, .. } => Some(match decision {
                Decision::Allow => "approved",
                Decision::Deny => "blocked",
                Decision::RequireApproval => "awaiting_approval",
            }),
            DeniedRuntime { reason } => Some(match reason {
                ReasonCode::WorkspacePaused => "refused_paused",
                ReasonCode::ApprovalRequired => "awaiting_approval",
                _ => "blocked",
            }),
            // Rejected attempts, legacy forwards, activations and a bare proposal decide nothing.
            _ => None,
        })
        // No decision recorded is never "executed"; a person should look.
        .unwrap_or("needs_review")
}
fn actor_kind(actor: &str) -> &'static str {
    if actor == "human" {
        "human"
    } else if Uuid::parse_str(actor).is_ok() {
        "agent_key"
    } else {
        "system"
    }
}
fn envelope(payload: &str) -> Option<Envelope> {
    serde_json::from_str(payload).ok()
}
fn page_limit(raw: Option<&String>) -> Result<usize, Refusal> {
    let l = &crate::mcp_policy::settings()
        .map_err(unavailable)?
        .approvals;
    let asked = match raw {
        None => l.list_page_size,
        Some(s) => s.parse::<usize>().map_err(|_| BAD_REQUEST)?,
    };
    Ok(asked.clamp(1, l.max_list_page_size))
}

/// `GET /v1/actions` (no id) or `/v1/actions/{action_id}`.
///
/// # Errors
/// Fail-CLOSED: the flag, the control plane and every parse refuse before any data returns.
#[tracing::instrument(skip_all, fields(tenant_id=%actor.tenant_id))]
pub async fn read(
    state: &AppState,
    actor: &ControlActor,
    action_id: Option<&str>,
    query: &HashMap<String, String>,
) -> Result<Value, Refusal> {
    let pool = state.pg.as_ref().ok_or(UNAVAILABLE)?;
    let cache = state.entitlements.as_ref().ok_or(UNAVAILABLE)?;
    let tenant = actor.tenant_id.as_uuid();
    if !super::enabled(Some(&*cache.resolved(*tenant).await)) {
        return Err((409, "action_control_disabled"));
    }
    let db = pool.get().await.map_err(unavailable)?;
    match action_id {
        None => list(&db, tenant, query).await,
        Some(raw) => detail(&db, tenant, Uuid::parse_str(raw).map_err(|_| NOT_FOUND)?).await,
    }
}

async fn list(
    db: &tokio_postgres::Client,
    tenant: &Uuid,
    query: &HashMap<String, String>,
) -> Result<Value, Refusal> {
    let limit = page_limit(query.get("limit"))?;
    let before = match query.get("before") {
        None => None,
        Some(s) => Some(
            s.parse::<i64>()
                .ok()
                .filter(|n| *n >= 0)
                .ok_or(BAD_REQUEST)?,
        ),
    };
    let fetch = i64::try_from(limit + 1).map_err(unavailable)?;
    let mut heads = db
        .query(HEADS_SQL, &[tenant, &before, &fetch])
        .await
        .map_err(unavailable)?;
    let next_before = (heads.len() > limit).then(|| heads[limit - 1].get::<_, i64>(0));
    heads.truncate(limit);
    let mut skipped = 0_u32;
    let envs: Vec<Envelope> = heads
        .iter()
        .filter_map(|r| {
            let e = envelope(&r.get::<_, String>(1));
            skipped += u32::from(e.is_none());
            e
        })
        .collect();
    let ids: Vec<String> = envs.iter().map(|e| e.action_id.to_string()).collect();
    let mut bodies: HashMap<Uuid, Vec<ActionPayload>> = HashMap::new();
    // An action with an unreadable state event must not show a state derived without it.
    let mut malformed: HashSet<Uuid> = HashSet::new();
    for r in db
        .query(PAGE_EVENTS_SQL, &[tenant, &ids])
        .await
        .map_err(unavailable)?
    {
        match envelope(&r.get::<_, String>(1)) {
            Some(e) => bodies.entry(e.action_id).or_default().push(e.body),
            None => {
                skipped += 1;
                malformed.extend(
                    r.get::<_, Option<String>>(2)
                        .and_then(|s| s.parse::<Uuid>().ok()),
                );
            }
        }
    }
    let refs: Vec<Uuid> = envs
        .iter()
        .filter_map(|e| match e.body {
            ActionPayload::ActionProposed { tool_ref, .. } => Some(tool_ref),
            _ => None,
        })
        .collect();
    let mut names: HashMap<(Uuid, i32), String> = HashMap::new();
    for r in db
        .query(
            "SELECT tool_ref,version,tool_name FROM action_tool_contracts WHERE tenant_id=$1 AND tool_ref=ANY($2)",
            &[tenant, &refs],
        )
        .await
        .map_err(unavailable)?
    {
        names.insert((r.get(0), r.get(1)), r.get(2));
    }
    if skipped > 0 {
        tracing::warn!(skipped, "malformed historical action rows skipped in list");
    }
    let actions: Vec<Value> = envs
        .iter()
        .map(|e| {
            let bad = malformed.contains(&e.action_id);
            let state = if bad {
                "needs_review"
            } else {
                action_state(bodies.get(&e.action_id).into_iter().flatten())
            };
            let at = e.occurred_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            let mut item = match &e.body {
                ActionPayload::ActionProposed {
                    tool_ref,
                    contract_version,
                    evidence_fields,
                    ..
                } => json!({"action_id":e.action_id,"occurred_at":at,"state":state,
                    "tool_ref":tool_ref,"evidence":evidence_fields,
                    "tool_name":i32::try_from(*contract_version).ok().and_then(|v| names.get(&(*tool_ref, v)))}),
                // A runtime denial with no proposal carries no tool: never guessed.
                _ => json!({"action_id":e.action_id,"occurred_at":at,"state":state,
                    "tool_ref":null,"tool_name":null,"evidence":{}}),
            };
            if bad {
                item["malformed"] = json!(true);
            }
            item
        })
        .collect();
    let mut out = json!({"actions":actions});
    if let Some(n) = next_before {
        out["next_before"] = json!(n);
    }
    if skipped > 0 {
        out["skipped_malformed"] = json!(skipped);
    }
    Ok(out)
}

async fn detail(db: &tokio_postgres::Client, tenant: &Uuid, id: Uuid) -> Result<Value, Refusal> {
    let max = crate::mcp_policy::settings()
        .map_err(unavailable)?
        .approvals
        .max_list_page_size;
    let mut rows = db
        .query(
            DETAIL_SQL,
            &[
                tenant,
                &id.to_string(),
                &i64::try_from(max + 1).map_err(unavailable)?,
            ],
        )
        .await
        .map_err(unavailable)?;
    if rows.is_empty() {
        return Err(NOT_FOUND);
    }
    // Newest first from SQL: past the cap the OLDEST events drop, so a later outcome is never cut.
    let truncated = rows.len() > max;
    rows.truncate(max);
    rows.reverse();
    let mut events = Vec::with_capacity(rows.len());
    for r in &rows {
        // A malformed historical payload fails the whole read: never a partial timeline.
        let env = envelope(&r.get::<_, String>(3)).ok_or(UNAVAILABLE)?;
        events.push(
            json!({"seq":r.get::<_, i64>(0),"event_type":r.get::<_, String>(1),
            "occurred_at":env.occurred_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "actor_kind":actor_kind(&r.get::<_, String>(2)),
            "body":serde_json::to_value(&env.body).map_err(unavailable)?,
            "row_hash":r.get::<_, String>(4),"signature_present":!r.get::<_, String>(5).is_empty()}),
        );
    }
    // State comes from the state-changing events alone, not from the (capped, paddable) list.
    let mut states = Vec::new();
    for r in db
        .query(PAGE_EVENTS_SQL, &[tenant, &vec![id.to_string()]])
        .await
        .map_err(unavailable)?
    {
        states.push(envelope(&r.get::<_, String>(1)).ok_or(UNAVAILABLE)?.body);
    }
    // Only an action has a timeline: an id that merely appears in some other event is not one.
    if !states.iter().any(|b| {
        matches!(
            b,
            ActionPayload::ActionProposed { .. } | ActionPayload::DeniedRuntime { .. }
        )
    }) {
        return Err(NOT_FOUND);
    }
    let mut out = json!({"action_id":id,"state":action_state(states.iter()),"events":events});
    if truncated {
        out["events_truncated"] = json!(true);
    }
    if let Some(row) = db
        .query_opt(APPROVAL_BY_ACTION, &[tenant, &id])
        .await
        .map_err(unavailable)?
    {
        match descriptor(&row)? {
            Some(d) => {
                out["descriptor_digest"] = json!(descriptor_digest(&d)?);
                out["approval"] = d;
            }
            // Retention clears the stored preview: the events stay readable, the descriptor is gone.
            None => {
                out["approval"] = json!({"approval_id":row.get::<_, Uuid>(0),
                    "status":row.get::<_, String>(1),"expires_at":expires_at(&row)});
                out["descriptor_digest"] = Value::Null;
                out["approval_expired"] = json!(true);
            }
        }
    }
    Ok(out)
}

fn expires_at(r: &tokio_postgres::Row) -> String {
    r.get::<_, chrono::DateTime<chrono::Utc>>(2)
        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}
#[derive(Deserialize)]
struct Preview {
    evidence_fields: BTreeMap<String, EvidenceField>,
}
/// The approval as the approver must decide it, built only from the bound row. Errors fail
/// CLOSED: unparsable stored evidence is an error; `None` only when retention cleared the preview.
fn descriptor(r: &tokio_postgres::Row) -> Result<Option<Value>, Refusal> {
    let Some(raw) = r.get::<_, Option<String>>(12) else {
        return Ok(None);
    };
    let preview: Preview = serde_json::from_str(&raw).map_err(unavailable)?;
    let at = expires_at(r);
    Ok(Some(
        json!({"approval_id":r.get::<_, Uuid>(0),"status":r.get::<_, String>(1),"expires_at":at,
        "tool_name":r.get::<_, String>(3),"server_id":r.get::<_, Uuid>(4),
        "tool_ref":r.get::<_, Uuid>(5),"contract_version":r.get::<_, i32>(6),
        "policy_id":r.get::<_, Uuid>(7),"policy_version":r.get::<_, i32>(8),
        "policy_hash":r.get::<_, String>(9),"proposer_key_id":r.get::<_, Uuid>(10),
        "request_digest":r.get::<_, String>(11),
        "evidence_fields":preview.evidence_fields}),
    ))
}
/// SHA-256 over the RFC 8785 bytes of the descriptor.
fn descriptor_digest(d: &Value) -> Result<String, Refusal> {
    Ok(super::sha(
        super::canonical(d).map_err(unavailable)?.as_bytes(),
    ))
}
/// Current descriptor digest of a protected approval, read on the caller's connection.
/// `Ok(None)` means there is no descriptor: no protected row, or retention cleared the preview.
///
/// # Errors
/// Fail-CLOSED: an unreadable or unparsable row is 503, never "no mismatch".
pub(crate) async fn approval_digest(
    db: &impl tokio_postgres::GenericClient,
    tenant: &Uuid,
    approval: Uuid,
) -> Result<Option<String>, Refusal> {
    match db
        .query_opt(APPROVAL_BY_ID, &[tenant, &approval])
        .await
        .map_err(unavailable)?
    {
        None => Ok(None),
        Some(row) => descriptor(&row)?.map(|d| descriptor_digest(&d)).transpose(),
    }
}
