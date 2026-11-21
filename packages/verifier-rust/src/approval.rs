//! Tool/model approval records on the default (non-protected) approval path (ACT-40).
//!
//! One strict schema shared by the gateway writer and this offline verifier, so the two
//! cannot drift. A record is an ordinary row of the tenant's hash-chained, batch-signed
//! ledger; its event type is `tool_approval.<transition>`. It deliberately carries no
//! `schema_version` member, so action-evidence parsing never claims it.
//!
//! What the record holds: approval id, tenant, the keyed request fingerprint (never raw
//! arguments), subject kind and name, server and rule ids, the requester and the decider
//! as pseudonymous subject ids (the same form as the ledger `actor`, ADR-068), and times.
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Ledger event-type prefix. `tool_approval.requested`, `.approved`, ...
pub const EVENT_PREFIX: &str = "tool_approval.";
/// The ledger actor of a system expiry (sweep or inline).
pub const EXPIRY_ACTOR: &str = "system:approval-expiry";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    ToolApproval,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Transition {
    Requested,
    Approved,
    Denied,
    Consumed,
    Expired,
}
impl Transition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
        }
    }
    pub fn event_type(self) -> String {
        format!("{EVENT_PREFIX}{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub record: Kind,
    pub v: u32,
    pub tenant_id: Uuid,
    pub approval_id: Uuid,
    pub transition: Transition,
    pub occurred_at: DateTime<Utc>,
    /// Keyed, purpose-separated digest of the request (64 lowercase hex). Not recomputable
    /// offline without the workspace key; it binds every record of one approval together.
    pub request_fingerprint: String,
    pub requester: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_creator: Option<String>,
    pub subject_kind: String,
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<Uuid>,
    /// Present only on `approved` and `denied`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    /// `requested`: when the pending request lapses. `approved`: when the grant lapses.
    /// Absent on every other transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

pub fn is_record(event_type: &str) -> bool {
    event_type.starts_with(EVENT_PREFIX)
}

fn identity(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
}

impl Record {
    /// Shape rules both sides enforce. Errors fail CLOSED.
    pub fn validate(&self) -> Result<()> {
        ensure!(self.v == 1, "unsupported approval record version");
        ensure!(
            self.request_fingerprint.len() == 64
                && self
                    .request_fingerprint
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "invalid approval fingerprint"
        );
        ensure!(
            identity(&self.requester)
                && self.requester_creator.as_deref().is_none_or(identity)
                && self.decided_by.as_deref().is_none_or(identity),
            "invalid approval identity"
        );
        ensure!(
            matches!(self.subject_kind.as_str(), "tool" | "model")
                && !self.subject.is_empty()
                && self.subject.len() <= 512
                && !self.subject.chars().any(char::is_control),
            "invalid approval subject"
        );
        let decided = matches!(self.transition, Transition::Approved | Transition::Denied);
        ensure!(
            self.decided_by.is_some() == decided,
            "decider present iff approved or denied"
        );
        let expiring = matches!(
            self.transition,
            Transition::Requested | Transition::Approved
        );
        ensure!(
            self.expires_at.is_some() == expiring
                && self.expires_at.is_none_or(|e| e > self.occurred_at),
            "invalid approval expiry"
        );
        Ok(())
    }
    /// The ledger `actor` this record must carry.
    pub fn expected_actor(&self) -> &str {
        match self.transition {
            Transition::Requested | Transition::Consumed => &self.requester,
            Transition::Approved | Transition::Denied => {
                self.decided_by.as_deref().unwrap_or_default()
            }
            Transition::Expired => EXPIRY_ACTOR,
        }
    }
    /// Parse one ledger row. Errors fail CLOSED.
    pub fn from_row(tenant: Uuid, event_type: &str, actor: &str, payload: &str) -> Result<Self> {
        ensure!(
            crate::action::canonical_json(payload)? == payload,
            "approval payload not original JCS"
        );
        let r: Record = serde_json::from_str(payload).context("invalid approval record")?;
        r.validate()?;
        ensure!(
            r.tenant_id == tenant
                && r.transition.event_type() == event_type
                && r.expected_actor() == actor,
            "approval record identity mismatch"
        );
        Ok(r)
    }
}

#[derive(Default, Debug, Serialize, PartialEq, Eq)]
pub struct Semantics {
    pub requested: u64,
    pub approved: u64,
    pub denied: u64,
    pub consumed: u64,
    pub expired: u64,
    /// Decisions made by the requester or the human who minted the requesting key. Allowed
    /// unless the workspace requires a second approver; reported so an auditor sees them.
    pub self_decided: u64,
    /// Approvals still pending or approved-unconsumed at the end of the range.
    pub open: u64,
}

struct State<'a> {
    first: &'a Record,
    status: Transition,
    pending_until: DateTime<Utc>,
    grant_until: Option<DateTime<Utc>>,
    last: DateTime<Utc>,
}

/// Replay every approval's lifecycle over a complete (genesis-first) range, in ledger order.
/// Errors fail CLOSED: a record that skips a state, repeats a terminal one, consumes twice,
/// decides after expiry, or changes the request it is bound to.
pub fn semantics(records: &[Record]) -> Result<Semantics> {
    use Transition::*;
    let mut out = Semantics::default();
    let mut states = BTreeMap::<Uuid, State<'_>>::new();
    for r in records {
        if r.transition == Requested {
            ensure!(
                !states.contains_key(&r.approval_id),
                "duplicate approval request"
            );
            states.insert(
                r.approval_id,
                State {
                    first: r,
                    status: Requested,
                    pending_until: r.expires_at.context("invalid approval expiry")?,
                    grant_until: None,
                    last: r.occurred_at,
                },
            );
            out.requested += 1;
            continue;
        }
        let s = states
            .get_mut(&r.approval_id)
            .context("approval reference outside range")?;
        let f = s.first;
        ensure!(
            r.request_fingerprint == f.request_fingerprint
                && r.requester == f.requester
                && r.requester_creator == f.requester_creator
                && r.subject_kind == f.subject_kind
                && r.subject == f.subject
                && r.server_id == f.server_id
                && r.rule_id == f.rule_id,
            "approval binding mismatch"
        );
        ensure!(r.occurred_at >= s.last, "approval time went backwards");
        s.last = r.occurred_at;
        match r.transition {
            Approved | Denied => {
                ensure!(
                    s.status == Requested && r.occurred_at < s.pending_until,
                    "decision on a request that is not pending"
                );
                let by = r.decided_by.as_deref();
                if by == Some(f.requester.as_str()) || by == f.requester_creator.as_deref() {
                    out.self_decided += 1;
                }
                if r.transition == Approved {
                    s.grant_until = r.expires_at;
                    out.approved += 1;
                } else {
                    out.denied += 1;
                }
            }
            Consumed => {
                ensure!(
                    s.status == Approved && s.grant_until.is_some_and(|g| r.occurred_at < g),
                    "approval not approved, expired or already consumed"
                );
                out.consumed += 1;
            }
            Expired => {
                let lapsed = match s.status {
                    Requested => r.occurred_at >= s.pending_until,
                    Approved => s.grant_until.is_some_and(|g| r.occurred_at >= g),
                    _ => false,
                };
                ensure!(lapsed, "expiry of a live or finished approval");
                out.expired += 1;
            }
            Requested => bail!("unreachable"),
        }
        s.status = r.transition;
    }
    out.open = states
        .values()
        .filter(|s| matches!(s.status, Requested | Approved))
        .count() as u64;
    Ok(out)
}

#[cfg(test)]
mod tests;
