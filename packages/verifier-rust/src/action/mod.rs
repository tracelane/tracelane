//! Strict action evidence schema shared by the writer and offline verifier.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;
mod canonical;
pub mod receipt;
pub mod replay;
pub use canonical::canonical_json;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum ClearValue {
    MinorUnits(u64),
    Currency(Usd),
    Boolean(bool),
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Usd {
    #[serde(rename = "USD")]
    Usd,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidenceField {
    Clear { value: ClearValue },
    Tokenize { hmac: String, last4: String },
    DigestOnly { sha256: String },
}
/// Minimized identity attested by the gateway, not an embedded IdP credential.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub iss: String,
    pub sub_digest: String,
    pub roles: Vec<String>,
}
impl Principal {
    /// Fail CLOSED on malformed signed identity evidence.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.iss.starts_with("https://") && !self.iss.chars().any(char::is_control),
            "invalid principal issuer"
        );
        anyhow::ensure!(
            self.sub_digest.len() == 64
                && self
                    .sub_digest
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "invalid principal digest"
        );
        anyhow::ensure!(
            self.roles.iter().all(|s| !s.is_empty()
                && s.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c)))
                && self.roles.windows(2).all(|w| w[0] < w[1]),
            "invalid principal roles"
        );
        Ok(())
    }
    pub fn matches_roles(&self, values: &serde_json::Value, exclude: bool) -> bool {
        let Some(values) = values.as_array() else {
            return false;
        };
        if !values.iter().all(|v| v.as_str().is_some()) {
            return false;
        }
        let intersects = values
            .iter()
            .any(|v| self.roles.iter().any(|r| Some(r.as_str()) == v.as_str()));
        if exclude { !intersects } else { intersects }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionPayload {
    ActionProposed {
        tool_ref: Uuid,
        contract_version: u32,
        args_digest: String,
        evidence_fields: BTreeMap<String, EvidenceField>,
        agent_claimed_labels: BTreeMap<String, EvidenceField>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        principal: Option<Principal>,
    },
    DecisionMade {
        decision: Decision,
        rule_id: String,
        reason_codes: Vec<ReasonCode>,
        policy_id: Uuid,
        policy_version: u32,
        policy_hash: String,
    },
    ApprovalRequested {
        approval_id: Uuid,
        required_role: String,
        expires_at: DateTime<Utc>,
    },
    ApprovalGranted {
        approval_id: Uuid,
        decider_digest: String,
        note_digest: String,
    },
    ApprovalDenied {
        approval_id: Uuid,
        decider_digest: String,
        note_digest: String,
    },
    ApprovalAttemptRejected {
        approval_id: Uuid,
        decider_digest: String,
        reason: ReasonCode,
    },
    ApprovalConsumed {
        approval_id: Uuid,
    },
    ApprovalExpired {
        approval_id: Uuid,
    },
    ApprovalInvalidated {
        approval_id: Uuid,
    },
    /// Forward attempted before protection activated; never a protected execution.
    LegacyForwardAttempted {
        server_id: Uuid,
        activation_epoch: i64,
    },
    ExecutionStarted {
        execution_id: Uuid,
        idempotency_key: Uuid,
        attestation_key_id: String,
        /// ACT-17: present only when a receipt key is registered for the tool server.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        receipt_expected: Option<receipt::Expected>,
    },
    ExecutionSucceeded {
        execution_id: Uuid,
        receipt_digest: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        countersignature: Option<receipt::Countersignature>,
    },
    ExecutionFailed {
        execution_id: Uuid,
        receipt_digest: String,
    },
    ExecutionUnknown {
        execution_id: Uuid,
        receipt_digest: Option<String>,
    },
    DeniedRuntime {
        reason: ReasonCode,
    },
    /// Binds the contract so a protection downgrade is ledger-visible.
    PolicyActivated {
        policy_id: Uuid,
        version: u32,
        policy_hash: String,
        publisher_digest: String,
        tool_ref: Uuid,
        contract_version: u32,
        contract_hash: String,
        protected: bool,
    },
    /// ACT-17: the Ed25519 key (hex) a tool server countersigns receipts with. The latest
    /// registration for a server applies to every execution that starts after it.
    ToolReceiptKeyRegistered {
        server_id: Uuid,
        receipt_key_id: String,
        public_key: String,
    },
}
/// Closed protocol vocabulary: raw customer strings cannot become reason codes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    PrincipalRequired,
    PrincipalInvalid,
    PrincipalUnverifiable,
    Limit,
    Unauthorized,
    WorkspacePaused,
    EvidenceUnavailable,
    PolicyDenied,
    ApprovalRequired,
    ApprovalExpired,
    ApprovalDenied,
    ApprovalMismatch,
    SeparationRequired,
    KeyRevoked,
    ContractInvalid,
    /// A protected call refused because the tool definition no longer matches its pin.
    ToolDefinitionChanged,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub schema_version: u32,
    pub event_id: Uuid,
    pub action_id: Uuid,
    pub tenant_id: Uuid,
    pub agent_key_id: Option<Uuid>,
    pub occurred_at: DateTime<Utc>,
    pub request_digest: String,
    pub body: ActionPayload,
}
#[derive(Default, Debug, Serialize)]
pub struct Semantics {
    pub principals: BTreeMap<Uuid, Principal>,
    pub unknown: Vec<Uuid>,
    pub denied: Vec<Uuid>,
    /// Decisions re-derived from the bundled policy and evidence (ACT-18).
    pub replayed: u64,
    /// Actions whose decision depends on an opaque (tokenized or digest-only) field.
    pub not_replayable: Vec<Uuid>,
    /// Successes whose tool signature verified under the ledger-registered key (ACT-17).
    pub countersigned: u64,
    /// Successes on a tool server with no registered receipt key.
    pub uncountersigned: u64,
}
#[derive(Default)]
struct State {
    principal: Option<Principal>,
    digest: String,
    key: Option<Uuid>,
    evidence: BTreeMap<String, EvidenceField>,
    tool: Uuid,
    version: u32,
    decision: Option<Decision>,
    publisher: Option<String>,
    activation: Option<Uuid>,
    approval: Option<Uuid>,
    consumed: bool,
    execution: Option<Uuid>,
    outcome: bool,
    time: DateTime<Utc>,
    /// Tool server of the decided contract, and the receipt key the start row committed to.
    server: Option<Uuid>,
    expected: Option<(receipt::Expected, Vec<u8>)>,
    binding: Option<receipt::Binding>,
}
#[derive(Debug)]
pub struct ReferenceOutsideRange(&'static str);
impl std::fmt::Display for ReferenceOutsideRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ReferenceOutsideRange {}
/// Verify causal references within this range. Errors fail CLOSED.
pub fn semantics(
    events: &[Envelope],
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> anyhow::Result<Semantics> {
    use ActionPayload::*;
    use anyhow::{Context, ensure};
    let mut result = Semantics::default();
    let mut policies = BTreeMap::new();
    let mut latest = BTreeMap::<Uuid, Uuid>::new();
    let mut actions = BTreeMap::<Uuid, State>::new();
    let mut approvals = BTreeMap::<Uuid, (Uuid, DateTime<Utc>, &str)>::new();
    let mut event_ids = std::collections::BTreeSet::new();
    let mut execution_ids = std::collections::BTreeSet::new();
    let mut idempotency_keys = std::collections::BTreeSet::new();
    let mut receipt_keys = BTreeMap::<Uuid, (String, Vec<u8>)>::new();
    let mut attestation_digests = std::collections::BTreeSet::<String>::new();
    for (hash, bytes) in artifacts {
        ensure!(
            hex::encode(crate::sha256(bytes)) == *hash,
            "artifact hash mismatch"
        );
        let text = std::str::from_utf8(bytes)?;
        ensure!(canonical_json(text)? == text, "unverifiable artifact bytes");
    }
    for e in events {
        let principal_reason = |reason: &ReasonCode| {
            matches!(
                reason,
                ReasonCode::PrincipalRequired
                    | ReasonCode::PrincipalInvalid
                    | ReasonCode::PrincipalUnverifiable
            )
        };
        let new_reason = match &e.body {
            DecisionMade { reason_codes, .. } => reason_codes.iter().any(principal_reason),
            DeniedRuntime { reason } | ApprovalAttemptRejected { reason, .. } => {
                principal_reason(reason)
            }
            _ => false,
        };
        let schema_allowed = match (&e.body, e.schema_version) {
            (ActionProposed { .. }, 1 | 2) => true,
            (DeniedRuntime { .. }, 2) => new_reason,
            (_, 1) => !new_reason,
            _ => false,
        };
        ensure!(
            schema_allowed && event_ids.insert(e.event_id),
            "invalid/duplicate action event"
        );
        if let PolicyActivated {
            policy_id,
            version,
            policy_hash,
            tool_ref,
            contract_version,
            contract_hash,
            protected,
            publisher_digest,
        } = &e.body
        {
            let p: serde_json::Value = serde_json::from_slice(
                artifacts
                    .get(policy_hash)
                    .context("missing original policy")?,
            )?;
            let c: serde_json::Value = serde_json::from_slice(
                artifacts
                    .get(contract_hash)
                    .context("missing original contract")?,
            )?;
            ensure!(
                p["policy_id"] == policy_id.to_string()
                    && p["version"] == *version
                    && c["tool_ref"] == tool_ref.to_string()
                    && c["version"] == *contract_version
                    && c["protected"] == *protected,
                "artifact identity mismatch"
            );
            ensure!(
                e.action_id == *policy_id && e.request_digest == *policy_hash,
                "activation binding mismatch"
            );
            ensure!(
                policies
                    .insert(
                        (*policy_id, *version),
                        (
                            policy_hash.clone(),
                            *tool_ref,
                            *contract_version,
                            publisher_digest.clone(),
                            e.event_id,
                            contract_hash.clone(),
                            c["server_id"]
                                .as_str()
                                .and_then(|s| s.parse::<Uuid>().ok())
                                .context("invalid contract server_id")?,
                        )
                    )
                    .is_none(),
                "duplicate policy activation"
            );
            latest.insert(*tool_ref, e.event_id);
            continue;
        }
        if let ToolReceiptKeyRegistered {
            server_id,
            receipt_key_id,
            public_key,
        } = &e.body
        {
            let public = hex::decode(public_key)
                .ok()
                .filter(|k| receipt::valid_public_key(k))
                .context("invalid receipt key registration")?;
            ensure!(
                e.agent_key_id.is_none()
                    && e.action_id == *server_id
                    && e.request_digest == *receipt_key_id
                    && receipt::key_id(&public) == *receipt_key_id,
                "invalid receipt key registration"
            );
            receipt_keys.insert(*server_id, (receipt_key_id.clone(), public));
            continue;
        }
        if matches!(e.body, LegacyForwardAttempted { .. } | DeniedRuntime { .. }) {
            continue;
        }
        if let ActionProposed {
            tool_ref,
            contract_version,
            evidence_fields,
            principal,
            ..
        } = &e.body
        {
            ensure!(e.agent_key_id.is_some(), "missing authenticated agent key");
            if let Some(principal) = principal {
                ensure!(e.schema_version == 2, "principal requires schema v2");
                principal.validate()?;
                result.principals.insert(e.action_id, principal.clone());
            }
            ensure!(
                actions
                    .insert(
                        e.action_id,
                        State {
                            digest: e.request_digest.clone(),
                            key: e.agent_key_id,
                            evidence: evidence_fields.clone(),
                            principal: principal.clone(),
                            tool: *tool_ref,
                            version: *contract_version,
                            time: e.occurred_at,
                            ..Default::default()
                        }
                    )
                    .is_none(),
                "duplicate action"
            );
            continue;
        }
        let a = actions
            .get_mut(&e.action_id)
            .ok_or(ReferenceOutsideRange("action reference outside range"))?;
        ensure!(
            e.request_digest == a.digest && e.occurred_at >= a.time,
            "action digest/time mismatch"
        );
        a.time = e.occurred_at;
        if matches!(
            e.body,
            DecisionMade { .. }
                | ApprovalRequested { .. }
                | ApprovalConsumed { .. }
                | ExecutionStarted { .. }
                | ExecutionSucceeded { .. }
                | ExecutionFailed { .. }
                | ExecutionUnknown { .. }
        ) {
            ensure!(e.agent_key_id == a.key, "agent binding mismatch");
        }
        match &e.body {
            DecisionMade {
                decision,
                rule_id,
                policy_id,
                policy_version,
                policy_hash,
                ..
            } => {
                let p = policies
                    .get(&(*policy_id, *policy_version))
                    .ok_or(ReferenceOutsideRange("policy reference outside range"))?;
                ensure!(
                    p.0 == *policy_hash
                        && p.1 == a.tool
                        && p.2 == a.version
                        && a.decision.is_none(),
                    "policy binding mismatch"
                );
                ensure!(
                    latest.get(&a.tool) == Some(&p.4),
                    "decision does not cite latest tool activation"
                );
                let outcome = replay::replay_with_principal(
                    artifacts
                        .get(policy_hash)
                        .context("missing original policy")?,
                    artifacts.get(&p.5).context("missing original contract")?,
                    a.key,
                    &a.evidence,
                    a.principal.as_ref(),
                    decision,
                    rule_id,
                )?;
                match outcome {
                    replay::Outcome::Match => result.replayed += 1,
                    replay::Outcome::NotReplayable => result.not_replayable.push(e.action_id),
                }
                a.activation = Some(p.4);
                a.server = Some(p.6);
                a.decision = Some(decision.clone());
                a.publisher = Some(p.3.clone());
            }
            ApprovalRequested {
                approval_id,
                expires_at,
                ..
            } => {
                ensure!(
                    matches!(a.decision, Some(Decision::RequireApproval))
                        && a.approval.is_none()
                        && *expires_at > e.occurred_at,
                    "invalid approval request"
                );
                ensure!(
                    approvals
                        .insert(*approval_id, (e.action_id, *expires_at, "pending"))
                        .is_none(),
                    "duplicate approval"
                );
                a.approval = Some(*approval_id);
            }
            ApprovalGranted { approval_id, .. }
            | ApprovalDenied { approval_id, .. }
            | ApprovalConsumed { approval_id }
            | ApprovalExpired { approval_id }
            | ApprovalInvalidated { approval_id } => {
                let g = approvals
                    .get_mut(approval_id)
                    .ok_or(ReferenceOutsideRange("approval reference outside range"))?;
                ensure!(
                    g.0 == e.action_id && a.approval == Some(*approval_id),
                    "approval action mismatch"
                );
                if let ApprovalGranted { decider_digest, .. }
                | ApprovalDenied { decider_digest, .. } = &e.body
                {
                    ensure!(
                        a.publisher
                            .as_ref()
                            .is_some_and(|publisher| publisher != decider_digest),
                        "approval decider matches policy publisher"
                    );
                }
                g.2 = match e.body {
                    ApprovalGranted { .. } => {
                        ensure!(
                            g.2 == "pending" && e.occurred_at < g.1,
                            "invalid approval grant"
                        );
                        "approved"
                    }
                    ApprovalDenied { .. } => {
                        ensure!(g.2 == "pending", "invalid approval denial");
                        result.denied.push(*approval_id);
                        "denied"
                    }
                    ApprovalConsumed { .. } => {
                        ensure!(
                            a.activation.as_ref() == latest.get(&a.tool),
                            "approval superseded by tool activation"
                        );
                        ensure!(
                            g.2 == "approved" && e.occurred_at < g.1 && !a.consumed,
                            "approval not approved, expired or consumed"
                        );
                        a.consumed = true;
                        "consumed"
                    }
                    ApprovalExpired { .. } => {
                        ensure!(
                            matches!(g.2, "pending" | "approved") && e.occurred_at >= g.1,
                            "denied is not expired"
                        );
                        "expired"
                    }
                    ApprovalInvalidated { .. } => {
                        ensure!(
                            matches!(g.2, "pending" | "approved"),
                            "invalid approval invalidation"
                        );
                        "invalidated"
                    }
                    _ => unreachable!(),
                };
            }
            ApprovalAttemptRejected { approval_id, .. } => {
                ensure!(
                    approvals
                        .get(approval_id)
                        .is_some_and(|g| g.0 == e.action_id),
                    ReferenceOutsideRange("approval reference outside range")
                );
            }
            ExecutionStarted {
                execution_id,
                idempotency_key,
                attestation_key_id,
                receipt_expected,
            } => {
                // Two-sided reconciliation (ACT-17): the start row must commit to the latest
                // receipt key the ledger registered for this tool server, or to none.
                let registered = a.server.and_then(|s| receipt_keys.get(&s));
                ensure!(
                    receipt_expected.as_ref().map(|x| &x.receipt_key_id)
                        == registered.map(|k| &k.0),
                    "receipt key expectation mismatch"
                );
                if let Some(x) = receipt_expected {
                    // The gateway's own attestation key never countersigns, and one attestation
                    // digest belongs to one execution.
                    ensure!(
                        x.receipt_key_id != *attestation_key_id,
                        "receipt key expectation mismatch"
                    );
                    ensure!(
                        attestation_digests.insert(x.attestation_digest.clone()),
                        "duplicate attestation digest"
                    );
                }
                a.expected = receipt_expected
                    .clone()
                    .zip(registered.map(|k| k.1.clone()));
                a.binding = a.server.map(|server_id| receipt::Binding {
                    execution_id: *execution_id,
                    action_id: e.action_id,
                    request_digest: e.request_digest.clone(),
                    tenant_id: e.tenant_id,
                    server_id,
                });
                ensure!(
                    a.activation.is_some() && a.activation.as_ref() == latest.get(&a.tool),
                    "execution superseded by tool activation"
                );
                ensure!(
                    matches!(a.decision, Some(Decision::Allow))
                        || (matches!(a.decision, Some(Decision::RequireApproval)) && a.consumed),
                    "execution lacks permission/consume"
                );
                ensure!(
                    a.execution.replace(*execution_id).is_none(),
                    "duplicate execution"
                );
                ensure!(
                    execution_ids.insert((e.tenant_id, *execution_id)),
                    "duplicate tenant execution ID"
                );
                ensure!(
                    idempotency_keys.insert((e.tenant_id, *idempotency_key)),
                    "duplicate tenant idempotency key"
                );
            }
            ExecutionSucceeded { execution_id, .. }
            | ExecutionFailed { execution_id, .. }
            | ExecutionUnknown { execution_id, .. } => {
                ensure!(
                    a.execution == Some(*execution_id) && !a.outcome,
                    "outcome without unique start"
                );
                a.outcome = true;
                if let ExecutionSucceeded {
                    receipt_digest,
                    countersignature,
                    ..
                } = &e.body
                {
                    match (&a.expected, countersignature) {
                        (None, None) => result.uncountersigned += 1,
                        (Some((expected, public)), Some(c)) => {
                            let binding =
                                a.binding.as_ref().context("countersignature mismatch")?;
                            receipt::verify(public, expected, binding, c)?;
                            ensure!(
                                receipt::receipt_digest(*execution_id, c)? == *receipt_digest,
                                "countersigned receipt digest mismatch"
                            );
                            result.countersigned += 1;
                        }
                        _ => anyhow::bail!("countersignature mismatch"),
                    }
                }
                if matches!(e.body, ExecutionUnknown { .. }) {
                    result.unknown.push(*execution_id);
                }
            }
            _ => anyhow::bail!("unexpected action state"),
        }
    }
    // No let-chain: the published crate's MSRV is 1.87 (let-chains stabilised in 1.88).
    for a in actions.values().filter(|a| !a.outcome) {
        if let Some(id) = a.execution {
            result.unknown.push(id);
        }
    }
    Ok(result)
}
pub mod archive;
pub mod bundle;
pub mod chain;
pub mod cose;
#[cfg(test)]
mod tests;

pub mod timestamp;
pub mod tree;
