//! Attestation and reservation boundary for synthetic protected calls.
use super::*;
use crate::entitlement_cache::ResolvedEntitlements;
use crate::{
    db::audit_chain_state::AtomicBatchAppend,
    mcp_policy::{Action, Mode},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ring::signature::{self, KeyPair};
use secrecy::zeroize::Zeroizing;

pub const HEADER: &str = "x-tracelane-execution-attestation";
const DOMAIN: &str = "tracelane.tool-execution.v1";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_digest: Option<String>,
    pub domain: String,
    pub key_id: String,
    pub tenant_id: Uuid,
    pub execution_id: Uuid,
    pub action_id: Uuid,
    pub request_digest: String,
    pub idempotency_key: Uuid,
    pub exp: i64,
    pub agent_key_id: Uuid,
    pub contract: policy::Contract,
    pub policy_version: u32,
}
pub struct AttestationSigner {
    private: SecretString,
    public: Vec<u8>,
}
impl AttestationSigner {
    pub fn configured(raw: Option<SecretString>, audit: Option<&str>) -> Result<Option<Self>> {
        let Some(raw) = raw else {
            return Ok(None);
        };
        let signer = Self::from_pkcs8(raw)?;
        if let Some(audit) = audit {
            let pin = crate::audit::platform_pubkey_b64(audit).context("audit_signer_invalid")?;
            ensure!(
                STANDARD.decode(pin)? != signer.public,
                "attestation_key_reuses_audit_key"
            );
        }
        Ok(Some(signer))
    }
    /// Operator-provisioned dedicated purpose key. Errors fail CLOSED.
    pub fn from_pkcs8(private: SecretString) -> Result<Self> {
        let der = Zeroizing::new(
            STANDARD
                .decode(private.expose_secret())
                .map_err(|_| anyhow::anyhow!("attestation_signer_unavailable"))?,
        );
        let pair = signature::Ed25519KeyPair::from_pkcs8(&der)
            .map_err(|_| anyhow::anyhow!("attestation_signer_unavailable"))?;
        Ok(Self {
            private,
            public: pair.public_key().as_ref().to_vec(),
        })
    }
    pub fn public_key(&self) -> Vec<u8> {
        self.public.clone()
    }
    pub fn key_id(&self) -> String {
        sha(&self.public)
    }
    pub fn issue(&self, a: &Attestation) -> Result<String> {
        ensure!(
            a.key_id == self.key_id() && a.domain == DOMAIN,
            "attestation_invalid"
        );
        let der = Zeroizing::new(
            STANDARD
                .decode(self.private.expose_secret())
                .map_err(|_| anyhow::anyhow!("attestation_signer_unavailable"))?,
        );
        let pair = signature::Ed25519KeyPair::from_pkcs8(&der)
            .map_err(|_| anyhow::anyhow!("attestation_signer_unavailable"))?;
        let body = canonical(a)?;
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(body.as_bytes()),
            URL_SAFE_NO_PAD.encode(pair.sign(body.as_bytes()).as_ref())
        ))
    }
}
/// Tool-side signature/intent boundary. The tool pins its own tenant/server/name/key.
/// Errors fail CLOSED. Caller MUST durably claim tenant/idempotency key in the SAME
/// transaction as its side effect. Verification alone does not provide replay protection.
#[allow(clippy::too_many_arguments)] // Complete independently pinned tool audience.
pub fn verify(
    header: Option<&str>,
    pin: &[u8],
    tenant: Uuid,
    server: Uuid,
    tool: &str,
    args: &str,
    now: i64,
) -> Result<Attestation> {
    let header = header.context("missing_attestation")?;
    ensure!(
        header.len() <= crate::mcp_policy::settings()?.limits.max_request_bytes,
        "attestation_invalid"
    );
    let (body, sig) = header.split_once('.').context("attestation_invalid")?;
    let body = URL_SAFE_NO_PAD.decode(body)?;
    signature::UnparsedPublicKey::new(&signature::ED25519, pin)
        .verify(&body, &URL_SAFE_NO_PAD.decode(sig)?)
        .map_err(|_| anyhow::anyhow!("attestation_invalid"))?;
    let raw = std::str::from_utf8(&body)?;
    ensure!(canonical_json(raw)? == raw, "attestation_invalid");
    let a: Attestation = serde_json::from_str(raw)?;
    ensure!(
        a.domain == DOMAIN
            && a.key_id == sha(pin)
            && a.tenant_id == tenant
            && a.contract.server_id == server
            && a.contract.tool_name == tool
            && a.contract.protected,
        "attestation_invalid"
    );
    ensure!(a.exp > now, "attestation_expired");
    let contract = policy::parse_contract(&canonical(&a.contract)?)?;
    ensure!(
        policy::intent_digest_bound(
            &TenantId::from_jwt_claim(tenant),
            a.agent_key_id,
            &contract,
            Some(a.policy_version),
            args,
            a.principal_digest.as_deref()
        )? == a.request_digest,
        "digest_mismatch"
    );
    Ok(a)
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    InFlight,
    Succeeded,
    Failed,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub execution_id: Uuid,
    pub state: State,
    pub tool_receipt: Option<Uuid>,
    /// ACT-17: the tool server's signature, present only when a receipt key is registered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub countersignature: Option<receipt_keys::Countersignature>,
}
pub enum Outcome {
    Succeeded(Uuid),
    /// A tool receipt id with the tool server's hex signature over it (ACT-17).
    Countersigned(Uuid, String),
    Failed,
    Unknown,
}
pub struct Call<'a> {
    pub principal: Option<&'a principal::Input>,
    pub server: Uuid,
    pub tool: &'a str,
    pub args: &'a str,
    pub execution_context: &'a str,
    pub idempotency_key: Uuid,
    pub approval_id: Option<Uuid>,
    pub legacy: Action,
    pub mode: Mode,
    /// The live tool definition no longer matches its approved pin (rug-pull): the call is
    /// refused with a signed `denied_runtime/tool_definition_changed` row and never forwarded.
    pub definition_changed: bool,
}
#[derive(Debug, thiserror::Error)]
#[error("approval_required")]
pub struct ApprovalRequired {
    pub id: Uuid,
    pub expires_at: DateTime<Utc>,
}
#[derive(Debug, thiserror::Error)]
#[error("late principal verification refused")]
struct LatePrincipal {
    invalid: bool,
}
impl LatePrincipal {
    fn code(&self) -> &'static str {
        if self.invalid {
            "principal_invalid"
        } else {
            "principal_unverifiable"
        }
    }
    fn reason(&self) -> ReasonCode {
        if self.invalid {
            ReasonCode::PrincipalInvalid
        } else {
            ReasonCode::PrincipalUnverifiable
        }
    }
}
pub enum Reservation {
    Pending(ApprovalRequired, Vec<AtomicBatchAppend>),
    Existing(Receipt),
    Blocked(&'static str, Vec<AtomicBatchAppend>),
    Started(
        Receipt,
        String,
        Vec<AtomicBatchAppend>,
        Option<Box<receipt_keys::ReceiptKey>>,
    ),
}
fn valid_key(row: &tokio_postgres::Row, now: DateTime<Utc>) -> Result<()> {
    ensure!(
        (0..2).all(|i| row
            .get::<_, Option<DateTime<Utc>>>(i)
            .is_none_or(|d| d > now)),
        "key_revoked"
    );
    Ok(())
}
fn api_key(claims: &crate::auth::Claims) -> Result<Uuid> {
    Uuid::parse_str(claims.api_key_id().context("unauthorized")?).context("unauthorized")
}
fn event(
    action_id: Uuid,
    request_digest: &str,
    event_id: Uuid,
    body: ActionPayload,
) -> ActionEvent {
    ActionEvent {
        event_id,
        action_id,
        request_digest: request_digest.into(),
        occurred_at: Utc::now(),
        body,
    }
}
async fn append(
    tx: &Transaction<'_>,
    claims: &crate::auth::Claims,
    resolved: Option<&ResolvedEntitlements>,
    e: ActionEvent,
) -> Result<AtomicBatchAppend> {
    let out = append_actions_tx(tx, claims, resolved, &[e])
        .await?
        .context("evidence_unavailable")?;
    ensure!(out.kept.len() == 1, "evidence_unavailable");
    Ok(out)
}
/// The protected call a paused workspace refused.
pub(crate) struct PausedCall<'a> {
    pub server: Uuid,
    pub tool: &'a str,
    pub args: &'a str,
}
/// Fixed UUIDv5 namespace for paused-refusal event/action ids (never change: ids are chain identity).
const PAUSED_NS: Uuid = Uuid::from_u128(0x7a3c_91e0_5b2d_4f68_9c14_0e6d_a8b3_52f1);
/// Paused-refusal evidence is best-effort: the refusal never depends on it, so a skipped
/// write is counted, not logged per request.
pub(crate) fn evidence_deferred() {
    tracelane_shared::degradation::note(
        tracelane_shared::degradation::Degradation::ActionEvidenceDeferred,
    );
}
/// One signed `denied_runtime/workspace_paused` row per (tenant, pause epoch, request digest),
/// for the background worker. `None` = flag off, tool not protected, key not valid AT
/// `refused_at` (revoked or expired before the refusal; checked under the key row lock, so a
/// key revoked AFTER the refusal still records), arguments undigestible (counted), or already
/// on the chain. `refused_at` is also the row's `occurred_at`.
/// # Errors
/// Fails CLOSED for the caller's transaction (it must roll back); the worker counts the gap.
pub(crate) async fn paused_refusal_tx(
    tx: &Transaction<'_>,
    claims: &crate::auth::Claims,
    resolved: Option<&ResolvedEntitlements>,
    call: &PausedCall<'_>,
    paused_at: DateTime<Utc>,
    refused_at: DateTime<Utc>,
) -> Result<Option<AtomicBatchAppend>> {
    let Some(active) =
        policy_store::protected_tx(tx, claims, resolved, call.server, call.tool).await?
    else {
        return Ok(None);
    };
    let key = api_key(claims)?;
    let valid = tx
        .query_opt(
            "SELECT revoked_at,expires_at FROM api_keys WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
            &[claims.tenant_id.as_uuid(), &key],
        )
        .await?;
    // silent-fallback-ok: a key already revoked or expired at the refusal is intentionally unrecorded (spec edge case 1)
    let Some(valid) = valid else { return Ok(None) };
    if valid_key(&valid, refused_at).is_err() {
        return Ok(None); // silent-fallback-ok: same as above
    }
    paused_event_tx(
        tx, claims, resolved, &active, key, call, paused_at, refused_at,
    )
    .await
}
/// # Errors
/// Fails CLOSED: the caller's transaction must roll back.
#[allow(clippy::too_many_arguments)] // Complete refusal context; a struct would be a one-use type.
async fn paused_event_tx(
    tx: &Transaction<'_>,
    claims: &crate::auth::Claims,
    resolved: Option<&ResolvedEntitlements>,
    active: &policy_store::ActivePolicy,
    key: Uuid,
    call: &PausedCall<'_>,
    paused_at: DateTime<Utc>,
    refused_at: DateTime<Utc>,
) -> Result<Option<AtomicBatchAppend>> {
    let Ok(digest) = policy::intent_digest_optional(
        &claims.tenant_id,
        key,
        &active.contract,
        active.policy.as_ref().map(|p| p.version),
        call.args,
    ) else {
        evidence_deferred(); // Malformed arguments: such a call could never have executed.
        return Ok(None);
    };
    let id = |prefix: &str| {
        let name = format!(
            "{prefix}{}{}{digest}",
            claims.tenant_id.as_uuid(),
            paused_at.to_rfc3339_opts(SecondsFormat::Micros, true)
        );
        Uuid::new_v5(&PAUSED_NS, name.as_bytes())
    };
    let mut e = event(
        id("paused-action:"),
        &digest,
        id("paused-refusal:"),
        ActionPayload::DeniedRuntime {
            reason: ReasonCode::WorkspacePaused,
        },
    );
    e.occurred_at = refused_at;
    // `None` = full dedup (the flag was checked by protected_tx): already on the chain, success.
    let Some(out) = append_actions_tx(tx, claims, resolved, &[e]).await? else {
        return Ok(None);
    };
    Ok(Some(out))
}
/// Fixed UUIDv5 namespace for changed-definition refusal ids (never change: ids are chain identity).
const CHANGED_NS: Uuid = Uuid::from_u128(0x3e1f_6b2a_9c47_4d05_8e3b_71a2_c9d4_0f68);
/// One signed `denied_runtime/tool_definition_changed` row per (tenant, idempotency key, request
/// digest), so a retried request does not add rows. `None` = arguments undigestible (counted; such
/// a call could never have executed) or already on the chain.
/// # Errors
/// Fails CLOSED: the caller's transaction must roll back, and the call stays refused.
async fn changed_event_tx(
    tx: &Transaction<'_>,
    claims: &crate::auth::Claims,
    resolved: Option<&ResolvedEntitlements>,
    active: &policy_store::ActivePolicy,
    key: Uuid,
    call: &Call<'_>,
) -> Result<Option<AtomicBatchAppend>> {
    let Ok(digest) = policy::intent_digest_optional(
        &claims.tenant_id,
        key,
        &active.contract,
        active.policy.as_ref().map(|p| p.version),
        call.args,
    ) else {
        evidence_deferred();
        return Ok(None);
    };
    let id = |prefix: &str| {
        let name = format!(
            "{prefix}{}{}{digest}",
            claims.tenant_id.as_uuid(),
            call.idempotency_key
        );
        Uuid::new_v5(&CHANGED_NS, name.as_bytes())
    };
    let e = event(
        id("changed-action:"),
        &digest,
        id("changed-refusal:"),
        ActionPayload::DeniedRuntime {
            reason: ReasonCode::ToolDefinitionChanged,
        },
    );
    append_actions_tx(tx, claims, resolved, &[e]).await
}
/// Candidate reservation only. Commit acknowledgment MUST precede exposing its
/// attestation to a tool, so only `execute` (and tests) may call this.
/// # Errors
/// Fails CLOSED on every error; the caller must roll the outer transaction back.
#[tracing::instrument(skip_all, fields(tenant_id=%claims.tenant_id))]
pub(super) async fn reserve_tx(
    tx: &Transaction<'_>,
    claims: &crate::auth::Claims,
    resolved: Option<&ResolvedEntitlements>,
    call: &Call<'_>,
    signer: &AttestationSigner,
) -> Result<Option<Reservation>> {
    let Some(active) =
        policy_store::protected_tx(tx, claims, resolved, call.server, call.tool).await?
    else {
        return Ok(None);
    };
    let t = claims.tenant_id.as_uuid();
    // Shared approval capacity: tenant precedes key and ledger-head locks.
    tx.query_one("SELECT id FROM tenants WHERE id=$1 FOR UPDATE", &[t])
        .await?;
    let key = api_key(claims)?;
    let valid = tx
        .query_opt(
            "SELECT revoked_at,expires_at FROM api_keys WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
            &[t, &key],
        )
        .await?
        .context("key_revoked")?;
    valid_key(&valid, super::db_now(tx).await?)?;
    // Checked before the idempotency replay and the pause, matching the pre-ledger refusal order.
    if call.definition_changed {
        let rows = changed_event_tx(tx, claims, resolved, &active, key, call).await?;
        return Ok(Some(Reservation::Blocked(
            "mcp_tool_definition_changed",
            rows.into_iter().collect(),
        )));
    }
    let input = call.principal.unwrap_or(&principal::Input::Missing);
    let verified = if let principal::Input::Verified(v) = input {
        Some(v)
    } else {
        None
    };
    let refusal = match input {
        principal::Input::Missing
            if active.policy.as_ref().is_some_and(|p| p.require_principal) =>
        {
            Some(("principal_required", ReasonCode::PrincipalRequired))
        }
        principal::Input::Invalid => Some(("principal_invalid", ReasonCode::PrincipalInvalid)),
        principal::Input::Unverifiable => {
            Some(("principal_unverifiable", ReasonCode::PrincipalUnverifiable))
        }
        principal::Input::Verified(v) => match v.recheck(tx, &claims.tenant_id).await {
            Ok(()) => None,
            Err(e) if e.to_string() == "principal_invalid" => {
                Some(("principal_invalid", ReasonCode::PrincipalInvalid))
            }
            Err(_) => Some(("principal_unverifiable", ReasonCode::PrincipalUnverifiable)),
        },
        _ => None,
    };
    if let Some((code, reason)) = refusal {
        let digest = sha(call.args.as_bytes());
        let rows = append(
            tx,
            claims,
            resolved,
            event(
                Uuid::new_v4(),
                &digest,
                Uuid::new_v4(),
                ActionPayload::DeniedRuntime { reason },
            ),
        )
        .await?;
        return Ok(Some(Reservation::Blocked(code, vec![rows])));
    }
    let principal = if let Some(v) = verified {
        let secret = tokenization_secret_tx(
            tx,
            &claims.tenant_id,
            resolved,
            crate::byok::master_key().context("evidence_unavailable")?,
        )
        .await?;
        Some(v.minimize(&secret)?)
    } else {
        None
    };
    let principal_digest = principal
        .as_ref()
        .map(|p| canonical(p).map(|s| sha(s.as_bytes())))
        .transpose()?;
    // Historical contract/version reproduce the original intent even after activation.
    if let Some(row)=tx.query_opt("SELECT x.agent_key_id,x.request_digest,x.receipt_jcs,x.policy_version,c.body_jcs FROM action_executions x JOIN action_policies p ON p.tenant_id=x.tenant_id AND p.policy_id=x.policy_id AND p.version=x.policy_version JOIN action_tool_contracts c ON c.tenant_id=p.tenant_id AND c.tool_ref=p.tool_ref AND c.version=p.contract_version WHERE x.tenant_id=$1 AND x.idempotency_key=$2 FOR UPDATE OF x",&[t,&call.idempotency_key]).await? {
        let c=policy::parse_contract(&row.get::<_,String>(4))?;
        ensure!(row.get::<_,Uuid>(0)==key && c.server_id==call.server && c.tool_name==call.tool && policy::intent_digest_bound(&claims.tenant_id,key,&c,Some(u32::try_from(row.get::<_,i32>(3))?),call.args,principal_digest.as_deref())?==row.get::<_,String>(1),"idempotency_mismatch");
        return Ok(Some(Reservation::Existing(serde_json::from_str(&row.get::<_,Option<String>>(2).context("receipt_unavailable")?)?)));
    }
    let controls = tx
        .query_one(
            "SELECT paused_at FROM workspace_controls WHERE tenant_id=$1",
            &[t],
        )
        .await?;
    // Pause is checked before `digest?` so malformed arguments still refuse 423, not 503.
    if let Some(since) = controls.get::<_, Option<DateTime<Utc>>>(0) {
        let call = PausedCall {
            server: call.server,
            tool: call.tool,
            args: call.args,
        };
        let rows =
            paused_event_tx(tx, claims, resolved, &active, key, &call, since, Utc::now()).await?;
        return Ok(Some(Reservation::Blocked(
            "workspace_paused",
            rows.into_iter().collect(),
        )));
    }
    let mut action = Uuid::new_v4();
    let mut decision = Uuid::new_v4();
    let execution = Uuid::new_v4();
    let request = policy_store::Request {
        principal: principal.as_ref(),
        server: call.server,
        tool: call.tool,
        args: call.args.as_bytes(),
        action_id: action,
        decision_id: decision,
        denial_id: Uuid::new_v4(),
    };
    let version = active.policy.as_ref().map(|p| p.version);
    let digest = policy::intent_digest_bound(
        &claims.tenant_id,
        key,
        &active.contract,
        version,
        call.args,
        principal_digest.as_deref(),
    )?;
    let (grant, mut evidence) =
        crate::approvals::protected::find_tx(tx, claims, &active, &digest, call.approval_id)
            .await?;
    if let Some(g) = grant {
        g.matches(&active, &digest, key, Some(call.execution_context))?;
        if let Some(reason) = g.refusal(super::db_now(tx).await?) {
            anyhow::bail!(reason);
        }
        ensure!(
            call.mode != Mode::Enforce || call.legacy != Action::Deny,
            "policy_denied"
        );
        if g.status == "pending" {
            return Ok(Some(Reservation::Pending(
                ApprovalRequired {
                    id: g.id,
                    expires_at: g.expires_at,
                },
                evidence,
            )));
        }
        action = g.action_id;
        decision = g.decision_id;
        evidence.push(crate::approvals::protected::consume_tx(tx, claims, resolved, &g).await?);
    } else {
        let values = policy::fields(
            &active.contract,
            &serde_json::from_str(&policy::bounded_json(call.args)?)?,
        )?;
        let mut evidence_fields = BTreeMap::new();
        for (name, field) in &active.contract.fields {
            if let Some(v) = values.get(name) {
                let evidence = match field.evidence {
                    policy::FieldMode::Clear => EvidenceField::Clear {
                        value: match field.kind {
                            policy::Kind::MinorUnits => {
                                ClearValue::MinorUnits(v.as_u64().context("contract_invalid")?)
                            }
                            policy::Kind::Currency => ClearValue::Currency(Usd::Usd),
                            policy::Kind::Boolean => {
                                ClearValue::Boolean(v.as_bool().context("contract_invalid")?)
                            }
                            policy::Kind::String => anyhow::bail!("contract_invalid"),
                        },
                    },
                    policy::FieldMode::DigestOnly => EvidenceField::DigestOnly {
                        sha256: sha(canonical(v)?.as_bytes()),
                    },
                    policy::FieldMode::Tokenize => {
                        let secret = tokenization_secret_tx(
                            tx,
                            &claims.tenant_id,
                            resolved,
                            crate::byok::master_key().context("evidence_unavailable")?,
                        )
                        .await?;
                        minimize(
                            &secret,
                            EvidenceMode::Tokenize,
                            v.as_str().context("contract_invalid")?,
                        )?
                    }
                };
                evidence_fields.insert(name.clone(), evidence);
            }
        }
        evidence.push(
            append(
                tx,
                claims,
                resolved,
                event(
                    action,
                    &digest,
                    action,
                    ActionPayload::ActionProposed {
                        tool_ref: active.contract.tool_ref,
                        contract_version: active.contract.version,
                        args_digest: sha(policy::bounded_json(call.args)?.as_bytes()),
                        evidence_fields: evidence_fields.clone(),
                        agent_claimed_labels: BTreeMap::new(),
                        principal: principal.clone(),
                    },
                ),
            )
            .await?,
        );
        let (verdict, rows) =
            policy_store::decide_tx(tx, claims, resolved, &request, call.legacy, call.mode)
                .await?
                .context("evidence_unavailable")?;
        evidence.push(rows);
        if verdict.decision == Action::RequireApproval {
            let (g, rows) = crate::approvals::protected::request_tx(
                tx,
                claims,
                resolved,
                &active,
                &digest,
                action,
                decision,
                call.args.len(),
                call.execution_context,
                &evidence_fields,
            )
            .await?;
            evidence.push(rows);
            return Ok(Some(Reservation::Pending(
                ApprovalRequired {
                    id: g.id,
                    expires_at: g.expires_at,
                },
                evidence,
            )));
        }
        if verdict.decision != Action::Allow {
            return Ok(Some(Reservation::Blocked(
                if verdict.decision == Action::RequireApproval {
                    "approval_required"
                } else {
                    "policy_denied"
                },
                evidence,
            )));
        }
    }
    let p = active.policy.context("contract_invalid")?;
    let ttl = i64::try_from(crate::mcp_policy::settings()?.limits.call_timeout_secs)?;
    ensure!(ttl > 0, "attestation_signer_unavailable");
    let mut a = Attestation {
        principal_digest,
        domain: DOMAIN.into(),
        key_id: signer.key_id(),
        tenant_id: *t,
        execution_id: execution,
        action_id: action,
        request_digest: digest.clone(),
        idempotency_key: call.idempotency_key,
        exp: Utc::now()
            .timestamp()
            .checked_add(ttl)
            .context("attestation_signer_unavailable")?,
        agent_key_id: key,
        contract: active.contract,
        policy_version: p.version,
    };
    if let Some(v) = verified {
        a.exp = a.exp.min(v.expires());
    }
    let header = signer.issue(&a)?;
    // After the tenant row lock above: a registration is wholly before or after this start.
    let receipt_key = receipt_keys::load_tx(
        tx,
        &claims.tenant_id,
        call.server,
        execution,
        action,
        &digest,
        &header,
    )
    .await?;
    // The verifier refuses a start row whose receipt key is the attestation key, and the ledger
    // is append-only: a key registered before a signer rotation must not reach the ledger.
    ensure!(
        receipt_key
            .as_ref()
            .is_none_or(|k| k.expected.receipt_key_id != signer.key_id()),
        "attestation_signer_unavailable"
    );
    let started = append(
        tx,
        claims,
        resolved,
        event(
            action,
            &digest,
            execution,
            ActionPayload::ExecutionStarted {
                execution_id: execution,
                idempotency_key: call.idempotency_key,
                attestation_key_id: signer.key_id(),
                receipt_expected: receipt_key.as_ref().map(|k| k.expected.clone()),
            },
        ),
    )
    .await?;
    valid_key(&valid, super::db_now(tx).await?)?; // Chain-head waits may have crossed the key expiry.
    if let Some(v) = verified {
        v.recheck(tx, &claims.tenant_id)
            .await
            .map_err(|e| LatePrincipal {
                invalid: e.to_string() == "principal_invalid",
            })?;
    }
    let receipt = Receipt {
        execution_id: execution,
        state: State::InFlight,
        tool_receipt: None,
        countersignature: None,
    };
    tx.execute("INSERT INTO action_executions(tenant_id,execution_id,action_id,agent_key_id,decision_id,policy_id,policy_version,policy_hash,idempotency_key,request_digest,ledger_seq,state,receipt_jcs) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'in_flight',$12)",&[t,&execution,&action,&key,&decision,&p.policy_id,&i32::try_from(p.version)?,&active.hash.context("contract_invalid")?,&call.idempotency_key,&digest,&i64::try_from(started.first_seq)?,&canonical(&receipt)?]).await?;
    evidence.push(started);
    Ok(Some(Reservation::Started(
        receipt,
        header,
        evidence,
        receipt_key.map(Box::new),
    )))
}
/// Atomic outcome + receipt + canonical ledger transition. Errors fail CLOSED:
/// outer rollback leaves the durable in_flight reservation for reconciliation.
#[tracing::instrument(skip_all, fields(tenant_id=%claims.tenant_id))]
pub async fn finish_tx(
    tx: &Transaction<'_>,
    claims: &crate::auth::Claims,
    _resolved: Option<&ResolvedEntitlements>,
    receipt: &Receipt,
) -> Result<AtomicBatchAppend> {
    let key = api_key(claims)?;
    let t = claims.tenant_id.as_uuid();
    let row=tx.query_opt("SELECT action_id,request_digest FROM action_executions WHERE tenant_id=$1 AND execution_id=$2 AND agent_key_id=$3 AND state='in_flight' FOR UPDATE",&[t,&receipt.execution_id,&key]).await?.context("execution_not_found")?;
    let digest = sha(canonical(receipt)?.as_bytes());
    let body = match receipt.state {
        State::Succeeded => {
            ensure!(receipt.tool_receipt.is_some(), "receipt_invalid");
            ActionPayload::ExecutionSucceeded {
                execution_id: receipt.execution_id,
                receipt_digest: digest.clone(),
                countersignature: receipt.countersignature.clone(),
            }
        }
        State::Failed => ActionPayload::ExecutionFailed {
            execution_id: receipt.execution_id,
            receipt_digest: digest.clone(),
        },
        State::Unknown => ActionPayload::ExecutionUnknown {
            execution_id: receipt.execution_id,
            receipt_digest: Some(digest.clone()),
        },
        State::InFlight => anyhow::bail!("receipt_invalid"),
    };
    let rows = append_committed_actions_tx(
        tx,
        claims,
        &[event(
            row.get(0),
            &row.get::<_, String>(1),
            Uuid::new_v4(),
            body,
        )],
    )
    .await?
    .context("evidence_unavailable")?;
    let state = match receipt.state {
        State::Succeeded => "succeeded",
        State::Failed => "failed",
        State::Unknown => "unknown",
        State::InFlight => anyhow::bail!("receipt_invalid"),
    };
    ensure!(tx.execute("UPDATE action_executions SET state=$4,receipt_jcs=$5,receipt_digest=$6 WHERE tenant_id=$1 AND execution_id=$2 AND agent_key_id=$3 AND state='in_flight'",&[t,&receipt.execution_id,&key,&state,&canonical(receipt)?,&digest]).await?==1,"execution_not_found");
    Ok(rows)
}
// Best-effort derived work is detached only AFTER the canonical commit. A
// timed-out/lost task is recovered by the existing canonical copy/anchor sweep.
pub(crate) fn after_commit(
    chain: Option<&std::sync::Arc<crate::audit::AuditChain>>,
    claims: &crate::auth::Claims,
    rows: Vec<AtomicBatchAppend>,
    timeout: std::time::Duration,
) {
    after_commit_for_tenant(chain, &claims.tenant_id, rows, timeout);
}
pub(crate) fn after_commit_for_tenant(
    chain: Option<&std::sync::Arc<crate::audit::AuditChain>>,
    tenant: &TenantId,
    rows: Vec<AtomicBatchAppend>,
    timeout: std::time::Duration,
) {
    if let Some(chain) = chain {
        let chain = std::sync::Arc::clone(chain);
        let tenant = tenant.clone();
        tokio::spawn(async move {
            let copy = async {
                let mut ok = true;
                // A full-dedup replay carries no rows; one failed batch must not skip the rest.
                for row in rows.into_iter().filter(|r| !r.rows.is_empty()) {
                    ok &= chain.after_outer_commit(&tenant, row).await.is_ok();
                }
                ok
            };
            if !matches!(tokio::time::timeout(timeout, copy).await, Ok(true)) {
                // Fail OPEN: canonical evidence is durable; never delay dispatch
                // or the outcome response for a stalled derived store.
                tracelane_shared::degradation::note(
                    tracelane_shared::degradation::Degradation::LedgerCopyFailed,
                );
                tracing::debug!(tenant_id=%tenant,"protected derived copy deferred to recovery");
            }
        });
    }
}
/// Bound backend work as well as the caller future: both `statement_timeout` and
/// `lock_timeout` for this transaction. Errors fail CLOSED.
pub(crate) async fn deadline_tx(tx: &Transaction<'_>, timeout: std::time::Duration) -> Result<()> {
    let millis = timeout.as_millis().to_string();
    tx.query_one(
        "SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)",
        &[&millis],
    )
    .await?;
    Ok(())
}
/// Only the committed winner can invoke forward, exactly once. Timeout is unknown.
/// # Errors
/// Canonical errors fail CLOSED; a failed outcome commit NEVER permits re-forwarding.
/// Countersignature (ACT-17): fail-CLOSED when a receipt key is registered for the server (a
/// missing or bad tool signature records Unknown, never Succeeded); fail-OPEN when none is.
/// Derived copying fails OPEN, is counted, and is recovered from canonical state.
#[tracing::instrument(skip_all, fields(tenant_id=%claims.tenant_id))]
pub async fn execute<F, Fut>(
    pool: &deadpool_postgres::Pool,
    claims: &crate::auth::Claims,
    resolved: Option<&ResolvedEntitlements>,
    call: &Call<'_>,
    signer: &AttestationSigner,
    chain: Option<&std::sync::Arc<crate::audit::AuditChain>>,
    forward: F,
) -> Result<Option<Receipt>>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Outcome>,
{
    if !enabled(resolved) {
        return Ok(None);
    }
    let timeout =
        std::time::Duration::from_secs(crate::mcp_policy::settings()?.limits.call_timeout_secs);
    let reserved = tokio::time::timeout(timeout, async {
        let mut db = pool.get().await?;
        let tx = db.transaction().await?;
        // Dropping a query future does not cancel a running PostgreSQL statement.
        // Bound server-side waits too, so cancellation cannot strand locks/pool slots.
        deadline_tx(&tx, timeout).await?;
        match reserve_tx(&tx, claims, resolved, call, signer).await {
            Ok(reserved) => {
                tx.commit().await?;
                Ok(reserved)
            }
            Err(error) => {
                let Some(late) = error.downcast_ref::<LatePrincipal>() else {
                    return Err(error);
                };
                let code = late.code();
                let reason = late.reason();
                // Discard candidate grants/execution events, then record only the refusal.
                tx.rollback().await?;
                let tx = db.transaction().await?;
                deadline_tx(&tx, timeout).await?;
                let rows = append(
                    &tx,
                    claims,
                    resolved,
                    event(
                        Uuid::new_v4(),
                        &sha(call.args.as_bytes()),
                        Uuid::new_v4(),
                        ActionPayload::DeniedRuntime { reason },
                    ),
                )
                .await?;
                tx.commit().await?;
                Ok(Some(Reservation::Blocked(code, vec![rows])))
            }
        }
    })
    .await
    .context("evidence_unavailable")??;
    let (mut receipt, header, rows, receipt_key) = match reserved {
        None => return Ok(None),
        Some(Reservation::Existing(r)) => return Ok(Some(r)),
        Some(Reservation::Pending(p, rows)) => {
            after_commit(chain, claims, rows, timeout);
            return Err(p.into());
        }
        Some(Reservation::Blocked(code, rows)) => {
            after_commit(chain, claims, rows, timeout);
            anyhow::bail!(code)
        }
        Some(Reservation::Started(r, h, rows, key)) => (r, h, rows, key),
    };
    after_commit(chain, claims, rows, timeout);
    let success = match tokio::time::timeout(timeout, forward(header)).await {
        Ok(Outcome::Succeeded(id)) => Some((id, None)),
        Ok(Outcome::Countersigned(id, signature)) => Some((id, Some(signature))),
        Ok(Outcome::Failed) => {
            receipt.state = State::Failed;
            None
        }
        Ok(Outcome::Unknown) | Err(_) => None,
    };
    receipt.state = match (receipt.state, success) {
        (State::Failed, _) => State::Failed,
        (_, Some((id, signature))) => {
            match receipt_keys::countersigned(receipt_key.as_deref(), id, signature.as_deref()) {
                Ok(countersignature) => {
                    receipt.tool_receipt = Some(id);
                    receipt.countersignature = countersignature;
                    State::Succeeded
                }
                // The tool's success is not accepted without its registered key's signature.
                // Counted, not logged per request (`.claude/rules/logging.md`).
                Err(_) => {
                    tracelane_shared::degradation::note(
                        tracelane_shared::degradation::Degradation::CountersignatureRejected,
                    );
                    State::Unknown
                }
            }
        }
        _ => State::Unknown,
    };
    // Once forwarding starts, every failure is terminal Unknown to this caller.
    // The committed reservation/consumed grant prevents retry under another key.
    let finish = async {
        let mut db = pool.get().await?;
        let tx = db.transaction().await?;
        deadline_tx(&tx, timeout).await?;
        let rows = finish_tx(&tx, claims, resolved, &receipt).await?;
        tx.commit().await?;
        Ok::<_, anyhow::Error>(rows)
    };
    match tokio::time::timeout(timeout, finish).await {
        Ok(Ok(rows)) => after_commit(chain, claims, vec![rows], timeout),
        _ => {
            receipt.state = State::Unknown;
            receipt.tool_receipt = None;
            receipt.countersignature = None;
        }
    }
    Ok(Some(receipt))
}

#[cfg(test)]
mod copy_tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn stalled_derived_copy_does_not_block_caller() {
        let manager =
            deadpool_postgres::Manager::new(tokio_postgres::Config::new(), tokio_postgres::NoTls);
        let pool = deadpool_postgres::Pool::builder(manager)
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .max_size(0)
            .build()
            .unwrap();
        // Block the hook's canonical read without any network access. This is
        // separate from the end-to-end stalled-ClickHouse Postgres probe.
        let chain = Arc::new(
            crate::audit::AuditChain::with_pg_pool(0, None, None, Some(pool.clone())).unwrap(),
        );
        let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
        let auth = super::super::tests::claims(&tenant);
        let row = crate::audit::AuditLogRow {
            tenant_id: tenant.to_string(),
            seq: 0,
            event_time: 0,
            event_type: "execution_started".into(),
            actor: "synthetic".into(),
            payload: "{}".into(),
            prev_hash: "0".repeat(64),
            row_hash: "1".repeat(64),
            rekor_entry_id: None,
            signature: String::new(),
            signing_pubkey: String::new(),
        };
        let rows = vec![AtomicBatchAppend {
            first_seq: 0,
            prev_hash: [0; 32],
            row_hashes: vec![[1; 32]],
            kept: vec![0],
            rows: vec![row],
        }];
        tokio::time::timeout(Duration::from_millis(50), async {
            after_commit(Some(&chain), &auth, rows, Duration::from_secs(1))
        })
        .await
        .expect("derived-copy work blocked the committed caller");
        // Witness the hook really starting, then prove its deadline drops the
        // blocked pool lease request instead of leaving a permanent task.
        tokio::time::timeout(Duration::from_millis(50), async {
            while pool.status().waiting == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("background copy was never attempted");
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        tokio::time::resume();
        assert_eq!(
            pool.status().waiting,
            0,
            "stalled copy task was not cancelled"
        );
    }
}

#[cfg(test)]
mod fix_timeout_tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn stalled_reservation_has_bounded_pre_send_refusal() {
        let manager =
            deadpool_postgres::Manager::new(tokio_postgres::Config::new(), tokio_postgres::NoTls);
        let pool = deadpool_postgres::Pool::builder(manager)
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .max_size(0)
            .build()
            .unwrap();
        let claims = super::super::tests::claims(&TenantId::from_jwt_claim(Uuid::new_v4()));
        let signer = super::super::execution_tests::signer();
        let call = Call {
            principal: None,
            server: Uuid::new_v4(),
            tool: "pay",
            args: super::super::execution_tests::ARGS,
            execution_context: "synthetic",
            idempotency_key: Uuid::new_v4(),
            approval_id: None,
            legacy: Action::Allow,
            mode: Mode::Observe,
            definition_changed: false,
        };
        let timeout = std::time::Duration::from_secs(
            crate::mcp_policy::settings()
                .unwrap()
                .limits
                .call_timeout_secs
                + 1,
        );
        let result = tokio::time::timeout(
            timeout,
            execute(
                &pool,
                &claims,
                Some(&super::super::tests::grants()),
                &call,
                &signer,
                None,
                |_| async { panic!("timed-out reservation forwarded") },
            ),
        )
        .await;
        assert!(
            result.is_ok(),
            "reservation did not honor the configured pre-send deadline"
        );
        assert_eq!(
            result.unwrap().unwrap_err().to_string(),
            "evidence_unavailable"
        );
    }
}
