//! Versioned protected tool policy. No legacy authorization semantics live here.
use super::*;
use crate::mcp_policy::{Action, Mode};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    pub tool_ref: Uuid,
    pub server_id: Uuid,
    pub tool_name: String,
    pub version: u32,
    pub protected: bool,
    pub fields: BTreeMap<String, Field>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub path: String,
    pub kind: Kind,
    pub required: bool,
    pub evidence: FieldMode,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldMode {
    Clear,
    Tokenize,
    DigestOnly,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    MinorUnits,
    Currency,
    String,
    Boolean,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub require_principal: bool,
    pub approval_ttl_secs: Option<u32>,
    pub policy_id: Uuid,
    pub version: u32,
    pub rules: Vec<Rule>,
    pub agents: Option<Vec<Uuid>>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub when: Vec<Condition>,
    pub decision: Action,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub field: String,
    pub op: Op,
    pub value: Option<Value>,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    InList,
    NotInList,
    Present,
    Absent,
}
fn valid_version(v: u32) -> bool {
    v > 0 && i32::try_from(v).is_ok()
}
fn valid_value(kind: Kind, value: &Value) -> bool {
    match kind {
        Kind::MinorUnits => value.as_u64().is_some_and(|n| n <= SAFE_INTEGER as u64),
        Kind::Currency => value.as_str() == Some("USD"), // C1 currency domain, not a currency-rate fallback.
        Kind::String => value.is_string(),
        Kind::Boolean => value.is_boolean(),
    }
}
pub(super) fn bounded_json(raw: &str) -> Result<String> {
    ensure!(
        raw.len() <= crate::mcp_policy::settings()?.limits.max_request_bytes,
        "contract_invalid"
    );
    canonical_json(raw)
}
pub fn parse_contract(raw: &str) -> Result<Contract> {
    let c: Contract = serde_json::from_str(&bounded_json(raw)?).context("contract_invalid")?;
    ensure!(
        valid_version(c.version)
            && !c.tool_name.is_empty()
            && c.tool_name.len() <= crate::mcp_policy::settings()?.limits.max_name_chars,
        "contract_invalid"
    );
    for (name, f) in &c.fields {
        validate_field_name(name)?;
        ensure!(f.path.starts_with('/'), "contract_invalid");
        let mut chars = f.path.chars();
        while let Some(ch) = chars.next() {
            if ch == '~' {
                ensure!(matches!(chars.next(), Some('0' | '1')), "contract_invalid");
            }
        }
        ensure!(
            !matches!((f.kind, f.evidence), (Kind::String, FieldMode::Clear)),
            "contract_invalid"
        );
        ensure!(
            !matches!(f.evidence, FieldMode::Tokenize) || matches!(f.kind, Kind::String),
            "contract_invalid"
        );
    }
    Ok(c)
}
pub fn parse_policy(raw: &str, contract: &Contract) -> Result<Policy> {
    let p: Policy = serde_json::from_str(&bounded_json(raw)?).context("contract_invalid")?;
    ensure!(
        valid_version(p.version)
            && p.rules.len()
                <= crate::mcp_policy::settings()?
                    .policy
                    .max_rules_per_workspace,
        "contract_invalid"
    );
    if p.rules
        .iter()
        .any(|r| r.decision == Action::RequireApproval)
    {
        let max = crate::mcp_policy::settings()?.approvals.max_ttl_secs;
        ensure!(
            p.approval_ttl_secs
                .is_some_and(|ttl| ttl > 0 && i64::from(ttl) <= i64::from(max)),
            "approval_policy_invalid"
        );
    }
    let mut ids = std::collections::BTreeSet::new();
    for rule in &p.rules {
        validate_field_name(&rule.id)?;
        ensure!(ids.insert(&rule.id), "contract_invalid");
        for cond in &rule.when {
            if cond.field == "principal.roles" && p.require_principal {
                ensure!(
                    p.require_principal
                        && matches!(cond.op, Op::InList | Op::NotInList)
                        && cond
                            .value
                            .as_ref()
                            .and_then(Value::as_array)
                            .is_some_and(|a| a.iter().all(Value::is_string)),
                    "contract_invalid"
                );
                continue;
            }
            let f = contract
                .fields
                .get(&cond.field)
                .context("contract_invalid")?;
            let value = match &cond.value {
                Some(v) => v,
                None => &Value::Null,
            }; // Absence only valid for presence operators.
            let valid = match cond.op {
                Op::Present | Op::Absent => value.is_null(),
                Op::InList | Op::NotInList => value
                    .as_array()
                    .is_some_and(|a| a.iter().all(|v| valid_value(f.kind, v))),
                Op::Gt | Op::Gte | Op::Lt | Op::Lte => {
                    matches!(f.kind, Kind::MinorUnits) && valid_value(f.kind, value)
                }
                Op::Eq | Op::Ne => valid_value(f.kind, value),
            };
            ensure!(valid, "contract_invalid");
        }
    }
    Ok(p)
}
pub fn fields(contract: &Contract, args: &Value) -> Result<BTreeMap<String, Value>> {
    ensure!(args.is_object(), "contract_invalid");
    let mut out = BTreeMap::new();
    for (name, f) in &contract.fields {
        match args.pointer(&f.path) {
            Some(v) => {
                match f.kind {
                    Kind::MinorUnits => {
                        ensure!(v.as_i64().is_none_or(|n| n >= 0), "amount_negative");
                        ensure!(v.as_u64().is_some(), "amount_not_integer");
                        ensure!(valid_value(f.kind, v), "amount_out_of_range");
                    }
                    Kind::Currency => ensure!(valid_value(f.kind, v), "currency_invalid"),
                    _ => ensure!(valid_value(f.kind, v), "contract_invalid"),
                }
                out.insert(name.clone(), v.clone());
            }
            None => ensure!(!f.required, "field_missing"),
        }
    }
    Ok(out)
}
fn matches(
    c: &Condition,
    fields: &BTreeMap<String, Value>,
    principal: Option<&tracelane_audit_verifier::action::Principal>,
    reserved: bool,
) -> bool {
    if c.field == "principal.roles" && reserved {
        return principal.is_some_and(|p| {
            p.validate().is_ok()
                && matches!(c.op, Op::InList | Op::NotInList)
                && c.value
                    .as_ref()
                    .is_some_and(|v| p.matches_roles(v, matches!(c.op, Op::NotInList)))
        });
    }
    let actual = fields.get(&c.field);
    if matches!(c.op, Op::Present) {
        return actual.is_some();
    }
    if matches!(c.op, Op::Absent) {
        return actual.is_none();
    }
    let (Some(a), Some(b)) = (actual, c.value.as_ref()) else {
        return false;
    };
    match c.op {
        Op::Eq => a == b,
        Op::Ne => std::mem::discriminant(a) == std::mem::discriminant(b) && a != b,
        Op::InList => b.as_array().is_some_and(|l| l.contains(a)),
        Op::NotInList => b.as_array().is_some_and(|l| {
            l.iter()
                .all(|v| std::mem::discriminant(a) == std::mem::discriminant(v))
                && !l.contains(a)
        }),
        Op::Gt | Op::Gte | Op::Lt | Op::Lte => {
            let (Some(a), Some(b)) = (a.as_u64(), b.as_u64()) else {
                return false;
            };
            match c.op {
                Op::Gt => a > b,
                Op::Gte => a >= b,
                Op::Lt => a < b,
                Op::Lte => a <= b,
                _ => false,
            }
        }
        Op::Present | Op::Absent => false,
    }
}
/// Requires fields validated against the contract. Legacy Observe rules cannot block.
pub fn evaluate(
    policy: Option<&Policy>,
    key: Uuid,
    fields: &BTreeMap<String, Value>,
    legacy: Action,
    mode: Mode,
) -> (Action, String) {
    evaluate_with_principal(policy, key, fields, legacy, mode, None)
}
pub fn evaluate_with_principal(
    policy: Option<&Policy>,
    key: Uuid,
    fields: &BTreeMap<String, Value>,
    legacy: Action,
    mode: Mode,
    principal: Option<&tracelane_audit_verifier::action::Principal>,
) -> (Action, String) {
    if policy.is_some_and(|p| p.require_principal)
        && principal.is_none_or(|p| p.validate().is_err())
    {
        return (Action::Deny, "principal_required".into());
    }
    let matched = policy
        .filter(|p| p.agents.as_ref().is_none_or(|a| a.contains(&key)))
        .and_then(|p| {
            p.rules.iter().find(|r| {
                r.when
                    .iter()
                    .all(|c| matches(c, fields, principal, p.require_principal))
            })
        });
    let (protected, id) =
        matched.map_or((Action::Deny, "default"), |r| (r.decision, r.id.as_str()));
    (
        if mode == Mode::Enforce {
            protected.max(legacy)
        } else {
            protected
        },
        id.into(),
    )
}
pub fn intent_digest(
    tenant: &TenantId,
    key: Uuid,
    contract: &Contract,
    version: u32,
    raw: &str,
) -> Result<String> {
    ensure!(valid_version(version), "contract_invalid");
    intent_digest_optional(tenant, key, contract, Some(version), raw)
}
pub(super) fn intent_digest_optional(
    tenant: &TenantId,
    key: Uuid,
    contract: &Contract,
    version: Option<u32>,
    raw: &str,
) -> Result<String> {
    intent_digest_bound(tenant, key, contract, version, raw, None)
}
pub(super) fn intent_digest_bound(
    tenant: &TenantId,
    key: Uuid,
    contract: &Contract,
    version: Option<u32>,
    raw: &str,
    principal_digest: Option<&str>,
) -> Result<String> {
    let args = bounded_json(raw)?;
    let f = fields(contract, &serde_json::from_str(&args)?)?;
    let mut intent = json!({"tenant_id":tenant.to_string(),"agent_key_id":key,
        "tool":{"server_id":contract.server_id,"name":contract.tool_name,"tool_ref":contract.tool_ref},
        "contract_version":contract.version,"fields":f,"args_digest":sha(args.as_bytes()),"policy_version":version});
    if let Some(digest) = principal_digest {
        crate::db::ledger::decode_hash_hex(digest)?;
        intent["principal_digest"] = json!(digest);
    }
    Ok(sha(canonical(&intent)?.as_bytes()))
}
#[cfg(test)]
#[path = "policy_tests.rs"]
mod policy_tests;
