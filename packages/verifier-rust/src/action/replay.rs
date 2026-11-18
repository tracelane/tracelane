//! Offline policy replay (ACT-18): re-run the recorded policy on the recorded evidence.
//!
//! Mirrors `crates/gateway/src/action_control/policy.rs` `evaluate`/`matches`. The gateway
//! test `verifier_replay_parity` holds the two in step. Values are known only for `Clear`
//! evidence; tokenized and digest-only fields are known to be present, their values opaque.
use super::{Decision, EvidenceField, Principal};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // fields are read for schema strictness, not all used by replay
struct Policy {
    #[serde(default)]
    require_principal: bool,
    approval_ttl_secs: Option<u32>,
    policy_id: Uuid,
    version: u32,
    rules: Vec<Rule>,
    agents: Option<Vec<Uuid>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    id: String,
    when: Vec<Condition>,
    decision: Decision,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Condition {
    field: String,
    op: Op,
    value: Option<Value>,
}
#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Op {
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct Contract {
    tool_ref: Uuid,
    server_id: Uuid,
    tool_name: String,
    version: u32,
    protected: bool,
    fields: BTreeMap<String, Value>,
}

/// Result of replaying one recorded decision.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The recorded rule and decision follow from the policy and evidence.
    Match,
    /// The outcome depends on a field whose value is not in the evidence.
    NotReplayable,
}

/// `None` = the evidence cannot decide (opaque value).
type Known = Option<bool>;

fn rank(d: &Decision) -> u8 {
    match d {
        Decision::Allow => 0,
        Decision::RequireApproval => 1,
        Decision::Deny => 2,
    }
}

fn value(field: &EvidenceField) -> Option<Value> {
    use super::{ClearValue, EvidenceField::*};
    match field {
        Clear { value } => Some(match value {
            ClearValue::MinorUnits(n) => json!(n),
            ClearValue::Currency(_) => json!("USD"),
            ClearValue::Boolean(b) => json!(b),
        }),
        Tokenize { .. } | DigestOnly { .. } => None,
    }
}

/// Same semantics as the gateway `matches` (`policy.rs:191`) on a known value.
fn matches_value(op: Op, a: &Value, b: &Value) -> bool {
    use std::mem::discriminant as d;
    match op {
        Op::Eq => a == b,
        Op::Ne => d(a) == d(b) && a != b,
        Op::InList => b.as_array().is_some_and(|l| l.contains(a)),
        Op::NotInList => b
            .as_array()
            .is_some_and(|l| l.iter().all(|v| d(a) == d(v)) && !l.contains(a)),
        Op::Gt | Op::Gte | Op::Lt | Op::Lte => {
            let (Some(a), Some(b)) = (a.as_u64(), b.as_u64()) else {
                return false;
            };
            match op {
                Op::Gt => a > b,
                Op::Gte => a >= b,
                Op::Lt => a < b,
                _ => a <= b,
            }
        }
        Op::Present | Op::Absent => false,
    }
}

fn condition(
    c: &Condition,
    evidence: &BTreeMap<String, EvidenceField>,
    principal: Option<&Principal>,
    reserved: bool,
) -> Known {
    if c.field == "principal.roles" && reserved {
        return Some(
            principal
                .zip(c.value.as_ref())
                .is_some_and(|(p, v)| match c.op {
                    Op::InList => p.matches_roles(v, false),
                    Op::NotInList => p.matches_roles(v, true),
                    _ => false,
                }),
        );
    }
    let actual = evidence.get(&c.field);
    match c.op {
        Op::Present => return Some(actual.is_some()),
        Op::Absent => return Some(actual.is_none()),
        _ => {}
    }
    let (Some(field), Some(literal)) = (actual, c.value.as_ref()) else {
        return Some(false);
    };
    value(field).map(|v| matches_value(c.op, &v, literal))
}

fn rule(
    r: &Rule,
    evidence: &BTreeMap<String, EvidenceField>,
    principal: Option<&Principal>,
    reserved: bool,
) -> Known {
    let mut unknown = false;
    for c in &r.when {
        match condition(c, evidence, principal, reserved) {
            Some(false) => return Some(false),
            None => unknown = true,
            Some(true) => {}
        }
    }
    if unknown { None } else { Some(true) }
}

/// Replays one `DecisionMade`. Errors fail CLOSED: a malformed artifact or a decision the
/// policy cannot produce fails the bundle.
pub fn replay(
    policy: &[u8],
    contract: &[u8],
    key: Option<Uuid>,
    evidence: &BTreeMap<String, EvidenceField>,
    recorded: &Decision,
    recorded_rule: &str,
) -> anyhow::Result<Outcome> {
    replay_with_principal(
        policy,
        contract,
        key,
        evidence,
        None,
        recorded,
        recorded_rule,
    )
}
/// Replay a gateway-attested principal without fetching identity material.
/// Errors fail CLOSED on malformed evidence or a mismatching decision.
pub fn replay_with_principal(
    policy: &[u8],
    contract: &[u8],
    key: Option<Uuid>,
    evidence: &BTreeMap<String, EvidenceField>,
    principal: Option<&Principal>,
    recorded: &Decision,
    recorded_rule: &str,
) -> anyhow::Result<Outcome> {
    use anyhow::{Context, ensure};
    if let Some(p) = principal {
        p.validate()?;
    }
    let policy: Policy = serde_json::from_slice(policy).context("unverifiable policy artifact")?;
    let contract: Contract =
        serde_json::from_slice(contract).context("unverifiable policy artifact")?;
    ensure!(
        evidence.keys().all(|k| contract.fields.contains_key(k)),
        "evidence does not match contract"
    );
    // The gateway records every present field in its contract mode (`execution.rs:422-455`);
    // a missing required field or a mode mismatch would make `absent`/`present` rules lie.
    for (name, field) in &contract.fields {
        let mode = evidence.get(name).map(|e| match e {
            EvidenceField::Clear { .. } => "clear",
            EvidenceField::Tokenize { .. } => "tokenize",
            EvidenceField::DigestOnly { .. } => "digest_only",
        });
        ensure!(
            mode.is_some() || field["required"] != json!(true),
            "evidence does not match contract"
        );
        ensure!(
            mode.is_none_or(|m| field["evidence"] == json!(m)),
            "evidence does not match contract"
        );
    }
    ensure!(
        policy
            .rules
            .iter()
            .flat_map(|r| &r.when)
            .filter(|c| c.field == "principal.roles" && policy.require_principal)
            .all(|c| policy.require_principal
                && matches!(c.op, Op::InList | Op::NotInList)
                && c.value
                    .as_ref()
                    .and_then(Value::as_array)
                    .is_some_and(|a| a.iter().all(Value::is_string))),
        "invalid principal policy"
    );
    if policy.require_principal && principal.is_none() {
        ensure!(
            matches!(recorded, Decision::Deny) && recorded_rule == "principal_required",
            "missing required principal"
        );
        return Ok(Outcome::Match);
    }
    let eligible = match (&policy.agents, key) {
        (None, _) => true,
        (Some(list), Some(k)) => list.contains(&k),
        (Some(_), None) => return Ok(Outcome::NotReplayable),
    };
    // Every (decision, rule) the policy could have produced. One entry when the evidence
    // decides every rule up to the match; several when an opaque value leaves rules open.
    // A record outside this set fails even when the outcome is not fully replayable.
    let mut candidates: Vec<(&Decision, &str)> = Vec::new();
    let mut undecided = false;
    let mut closed = false;
    if eligible {
        for r in &policy.rules {
            match rule(r, evidence, principal, policy.require_principal) {
                Some(false) => continue,
                Some(true) => {
                    candidates.push((&r.decision, r.id.as_str()));
                    closed = true;
                    break;
                }
                None => {
                    undecided = true;
                    candidates.push((&r.decision, r.id.as_str()));
                }
            }
        }
    }
    if !closed {
        candidates.push((&Decision::Deny, "default"));
    }
    ensure!(
        candidates
            .iter()
            .any(|(d, id)| *id == recorded_rule && rank(recorded) >= rank(d)),
        "policy replay mismatch"
    );
    Ok(if undecided {
        Outcome::NotReplayable
    } else {
        Outcome::Match
    })
}

#[cfg(test)]
mod tests {
    use super::super::{ClearValue, Usd};
    use super::*;

    const AGENT: Uuid = Uuid::from_u128(7);

    fn contract() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "tool_ref": Uuid::from_u128(1), "server_id": Uuid::from_u128(2),
            "tool_name": "pay", "version": 1, "protected": true,
            "fields": {
                "amount": {"path":"/amount","kind":"minor_units","required":true,"evidence":"clear"},
                "currency": {"path":"/currency","kind":"currency","required":false,"evidence":"clear"},
                "recipient": {"path":"/to","kind":"string","required":false,"evidence":"tokenize"},
                "memo": {"path":"/memo","kind":"string","required":false,"evidence":"digest_only"}
            }
        }))
        .unwrap()
    }
    fn policy(rules: Value, agents: Value) -> Vec<u8> {
        serde_json::to_vec(
            &json!({"approval_ttl_secs": null, "policy_id": Uuid::from_u128(3),
            "version": 1, "rules": rules, "agents": agents}),
        )
        .unwrap()
    }
    fn threshold() -> Vec<u8> {
        policy(
            json!([
                {"id":"small","when":[{"field":"amount","op":"lt","value":10000}],"decision":"allow"},
                {"id":"big","when":[{"field":"amount","op":"gte","value":10000}],"decision":"require_approval"}
            ]),
            Value::Null,
        )
    }
    fn amount(n: u64) -> BTreeMap<String, EvidenceField> {
        BTreeMap::from([(
            "amount".to_string(),
            EvidenceField::Clear {
                value: ClearValue::MinorUnits(n),
            },
        )])
    }
    fn tokenized(mut e: BTreeMap<String, EvidenceField>) -> BTreeMap<String, EvidenceField> {
        e.insert(
            "recipient".into(),
            EvidenceField::Tokenize {
                hmac: "aa".into(),
                last4: "1234".into(),
            },
        );
        e
    }
    fn run(
        p: &[u8],
        e: &BTreeMap<String, EvidenceField>,
        d: Decision,
        r: &str,
    ) -> anyhow::Result<Outcome> {
        replay(p, &contract(), Some(AGENT), e, &d, r)
    }

    #[test]
    fn allow_rule_replays() {
        assert_eq!(
            run(&threshold(), &amount(500), Decision::Allow, "small").unwrap(),
            Outcome::Match
        );
    }
    #[test]
    fn approval_rule_replays() {
        assert_eq!(
            run(
                &threshold(),
                &amount(10000),
                Decision::RequireApproval,
                "big"
            )
            .unwrap(),
            Outcome::Match
        );
    }
    #[test]
    fn default_deny_replays() {
        let p = policy(
            json!([{"id":"x","when":[{"field":"amount","op":"eq","value":1}],"decision":"allow"}]),
            Value::Null,
        );
        assert_eq!(
            run(&p, &amount(2), Decision::Deny, "default").unwrap(),
            Outcome::Match
        );
    }
    #[test]
    fn agent_filter_replays() {
        let p = policy(
            json!([{"id":"any","when":[],"decision":"allow"}]),
            json!([Uuid::from_u128(99)]),
        );
        assert_eq!(
            run(&p, &amount(1), Decision::Deny, "default").unwrap(),
            Outcome::Match
        );
        assert!(run(&p, &amount(1), Decision::Allow, "any").is_err());
    }
    #[test]
    fn present_on_opaque_is_known() {
        let p = policy(
            json!([{"id":"has","when":[{"field":"recipient","op":"present"}],"decision":"require_approval"}]),
            Value::Null,
        );
        assert_eq!(
            run(&p, &tokenized(amount(1)), Decision::RequireApproval, "has").unwrap(),
            Outcome::Match
        );
    }
    #[test]
    fn absent_field_is_false() {
        let p = policy(
            json!([
                {"id":"usd","when":[{"field":"currency","op":"eq","value":"USD"}],"decision":"allow"},
                {"id":"rest","when":[],"decision":"require_approval"}
            ]),
            Value::Null,
        );
        assert_eq!(
            run(&p, &amount(1), Decision::RequireApproval, "rest").unwrap(),
            Outcome::Match
        );
    }
    #[test]
    fn false_short_circuits_unknown() {
        let p = policy(
            json!([
                {"id":"a","when":[{"field":"recipient","op":"eq","value":"x"},{"field":"amount","op":"gt","value":100}],"decision":"deny"},
                {"id":"b","when":[],"decision":"allow"}
            ]),
            Value::Null,
        );
        assert_eq!(
            run(&p, &tokenized(amount(5)), Decision::Allow, "b").unwrap(),
            Outcome::Match
        );
    }
    #[test]
    fn stricter_record_accepted() {
        assert_eq!(
            run(&threshold(), &amount(5), Decision::Deny, "small").unwrap(),
            Outcome::Match
        );
    }
    #[test]
    fn in_list_currency() {
        let p = policy(
            json!([{"id":"c","when":[{"field":"currency","op":"in_list","value":["USD"]}],"decision":"allow"}]),
            Value::Null,
        );
        let mut e = amount(1);
        e.insert(
            "currency".into(),
            EvidenceField::Clear {
                value: ClearValue::Currency(Usd::Usd),
            },
        );
        assert_eq!(run(&p, &e, Decision::Allow, "c").unwrap(), Outcome::Match);
    }
    #[test]
    fn opaque_is_not_replayable() {
        let p = policy(
            json!([{"id":"vendor","when":[{"field":"memo","op":"eq","value":"rent"}],"decision":"allow"}]),
            Value::Null,
        );
        let mut e = amount(1);
        e.insert(
            "memo".into(),
            EvidenceField::DigestOnly {
                sha256: "00".into(),
            },
        );
        assert_eq!(
            run(&p, &e, Decision::Allow, "vendor").unwrap(),
            Outcome::NotReplayable
        );
    }
    #[test]
    fn wrong_rule_rejected() {
        let err = run(&threshold(), &amount(5), Decision::Allow, "big").unwrap_err();
        assert!(err.to_string().contains("policy replay mismatch"));
    }
    #[test]
    fn weaker_decision_rejected() {
        assert!(run(&threshold(), &amount(20000), Decision::Allow, "big").is_err());
    }
    #[test]
    fn allow_over_default_rejected() {
        let p = policy(json!([]), Value::Null);
        assert!(run(&p, &amount(1), Decision::Allow, "default").is_err());
    }
    #[test]
    fn gt_on_non_number_false() {
        assert!(!matches_value(Op::Gt, &json!(5), &json!("4")));
        assert!(!matches_value(Op::Lte, &json!("USD"), &json!(4)));
    }
    #[test]
    fn ne_across_types_false() {
        assert!(!matches_value(Op::Ne, &json!(5), &json!("5")));
        assert!(matches_value(Op::Ne, &json!(5), &json!(6)));
    }
    #[test]
    fn not_in_list_mixed_false() {
        assert!(!matches_value(Op::NotInList, &json!(5), &json!([1, "x"])));
        assert!(matches_value(Op::NotInList, &json!(5), &json!([1, 2])));
    }
    #[test]
    fn unknown_policy_field_rejected() {
        let p = serde_json::to_vec(
            &json!({"approval_ttl_secs":null,"policy_id":Uuid::from_u128(3),
            "version":1,"rules":[],"agents":null,"extra":1}),
        )
        .unwrap();
        let err = run(&p, &amount(1), Decision::Deny, "default").unwrap_err();
        assert!(err.to_string().contains("unverifiable policy artifact"));
    }
    #[test]
    fn bad_contract_rejected() {
        let err = replay(
            &threshold(),
            b"{\"tool_ref\":1}",
            Some(AGENT),
            &amount(1),
            &Decision::Allow,
            "small",
        )
        .unwrap_err();
        assert!(err.to_string().contains("unverifiable policy artifact"));
    }
    #[test]
    fn missing_literal_false() {
        let p = policy(
            json!([
                {"id":"x","when":[{"field":"amount","op":"eq","value":null}],"decision":"allow"},
                {"id":"y","when":[],"decision":"deny"}
            ]),
            Value::Null,
        );
        assert_eq!(
            run(&p, &amount(1), Decision::Deny, "y").unwrap(),
            Outcome::Match
        );
    }
    #[test]
    fn agents_without_key_unknown() {
        let p = policy(
            json!([{"id":"any","when":[],"decision":"allow"}]),
            json!([AGENT]),
        );
        assert_eq!(
            replay(&p, &contract(), None, &amount(1), &Decision::Allow, "any").unwrap(),
            Outcome::NotReplayable
        );
    }
    #[test]
    fn undecided_still_rejects_impossible_records() {
        // Review finding (Medium): an opaque rule must not hide a record the policy cannot produce.
        let p = policy(
            json!([
                {"id":"A","when":[{"field":"amount","op":"gt","value":100}],"decision":"allow"},
                {"id":"B","when":[{"field":"recipient","op":"eq","value":"x"}],"decision":"deny"},
                {"id":"C","when":[],"decision":"allow"}
            ]),
            Value::Null,
        );
        let e = tokenized(amount(5));
        for (d, r) in [
            (Decision::Allow, "B"),
            (Decision::Allow, "A"),
            (Decision::Deny, "default"),
            (Decision::Allow, "nope"),
        ] {
            assert!(run(&p, &e, d, r).is_err(), "{r}");
        }
        assert_eq!(
            run(&p, &e, Decision::Deny, "B").unwrap(),
            Outcome::NotReplayable
        );
        assert_eq!(
            run(&p, &e, Decision::Allow, "C").unwrap(),
            Outcome::NotReplayable
        );
    }
    #[test]
    fn missing_required_field_rejected() {
        let err = run(&threshold(), &BTreeMap::new(), Decision::Deny, "default").unwrap_err();
        assert!(err.to_string().contains("evidence does not match contract"));
    }
    #[test]
    fn evidence_mode_mismatch_rejected() {
        let mut e = amount(1);
        e.insert(
            "memo".into(),
            EvidenceField::Clear {
                value: ClearValue::Boolean(true),
            },
        );
        assert!(run(&threshold(), &e, Decision::Allow, "small").is_err());
    }
    #[test]
    fn evidence_outside_contract_rejected() {
        let mut e = amount(1);
        e.insert(
            "ghost".into(),
            EvidenceField::DigestOnly {
                sha256: "00".into(),
            },
        );
        assert!(run(&threshold(), &e, Decision::Allow, "small").is_err());
    }
}

#[cfg(test)]
#[test]
fn historical_principal_named_contract_field_replays() {
    let p = serde_json::to_vec(&json!({"policy_id":Uuid::nil(),"version":1,"rules":[{"id":"legacy","when":[{"field":"principal.roles","op":"present"}],"decision":"allow"}]})).unwrap();
    let c = serde_json::to_vec(&json!({"tool_ref":Uuid::nil(),"server_id":Uuid::nil(),"tool_name":"pay","version":1,"protected":true,"fields":{"principal.roles":{"path":"/label","kind":"string","required":false,"evidence":"digest_only"}}})).unwrap();
    let evidence = BTreeMap::from([(
        "principal.roles".into(),
        EvidenceField::DigestOnly {
            sha256: "00".repeat(32),
        },
    )]);
    assert_eq!(
        replay(
            &p,
            &c,
            Some(Uuid::nil()),
            &evidence,
            &Decision::Allow,
            "legacy"
        )
        .unwrap(),
        Outcome::Match
    );
}
