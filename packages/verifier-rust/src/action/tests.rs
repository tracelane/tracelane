use super::*;
use serde_json::json;
fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
// Full policy/contract artifacts: the verifier replays them (ACT-18).
fn policy_doc(version: u32) -> String {
    canonical_json(&json!({"approval_ttl_secs":null,"policy_id":id(3),"version":version,"agents":null,
        "rules":[{"id":"small","when":[{"field":"amount","op":"lt","value":100}],"decision":"allow"},
                 {"id":"review","when":[],"decision":"require_approval"}]}).to_string()).unwrap()
}
fn contract_doc(tool: Uuid, protected: bool) -> String {
    canonical_json(&json!({"tool_ref":tool,"server_id":id(9),"tool_name":"pay","version":1,"protected":protected,
        "fields":{"amount":{"path":"/amount","kind":"minor_units","required":false,"evidence":"clear"}}}).to_string()).unwrap()
}
/// Turn the fixture's decision into a replayable Allow (amount below the `small` threshold).
fn allow(e: &mut [Envelope]) {
    if let ActionPayload::ActionProposed {
        evidence_fields, ..
    } = &mut e[1].body
    {
        evidence_fields.insert(
            "amount".into(),
            EvidenceField::Clear {
                value: ClearValue::MinorUnits(5),
            },
        );
    }
    if let ActionPayload::DecisionMade {
        decision, rule_id, ..
    } = &mut e[2].body
    {
        *decision = Decision::Allow;
        *rule_id = "small".into();
    }
}
pub(super) fn fixture() -> (Vec<Envelope>, BTreeMap<String, Vec<u8>>) {
    let policy = policy_doc(1);
    let contract = contract_doc(id(4), true);
    let ph = hex::encode(crate::sha256(policy.as_bytes()));
    let ch = hex::encode(crate::sha256(contract.as_bytes()));
    let bodies = vec![
        json!({"event_type":"policy_activated","policy_id":id(3),"version":1,"policy_hash":ph,"publisher_digest":"a".repeat(64),"tool_ref":id(4),"contract_version":1,"contract_hash":ch,"protected":true}),
        json!({"event_type":"action_proposed","tool_ref":id(4),"contract_version":1,"args_digest":"a".repeat(64),"evidence_fields":{},"agent_claimed_labels":{}}),
        json!({"event_type":"decision_made","decision":"require_approval","rule_id":"review","reason_codes":["approval_required"],"policy_id":id(3),"policy_version":1,"policy_hash":ph}),
        json!({"event_type":"approval_requested","approval_id":id(5),"required_role":"admin","expires_at":"2026-10-30T12:15:00Z"}),
        json!({"event_type":"approval_granted","approval_id":id(5),"decider_digest":"b".repeat(64),"note_digest":"c".repeat(64)}),
        json!({"event_type":"approval_consumed","approval_id":id(5)}),
        json!({"event_type":"execution_started","execution_id":id(6),"idempotency_key":id(7),"attestation_key_id":"a".repeat(64)}),
        json!({"event_type":"execution_succeeded","execution_id":id(6),"receipt_digest":"d".repeat(64)}),
    ];
    let events = bodies.into_iter().enumerate().map(|(i, body)| serde_json::from_value(json!({"schema_version":1,"event_id":id(20+i as u128),"action_id":if i==0 {id(3)} else {id(2)},"tenant_id":id(1),"agent_key_id":if i==0 || i==4 {None} else {Some(id(8))},"occurred_at":"2026-10-30T12:00:00Z","request_digest":if i==0 {ph.clone()} else {"e".repeat(64)},"body":body})).unwrap()).collect();
    (
        events,
        [(ph, policy.into_bytes()), (ch, contract.into_bytes())].into(),
    )
}
#[test]
fn clean_semantics() {
    let (e, a) = fixture();
    assert!(semantics(&e, &a).is_ok());
}
#[test]
fn consumed_without_approved() {
    let (mut e, a) = fixture();
    e.remove(4);
    assert_eq!(
        semantics(&e, &a).unwrap_err().to_string(),
        "approval not approved, expired or consumed"
    );
}
#[test]
fn mutated_digest() {
    let (mut e, a) = fixture();
    e[6].request_digest = "f".repeat(64);
    assert_eq!(
        semantics(&e, &a).unwrap_err().to_string(),
        "action digest/time mismatch"
    );
}
#[test]
fn outcome_without_start() {
    let (mut e, a) = fixture();
    e.remove(6);
    assert_eq!(
        semantics(&e, &a).unwrap_err().to_string(),
        "outcome without unique start"
    );
}
#[test]
fn expired_approval() {
    let (mut e, a) = fixture();
    for event in &mut e[5..] {
        event.occurred_at = "2026-10-30T12:15:00Z".parse().unwrap();
    }
    assert_eq!(
        semantics(&e, &a).unwrap_err().to_string(),
        "approval not approved, expired or consumed"
    );
}
#[test]
fn double_consume() {
    let (mut e, a) = fixture();
    let mut duplicate = e[5].clone();
    duplicate.event_id = id(99);
    e.insert(6, duplicate);
    assert_eq!(
        semantics(&e, &a).unwrap_err().to_string(),
        "approval not approved, expired or consumed"
    );
}
#[test]
fn policy_outside_range() {
    let (mut e, a) = fixture();
    e.remove(0);
    assert_eq!(
        semantics(&e, &a).unwrap_err().to_string(),
        "policy reference outside range"
    );
}
#[test]
fn artifact_tamper() {
    let (e, mut a) = fixture();
    a.values_mut().next().unwrap().push(b' ');
    assert_eq!(
        semantics(&e, &a).unwrap_err().to_string(),
        "artifact hash mismatch"
    );
}
#[test]
fn wrong_policy() {
    let (mut e, a) = fixture();
    if let ActionPayload::DecisionMade { policy_hash, .. } = &mut e[2].body {
        *policy_hash = "f".repeat(64)
    }
    assert_eq!(
        semantics(&e, &a).unwrap_err().to_string(),
        "policy binding mismatch"
    );
}
#[test]
fn unknown_is_unknown() {
    let (mut e, a) = fixture();
    e[7].body = ActionPayload::ExecutionUnknown {
        execution_id: id(6),
        receipt_digest: None,
    };
    assert_eq!(semantics(&e, &a).unwrap().unknown, vec![id(6)]);
}
#[test]
fn denied_is_denied() {
    let (mut e, a) = fixture();
    e.truncate(5);
    if let ActionPayload::ApprovalGranted {
        approval_id,
        decider_digest,
        note_digest,
        ..
    } = &e[4].body
    {
        e[4].body = ActionPayload::ApprovalDenied {
            approval_id: *approval_id,
            decider_digest: decider_digest.clone(),
            note_digest: note_digest.clone(),
            channel: None,
            link_digest: None,
        }
    }
    assert_eq!(semantics(&e, &a).unwrap().denied, vec![id(5)]);
}
#[test]
fn denied_never_consumes() {
    let (mut e, a) = fixture();
    e[4].body = ActionPayload::ApprovalDenied {
        approval_id: id(5),
        decider_digest: "b".repeat(64),
        note_digest: "c".repeat(64),
        channel: None,
        link_digest: None,
    };
    assert_eq!(
        semantics(&e, &a).unwrap_err().to_string(),
        "approval not approved, expired or consumed"
    );
}
#[test]
fn schema_extra_field() {
    let (e, _) = fixture();
    for event in e {
        let mut v = serde_json::to_value(event).unwrap();
        v["body"]["raw_args"] = json!({});
        assert!(
            serde_json::from_value::<Envelope>(v)
                .err()
                .unwrap()
                .to_string()
                .contains("unknown field `raw_args`")
        );
    }
}
#[test]
fn envelope_extra_field() {
    let (e, _) = fixture();
    let mut v = serde_json::to_value(&e[1]).unwrap();
    v["raw_args"] = json!({});
    assert!(
        serde_json::from_value::<Envelope>(v)
            .err()
            .unwrap()
            .to_string()
            .contains("unknown field `raw_args`")
    );
}
#[test]
fn execution_requires_consume() {
    let (mut e, a) = fixture();
    e.remove(5);
    assert_eq!(
        semantics(&e, &a).unwrap_err().to_string(),
        "execution lacks permission/consume"
    );
}
#[test]
fn allow_without_approval() {
    let (mut e, a) = fixture();
    allow(&mut e);
    e.drain(3..6);
    assert!(semantics(&e, &a).is_ok());
}
#[test]
fn missing_artifact() {
    let (e, _) = fixture();
    assert_eq!(
        semantics(&e, &BTreeMap::new()).unwrap_err().to_string(),
        "missing original policy"
    );
}
#[test]
fn event_time_order() {
    let (mut e, a) = fixture();
    e[5].occurred_at = "2026-10-29T12:00:00Z".parse().unwrap();
    assert_eq!(
        semantics(&e, &a).unwrap_err().to_string(),
        "action digest/time mismatch"
    );
}
#[test]
fn actor_key_mutation() {
    let (mut e, a) = fixture();
    e[6].agent_key_id = Some(id(99));
    assert_eq!(
        semantics(&e, &a).unwrap_err().to_string(),
        "agent binding mismatch"
    );
}
#[test]
fn foreign_action_reference() {
    let (mut e, a) = fixture();
    e[5].action_id = id(99);
    assert_eq!(
        semantics(&e, &a).unwrap_err().to_string(),
        "action reference outside range"
    );
}

#[test]
fn legacy_float_unverifiable() {
    assert_eq!(
        canonical_json(r#"{"amount":1.0}"#).unwrap_err().to_string(),
        "floats are outside the action contract"
    );
}

fn two_actions() -> (Vec<Envelope>, BTreeMap<String, Vec<u8>>) {
    let (mut events, artifacts) = fixture();
    let mut second = events[1..].to_vec();
    for event in &mut second {
        event.event_id = id(event.event_id.as_u128() + 100);
        event.action_id = id(102);
        match &mut event.body {
            ActionPayload::ApprovalRequested { approval_id, .. }
            | ActionPayload::ApprovalGranted { approval_id, .. }
            | ActionPayload::ApprovalConsumed { approval_id } => *approval_id = id(105),
            ActionPayload::ExecutionStarted {
                execution_id,
                idempotency_key,
                ..
            } => {
                *execution_id = id(106);
                *idempotency_key = id(107);
            }
            ActionPayload::ExecutionSucceeded { execution_id, .. } => *execution_id = id(106),
            _ => {}
        }
    }
    events.extend(second);
    (events, artifacts)
}
#[test]
fn distinct_executions_pass() {
    let (events, artifacts) = two_actions();
    semantics(&events, &artifacts).unwrap();
}
#[test]
fn shared_idempotency_key_rejects_double_execution() {
    let (mut events, artifacts) = two_actions();
    if let ActionPayload::ExecutionStarted {
        idempotency_key, ..
    } = &mut events[13].body
    {
        *idempotency_key = id(7);
    }
    assert_eq!(
        semantics(&events, &artifacts).unwrap_err().to_string(),
        "duplicate tenant idempotency key"
    );
}
#[test]
fn shared_execution_id_rejects_double_execution() {
    let (mut events, artifacts) = two_actions();
    for event in &mut events[13..] {
        match &mut event.body {
            ActionPayload::ExecutionStarted { execution_id, .. }
            | ActionPayload::ExecutionSucceeded { execution_id, .. } => *execution_id = id(6),
            _ => {}
        }
    }
    assert_eq!(
        semantics(&events, &artifacts).unwrap_err().to_string(),
        "duplicate tenant execution ID"
    );
}
#[test]
fn publisher_cannot_approve() {
    let (mut events, artifacts) = fixture();
    if let ActionPayload::ApprovalGranted { decider_digest, .. } = &mut events[4].body {
        *decider_digest = "a".repeat(64);
    }
    assert_eq!(
        semantics(&events, &artifacts).unwrap_err().to_string(),
        "approval decider matches policy publisher"
    );
}
#[test]
fn publisher_cannot_deny() {
    let (mut events, artifacts) = fixture();
    events.truncate(5);
    events[4].body = ActionPayload::ApprovalDenied {
        approval_id: id(5),
        decider_digest: "a".repeat(64),
        note_digest: "c".repeat(64),
        channel: None,
        link_digest: None,
    };
    assert_eq!(
        semantics(&events, &artifacts).unwrap_err().to_string(),
        "approval decider matches policy publisher"
    );
}

// A newer activation has distinct original bytes and may change protection.
fn activate_newer(
    events: &mut Vec<Envelope>,
    artifacts: &mut BTreeMap<String, Vec<u8>>,
    at: usize,
    tool: Uuid,
) {
    let policy = policy_doc(2);
    let contract = contract_doc(tool, false);
    let ph = hex::encode(crate::sha256(policy.as_bytes()));
    let ch = hex::encode(crate::sha256(contract.as_bytes()));
    let mut activation = events[0].clone();
    activation.event_id = id(200);
    activation.request_digest = ph.clone();
    activation.body = ActionPayload::PolicyActivated {
        policy_id: id(3),
        version: 2,
        policy_hash: ph.clone(),
        publisher_digest: "a".repeat(64),
        tool_ref: tool,
        contract_version: 1,
        contract_hash: ch.clone(),
        protected: false,
    };
    artifacts.insert(ph, policy.into_bytes());
    artifacts.insert(ch, contract.into_bytes());
    events.insert(at, activation);
}
#[test]
fn stale_policy_decision_is_rejected() {
    let (mut e, mut a) = fixture();
    activate_newer(&mut e, &mut a, 2, id(4));
    assert_eq!(
        semantics(&e, &a).unwrap_err().to_string(),
        "decision does not cite latest tool activation"
    );
}
#[test]
fn stale_policy_consume_is_rejected() {
    let (mut e, mut a) = fixture();
    activate_newer(&mut e, &mut a, 5, id(4));
    assert_eq!(
        semantics(&e, &a).unwrap_err().to_string(),
        "approval superseded by tool activation"
    );
}
#[test]
fn stale_policy_start_is_rejected() {
    let (mut e, mut a) = fixture();
    activate_newer(&mut e, &mut a, 6, id(4));
    assert_eq!(
        semantics(&e, &a).unwrap_err().to_string(),
        "execution superseded by tool activation"
    );
}
#[test]
fn stale_allow_start_is_rejected() {
    let (mut e, mut a) = fixture();
    allow(&mut e);
    e.drain(3..6);
    activate_newer(&mut e, &mut a, 3, id(4));
    assert_eq!(
        semantics(&e, &a).unwrap_err().to_string(),
        "execution superseded by tool activation"
    );
}
#[test]
fn activation_after_start_does_not_retroactively_reject_outcome() {
    let (mut e, mut a) = fixture();
    activate_newer(&mut e, &mut a, 7, id(4));
    semantics(&e, &a).unwrap();
}
#[test]
fn another_tool_activation_does_not_supersede_grant() {
    let (mut e, mut a) = fixture();
    activate_newer(&mut e, &mut a, 5, id(400));
    semantics(&e, &a).unwrap();
}
#[test]
fn superseded_pending_approval_can_be_invalidated() {
    let (mut e, mut a) = fixture();
    e.truncate(4);
    let mut invalidation = e[3].clone();
    invalidation.event_id = id(201);
    invalidation.body = ActionPayload::ApprovalInvalidated { approval_id: id(5) };
    activate_newer(&mut e, &mut a, 4, id(4));
    e.push(invalidation);
    semantics(&e, &a).unwrap();
}
#[test]
fn replay_counts_decisions() {
    let (e, a) = fixture();
    let s = semantics(&e, &a).unwrap();
    assert_eq!((s.replayed, s.not_replayable.len()), (1, 0));
}
#[test]
fn semantics_rejects_tampered_decision() {
    let (mut e, a) = fixture();
    if let ActionPayload::DecisionMade { decision, .. } = &mut e[2].body {
        *decision = Decision::Allow;
    }
    e.drain(3..6);
    assert_eq!(
        semantics(&e, &a).unwrap_err().to_string(),
        "policy replay mismatch"
    );
}

#[test]
fn principal_envelope_roundtrip() {
    let body = json!({"event_type":"action_proposed", "tool_ref":id(1),
        "contract_version":1,"args_digest":"a".repeat(64),"evidence_fields":{},
        "agent_claimed_labels":{},"principal":{"iss":"https://issuer.example",
        "sub_digest":"b".repeat(64),"roles":["treasury"]}});
    let parsed: ActionPayload =
        serde_json::from_value(body.clone()).expect("verified principal protocol");
    assert_eq!(serde_json::to_value(parsed).unwrap(), body);
}

pub(super) fn principal_fixture() -> (Vec<Envelope>, BTreeMap<String, Vec<u8>>) {
    let (mut events, mut artifacts) = fixture();
    let policy = canonical_json(
        &json!({"policy_id":id(3),"version":1,
        "require_principal":true,"rules":[{"id":"review","when":[
        {"field":"principal.roles","op":"in_list","value":["treasury"]}],
        "decision":"require_approval"}]})
        .to_string(),
    )
    .unwrap();
    let hash = hex::encode(crate::sha256(policy.as_bytes()));
    if let ActionPayload::PolicyActivated { policy_hash, .. } = &mut events[0].body {
        *policy_hash = hash.clone();
    }
    events[0].request_digest = hash.clone();
    if let ActionPayload::DecisionMade { policy_hash, .. } = &mut events[2].body {
        *policy_hash = hash.clone();
    }
    artifacts.insert(hash, policy.into_bytes());
    let mut proposed = serde_json::to_value(&events[1]).unwrap();
    proposed["schema_version"] = json!(2);
    proposed["body"]["principal"] =
        json!({"iss":"https://issuer.example", "sub_digest":"b".repeat(64),"roles":["treasury"]});
    events[1] = serde_json::from_value(proposed).unwrap();
    (events, artifacts)
}
#[test]
fn mixed_principal_versions_verify() {
    let (events, artifacts) = principal_fixture();
    let report = semantics(&events, &artifacts).unwrap();
    assert_eq!(report.replayed, 1);
    let report = serde_json::to_value(report).unwrap();
    assert_eq!(
        report["principals"][id(2).to_string()]["roles"],
        json!(["treasury"])
    );
}
#[test]
fn v1_principal_rejected() {
    let (mut events, artifacts) = principal_fixture();
    events[1].schema_version = 1;
    assert!(semantics(&events, &artifacts).is_err());
}
#[test]
fn missing_required_principal_rejected() {
    let (mut events, artifacts) = principal_fixture();
    let mut proposed = serde_json::to_value(&events[1]).unwrap();
    proposed["body"]
        .as_object_mut()
        .unwrap()
        .remove("principal");
    events[1] = serde_json::from_value(proposed).unwrap();
    assert!(semantics(&events, &artifacts).is_err());
}
#[test]
fn principal_role_mismatch_rejected() {
    let (mut events, artifacts) = principal_fixture();
    let mut proposed = serde_json::to_value(&events[1]).unwrap();
    proposed["body"]["principal"]["roles"] = json!(["sales"]);
    events[1] = serde_json::from_value(proposed).unwrap();
    assert!(semantics(&events, &artifacts).is_err());
}

#[test]
fn tool_definition_changed_reason_round_trips() {
    let body: ActionPayload = serde_json::from_value(
        serde_json::json!({"event_type":"denied_runtime","reason":"tool_definition_changed"}),
    )
    .unwrap();
    assert!(matches!(
        body,
        ActionPayload::DeniedRuntime {
            reason: ReasonCode::ToolDefinitionChanged
        }
    ));
    assert!(
        serde_json::from_value::<ActionPayload>(
            serde_json::json!({"event_type":"denied_runtime","reason":"free text"})
        )
        .is_err(),
        "the reason vocabulary stays closed"
    );
}

#[test]
fn schema_v2_rejects_non_principal_event_types() {
    let (events, artifacts) = fixture();
    for index in [0, 2] {
        let mut changed = events.clone();
        changed[index].schema_version = 2;
        assert!(semantics(&changed, &artifacts).is_err());
    }
}

#[test]
fn principal_refusal_vocabulary_requires_schema_v2() {
    let (events, _) = fixture();
    for reason in [
        ReasonCode::PrincipalRequired,
        ReasonCode::PrincipalInvalid,
        ReasonCode::PrincipalUnverifiable,
    ] {
        let mut event = events[0].clone();
        event.body = ActionPayload::DeniedRuntime { reason };
        event.schema_version = 1;
        assert!(semantics(&[event.clone()], &BTreeMap::new()).is_err());
        event.schema_version = 2;
        assert!(semantics(&[event], &BTreeMap::new()).is_ok());
    }
}

#[test]
fn workspace_paused_refusals_are_counted_and_other_reasons_are_not() {
    let (events, artifacts) = fixture();
    let refusal = |reason, n: u128| {
        let mut e = events[0].clone();
        e.body = ActionPayload::DeniedRuntime { reason };
        e.event_id = Uuid::from_u128(0xfeed_0000 + n);
        e
    };
    let mut all = events.clone();
    all.push(refusal(ReasonCode::WorkspacePaused, 1));
    all.push(refusal(ReasonCode::WorkspacePaused, 2));
    all.push(refusal(ReasonCode::ToolDefinitionChanged, 3));
    let counted = semantics(&all, &artifacts).unwrap();
    assert_eq!(counted.refused_workspace_paused, 2);
    assert_eq!(
        semantics(&events, &artifacts)
            .unwrap()
            .refused_workspace_paused,
        0
    );
}

// ---- ACT-23 schema 3: approval decisions made in a chat channel ----
/// Event 4 of the fixture is the grant; rebuild it as a Slack decision at schema 3.
fn slack_decision(deny: bool, channel: Option<Channel>, schema: u32) -> Envelope {
    let (mut e, _) = fixture();
    let mut ev = e.remove(4);
    let (approval_id, decider_digest, note_digest) = (id(5), "b".repeat(64), "c".repeat(64));
    let link_digest = channel.map(|_| "d".repeat(64));
    ev.schema_version = schema;
    ev.body = if deny {
        ActionPayload::ApprovalDenied {
            approval_id,
            decider_digest,
            note_digest,
            channel,
            link_digest,
        }
    } else {
        ActionPayload::ApprovalGranted {
            approval_id,
            decider_digest,
            note_digest,
            channel,
            link_digest,
        }
    };
    ev
}
fn with_event(ev: Envelope) -> anyhow::Result<Semantics> {
    let (mut e, a) = fixture();
    if matches!(ev.body, ActionPayload::ApprovalDenied { .. }) {
        e.truncate(5); // a denied approval is never consumed or executed
    }
    e[4] = ev;
    semantics(&e, &a)
}
#[test]
fn web_decision_unchanged_schema1() {
    // P16: the pre-ACT-23 bytes of a web grant. Captured before the change; must not move.
    let (e, _) = fixture();
    assert_eq!(
        serde_json::to_string(&e[4]).unwrap(),
        concat!(
            r#"{"schema_version":1,"event_id":"00000000-0000-0000-0000-000000000018","#,
            r#""action_id":"00000000-0000-0000-0000-000000000002","#,
            r#""tenant_id":"00000000-0000-0000-0000-000000000001","agent_key_id":null,"#,
            r#""occurred_at":"2026-10-30T12:00:00Z","#,
            r#""request_digest":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","#,
            r#""body":{"event_type":"approval_granted","approval_id":"00000000-0000-0000-0000-000000000005","#,
            r#""decider_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","#,
            r#""note_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}"#
        )
    );
    assert!(with_event(e[4].clone()).is_ok());
}
#[test]
fn verifier_accepts_schema3_slack_decision() {
    // P15
    for deny in [false, true] {
        let ev = slack_decision(deny, Some(Channel::Slack), 3);
        let out = with_event(ev).unwrap();
        assert_eq!(out.denied.len(), usize::from(deny));
    }
    assert!(with_event(slack_decision(false, Some(Channel::Teams), 3)).is_ok());
}
#[test]
fn verifier_rejects_schema3_without_channel() {
    // N43
    for deny in [false, true] {
        let err = with_event(slack_decision(deny, None, 3)).unwrap_err();
        assert_eq!(err.to_string(), "invalid/duplicate action event");
    }
}
#[test]
fn verifier_rejects_schema3_channel_without_link_digest() {
    // Every chat decision comes from a linked approver, so schema 3 must name the link.
    for deny in [false, true] {
        let mut ev = slack_decision(deny, Some(Channel::Slack), 3);
        match &mut ev.body {
            ActionPayload::ApprovalGranted { link_digest, .. }
            | ActionPayload::ApprovalDenied { link_digest, .. } => *link_digest = None,
            _ => unreachable!(),
        }
        let err = with_event(ev).unwrap_err();
        assert_eq!(err.to_string(), "invalid/duplicate action event");
    }
}
#[test]
fn verifier_rejects_schema1_with_channel() {
    // N44
    for deny in [false, true] {
        let err = with_event(slack_decision(deny, Some(Channel::Slack), 1)).unwrap_err();
        assert_eq!(err.to_string(), "invalid/duplicate action event");
    }
}
#[test]
fn verifier_rejects_channel_at_schema2() {
    let err = with_event(slack_decision(false, Some(Channel::Slack), 2)).unwrap_err();
    assert_eq!(err.to_string(), "invalid/duplicate action event");
}
#[test]
fn verifier_rejects_schema3_on_other_events() {
    let (mut e, a) = fixture();
    e[5].schema_version = 3; // approval_consumed carries no channel
    assert_eq!(
        semantics(&e, &a).unwrap_err().to_string(),
        "invalid/duplicate action event"
    );
}
#[test]
fn verifier_rejects_link_digest_without_channel() {
    let mut ev = slack_decision(false, None, 1);
    if let ActionPayload::ApprovalGranted { link_digest, .. } = &mut ev.body {
        *link_digest = Some("d".repeat(64));
    }
    assert_eq!(
        with_event(ev).unwrap_err().to_string(),
        "invalid link digest"
    );
}
#[test]
fn verifier_rejects_malformed_link_digest() {
    for bad in ["", "D".repeat(64).as_str(), "d".repeat(63).as_str(), "xyz"] {
        let mut ev = slack_decision(false, Some(Channel::Slack), 3);
        if let ActionPayload::ApprovalGranted { link_digest, .. } = &mut ev.body {
            *link_digest = Some(bad.to_string());
        }
        let err = with_event(ev).expect_err("accepted a malformed link_digest");
        assert_eq!(err.to_string(), "invalid link digest", "{bad:?}");
    }
}
#[test]
fn schema3_attempt_rejected_needs_channel() {
    let rejected = |channel, schema| {
        let mut ev = slack_decision(false, channel, schema);
        ev.body = ActionPayload::ApprovalAttemptRejected {
            approval_id: id(5),
            decider_digest: "b".repeat(64),
            reason: ReasonCode::ApprovalDenied,
            channel,
            link_digest: channel.map(|_| "d".repeat(64)),
        };
        ev
    };
    let (mut e, a) = fixture();
    e.insert(4, rejected(Some(Channel::Slack), 3));
    e[4].event_id = id(77);
    assert!(semantics(&e, &a).is_ok());
    for (channel, schema) in [(None, 3), (Some(Channel::Slack), 1)] {
        let (mut e, a) = fixture();
        e.insert(4, rejected(channel, schema));
        e[4].event_id = id(77);
        assert!(semantics(&e, &a).is_err());
    }
}
#[test]
fn channel_wire_form_is_strict() {
    let ev = slack_decision(false, Some(Channel::Slack), 3);
    let text = serde_json::to_string(&ev).unwrap();
    assert!(text.contains(r#""channel":"slack""#));
    assert!(text.contains(&format!(r#""link_digest":"{}""#, "d".repeat(64))));
    assert_eq!(
        serde_json::from_str::<Envelope>(&text)
            .unwrap()
            .schema_version,
        3
    );
    for bad in [
        r#""channel":"email""#,
        r#""channel":"Slack""#,
        r#""channel":null,"x":1"#,
    ] {
        let tampered = text.replacen(r#""channel":"slack""#, bad, 1);
        assert!(
            serde_json::from_str::<Envelope>(&tampered).is_err(),
            "{bad}"
        );
    }
}
