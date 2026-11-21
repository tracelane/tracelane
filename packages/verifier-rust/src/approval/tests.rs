//! ACT-40 verifier scenarios: record shape, row identity and lifecycle replay.
use super::*;
use chrono::{Duration, TimeZone};
use serde_json::json;

const FP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
fn t(s: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 20, 12, 0, 0).unwrap() + Duration::seconds(s)
}
fn tenant() -> Uuid {
    Uuid::from_u128(1)
}
fn id(n: u128) -> Uuid {
    Uuid::from_u128(100 + n)
}
fn base(n: u128, transition: Transition, at: i64) -> Record {
    Record {
        record: Kind::ToolApproval,
        v: 1,
        tenant_id: tenant(),
        approval_id: id(n),
        transition,
        occurred_at: t(at),
        request_fingerprint: FP.into(),
        requester: "apikey:7f".into(),
        requester_creator: Some("user_creator".into()),
        subject_kind: "tool".into(),
        subject: "delete_repo".into(),
        server_id: Some(Uuid::from_u128(9)),
        rule_id: Some(Uuid::from_u128(8)),
        decided_by: None,
        expires_at: None,
    }
}
fn requested(n: u128, at: i64, until: i64) -> Record {
    Record {
        expires_at: Some(t(until)),
        ..base(n, Transition::Requested, at)
    }
}
fn approved(n: u128, at: i64, grant: i64) -> Record {
    Record {
        decided_by: Some("user_approver".into()),
        expires_at: Some(t(grant)),
        ..base(n, Transition::Approved, at)
    }
}
fn denied(n: u128, at: i64) -> Record {
    Record {
        decided_by: Some("user_approver".into()),
        ..base(n, Transition::Denied, at)
    }
}
fn consumed(n: u128, at: i64) -> Record {
    base(n, Transition::Consumed, at)
}
fn expired(n: u128, at: i64) -> Record {
    base(n, Transition::Expired, at)
}
fn err(records: &[Record]) -> String {
    semantics(records).unwrap_err().to_string()
}
fn payload(r: &Record) -> String {
    crate::action::canonical_json(&serde_json::to_string(r).unwrap()).unwrap()
}

// ---- lifecycle: positive ----
#[test]
fn request_approve_consume_is_one_consumed_approval() {
    let s = semantics(&[requested(1, 0, 60), approved(1, 10, 100), consumed(1, 20)]).unwrap();
    assert_eq!(
        s,
        Semantics {
            requested: 1,
            approved: 1,
            consumed: 1,
            ..Default::default()
        }
    );
}
#[test]
fn request_deny_is_terminal_and_closed() {
    let s = semantics(&[requested(1, 0, 60), denied(1, 5)]).unwrap();
    assert_eq!((s.denied, s.open), (1, 0));
}
#[test]
fn pending_request_lapses() {
    let s = semantics(&[requested(1, 0, 60), expired(1, 60)]).unwrap();
    assert_eq!((s.expired, s.open), (1, 0));
}
#[test]
fn unconsumed_grant_lapses() {
    let s = semantics(&[requested(1, 0, 60), approved(1, 10, 100), expired(1, 100)]).unwrap();
    assert_eq!((s.approved, s.expired, s.consumed), (1, 1, 0));
}
#[test]
fn consume_after_pending_deadline_within_grant_is_valid() {
    // The grant, not the pending deadline, governs consumption.
    semantics(&[requested(1, 0, 60), approved(1, 50, 200), consumed(1, 150)]).unwrap();
}
#[test]
fn open_counts_pending_and_unconsumed() {
    let s = semantics(&[requested(1, 0, 60), requested(2, 1, 60), approved(2, 2, 90)]).unwrap();
    assert_eq!(s.open, 2);
}
#[test]
fn interleaved_approvals_replay_independently() {
    let s = semantics(&[
        requested(1, 0, 60),
        requested(2, 1, 60),
        approved(1, 2, 90),
        denied(2, 3),
        consumed(1, 4),
    ])
    .unwrap();
    assert_eq!((s.consumed, s.denied, s.open), (1, 1, 0));
}
#[test]
fn self_decision_by_requester_is_counted() {
    let mut a = approved(1, 1, 90);
    a.decided_by = Some("apikey:7f".into());
    assert_eq!(
        semantics(&[requested(1, 0, 60), a]).unwrap().self_decided,
        1
    );
}
#[test]
fn self_decision_by_key_creator_is_counted() {
    let mut d = denied(1, 1);
    d.decided_by = Some("user_creator".into());
    assert_eq!(
        semantics(&[requested(1, 0, 60), d]).unwrap().self_decided,
        1
    );
}
#[test]
fn independent_decider_is_not_self_decided() {
    assert_eq!(
        semantics(&[requested(1, 0, 60), approved(1, 1, 90)])
            .unwrap()
            .self_decided,
        0
    );
}
#[test]
fn model_subject_without_server_is_valid() {
    let mut r = requested(1, 0, 60);
    r.subject_kind = "model".into();
    r.server_id = None;
    r.validate().unwrap();
}
#[test]
fn empty_range_is_empty() {
    assert_eq!(semantics(&[]).unwrap(), Semantics::default());
}
#[test]
fn same_instant_transitions_are_ordered_by_ledger() {
    semantics(&[requested(1, 0, 60), approved(1, 0, 90), consumed(1, 0)]).unwrap();
}

// ---- lifecycle: negative ----
#[test]
fn second_consume_is_refused() {
    assert_eq!(
        err(&[
            requested(1, 0, 60),
            approved(1, 1, 90),
            consumed(1, 2),
            consumed(1, 3)
        ]),
        "approval not approved, expired or already consumed"
    );
}
#[test]
fn consume_without_approval_is_refused() {
    assert_eq!(
        err(&[requested(1, 0, 60), consumed(1, 2)]),
        "approval not approved, expired or already consumed"
    );
}
#[test]
fn consume_after_denial_is_refused() {
    assert_eq!(
        err(&[requested(1, 0, 60), denied(1, 1), consumed(1, 2)]),
        "approval not approved, expired or already consumed"
    );
}
#[test]
fn consume_at_grant_expiry_is_refused() {
    assert_eq!(
        err(&[requested(1, 0, 60), approved(1, 1, 90), consumed(1, 90)]),
        "approval not approved, expired or already consumed"
    );
}
#[test]
fn consume_after_expiry_record_is_refused() {
    assert_eq!(
        err(&[
            requested(1, 0, 60),
            approved(1, 1, 90),
            expired(1, 90),
            consumed(1, 91)
        ]),
        "approval not approved, expired or already consumed"
    );
}
#[test]
fn decision_after_pending_deadline_is_refused() {
    assert_eq!(
        err(&[requested(1, 0, 60), approved(1, 60, 120)]),
        "decision on a request that is not pending"
    );
}
#[test]
fn second_decision_is_refused() {
    assert_eq!(
        err(&[requested(1, 0, 60), approved(1, 1, 90), denied(1, 2)]),
        "decision on a request that is not pending"
    );
}
#[test]
fn decision_after_denial_is_refused() {
    assert_eq!(
        err(&[requested(1, 0, 60), denied(1, 1), approved(1, 2, 90)]),
        "decision on a request that is not pending"
    );
}
#[test]
fn early_expiry_of_pending_is_refused() {
    assert_eq!(
        err(&[requested(1, 0, 60), expired(1, 59)]),
        "expiry of a live or finished approval"
    );
}
#[test]
fn early_expiry_of_grant_is_refused() {
    assert_eq!(
        err(&[requested(1, 0, 60), approved(1, 1, 90), expired(1, 89)]),
        "expiry of a live or finished approval"
    );
}
#[test]
fn expiry_after_consume_is_refused() {
    assert_eq!(
        err(&[
            requested(1, 0, 60),
            approved(1, 1, 90),
            consumed(1, 2),
            expired(1, 100)
        ]),
        "expiry of a live or finished approval"
    );
}
#[test]
fn expiry_after_denial_is_refused() {
    assert_eq!(
        err(&[requested(1, 0, 60), denied(1, 1), expired(1, 100)]),
        "expiry of a live or finished approval"
    );
}
#[test]
fn transition_without_request_is_outside_range() {
    assert_eq!(err(&[consumed(1, 2)]), "approval reference outside range");
}
#[test]
fn duplicate_request_is_refused() {
    assert_eq!(
        err(&[requested(1, 0, 60), requested(1, 1, 60)]),
        "duplicate approval request"
    );
}
#[test]
fn time_going_backwards_is_refused() {
    assert_eq!(
        err(&[requested(1, 10, 60), approved(1, 5, 90)]),
        "approval time went backwards"
    );
}
#[test]
fn every_binding_field_is_bound() {
    // Approving one call and consuming the grant for another is the attack this blocks.
    let changes: [fn(&mut Record); 7] = [
        |r| r.request_fingerprint = "f".repeat(64),
        |r| r.requester = "apikey:other".into(),
        |r| r.requester_creator = None,
        |r| r.subject_kind = "model".into(),
        |r| r.subject = "other_tool".into(),
        |r| r.server_id = None,
        |r| r.rule_id = Some(Uuid::from_u128(77)),
    ];
    for change in changes {
        let mut c = consumed(1, 2);
        change(&mut c);
        assert_eq!(
            err(&[requested(1, 0, 60), approved(1, 1, 90), c]),
            "approval binding mismatch"
        );
    }
}

// ---- record shape ----
/// One malformed-field case: the mutation and the error it must produce.
type ShapeCase = (fn(&mut Record), &'static str);

#[test]
fn shape_rejects_each_malformed_field() {
    let cases: [ShapeCase; 13] = [
        (|r| r.v = 2, "unsupported approval record version"),
        (
            |r| r.request_fingerprint = FP.to_uppercase(),
            "invalid approval fingerprint",
        ),
        (
            |r| r.request_fingerprint = FP[..63].into(),
            "invalid approval fingerprint",
        ),
        (|r| r.requester = String::new(), "invalid approval identity"),
        (|r| r.requester = "a\nb".into(), "invalid approval identity"),
        (
            |r| r.requester_creator = Some("x".repeat(257)),
            "invalid approval identity",
        ),
        (
            |r| r.subject_kind = "agent".into(),
            "invalid approval subject",
        ),
        (|r| r.subject = String::new(), "invalid approval subject"),
        (
            |r| r.subject = "tool\u{7}".into(),
            "invalid approval subject",
        ),
        (|r| r.subject = "x".repeat(513), "invalid approval subject"),
        (
            |r| r.decided_by = Some("user_x".into()),
            "decider present iff approved or denied",
        ),
        (|r| r.expires_at = None, "invalid approval expiry"),
        (|r| r.expires_at = Some(t(0)), "invalid approval expiry"),
    ];
    for (change, message) in cases {
        let mut r = requested(1, 0, 60);
        change(&mut r);
        assert_eq!(r.validate().unwrap_err().to_string(), message);
    }
}
#[test]
fn decided_record_requires_decider() {
    let mut r = approved(1, 1, 90);
    r.decided_by = None;
    assert_eq!(
        r.validate().unwrap_err().to_string(),
        "decider present iff approved or denied"
    );
}
#[test]
fn consumed_record_must_not_carry_expiry() {
    let mut r = consumed(1, 1);
    r.expires_at = Some(t(90));
    assert_eq!(
        r.validate().unwrap_err().to_string(),
        "invalid approval expiry"
    );
}

// ---- row identity ----
#[test]
fn row_round_trips_with_expected_actor() {
    for r in [
        requested(1, 0, 60),
        approved(1, 1, 90),
        denied(1, 1),
        consumed(1, 2),
        expired(1, 90),
    ] {
        let actor = r.expected_actor().to_owned();
        let back =
            Record::from_row(tenant(), &r.transition.event_type(), &actor, &payload(&r)).unwrap();
        assert_eq!(back, r);
    }
}
#[test]
fn row_actor_must_match_transition() {
    let r = approved(1, 1, 90);
    // The requester cannot appear as the actor of an approval decision.
    assert_eq!(
        Record::from_row(
            tenant(),
            "tool_approval.approved",
            "apikey:7f",
            &payload(&r)
        )
        .unwrap_err()
        .to_string(),
        "approval record identity mismatch"
    );
}
#[test]
fn expiry_actor_is_the_system() {
    let r = expired(1, 90);
    assert_eq!(r.expected_actor(), EXPIRY_ACTOR);
    assert!(
        Record::from_row(tenant(), "tool_approval.expired", "apikey:7f", &payload(&r)).is_err()
    );
}
#[test]
fn row_event_type_must_match_transition() {
    let r = consumed(1, 2);
    assert!(
        Record::from_row(
            tenant(),
            "tool_approval.approved",
            "apikey:7f",
            &payload(&r)
        )
        .is_err()
    );
}
#[test]
fn row_tenant_must_match_ledger() {
    let r = requested(1, 0, 60);
    assert!(
        Record::from_row(
            Uuid::from_u128(2),
            "tool_approval.requested",
            "apikey:7f",
            &payload(&r)
        )
        .is_err()
    );
}
#[test]
fn row_payload_must_be_original_jcs() {
    let r = requested(1, 0, 60);
    let spaced = serde_json::to_string_pretty(&r).unwrap();
    assert_eq!(
        Record::from_row(tenant(), "tool_approval.requested", "apikey:7f", &spaced)
            .unwrap_err()
            .to_string(),
        "approval payload not original JCS"
    );
}
#[test]
fn row_rejects_unknown_member() {
    // An argument value smuggled into a record is refused, not carried.
    let mut v = serde_json::to_value(requested(1, 0, 60)).unwrap();
    v["arguments"] = json!({"amount": 1});
    let p = crate::action::canonical_json(&v.to_string()).unwrap();
    assert!(Record::from_row(tenant(), "tool_approval.requested", "apikey:7f", &p).is_err());
}
#[test]
fn record_never_carries_schema_version() {
    // Action-evidence parsing claims any payload with `schema_version`; ours must not.
    for r in [requested(1, 0, 60), approved(1, 1, 90), consumed(1, 2)] {
        assert!(!payload(&r).contains("schema_version"));
        assert!(!crate::action::bundle::is_action(
            &r.transition.event_type()
        ));
        assert!(is_record(&r.transition.event_type()));
    }
}
#[test]
fn absent_optionals_are_omitted_not_null() {
    let mut r = requested(1, 0, 60);
    r.server_id = None;
    r.rule_id = None;
    r.requester_creator = None;
    let p = payload(&r);
    assert!(!p.contains("null"), "{p}");
    Record::from_row(tenant(), "tool_approval.requested", "apikey:7f", &p).unwrap();
}
