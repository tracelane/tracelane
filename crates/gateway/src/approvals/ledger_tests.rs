//! ACT-40 writer shape. Lifecycle, fault and chain proofs: `mcp_security_tests.rs` `act40_*`.
use super::*;
use chrono::TimeZone;

fn row() -> Row {
    Row {
        args_fp: "ab".repeat(32),
        requester_sub: "apikey:7f".into(),
        requester_creator: Some("user_creator".into()),
        subject_kind: "tool".into(),
        subject: "delete_repo".into(),
        server_id: Some(Uuid::from_u128(9)),
        rule_id: None,
        decided_by: Some("user_approver".into()),
        expires_at: Utc.with_ymd_and_hms(2026, 11, 20, 12, 10, 0).unwrap(),
        grant_expires_at: Some(Utc.with_ymd_and_hms(2026, 11, 20, 12, 20, 0).unwrap()),
    }
}
fn at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 20, 12, 0, 0).unwrap()
}
fn tenant() -> TenantId {
    TenantId::from_jwt_claim(Uuid::from_u128(1))
}

#[test]
fn writer_output_is_accepted_by_the_offline_verifier() {
    for t in [
        Transition::Requested,
        Transition::Approved,
        Transition::Denied,
        Transition::Consumed,
        Transition::Expired,
    ] {
        let r = build(&tenant(), Uuid::from_u128(5), t, at(), row()).unwrap();
        let (event_type, actor, payload) = encode(&r).unwrap();
        let back = Record::from_row(Uuid::from_u128(1), &event_type, &actor, &payload).unwrap();
        assert_eq!(back, r);
    }
}
#[test]
fn decider_is_written_only_on_a_decision() {
    let consumed = build(
        &tenant(),
        Uuid::from_u128(5),
        Transition::Consumed,
        at(),
        row(),
    )
    .unwrap();
    assert!(consumed.decided_by.is_none() && consumed.expires_at.is_none());
    let approved = build(
        &tenant(),
        Uuid::from_u128(5),
        Transition::Approved,
        at(),
        row(),
    )
    .unwrap();
    assert_eq!(approved.decided_by.as_deref(), Some("user_approver"));
    assert_eq!(approved.expires_at, row().grant_expires_at);
}
#[test]
fn approved_without_grant_fails_closed() {
    let mut r = row();
    r.grant_expires_at = None;
    assert!(build(&tenant(), Uuid::from_u128(5), Transition::Approved, at(), r).is_err());
}
#[test]
fn decision_without_decider_fails_closed() {
    let mut r = row();
    r.decided_by = None;
    assert!(build(&tenant(), Uuid::from_u128(5), Transition::Denied, at(), r).is_err());
}
#[test]
fn request_recorded_after_its_deadline_fails_closed() {
    let late = Utc.with_ymd_and_hms(2026, 11, 20, 12, 10, 0).unwrap();
    assert!(
        build(
            &tenant(),
            Uuid::from_u128(5),
            Transition::Requested,
            late,
            row()
        )
        .is_err()
    );
}
#[test]
fn every_transition_but_request_needs_its_recorded_predecessor() {
    use Transition::*;
    assert_eq!(predecessor(Requested, false), None);
    assert_eq!(predecessor(Approved, false), Some(Requested));
    assert_eq!(predecessor(Denied, false), Some(Requested));
    assert_eq!(predecessor(Consumed, true), Some(Approved));
    assert_eq!(predecessor(Expired, false), Some(Requested));
    assert_eq!(predecessor(Expired, true), Some(Approved));
}
#[test]
fn event_id_names_tenant_approval_and_transition() {
    assert_eq!(
        event_id(&tenant(), Uuid::from_u128(5), Transition::Requested),
        format!(
            "tool_approval:{}:{}:requested",
            tenant(),
            Uuid::from_u128(5)
        )
    );
}
#[test]
fn control_character_subject_fails_closed() {
    let mut r = row();
    r.subject = "tool\u{0}".into();
    assert!(
        build(
            &tenant(),
            Uuid::from_u128(5),
            Transition::Requested,
            at(),
            r
        )
        .is_err()
    );
}
