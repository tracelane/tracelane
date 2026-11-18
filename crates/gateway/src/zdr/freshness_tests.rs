use super::*;

#[tokio::test]
#[ignore = "requires POSTGRES_TEST_URL"]
async fn pg_unverified_default_is_ineligible() {
    let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
    pool.get().await.unwrap().execute(
        "INSERT INTO provider_capabilities (provider_id, zdr) VALUES ('freshness-test', 'default')",
        &[],
    ).await.unwrap();
    let snapshot = ZdrCapabilities::load(&pool).await.unwrap();
    assert!(
        !snapshot.eligible("freshness-test"),
        "a default label without verified_at and policy_url must not authorize ZDR traffic"
    );
}

fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap()
}

fn evidence(
    zdr: &str,
    url: Option<&str>,
    verified: Option<chrono::DateTime<chrono::Utc>>,
) -> ZdrCapabilities {
    ZdrCapabilities::from_evidence_rows([(
        "test".to_owned(),
        zdr.to_owned(),
        url.map(str::to_owned),
        verified,
    )])
}

fn fresh() -> ZdrCapabilities {
    evidence("default", Some("https://example.com/privacy"), Some(now()))
}

fn expiry() -> chrono::DateTime<chrono::Utc> {
    now() + policy_max_age().unwrap()
}

#[test]
fn verified_now_is_eligible() {
    assert!(fresh().eligible_at("test", now()));
}
#[test]
fn before_expiry_is_eligible() {
    assert!(fresh().eligible_at("test", expiry() - chrono::Duration::nanoseconds(1)));
}
#[test]
fn cached_evidence_remains_valid_before_expiry() {
    let snapshot = fresh();
    assert!(snapshot.eligible_at("test", now()));
    assert!(snapshot.eligible_at("test", now() + policy_max_age().unwrap() / 2));
}
#[test]
fn bad_sibling_does_not_hide_valid_provider() {
    let snapshot = ZdrCapabilities::from_evidence_rows([
        ("bad".into(), "default".into(), None, None),
        (
            "test".into(),
            "default".into(),
            Some("https://example.com/privacy".into()),
            Some(now()),
        ),
    ]);
    assert!(snapshot.eligible_at("test", now()));
    assert!(!snapshot.eligible_at("bad", now()));
}
#[test]
fn renewed_evidence_restores_eligibility() {
    assert!(!fresh().eligible_at("test", expiry()));
    assert!(
        evidence(
            "default",
            Some("https://example.com/privacy"),
            Some(expiry())
        )
        .eligible_at("test", expiry())
    );
}
#[test]
fn unconstrained_request_ignores_expired_evidence() {
    let old = evidence(
        "default",
        Some("https://example.com/privacy"),
        Some(chrono::DateTime::UNIX_EPOCH),
    );
    assert!(gate(&HeaderMap::new(), &old, "test", ZdrBinding::Gated).is_ok());
}
#[test]
fn https_policy_path_is_accepted() {
    assert!(
        evidence(
            "default",
            Some("https://example.com/legal/privacy#retention"),
            Some(now())
        )
        .eligible_at("test", now())
    );
}
#[test]
fn reference_policy_loads() {
    let raw: serde_json::Value =
        serde_json::from_str(include_str!("../../translation_policy.v1.json")).unwrap();
    let days = raw["zdr_policy"]["max_age_days"].as_i64().unwrap();
    assert!(days > 0);
    assert_eq!(policy_max_age(), chrono::Duration::try_days(days));
}
#[test]
fn count_excludes_expired_evidence() {
    assert_eq!(fresh().default_count_at(now()), 1);
    assert_eq!(fresh().default_count_at(expiry()), 0);
}
#[test]
fn oldest_verified_date_is_reported() {
    let snapshot = ZdrCapabilities::from_evidence_rows([
        (
            "a".into(),
            "default".into(),
            Some("https://example.com/a".into()),
            Some(now()),
        ),
        (
            "b".into(),
            "default".into(),
            Some("https://example.com/b".into()),
            Some(now() - chrono::Duration::seconds(1)),
        ),
        (
            "c".into(),
            "enterprise".into(),
            Some("https://example.com/c".into()),
            Some(chrono::DateTime::UNIX_EPOCH),
        ),
    ]);
    assert_eq!(
        snapshot.oldest_verified_at(),
        Some(now() - chrono::Duration::seconds(1))
    );
    assert_eq!(ZdrCapabilities::unavailable().oldest_verified_at(), None);
}
#[test]
fn exact_expiry_is_ineligible() {
    assert!(!fresh().eligible_at("test", expiry()));
}
#[test]
fn expired_snapshot_cannot_keep_granting() {
    let snapshot = fresh();
    assert!(snapshot.eligible_at("test", now()));
    assert!(!snapshot.eligible_at("test", expiry() + chrono::Duration::seconds(1)));
}
#[test]
fn future_verification_is_ineligible() {
    assert!(!fresh().eligible_at("test", now() - chrono::Duration::nanoseconds(1)));
}
#[test]
fn missing_verification_is_ineligible() {
    assert!(
        !evidence("default", Some("https://example.com/policy"), None).eligible_at("test", now())
    );
}
#[test]
fn missing_policy_url_is_ineligible() {
    assert!(!evidence("default", None, Some(now())).eligible_at("test", now()));
}
#[test]
fn insecure_policy_url_is_ineligible() {
    assert!(
        !evidence("default", Some("http://example.com/policy"), Some(now()))
            .eligible_at("test", now())
    );
}
#[test]
fn malformed_policy_url_is_ineligible() {
    for url in [
        "",
        "not a URL",
        "https://",
        "file:///policy",
        "https:policy",
    ] {
        assert!(
            !evidence("default", Some(url), Some(now())).eligible_at("test", now()),
            "{url}"
        );
    }
}
#[test]
fn credential_policy_url_is_ineligible() {
    assert!(
        !evidence(
            "default",
            Some("https://user:fixture@example.com/policy"),
            Some(now())
        )
        .eligible_at("test", now())
    );
}
#[test]
fn enterprise_evidence_does_not_grant() {
    for category in ["enterprise", "none", "unknown"] {
        assert!(
            !evidence(category, Some("https://example.com/policy"), Some(now()))
                .eligible_at("test", now())
        );
    }
    assert!(!fresh().eligible_at("unknown", now()));
}
#[test]
fn invalid_freshness_policy_denies() {
    for raw in [
        "{}",
        "null",
        "broken",
        r#"{"zdr_policy":{"max_age_days":0}}"#,
        r#"{"zdr_policy":{"max_age_days":-1}}"#,
        r#"{"zdr_policy":{"max_age_days":9223372036854775807}}"#,
    ] {
        assert!(parse_max_age(raw).is_none());
    }
    assert!(!fresh().by_provider["test"].eligible_at(now(), None));
}
#[test]
fn expiry_overflow_denies() {
    let max = chrono::DateTime::<chrono::Utc>::MAX_UTC;
    assert!(
        !evidence("default", Some("https://example.com/policy"), Some(max))
            .eligible_at("test", max)
    );
}

#[tokio::test]
#[ignore = "requires POSTGRES_TEST_URL"]
async fn pg_valid_evidence_is_loaded() {
    let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
    let verified = chrono::Utc::now();
    pool.get().await.unwrap().execute(
        "INSERT INTO provider_capabilities (provider_id, zdr, policy_url, verified_at) VALUES ('freshness-valid', 'default', 'https://example.com/privacy', $1)",
        &[&verified],
    ).await.unwrap();
    let snapshot = ZdrCapabilities::load(&pool).await.unwrap();
    assert!(snapshot.eligible("freshness-valid"));
    assert!(!snapshot.eligible_at("freshness-valid", verified + policy_max_age().unwrap()));
    pool.get().await.unwrap().execute(
        "UPDATE provider_capabilities SET verified_at = '2000-01-01 UTC' WHERE provider_id = 'freshness-valid'", &[],
    ).await.unwrap();
    assert!(
        !ZdrCapabilities::load(&pool)
            .await
            .unwrap()
            .eligible("freshness-valid")
    );
}
