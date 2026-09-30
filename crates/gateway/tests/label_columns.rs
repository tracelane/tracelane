//! Schema contract plus an opt-in read-back proof. This test never applies DDL.
use std::path::Path;

#[test]
fn label_columns_are_declared_in_schema_and_migration() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let schema = std::fs::read_to_string(root.join("infra/dev/clickhouse/schema.sql")).unwrap();
    for expression in [
        "environment LowCardinality(String)",
        "release String",
        "service LowCardinality(String)",
        "tags Array(LowCardinality(String))",
        "JSONExtractString(attributes, 'deployment_environment')",
        "JSONExtractString(attributes, 'service_version')",
        "JSONExtractString(attributes, 'service_name')",
        "JSONExtract(attributes, 'tracelane_tags', 'Array(String)')",
        "idx_tags tags TYPE bloom_filter(0.01) GRANULARITY 4",
    ] {
        assert!(
            schema.contains(expression),
            "missing schema expression: {expression}"
        );
    }
    let migration = std::fs::read_to_string(
        root.join("infra/dev/clickhouse/migrations/31_gwy54_label_columns.sql"),
    )
    .unwrap();
    assert_eq!(migration.matches("ADD COLUMN IF NOT EXISTS").count(), 4);
    assert!(migration.contains("ADD INDEX IF NOT EXISTS idx_tags"));
    assert!(
        !migration.contains("MATERIALIZE COLUMN"),
        "no historical rewrite"
    );
}

#[derive(Debug, serde::Deserialize, clickhouse::Row)]
struct LabelsRow {
    environment: String,
    release: String,
    service: String,
    tags: Vec<String>,
}
const READ_LABELS: &str = "SELECT environment, release, service, tags FROM tracelane.spans WHERE tenant_id = ? AND trace_id = ? LIMIT 1";

#[test]
fn label_readback_is_tenant_first_and_parameter_bound() {
    assert!(READ_LABELS.contains("WHERE tenant_id = ? AND trace_id = ?"));
}

/// Operator supplies an authorized local proof database with two existing rows:
/// NEW has production/v1/checkout/[beta] attributes; OLD has none of those keys.
/// No test here inserts data, applies migrations, or defaults to a production URL.
#[tokio::test]
#[ignore = "requires an authorized ClickHouse fixture with the migration already applied"]
async fn label_columns_live_readback_new_and_old_rows() {
    let env =
        |key| std::env::var(key).expect("explicit local proof fixture configuration required");
    let client = clickhouse::Client::default().with_url(env("LABEL_PROOF_CLICKHOUSE_URL"));
    let tenant = env("LABEL_PROOF_TENANT");
    let new = client
        .query(READ_LABELS)
        .bind(&tenant)
        .bind(env("LABEL_PROOF_NEW_TRACE"))
        .fetch_one::<LabelsRow>()
        .await
        .unwrap();
    assert_eq!(
        (
            new.environment.as_str(),
            new.release.as_str(),
            new.service.as_str()
        ),
        ("production", "v1", "checkout")
    );
    assert_eq!(new.tags, vec!["beta"]);
    let old = client
        .query(READ_LABELS)
        .bind(&tenant)
        .bind(env("LABEL_PROOF_OLD_TRACE"))
        .fetch_one::<LabelsRow>()
        .await
        .unwrap();
    assert!(
        old.environment.is_empty()
            && old.release.is_empty()
            && old.service.is_empty()
            && old.tags.is_empty()
    );
}
