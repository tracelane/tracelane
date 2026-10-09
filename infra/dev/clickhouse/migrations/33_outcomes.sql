-- Explicit task outcomes. Apply by hand before deploying the outcome routes.
-- Reserved decision/label vocabulary is deliberately refused by the initial API.
-- No time partition: a corrected outcome must replace the same key across months.
CREATE TABLE IF NOT EXISTS tracelane.outcomes
(
    tenant_id String,
    subject_kind Enum8('trace' = 1, 'session' = 2, 'decision' = 3),
    subject_id String,
    question_id String DEFAULT '',
    result Enum8('success' = 1, 'failure' = 2, 'label' = 3),
    actual String DEFAULT '',
    reason String DEFAULT '',
    source String,
    version UInt64,
    recorded_at DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (tenant_id, subject_kind, subject_id, question_id)
PARTITION BY tuple()
TTL toDate(recorded_at) + INTERVAL 365 DAY;
