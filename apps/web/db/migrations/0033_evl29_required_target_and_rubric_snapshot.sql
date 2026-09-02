-- 0033 — EVL-29 corrections from founder rulings R222 / R223 / R224.
--
-- 0032 landed minutes earlier with a NULLABLE `default_dataset_id` and a
-- `rubric_version` COUNTER. Both are wrong and the reasons are worth keeping.
-- The table is EMPTY and has NO reader (the gateway routes are not written), so
-- this corrects rather than migrates data.
--
-- ── R222: THE TARGET DATASET IS REQUIRED ───────────────────────────────────
-- A nullable default plus a fallback picker is TWO PATHS where one is exercised
-- rarely and rots. "The loop closes by construction" is only true if the field
-- CANNOT BE ABSENT. Same shape as `online_eval_policies.judge_budget_usd_monthly`
-- (NOT NULL, no default): put the constraint where the writer cannot be, because
-- a handler is bypassed by any writer that is not the handler.
--
-- ── R223: THE QUEUE MUST NAME WHICH FIELD IS THE REFERENCE ──────────────────
-- A queue that produces items with a NULL `expected_output` silently produces
-- items that reference-based scorers CANNOT SCORE — the exact hole item 12
-- exists to close. A queue that cannot close the loop should not be creatable.
-- The value names a `rubric_json` field key; the validator enforces that the
-- named field exists and is NOT of type `boolean` — "true"/"false" as an
-- expected_output is a scorer comparing against a string that means nothing.
--
-- ── R224: AN IMMUTABLE SNAPSHOT ON THE LABEL, NOT A COUNTER ─────────────────
-- Same class as `dataset_snapshots`: the FROZEN SET is what makes a past
-- judgement re-readable. A counter tells you the rubric changed; it does not
-- tell you what it SAID, so a v1 label stays uninterpretable. The label now
-- carries the rubric definition it was answered under, and the queue's counter
-- is dropped so there is ONE mechanism rather than two.

ALTER TABLE annotation_queues
    ADD COLUMN IF NOT EXISTS expected_output_field text NOT NULL DEFAULT '';

-- Both are NOT NULL with no usable default: a queue is uncreatable without a
-- target dataset and without naming its reference field. The `''` default above
-- exists only so the ADD COLUMN succeeds on an empty table; the CHECK below is
-- what makes it unreachable.
ALTER TABLE annotation_queues
    ALTER COLUMN default_dataset_id SET NOT NULL;

ALTER TABLE annotation_queues
    DROP CONSTRAINT IF EXISTS annotation_queues_expected_field_chk;
ALTER TABLE annotation_queues
    ADD CONSTRAINT annotation_queues_expected_field_chk
    CHECK (length(expected_output_field) > 0);

-- The counter goes; the snapshot replaces it.
ALTER TABLE annotation_queues
    DROP CONSTRAINT IF EXISTS annotation_queues_rubric_version_chk;
ALTER TABLE annotation_queues
    DROP COLUMN IF EXISTS rubric_version;

ALTER TABLE trace_annotations
    DROP COLUMN IF EXISTS rubric_version;

-- The rubric DEFINITION as it stood at the moment this label was given —
-- ordered field list, types, options. Frozen. Editing the queue's rubric later
-- cannot reinterpret this answer, because the meaning travelled with it.
ALTER TABLE trace_annotations
    ADD COLUMN IF NOT EXISTS rubric_snapshot jsonb NOT NULL DEFAULT '{}';

COMMENT ON COLUMN annotation_queues.default_dataset_id IS
    'REQUIRED (R222). Every review through this queue creates a dataset item in '
    'the same request. Nullable-plus-picker would be two paths, one of which rots.';

COMMENT ON COLUMN annotation_queues.expected_output_field IS
    'REQUIRED (R223). The rubric field key whose answer becomes the dataset '
    'item''s expected_output. Must exist in rubric_json and must NOT be boolean.';

COMMENT ON COLUMN trace_annotations.rubric_snapshot IS
    'IMMUTABLE SNAPSHOT of the rubric definition this answer was given under '
    '(R224). Same class as dataset_snapshots: the frozen set is what makes a '
    'past judgement re-readable. A counter would say it changed, not what it said.';
