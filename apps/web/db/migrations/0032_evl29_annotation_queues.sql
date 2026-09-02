-- 0032 — `annotation_queues` (EVL-29 / Sprint 3 item 12: human review closes the loop).
--
-- UN-JOURNALED, hand-written, and it lands in Neon BEFORE the gateway that reads
-- it deploys. Same ordering rule as 0031: a gateway ahead of its column 500s on
-- every request that touches it.
--
-- **THE NUMBER IS 0032, NOT 0030.** `specs/EVL-29` says `0030_evl29_…`; 0030 was
-- taken by EVL-04 (dataset entitlements) and 0031 by EVL-28 (online-eval
-- policies). Caught by re-reading the tree rather than the spec — §16, and the
-- second of two spec claims that were already false when this was built.
--
-- ADDITIVE ONLY. One new table plus four defaulted columns on an existing one,
-- so a gateway that predates this is unaffected by it existing.
--
-- **THE ENTITLEMENT IS ALREADY HERE AND IS NOT RE-ADDED.** `f_annotation_queues`
-- landed in 0030 on both `plan_entitlements` and the per-workspace override
-- table, and the gateway already carries `FeatureKey::AnnotationQueues ->
-- "f_annotation_queues"` in its named `column()` map. The spec listed all four as
-- work to do; all four exist.

CREATE TABLE IF NOT EXISTS annotation_queues (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                text NOT NULL,
    -- A SAVED FILTER, evaluated at READ TIME. Never a materialised member list.
    -- Founder ruling R221.1, and the reason belongs at the site: a materialised
    -- queue is a SECOND COPY OF A JUDGEMENT that goes stale the moment a policy
    -- threshold changes, and we would then own reconciliation between the queue
    -- and the scores it came from. Read-time evaluation cannot drift because
    -- there is nothing to drift from. The cost — a reviewer's list is a live
    -- query — is accepted knowingly at our volumes.
    filter_json         jsonb NOT NULL,
    -- An ORDERED list of typed fields. Three types only: boolean | choice | text.
    -- No nesting, no conditionals, no scoring formulas (R221.2). A 1-5 rating is
    -- a `choice` with five options, so nothing is lost by the narrowing.
    rubric_json         jsonb NOT NULL DEFAULT '[]',
    -- **A LABEL CAPTURED UNDER v1 MUST NOT BE REINTERPRETED UNDER v2** (R221.2).
    -- Editing the rubric BUMPS this; every review stores the version it answered
    -- under. Without it, renaming one `choice` option silently rewrites the
    -- meaning of every label already collected — which is the same defect class
    -- as a metric whose definition moves under its own history.
    rubric_version      integer NOT NULL DEFAULT 1,
    -- THE LOOP CLOSES BY CONSTRUCTION (R221.3). When set, every review through
    -- this queue creates a dataset item WITHOUT the reviewer choosing a target.
    -- A per-request `add_to_dataset_id` can still override it, but the default is
    -- what makes the loop structural rather than dependent on a reviewer
    -- remembering the second step.
    default_dataset_id  uuid NULL,
    created_by          text NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    -- ARCHIVE, NEVER DELETE. A review's `queue_id` must never dangle
    -- (`CLAUDE.md` §19 — supersession, not silent deletion).
    archived_at         timestamptz NULL
);

-- One queue name per workspace, case-insensitively. A second "Low scores" is a
-- rename mistake, not a second queue.
CREATE UNIQUE INDEX IF NOT EXISTS annotation_queues_tenant_name_uniq
    ON annotation_queues (tenant_id, lower(name));

CREATE INDEX IF NOT EXISTS annotation_queues_tenant_idx
    ON annotation_queues (tenant_id) WHERE archived_at IS NULL;

ALTER TABLE annotation_queues
    DROP CONSTRAINT IF EXISTS annotation_queues_rubric_version_chk;
ALTER TABLE annotation_queues
    ADD CONSTRAINT annotation_queues_rubric_version_chk CHECK (rubric_version >= 1);

-- ── the four additive columns on OBS-18's existing table ────────────────────
--
-- `queue_id` is deliberately NOT in the primary key. The PK stays
-- `(tenant_id, trace_id, span_id, author_sub)` — the concurrency control that
-- makes two reviewers racing one trace produce exactly one row per author with
-- no read-modify-write window. Adding `queue_id` to it would re-open the
-- duplicate-row bug the `span_id = ''` sentinel exists to prevent.
--
-- NULL `queue_id` means an ad-hoc OBS-18 flag rather than a queue review, so a
-- trace flagged from the trace header and one reviewed in a queue remain the
-- same row in the same table.
ALTER TABLE trace_annotations
    ADD COLUMN IF NOT EXISTS queue_id uuid NULL REFERENCES annotation_queues(id);

ALTER TABLE trace_annotations
    ADD COLUMN IF NOT EXISTS rubric_json jsonb NOT NULL DEFAULT '{}';

-- 0 = "not answered under any rubric" (an ad-hoc OBS-18 flag). A queue review
-- always stores the queue's version at the moment of submission.
ALTER TABLE trace_annotations
    ADD COLUMN IF NOT EXISTS rubric_version integer NOT NULL DEFAULT 0;

-- **THE REFERENCE. This column is the whole point of item 12.**
-- `dataset_routes.rs:35-42` states the hole in its own words: production
-- captures INPUT ONLY, so a trace-derived dataset item ALWAYS has
-- `expected_output = NULL` with reason `output_not_captured`. A human review is
-- the only place a reference can come from, which is why item 12 COMPLETES
-- items 8-10 rather than merely following them.
ALTER TABLE trace_annotations
    ADD COLUMN IF NOT EXISTS expected_output text NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS trace_annotations_queue_idx
    ON trace_annotations (tenant_id, queue_id) WHERE queue_id IS NOT NULL;

COMMENT ON COLUMN annotation_queues.filter_json IS
    'Saved filter, evaluated at READ time (R221.1). Never a materialised member '
    'list: a stored membership is a second copy of a judgement that goes stale '
    'when a threshold moves, and reconciling it becomes ours to own.';

COMMENT ON COLUMN annotation_queues.default_dataset_id IS
    'When set, a review through this queue creates a dataset item in the SAME '
    'request with the reviewer choosing nothing (R221.3) — the loop closes by '
    'construction rather than by anyone remembering a second step.';

COMMENT ON COLUMN trace_annotations.expected_output IS
    'The human-authored reference. Production captures input only, so this is '
    'the ONLY source of an expected_output for a trace-derived dataset item.';
