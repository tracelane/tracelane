-- 0031 — `online_eval_policies` (EVL-28 / Sprint 3 item 11: score live traffic).
--
-- UN-JOURNALED, hand-written, and it lands in Neon BEFORE the gateway that reads
-- it deploys. That ordering is the rule this repo keeps paying for when it is
-- skipped: a gateway ahead of its column 500s on every request that touches it.
--
-- ADDITIVE ONLY. One new table, no ALTER on anything live, so an older gateway is
-- unaffected by it existing — which is what makes the ordered deploy safe rather
-- than merely conventional.
--
-- THE ENTITLEMENT FLAG IS ALREADY HERE. `f_online_evals` landed in 0030 on both
-- `plan_entitlements` and the per-workspace override table, and the gateway
-- already carries `FeatureKey::OnlineEvals -> "f_online_evals"` in its named
-- `column()` map. Nothing in this file touches entitlements.

CREATE TABLE IF NOT EXISTS online_eval_policies (
    id                        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                 uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    enabled                   boolean NOT NULL DEFAULT true,
    rubric_kind               text NOT NULL,
    rubric                    text NOT NULL,
    judge_model               text NOT NULL,
    sample_rate               double precision NOT NULL DEFAULT 0.01,
    sample_salt               text NOT NULL,
    -- NO DEFAULT, NOT NULL. See the CHECK below and the schema.ts doc: an
    -- unnamed cap is how a customer meets eval spend for the first time on an
    -- invoice. The route returns a typed 400; this makes it unreachable anyway.
    judge_budget_usd_monthly  double precision NOT NULL,
    created_at                timestamptz NOT NULL DEFAULT now(),
    updated_at                timestamptz NOT NULL DEFAULT now()
);

-- ONE POLICY PER WORKSPACE. A unique INDEX rather than a primary key on
-- `tenant_id`, so allowing a second policy later is a schema change and not a
-- data migration.
CREATE UNIQUE INDEX IF NOT EXISTS online_eval_policies_tenant_uniq
    ON online_eval_policies (tenant_id);

-- THE CEILING IS OURS AND IT IS ENFORCED AT THE DATABASE, not only in a handler.
-- A handler check is bypassed by any other writer — a backfill, a support script,
-- a future admin route. 0.10 is the founder-set ceiling (R208); the tenant picks
-- anything at or below it, because coverage is their judgement and volume is our
-- exposure.
ALTER TABLE online_eval_policies
    DROP CONSTRAINT IF EXISTS online_eval_policies_sample_rate_chk;
ALTER TABLE online_eval_policies
    ADD CONSTRAINT online_eval_policies_sample_rate_chk
    CHECK (sample_rate >= 0.0 AND sample_rate <= 0.10);

-- A cap of zero is not a cap, it is a disabled policy expressed confusingly —
-- and `enabled` already says that, unambiguously. Refusing it here keeps the two
-- controls from meaning the same thing in two places.
ALTER TABLE online_eval_policies
    DROP CONSTRAINT IF EXISTS online_eval_policies_budget_positive_chk;
ALTER TABLE online_eval_policies
    ADD CONSTRAINT online_eval_policies_budget_positive_chk
    CHECK (judge_budget_usd_monthly > 0.0);

ALTER TABLE online_eval_policies
    DROP CONSTRAINT IF EXISTS online_eval_policies_rubric_kind_chk;
ALTER TABLE online_eval_policies
    ADD CONSTRAINT online_eval_policies_rubric_kind_chk
    CHECK (rubric_kind IN ('builtin', 'prompt_version'));

COMMENT ON COLUMN online_eval_policies.judge_budget_usd_monthly IS
    'Monthly cap on JUDGE spend for this policy, in USD. Required — no default. '
    'This is a SUB-LIMIT: judge spend is real money from the workspace wallet and '
    'is ALSO recorded against the workspace budget. Never one instead of the other.';

COMMENT ON COLUMN online_eval_policies.sample_salt IS
    'Per-policy salt. Sampling is hash(salt || trace_id) < rate — DETERMINISTIC, '
    'never random, so a customer can say which traces were scored and re-run '
    'exactly that set.';
