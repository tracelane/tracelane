-- Migration 12: Inline guardrails V1 entitlements (the guardrail spec §2.7).
-- Postgres 17 + Neon-compatible. Idempotent (ALTER … IF NOT EXISTS).
--
-- Adds the six GATED guardrail-rail flags to the entitlement tables created in
-- Migration 09. The free-tier defaults — R1 (cost/loop), R3 schema-validation,
-- and R8 (injection heuristic) — are NOT represented here: they are always on
-- and carry no entitlement flag (§2.7). Only the gated rails get a row flag:
--   R2 (secrets+PII), R3 definition-pinning, R4 (lethal-trifecta, flagship),
--   R5 (format), R6 (sys-prompt-leak), R7 (topic/competitor).
--
-- deny-overrides-grant carries over from Migration 09: plan_entitlements holds
-- NOT NULL defaults; workspace_entitlements holds nullable overrides where a
-- non-NULL FALSE beats a TRUE plan default.
--
-- Tiering is DEFERRED to a pricing ADR: the gated guardrail rails default
-- **OFF for every plan** (column DEFAULT FALSE). We deliberately do NOT seed
-- any plan ON here — seeding a tier ON would pre-empt the pricing decision and
-- ship an unintended entitlement state. The pricing ADR will add a targeted
-- seeding migration once the tier split is locked. The split is tunable without
-- a gateway rebuild either way — a workspace_entitlements row (or a future plan
-- seed) flips a rail on. OSS self-host (no Postgres) gets every rail anyway
-- (the gateway defaults the RailGate to all-granted when no entitlement cache
-- is wired).

------------------------------------------------------------------------------
-- 1. plan_entitlements: per-plan defaults (NOT NULL).
------------------------------------------------------------------------------
ALTER TABLE plan_entitlements
    ADD COLUMN IF NOT EXISTS f_guardrail_r2          BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS f_guardrail_r3_pinning  BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS f_guardrail_r4          BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS f_guardrail_r5          BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS f_guardrail_r6          BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS f_guardrail_r7          BOOLEAN NOT NULL DEFAULT FALSE;

------------------------------------------------------------------------------
-- 2. workspace_entitlements: per-tenant overrides (NULL = inherit plan).
------------------------------------------------------------------------------
ALTER TABLE workspace_entitlements
    ADD COLUMN IF NOT EXISTS f_guardrail_r2          BOOLEAN,
    ADD COLUMN IF NOT EXISTS f_guardrail_r3_pinning  BOOLEAN,
    ADD COLUMN IF NOT EXISTS f_guardrail_r4          BOOLEAN,
    ADD COLUMN IF NOT EXISTS f_guardrail_r5          BOOLEAN,
    ADD COLUMN IF NOT EXISTS f_guardrail_r6          BOOLEAN,
    ADD COLUMN IF NOT EXISTS f_guardrail_r7          BOOLEAN;

------------------------------------------------------------------------------
-- 3. NO plan seeding. Every gated guardrail rail stays OFF (column DEFAULT
--    FALSE) on every plan until a pricing ADR adds a targeted seeding
--    migration. Only the ungated free rails (R1 / R3-schema / R8) run by
--    default. A workspace_entitlements override can flip an individual rail on
--    per tenant in the meantime.
------------------------------------------------------------------------------
