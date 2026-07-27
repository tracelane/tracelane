-- Migration 13: gateway-overhead as a first-class queryable column (§ latency framing).
--
-- The gateway now records `tracelane_gateway_overhead_us` on each span — the time
-- Tracelane ADDS, EXCLUDING the upstream provider round-trip: `(dispatch −
-- received) + (sent − provider-complete)`. With `duration_us` (total end-to-end),
-- this splits latency into two segments that SUM to total, no unattributed bucket:
--     provider_us = duration_us − gateway_overhead_us
-- Materialized from the attributes JSON (same pattern as `time_to_first_chunk_s`,
-- migration 04). Computed on INSERT, so only spans written after this deploy carry
-- it — that is correct: it is a measured value, never backfilled/estimated.
--
-- This is the SRE metric: the gateway budget is p99 < 15ms; total duration is
-- dominated by provider generation time. Surfacing overhead separately makes the
-- low number visible (the "what Tracelane adds" tile) and kills the "slow" misread.
ALTER TABLE tracelane.spans
    ADD COLUMN IF NOT EXISTS gateway_overhead_us UInt32
        MATERIALIZED JSONExtractUInt(attributes, 'tracelane_gateway_overhead_us');
