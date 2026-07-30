--
-- Gateway-overhead p99 (the time Tracelane adds, excluding the provider
-- round-trip; span field `gateway_overhead_us`, CH migration 13) becomes a
-- budgetable alert metric so a latency-tax regression (the ~6s
-- transcontinental-Postgres overhead) FIRES instead of hiding. Budget: < 10ms
--
-- The 0012 inline CHECK is auto-named, so look it up dynamically and drop by
-- name (a hard-coded name misses it), then re-add with the sixth metric.
DO $$
DECLARE cname text;
BEGIN
  SELECT conname INTO cname FROM pg_constraint
   WHERE conrelid = 'alert_rules'::regclass AND contype = 'c'
     AND pg_get_constraintdef(oid) ILIKE '%metric%IN%';
  IF cname IS NOT NULL THEN
    EXECUTE format('ALTER TABLE alert_rules DROP CONSTRAINT %I', cname);
  END IF;
END $$;
ALTER TABLE alert_rules
  ADD CONSTRAINT alert_rules_metric_check
  CHECK (metric IN ('error_rate','burn_rate','latency_p95','overhead_p99','cost_usd','quota_pct'));
