-- Webhook event deduplication ledger.
--
-- Polar and WorkOS both retry webhook deliveries on non-2xx and on
-- network failure. Without dedup, a replayed signed event re-runs its
-- side effects (set_plan_tier, INSERT INTO users, ...). For Polar in
-- particular this can downgrade a paying tenant on the second arrival
-- of subscription.canceled, or double-charge on a re-fired order.
--
-- Each row records that we have ALREADY processed a given event_id from
-- a given source. The unique constraint on (source, event_id) is the
-- idempotency primitive: handlers call try_record() which INSERTs with
-- ON CONFLICT DO NOTHING and checks affected_rows == 1 — if 0, the
-- event was processed before and the handler skips its side effects.
--

CREATE TABLE IF NOT EXISTS webhook_events (
    source       TEXT        NOT NULL,
    event_id     TEXT        NOT NULL,
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (source, event_id)
);

-- The (source, event_id) primary key already provides the uniqueness.
-- An index on received_at supports the future janitor that prunes
-- rows older than 30 days (Polar's retry window is bounded; we keep
-- 30 for forensic value).
CREATE INDEX IF NOT EXISTS webhook_events_received_at_idx
    ON webhook_events (received_at);
