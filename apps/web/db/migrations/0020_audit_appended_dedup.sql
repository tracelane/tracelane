-- 0020 (B-119 fix C / ADR-069): idempotency backstop for the async audit consumer.
--
-- The consumer assigns `seq` at head-advance inside `append_atomic`'s tx. A
-- JetStream redelivery (a crash between the append COMMIT and the message ack)
-- must NOT mint a duplicate seq — that is the B-108 dup-seq class. Inside the
-- same append transaction the consumer does
--   INSERT INTO audit_appended (event_id) VALUES ($1) ON CONFLICT DO NOTHING
-- and if it conflicts (0 rows), the event was already appended → the tx rolls
-- back, no seq is consumed, no row is written, the message is acked. This is the
-- durable backstop beyond the stream's `Nats-Msg-Id` dedup window.
--
-- Idempotent (CREATE TABLE IF NOT EXISTS). Applied to prod directly (the file-glob
-- migration path; the drizzle journal is vestigial from 0009 onward).

CREATE TABLE IF NOT EXISTS audit_appended (
  event_id    text PRIMARY KEY,
  appended_at timestamptz NOT NULL DEFAULT now()
);
