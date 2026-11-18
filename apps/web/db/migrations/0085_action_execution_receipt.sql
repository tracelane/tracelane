-- Additive protected execution receipt. Written only; apply before gateway readers.
SET lock_timeout = '5s';
ALTER TABLE action_executions ADD COLUMN receipt_jcs text;
