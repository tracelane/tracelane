-- GWY-53 (2026-09-27): a workspace owner chooses to record prompt and response text on
-- its gateway spans. `specs/GWY-53-self-serve-content-capture.md`. Default OFF: no row, or
-- a row with both flags false, records nothing (the operator's `trace_content:` allowlist
-- in tracelane.yaml is separate and dogfood-only).
-- Apply BEFORE the gateway that reads it (S2). Read inside the entitlement refresh (never
-- per request); a missing table resolves to capture OFF + a counted degradation.
-- Written only by the owner-gated `PUT /v1/workspace/capture`, which records every change
-- on the tamper-evident ledger (`workspace.content_capture.set`) in the same transaction.
-- Un-journaled like every migration from 0009 (apps/web/CLAUDE.md "Migrations").
CREATE TABLE IF NOT EXISTS workspace_content_capture (
  tenant_id   uuid        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  input       boolean     NOT NULL DEFAULT false,
  output      boolean     NOT NULL DEFAULT false,
  updated_by  text        NOT NULL DEFAULT '',
  updated_at  timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE workspace_content_capture IS
  'GWY-53: per-workspace opt-in to record prompt (input) and response (output) text on gateway spans. Read by the gateway entitlement refresh; written only by the owner-gated PUT /v1/workspace/capture, ledgered.';
