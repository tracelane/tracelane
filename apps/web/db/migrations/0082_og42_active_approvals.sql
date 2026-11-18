-- Hand-apply after 0081 and before the gateway that permits approval re-requests.
BEGIN;
ALTER TABLE approvals DROP CONSTRAINT IF EXISTS approvals_tenant_id_requester_sub_args_fp_key;
CREATE UNIQUE INDEX IF NOT EXISTS approvals_active_request
 ON approvals(tenant_id, requester_sub, args_fp)
 WHERE status IN ('pending','approved');
COMMIT;
