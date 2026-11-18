"""Portable regression checks; PG concurrency/evidence still require real Postgres."""

import re
import sqlite3
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]


class FixPassSqlTests(unittest.TestCase):
    def test_fix_pass_ledger_index_is_concurrent_standalone(self):
        migrations = ROOT / "apps/web/db/migrations"
        sql = (migrations / "0086_bound_human_approvals.sql").read_text()
        self.assertNotRegex(
            sql,
            r"CREATE INDEX\s+audit_protected_event_id",
            "blocking ledger index remains in transactional migration",
        )
        files = list(migrations.glob("*_protected_event_index.sql"))
        self.assertEqual(len(files), 1)
        sql = re.sub(r"--[^\n]*", "", files[0].read_text()).strip()
        statements = [s.strip() for s in sql.split(";") if s.strip()]
        self.assertEqual(len(statements), 1)
        self.assertRegex(
            statements[0],
            r"^CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_protected_event_id\b",
        )

    def test_fix_pass_consumed_digest_can_request_fresh_grant(self):
        source = (ROOT / "crates/gateway/src/approvals/protected.rs").read_text()
        query = re.search(
            r'"(SELECT to_jsonb\(a\) FROM approvals a WHERE tenant_id=\$1 AND requester_sub=\$2[^"\n]+)"',
            source,
        ).group(1)
        query = query.replace("to_jsonb(a)", "id").replace(" FOR UPDATE", "")
        db = sqlite3.connect(":memory:")
        db.execute(
            "CREATE TABLE approvals(tenant_id TEXT,id TEXT,requester_sub TEXT,request_digest TEXT,policy_hash TEXT,action_id TEXT,status TEXT,created_at INT)"
        )
        db.execute(
            "INSERT INTO approvals VALUES('t','consumed','key','digest','hash','action','consumed',1)"
        )
        bindings = {"1": "t", "2": "key", "3": "digest", "4": "hash"}
        self.assertIsNone(
            db.execute(query, bindings).fetchone(),
            "consumed row blocked creation of a fresh request",
        )
        db.execute(
            "INSERT INTO approvals VALUES('t','fresh','key','digest','hash','new-action','pending',2)"
        )
        self.assertEqual(db.execute(query, bindings).fetchone(), ("fresh",))
        db.execute("UPDATE approvals SET status='denied' WHERE id='fresh'")
        self.assertEqual(
            db.execute(query, bindings).fetchone(),
            ("fresh",),
            "terminal deny must remain selected",
        )
        db.execute("UPDATE approvals SET tenant_id='foreign' WHERE id='fresh'")
        self.assertIsNone(db.execute(query, bindings).fetchone())

    def test_fix_pass_new_action_events_are_append_only(self):
        migrations = ROOT / "apps/web/db/migrations"
        functions = [
            p.read_text()
            for p in sorted(migrations.glob("*.sql"))
            if "FUNCTION protect_action_evidence()" in p.read_text()
        ]
        latest = functions[-1]
        protected = re.search(
            r"protected_types text\[\] := ARRAY\[(.*?)\];", latest, re.DOTALL
        ).group(1)
        for tag in [
            "approval_expired",
            "approval_invalidated",
            "legacy_forward_attempted",
        ]:
            self.assertIn(
                "'" + tag + "'",
                protected,
                f"{tag} has no append-only trigger protection",
            )

    def test_fix_pass_sweeper_preserves_committed_copy_batches(self):
        source = (ROOT / "crates/gateway/src/approvals.rs").read_text()
        sweep = source[
            source.index("pub async fn expire(") : source.index("pub fn spawn_sweeper(")
        ]
        self.assertTrue(
            "after_commit_for_tenant(" in sweep,
            "sweeper discards committed action copy batches",
        )
        self.assertLess(
            sweep.index("tx.commit().await?"), sweep.index("after_commit_for_tenant(")
        )

    def test_fix_pass_dispatch_releases_transaction_before_network(self):
        source = (ROOT / "crates/gateway/src/mcp_proxy.rs").read_text()
        dispatch = source[source.index("async fn dispatch<const INVOKE: bool>") :]
        # A transaction returned from this scope retains the pooled connection
        # until the upstream send completes. The PG resource test checks behavior.
        self.assertFalse(
            "Ok::<_, anyhow::Error>(tx)" in dispatch,
            "legacy dispatch returns a live transaction across send()",
        )
        self.assertFalse(
            "drop(fence_db)" in dispatch, "pooled lease still lives across network I/O"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
