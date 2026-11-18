"""Exercise the sweeper's exact portable SQL against fixed-clock fixture rows.

SQLite replaces only PostgreSQL's row-lock clause. This checks selection, bounded
batches and status updates; real-PG tests remain necessary for locks/audit rollback.
No production SQL is reimplemented here.
"""

import re
import sqlite3
from pathlib import Path


def test_past_expiry_protected_grants_are_swept():
    source = Path(__file__).parents[1].joinpath("approvals.rs").read_text()
    sweep = source[
        source.index("pub async fn expire(") : source.index("pub fn spawn_sweeper(")
    ]
    select = re.search(r'"(SELECT tenant_id,id,status[^"\n]+)"', sweep).group(1)
    update = re.search(
        r'"(UPDATE approvals SET status=\'expired\'[^"\n]+)"', sweep
    ).group(1)
    select = select.replace(" FOR UPDATE SKIP LOCKED", "")
    db = sqlite3.connect(":memory:")
    db.create_function("now", 0, lambda: 100)
    db.execute(
        "CREATE TABLE approvals(tenant_id TEXT,id TEXT,status TEXT,expires_at INT,grant_expires_at INT,action_id TEXT)"
    )
    rows = [
        ("tenant-a", "protected-pending", "pending", 99, None, "action-1"),
        ("tenant-a", "protected-approved", "approved", 99, 200, "action-2"),
        ("tenant-a", "protected-future", "approved", 200, 99, "action-3"),
        ("tenant-a", "protected-consumed", "consumed", 99, 99, "action-4"),
        ("tenant-a", "legacy-pending", "pending", 99, None, None),
        ("tenant-a", "legacy-approved", "approved", 200, 99, None),
        ("tenant-b", "protected-pending", "pending", 200, None, "action-5"),
    ]
    db.executemany("INSERT INTO approvals VALUES(?,?,?,?,?,?)", rows)
    selected = db.execute(select, {"1": 20}).fetchall()
    for tenant, approval, _status, *_ in selected:
        db.execute(update, {"1": tenant, "2": approval})
    states = {
        (t, i): s for t, i, s in db.execute("SELECT tenant_id,id,status FROM approvals")
    }
    for approval in (
        "protected-pending",
        "protected-approved",
        "legacy-pending",
        "legacy-approved",
    ):
        assert states["tenant-a", approval] == "expired", (
            f"{approval} remained {states['tenant-a', approval]} after sweep"
        )
    assert states["tenant-a", "protected-future"] == "approved"
    assert states["tenant-a", "protected-consumed"] == "consumed"
    assert states["tenant-b", "protected-pending"] == "pending"
    db.execute(
        "UPDATE approvals SET status='pending',expires_at=99,grant_expires_at=99"
    )
    assert len(db.execute(select, {"1": 2}).fetchall()) == 2, (
        "sweep ignored its batch bound"
    )
    print("test_past_expiry_protected_grants_are_swept ... ok")


if __name__ == "__main__":
    test_past_expiry_protected_grants_are_swept()
