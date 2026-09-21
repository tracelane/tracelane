#!/usr/bin/env python3
"""The self-host ClickHouse schema must be BYTE-IDENTICAL to the dev schema.

WHY THIS EXISTS — B-482, found 2026-09-21 by the REV-2 benchmark run, not by any gate.
`infra/self-host/clickhouse/schema.sql` is what a fresh self-host install (and the PLT-23
bench stack, `bench/gateway/aigatewaybench/tracelane.compose.yml`) mounts into ClickHouse's
init directory. It was a hand-made COPY of `infra/dev/clickhouse/schema.sql`, last refreshed
2026-09-14 — before BILL-01 made the ingest writer set `span_bytes` on every span. From that
day every fresh self-host install crashed its ingest on the first batch:

    Code: 16. DB::Exception: No such column span_bytes in table tracelane.spans

and the bench stack reported "capture proof: 0 rows" while the gateway kept answering 200 —
which is how it was noticed: a number that looked fine beside one that did not. Nothing
compared the two files. This does, and it is the only control: a copy that is not held
equal by a guard is a copy that drifts (CLAUDE.md §23's shape, applied to a schema).

    check-self-host-schema-parity.py             # exit 0 iff identical
    check-self-host-schema-parity.py --selftest  # plants a one-column drift, proves red

The fix for a red run is `cp infra/dev/clickhouse/schema.sql infra/self-host/clickhouse/schema.sql`
— the dev file is the ONE source (`check-deploy-schema.py` reads it as the base contract).
"""

from __future__ import annotations

import filecmp
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEV = ROOT / "infra/dev/clickhouse/schema.sql"
SELF_HOST = ROOT / "infra/self-host/clickhouse/schema.sql"


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(ROOT))
    except ValueError:  # the selftest's temp copies live outside the repo
        return p.name


def check(dev: Path, self_host: Path) -> int:
    if not dev.is_file() or not self_host.is_file():
        print(
            f"FAIL — missing file: dev={dev.is_file()} self-host={self_host.is_file()}"
        )
        return 1
    if filecmp.cmp(dev, self_host, shallow=False):
        print(f"OK — {_rel(self_host)} is byte-identical to {_rel(dev)}")
        return 0
    a = dev.read_text(encoding="utf-8").splitlines()
    b = self_host.read_text(encoding="utf-8").splitlines()
    only_dev = [l for l in a if l not in b][:5]
    print(
        f"FAIL — {_rel(self_host)} DRIFTED from {_rel(dev)} "
        f"({len(a)} vs {len(b)} lines). A fresh self-host install gets a schema the ingest "
        f"writer does not write to (B-482: `No such column span_bytes`). First lines only in dev:"
    )
    for l in only_dev:
        print(f"    {l[:110]}")
    print(f"  Fix: cp {_rel(dev)} {_rel(self_host)}")
    return 1


def selftest() -> int:
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        dev = d / "dev.sql"
        sh = d / "self-host.sql"
        shutil.copy(DEV, dev)
        shutil.copy(DEV, sh)
        ok = check(dev, sh) == 0
        print(f"selftest: identical copies ... {'PASS' if ok else 'FAIL'}")
        # Plant B-482's exact shape: the self-host copy lacks one column.
        text = sh.read_text(encoding="utf-8")
        planted = (
            "\n".join(l for l in text.splitlines() if "span_bytes" not in l) + "\n"
        )
        assert planted != text, "the plant must remove something"
        sh.write_text(planted, encoding="utf-8")
        red = check(dev, sh) != 0
        print(
            f"selftest: a self-host copy missing `span_bytes` ... {'BLOCKED' if red else 'NOT CAUGHT'}"
        )
        return 0 if (ok and red) else 1


if __name__ == "__main__":
    # ARGV IS AN ALLOWLIST — a guard that accepts any flag makes its own `--selftest`
    # meaningless (the meta-gate refuses exactly that shape).
    args = sys.argv[1:]
    if args == ["--selftest"]:
        sys.exit(selftest())
    if args:
        print(
            f"usage: {sys.argv[0]} [--selftest]  (unknown argument: {' '.join(args)})"
        )
        sys.exit(2)
    sys.exit(check(DEV, SELF_HOST))
