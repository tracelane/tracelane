#!/usr/bin/env python3
"""PLT-23 — compute per-gateway overhead against the direct-to-mock baseline.

AIGatewayBench's definition (README.md, pinned commit ff372fc):

    overhead = latency(client -> gateway -> mock) - latency(client -> mock directly)

This script takes the raw per-percentile latencies already measured by
`run.sh` (one row per gateway, read from a `results/<date>-<host>.csv`) and
subtracts the `direct` row's percentiles from every other row, percentile by
percentile. It performs no measurement itself — it only subtracts numbers
that are already in the CSV, which is why the unit test below is exhaustive:
there is nothing else in this file to get wrong.

Usage:
    python3 compute_overhead.py results/2026-09-06-dev-wsl2.csv
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

PERCENTILE_COLUMNS = ("p50_ms", "p95_ms", "p99_ms")


def compute_overhead(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    """Return one row per non-direct gateway with overhead_<pct>_ms columns.

    Raises ValueError if there is no `direct` baseline row, or if a
    percentile column is missing/non-numeric on a row that needs it — a
    silent `None` here would be reported as "0ms overhead", which is a
    fabricated number, not a missing one (CLAUDE.md §1, TRAPS.md §11).
    """
    baseline = next((r for r in rows if r["gateway"] == "direct"), None)
    if baseline is None:
        raise ValueError(
            "no 'direct' baseline row in the input — cannot compute overhead"
        )

    out: list[dict[str, object]] = []
    for row in rows:
        if row["gateway"] == "direct":
            continue
        if row.get("status", "ok") != "ok":
            # CANNOT DETERMINE rows carry no percentiles — pass them through
            # unchanged rather than subtracting into a fabricated number.
            out.append({**row, **{f"overhead_{c}": None for c in PERCENTILE_COLUMNS}})
            continue
        overhead_row: dict[str, object] = dict(row)
        for col in PERCENTILE_COLUMNS:
            gw_val = row.get(col, "")
            base_val = baseline.get(col, "")
            if gw_val in ("", None) or base_val in ("", None):
                raise ValueError(
                    f"missing '{col}' on gateway={row.get('gateway')!r} or baseline"
                )
            overhead_row[f"overhead_{col}"] = round(float(gw_val) - float(base_val), 3)
        out.append(overhead_row)
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <results.csv>", file=sys.stderr)
        return 2
    path = Path(argv[1])
    with path.open(newline="", encoding="utf-8") as fh:
        # run.sh's CSVs carry `#`-prefixed provenance lines (harness commit,
        # host, versions) above the real header — skip them so DictReader
        # reads "gateway,status,..." as the header, not the first comment.
        data_lines = [line for line in fh if not line.startswith("#")]
    rows = list(csv.DictReader(data_lines))
    for row in compute_overhead(rows):
        pieces = ", ".join(
            f"overhead_{c}={row.get(f'overhead_{c}')}" for c in PERCENTILE_COLUMNS
        )
        print(f"{row['gateway']}: {pieces}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
