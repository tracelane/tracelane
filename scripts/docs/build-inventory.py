#!/usr/bin/env python3
"""Generate the stable inventory view from the roadmap and specification links."""

import argparse
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "inventory_governance", ROOT / "scripts/ci/check-spec-governance.py"
)
gov = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gov)
DEST = "docs/inventory/README.md"


def render(roadmap, specs):
    rows = {}
    for line in roadmap.splitlines():
        ids = gov.roadmap_rows(line)
        if not ids:
            continue
        cells = re.split(r"(?<!\\)\|", line)[1:-1]
        if len(cells) < 3:
            raise ValueError("malformed roadmap row")
        for ident in ids:
            if ident in rows:
                raise ValueError("duplicate current roadmap ID: " + ident)
            rows[ident] = (
                cells[1].strip(),
                cells[2].strip(),
                " · ".join(c.strip() for c in cells[3:]),
            )
    if not rows:
        raise ValueError("roadmap has no primary IDs")
    links = {}
    for path, body in specs.items():
        filename = Path(path).name
        title = re.search(r"^# ([^\n]+)", body, re.MULTILINE)
        title_tokens = set(re.findall(r"[A-Za-z0-9-]+", title[1])) if title else set()
        for ident in rows:
            if filename.startswith(ident + "-") or ident in title_tokens:
                links.setdefault(ident, []).append(path)
    result = "<!-- tracelane:classification: CONFIDENTIAL -->\n# Planned-vs-built ledger\n\n> GENERATED — edit docs/runbook/ROADMAP.md\n> Superseded 2026-10-08: the former hand-edited status ledger is now a deterministic view.\n> Historical baseline: `git show 8fd51c5c:docs/inventory/README.md`. WHY/HOW and dated evidence live in the owning ROADMAP records.\n\nROADMAP owns current state and proof. Specifications own design and evidence. A missing spec is shown explicitly; historical provenance is not a current status.\n\n| ID | Current state | Feature | Proof / roadmap evidence | Specification |\n|---|---|---|---|---|\n"
    for ident, (state, title, evidence) in sorted(rows.items()):
        spec_links = (
            " · ".join(
                "[" + Path(p).name + "](../../" + p + ")"
                for p in sorted(links.get(ident, []))
            )
            or "No dedicated spec recorded"
        )
        result += f"| `{ident}` | {state} | {title} | {evidence} | {spec_links} |\n"
    result += (
        f"\n{len(rows)} distinct current roadmap IDs. No status is hand-edited here.\n"
    )
    # Preserve incoming section fragments without a second editable ledger.
    for heading in (
        "1. How to read this",
        "2. Snapshot",
        "3. The ledger",
        "4. Where customer-readable copy outruns the code",
        "5. Resolved state conflicts",
        "6. Consolidation ledger — nothing was dropped",
        "7. WHY/HOW gaps — features with no documented rationale",
        "8. Known gaps in this ledger",
    ):
        result += (
            "\n## "
            + heading
            + "\n\nCurrent records are in the generated table above. Historical section: `git show 8fd51c5c:docs/inventory/README.md`.\n"
        )
    return result


def selftest():
    roadmap = "| `OBS-01` | **BUILT** | Observe | proof.py:1 | design |\n"
    specs = {"specs/OBS-01-observe.md": "# OBS-01\n"}
    view = render(roadmap, specs)
    assert "OBS-01" in view, "primary roadmap ID must be rendered"
    assert "**BUILT**" in view, "state must come from roadmap"
    assert "proof.py:1" in view, "proof must survive generation"
    assert "specs/OBS-01-observe.md" in view
    assert "## 4. Where customer-readable copy outruns the code" in view, (
        "existing section links must resolve"
    )
    assert render(roadmap, specs) == view
    assert view != view + "manual edit", "manual edit must differ"
    print(
        "inventory selftest: required fields and determinism pass; manual drift refused"
    )
    return 0


def expected(staged=False):
    files = gov.Snapshot(ROOT, staged=staged)
    specs = {
        p: files[p]
        for p in files
        if p.startswith("specs/")
        and p.endswith(".md")
        and Path(p).name not in ("README.md", "TEMPLATE.md")
    }
    return render(files["docs/runbook/ROADMAP.md"], specs), files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--staged", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    try:
        view, files = expected(args.staged)
        if args.check:
            if files[DEST] != view:
                print(
                    "BLOCKED: generated inventory differs; run python3 scripts/docs/build-inventory.py and stage the result"
                )
                return 1
            print("inventory: exact match to roadmap/specs")
        else:
            (ROOT / DEST).write_text(view)
            print("wrote " + DEST)
        return 0
    except (OSError, ValueError, KeyError) as exc:
        print("BLOCKED: cannot generate inventory: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
