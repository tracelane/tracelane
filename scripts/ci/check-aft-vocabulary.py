#!/usr/bin/env python3
"""
AFT-1 vocabulary guard — keeps ONE canonical id vocabulary consistent across the
real detectors, the Signatures taxonomy map, and the demo seeder, so the class of
bug that shipped once (the page mapped demo *slugs* while detectors emit *canonical
ids*, and two "detectors" didn't exist) can never silently return.

Ground truth = the canonical AFT-1 ids that real detectors emit
(`crates/gateway/src/predictive/*.rs`, as quoted "AFT-…" literals).

Enforced invariants:
  1. detector ids ⊆ taxonomy keys      — every real detection resolves in the map
                                          (never a raw id / "unmapped" on the page).
  2. taxonomy `live` set == detector set — a `live` label ⟺ a real detector emits
                                          it (no detector labelled roadmap; no
                                          roadmap entry secretly detected).
  3. seeder ids ⊆ taxonomy keys         — the demo seeder may only emit ids the
                                          map knows (no reintroduced slug).

Exit 0 iff all hold. Wired into scripts/verify-all.sh.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PREDICTIVE = ROOT / "crates/gateway/src/predictive"
TAXONOMY = ROOT / "apps/web/lib/aft-taxonomy.ts"
SEEDER = ROOT / "scripts/seed/demo_traces.py"

AFT_LITERAL = re.compile(r'"(AFT-[A-Z0-9-]+)"')


def detector_ids() -> set[str]:
    """Canonical ids emitted by real detectors = quoted AFT-… literals in predictive/."""
    ids: set[str] = set()
    for rs in sorted(PREDICTIVE.glob("*.rs")):
        ids |= set(AFT_LITERAL.findall(rs.read_text()))
    return ids


def taxonomy_entries() -> dict[str, str]:
    """{canonical id -> detectorStatus} parsed from aft-taxonomy.ts."""
    text = TAXONOMY.read_text()
    # each entry: "AFT-…": { … detectorStatus: "live"|"roadmap" … }
    pairs = re.findall(
        r'"(AFT-[A-Z0-9-]+)":\s*\{.*?detectorStatus:\s*"(live|roadmap)"',
        text,
        re.DOTALL,
    )
    return {aft: status for aft, status in pairs}


def seeder_ids() -> set[str]:
    """EVERY quoted entry in the demo seeder's AFT_SIGNATURES list.

    Deliberately NOT limited to the AFT- prefix: the whole point of the inverse
    lint is to catch a reintroduced *slug* (e.g. "retry-storm"), which has no
    AFT- prefix and would otherwise be invisible.
    """
    text = SEEDER.read_text()
    m = re.search(r"AFT_SIGNATURES\s*=\s*\[(.*?)\]", text, re.DOTALL)
    if not m:
        return set()
    return set(re.findall(r'"([^"]+)"', m.group(1)))


def main() -> int:
    detectors = detector_ids()
    taxo = taxonomy_entries()
    taxo_ids = set(taxo)
    live = {a for a, s in taxo.items() if s == "live"}
    seeder = seeder_ids()

    print("== AFT-1 vocabulary guard ==")
    print(f"  detectors emit : {len(detectors)} ids")
    print(f"  taxonomy map   : {len(taxo_ids)} ids ({len(live)} live)")
    print(f"  seeder emits   : {len(seeder)} ids")

    errors: list[str] = []

    missing_from_map = detectors - taxo_ids
    if missing_from_map:
        errors.append(
            "detector ids NOT in aft-taxonomy.ts (would render as a raw/unmapped id): "
            + ", ".join(sorted(missing_from_map))
        )

    if live != detectors:
        labelled_live_no_detector = live - detectors
        detector_not_live = detectors - live
        if labelled_live_no_detector:
            errors.append(
                "taxonomy entries labelled detectorStatus:'live' with NO real detector "
                "(dishonest — mark roadmap or add the detector): "
                + ", ".join(sorted(labelled_live_no_detector))
            )
        if detector_not_live:
            errors.append(
                "real detectors NOT labelled detectorStatus:'live' in the map "
                "(under-claims a shipped detector): "
                + ", ".join(sorted(detector_not_live))
            )

    seeder_unknown = seeder - taxo_ids
    if seeder_unknown:
        errors.append(
            "demo seeder emits ids the taxonomy map does not know "
            "(reintroduced slug / unknown id): " + ", ".join(sorted(seeder_unknown))
        )

    if not taxo_ids:
        errors.append(
            "parsed ZERO taxonomy entries — parser/format drift, refusing to pass"
        )
    if not detectors:
        errors.append("parsed ZERO detector ids — parser/path drift, refusing to pass")

    if errors:
        print("\nx AFT-1 vocabulary guard FAILED:")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(
        "✓ AFT-1 vocabulary consistent (detectors ⊆ map, live ⟺ detector, seeder ⊆ map)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
