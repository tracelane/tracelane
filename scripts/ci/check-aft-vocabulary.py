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
# Guardrail rails are real detectors too: R3 (tool safety) emits the canonical
# tool AFT ids, including AFT-TOOL-POISON-001 (tool-description injection) which
# has no predictive counterpart. Scraping this dir keeps the `live` taxonomy set
GUARDRAIL_RAILS = ROOT / "crates/gateway/src/guardrail/rails"
TAXONOMY = ROOT / "apps/web/lib/aft-taxonomy.ts"
SEEDER = ROOT / "scripts/seed/demo_traces.py"

AFT_LITERAL = re.compile(r'"(AFT-[A-Z0-9-]+)"')


# A detector that CANNOT FIRE is not a detector, however many AFT ids it names.
#
# This guard originally equated "a source file mentions this id" with "this detector is
# live", and that is a PRESENCE check wearing a behaviour check's clothes. It failed on
# 2026-08-08 by demanding that AFT-TRAJ-ANOMALY-001 stay labelled `live` — while
# predictive/trajectory_guard.rs:72-85 returns 0.0 unconditionally, ships no model, and
# has zero .onnx files anywhere in the tree. It can never return anything but Allow. The
# guard was defending a false customer-facing claim.
#
# A module counts as a real detector only if it is not a STUB. A stub is recognised the
# way the code itself announces it: an inference/scoring fn whose body is a bare constant
# return with the real implementation left as commented-out code. If you add a detector
# and this misclassifies it, make the detector actually compute something — do not widen
# the exemption.
STUB_MARKERS = (
    "Model not yet trained",
    "Stub: returns",
    "until the model is trained",
    "NOT TRAINED",
)


def _is_stub(src: str) -> bool:
    return any(m in src for m in STUB_MARKERS)


def detector_ids() -> tuple[set[str], set[str]]:
    """(live_ids, stub_ids).

    live_ids  — canonical ids emitted by detectors that can actually produce a verdict.
    stub_ids  — ids named ONLY by stub modules; these must be `roadmap`, never `live`.
    """
    live: set[str] = set()
    stub: set[str] = set()
    for src_dir in (PREDICTIVE, GUARDRAIL_RAILS):
        for rs in sorted(src_dir.glob("*.rs")):
            src = rs.read_text()
            found = set(AFT_LITERAL.findall(src))
            if _is_stub(src):
                stub |= found
            else:
                live |= found
    # An id emitted by BOTH a stub and a real detector is live on the real one.
    return live, stub - live


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
    detectors, stubbed = detector_ids()
    taxo = taxonomy_entries()
    taxo_ids = set(taxo)
    live = {a for a, s in taxo.items() if s == "live"}
    seeder = seeder_ids()

    print("== AFT-1 vocabulary guard ==")
    print(
        f"  detectors emit : {len(detectors)} ids ({len(stubbed)} stubbed -> must be roadmap)"
    )
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
