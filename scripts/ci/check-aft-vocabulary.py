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

Exit codes:
    0 — all three invariants hold
    1 — at least one is violated
    2 — --selftest failed, or an unrecognised argument was passed

Wired into scripts/verify-all.sh.
Falsify it:  python3 scripts/ci/check-aft-vocabulary.py --selftest
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PREDICTIVE = ROOT / "crates/gateway/src/predictive"
# Guardrail rails are real detectors too: R3 (tool safety) emits the canonical
# tool AFT ids, including AFT-TOOL-POISON-001 (tool-description injection) which
# has no predictive counterpart. Scraping this dir keeps the `live` taxonomy set
# honest against what the guardrail actually emits (#5).
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


def detector_ids(src_dirs: list[Path]) -> tuple[set[str], set[str]]:
    """(live_ids, stub_ids).

    live_ids  — canonical ids emitted by detectors that can actually produce a verdict.
    stub_ids  — ids named ONLY by stub modules; these must be `roadmap`, never `live`.
    """
    live: set[str] = set()
    stub: set[str] = set()
    for src_dir in src_dirs:
        for rs in sorted(src_dir.glob("*.rs")):
            src = rs.read_text()
            found = set(AFT_LITERAL.findall(src))
            if _is_stub(src):
                stub |= found
            else:
                live |= found
    # An id emitted by BOTH a stub and a real detector is live on the real one.
    return live, stub - live


def taxonomy_entries(path: Path) -> dict[str, str]:
    """{canonical id -> detectorStatus} parsed from aft-taxonomy.ts."""
    text = path.read_text()
    # each entry: "AFT-…": { … detectorStatus: "live"|"roadmap" … }
    pairs = re.findall(
        r'"(AFT-[A-Z0-9-]+)":\s*\{.*?detectorStatus:\s*"(live|roadmap)"',
        text,
        re.DOTALL,
    )
    return {aft: status for aft, status in pairs}


def seeder_ids(path: Path) -> set[str]:
    """EVERY quoted entry in the demo seeder's AFT_SIGNATURES list.

    Deliberately NOT limited to the AFT- prefix: the whole point of the inverse
    lint is to catch a reintroduced *slug* (e.g. "retry-storm"), which has no
    AFT- prefix and would otherwise be invisible.
    """
    text = path.read_text()
    m = re.search(r"AFT_SIGNATURES\s*=\s*\[(.*?)\]", text, re.DOTALL)
    if not m:
        return set()
    return set(re.findall(r'"([^"]+)"', m.group(1)))


def check(
    src_dirs: list[Path],
    taxonomy_path: Path,
    seeder_path: Path,
    quiet: bool = False,
) -> list[str]:
    """Return every vocabulary inconsistency. Empty list == all invariants hold."""
    detectors, stubbed = detector_ids(src_dirs)
    taxo = taxonomy_entries(taxonomy_path)
    taxo_ids = set(taxo)
    live = {a for a, s in taxo.items() if s == "live"}
    seeder = seeder_ids(seeder_path)

    if not quiet:
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

    return errors


# --------------------------------------------------------------------------
# selftest
#
# The guard reads three surfaces (detector .rs files, the taxonomy .ts map, the
# seeder .py), so the fixtures are a miniature of that tree built under a temp
# dir — nothing under the repo is written or edited. Each case mutates ONE
# surface and asserts the guard blocks; the first case asserts a consistent
# vocabulary passes, without which "blocks on everything" would look correct.
# --------------------------------------------------------------------------

_REAL_DETECTOR = """
pub fn detect(&self, req: &Request) -> Option<Finding> {
    if req.tools.iter().any(|t| POISON.is_match(&t.description)) {
        return Some(Finding::new("AFT-TOOL-POISON-001"));
    }
    None
}
"""

_STUB_DETECTOR = """
/// Stub: returns 0.0 until the model is trained. Emits "AFT-TRAJ-ANOMALY-001".
pub fn score(&self, _t: &Trajectory) -> f32 {
    0.0
}
"""


def _taxonomy_src(entries: dict[str, str]) -> str:
    body = "\n".join(
        f'  "{aft}": {{ label: "x", detectorStatus: "{status}" }},'
        for aft, status in entries.items()
    )
    return "export const AFT_TAXONOMY = {\n" + body + "\n};\n"


def _seeder_src(ids: list[str]) -> str:
    body = ", ".join(f'"{i}"' for i in ids)
    return f"AFT_SIGNATURES = [{body}]\n"


def _fixture(
    td: Path,
    name: str,
    taxonomy: dict[str, str],
    seeder: list[str],
    detectors: bool = True,
) -> tuple[list[Path], Path, Path]:
    case = td / name
    det = case / "detectors"
    det.mkdir(parents=True)
    if detectors:
        (det / "tool_safety.rs").write_text(_REAL_DETECTOR)
        (det / "trajectory_guard.rs").write_text(_STUB_DETECTOR)
    tax = case / "aft-taxonomy.ts"
    tax.write_text(_taxonomy_src(taxonomy))
    seed = case / "demo_traces.py"
    seed.write_text(_seeder_src(seeder))
    return [det], tax, seed


LIVE = "AFT-TOOL-POISON-001"
STUBBED = "AFT-TRAJ-ANOMALY-001"


def selftest() -> int:
    before = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    ).stdout

    # (name, taxonomy map, seeder ids, has detector files, expected substring | None)
    cases: list[tuple[str, dict[str, str], list[str], bool, str | None]] = [
        (
            "consistent_vocabulary",
            {LIVE: "live", STUBBED: "roadmap"},
            [LIVE, STUBBED],
            True,
            None,
        ),
        (
            "detector_id_missing_from_map",
            {STUBBED: "roadmap"},
            [STUBBED],
            True,
            "NOT in aft-taxonomy.ts",
        ),
        (
            "stub_labelled_live",
            {LIVE: "live", STUBBED: "live"},
            [LIVE],
            True,
            "labelled detectorStatus:'live' with NO real detector",
        ),
        (
            "real_detector_labelled_roadmap",
            {LIVE: "roadmap", STUBBED: "roadmap"},
            [LIVE],
            True,
            "NOT labelled detectorStatus:'live'",
        ),
        (
            "seeder_reintroduces_a_slug",
            {LIVE: "live", STUBBED: "roadmap"},
            [LIVE, "retry-storm"],
            True,
            "reintroduced slug / unknown id",
        ),
        (
            "taxonomy_parse_drift",
            {},
            [],
            True,
            "parsed ZERO taxonomy entries",
        ),
        (
            "detector_path_drift",
            {LIVE: "live"},
            [LIVE],
            False,
            "parsed ZERO detector ids",
        ),
    ]

    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        td = Path(tmp)
        for name, taxonomy, seeder, has_det, expect in cases:
            dirs, tax, seed = _fixture(td, name, taxonomy, seeder, has_det)
            errors = check(dirs, tax, seed, quiet=True)
            if expect is None:
                ok = not errors
                detail = "clean vocabulary passes" if ok else f"unexpected: {errors}"
            else:
                ok = any(expect in e for e in errors)
                detail = (
                    f"blocked on {expect!r}"
                    if ok
                    else f"NOT blocked; got {errors or 'no errors'}"
                )
            print(f"  {'✓' if ok else '✗'} {name}: {detail}")
            if not ok:
                failures += 1

    after = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    if before != after:
        print("  ✗ tree_unchanged: the selftest left the working tree modified")
        failures += 1
    else:
        print("  ✓ tree_unchanged: git status --porcelain identical before/after")

    if failures:
        print(f"\nselftest FAILED — {failures} case(s). The guard is not trustworthy.")
        return 2
    print(
        f"\n{len(cases)} cases: the guard blocks an unmapped detector id, a stub claimed "
        "live, an under-claimed detector, a reintroduced seeder slug and both parser "
        "drifts — and passes a consistent vocabulary."
    )
    print("selftest PASSED.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="AFT-1 vocabulary guard (detectors ⊆ map, live ⟺ detector, seeder ⊆ map)"
    )
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="plant vocabulary inconsistencies and prove the guard blocks them",
    )
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    errors = check([PREDICTIVE, GUARDRAIL_RAILS], TAXONOMY, SEEDER)
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
