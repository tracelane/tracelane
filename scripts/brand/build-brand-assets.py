#!/usr/bin/env python3
"""Build the founder-traced brand asset set or check all referenced runtime icons.

The geometry source is apps/site/public/brand/tracelane-mark.svg. The Node renderer
uses the workspace's existing Playwright dependency to rasterize that same path.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REF_SOURCES = (
    ("apps/web/app/layout.tsx", "apps/web/public"),
    ("apps/web/app/manifest.ts", "apps/web/public"),
    ("apps/site/src/layouts/Base.astro", "apps/site/public"),
)


def check_refs():
    refs = {}
    for rel, public in REF_SOURCES:
        text = (ROOT / rel).read_text()
        for url in re.findall(r'"(/brand/[^"?]+)', text):
            refs.setdefault((public, url), []).append(rel)
    missing = [
        (public, url, from_files)
        for (public, url), from_files in refs.items()
        if not (ROOT / public / url.lstrip("/")).exists()
    ]
    if missing:
        for public, url, from_files in missing:
            print(f"MISSING {public}{url} referenced from {', '.join(from_files)}")
        return 1
    if len({public for public, _ in refs}) != len(
        {public for _, public in REF_SOURCES}
    ):
        print("reference scan did not reach both runtime public roots")
        return 1
    print(f"OK — all {len(refs)} referenced /brand/* assets exist on both surfaces.")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-refs", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.check_refs:
        return check_refs()
    flag = "--selftest" if args.selftest else "--verify" if args.verify else None
    cmd = ["node", str(ROOT / "scripts/brand/build-traced-assets.mjs")]
    if flag:
        cmd.append(flag)
    return subprocess.run(cmd, cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
