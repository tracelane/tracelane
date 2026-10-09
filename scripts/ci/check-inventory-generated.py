#!/usr/bin/env python3
"""Refuse a manually edited or stale generated inventory, including staged drift."""

import argparse
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATE_ROW = re.compile(
    r"^\|\s*`?(?P<id>(?:[A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*-\d+[a-z]?|A\d+))`?"
    r"\s*\|\s*\*{0,2}(?:IN-PROGRESS|BUILT|DEPLOYED|PENDING|PLANNED|CUT|DEFERRED|SHIPPED|DONE|NOT_BUILT)\b",
    re.IGNORECASE,
)
SPEC = importlib.util.spec_from_file_location(
    "inventory_builder", ROOT / "scripts/docs/build-inventory.py"
)
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def selftest():
    builder.selftest()
    source = "| `OBS-01` | **BUILT** | Observe | proof.py:1 | spec |\n"
    clean = builder.render(source, {})
    assert clean != builder.render(source.replace("BUILT", "IN-PROGRESS"), {}), (
        "state change must invalidate view"
    )
    assert clean != builder.render(source.replace("proof.py:1", "proof.py:2"), {}), (
        "proof change must invalidate view"
    )
    try:
        builder.render(source + source, {})
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate current IDs accepted")
    try:
        builder.render("", {})
    except ValueError:
        pass
    else:
        raise AssertionError("empty roadmap accepted")
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        for name in (
            "scripts/ci/check-inventory-generated.py",
            "scripts/docs/build-inventory.py",
            "scripts/ci/check-spec-governance.py",
        ):
            target = temp / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        (temp / "docs/runbook").mkdir(parents=True)
        (temp / "docs/inventory").mkdir(parents=True)
        (temp / "docs/runbook/ROADMAP.md").write_text(source)
        (temp / builder.DEST).write_text(clean)
        subprocess.run(["git", "init", "-q", str(temp)], env=env, check=True)

        def run():
            subprocess.run(["git", "-C", str(temp), "add", "docs"], env=env, check=True)
            return subprocess.run(
                [sys.executable, str(temp / "scripts/ci/check-inventory-generated.py")],
                cwd=temp,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

        assert run().returncode == 0
        (temp / "specs").mkdir()
        (temp / "specs/GOV-01-example.md").write_text(
            "| `OBS-47` | **BUILT** | Competing state |\n"
        )
        subprocess.run(["git", "-C", str(temp), "add", "specs"], env=env, check=True)
        planted = run()
        assert planted.returncode == 1 and "OBS-47" in planted.stderr
        (temp / "specs/GOV-01-example.md").unlink()
        subprocess.run(["git", "-C", str(temp), "add", "specs"], env=env, check=True)
        (temp / builder.DEST).write_text(clean + "manual edit")
        planted = run()
        assert planted.returncode == 1 and "inventory differs" in planted.stdout
        (temp / builder.DEST).write_text(clean)
        (temp / "docs/runbook/ROADMAP.md").write_text(
            source.replace("BUILT", "IN-PROGRESS")
        )
        assert run().returncode == 1
    print(
        "inventory guard selftest: actual CLI accepts clean view and BLOCKS manual edit + stale source; duplicate and empty source also refused"
    )
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--worktree", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    try:
        expected, files = builder.expected(not args.worktree)
        changed = set(
            subprocess.check_output(
                ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
                text=True,
            ).splitlines()
        )
        if args.worktree:
            changed.update(
                subprocess.check_output(
                    ["git", "diff", "--name-only", "--diff-filter=ACMR"],
                    text=True,
                ).splitlines()
            )
        for path in sorted(changed):
            if (
                path in ("docs/runbook/ROADMAP.md", builder.DEST)
                or not path.endswith((".md", ".mdx"))
                or path not in files
            ):
                continue
            for number, line in enumerate(files[path].splitlines(), 1):
                match = STATE_ROW.match(line)
                if match:
                    print(
                        f"BLOCKED: {path}:{number}: {match['id']} state row duplicates ROADMAP ownership",
                        file=sys.stderr,
                    )
                    return 1
        if files[builder.DEST] != expected:
            print(
                "BLOCKED: inventory differs from fresh generation; regenerate and stage it"
            )
            return 1
        print("inventory: exact match to roadmap/specs")
        return 0
    except (OSError, ValueError, KeyError) as exc:
        print("BLOCKED: inventory: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
