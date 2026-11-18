#!/usr/bin/env python3
"""Validate that ledger falsification failed at the canonical-row assertion."""

import argparse
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST = (
    "adr078_a_copy_failure_leaves_the_chain_green_and_the_reconcile_rebuilds_the_copy"
)


def discriminating_failure(log, code):
    return (
        code == 101
        and re.search(r"^test .*::" + TEST + r" \.\.\. FAILED$", log, re.MULTILINE)
        and "assertion `left == right` failed" in log
        and "left: (None, None, 0)" in log
        and "right: (Some(0), Some(4), 5)" in log
        and re.search(
            r"^test result: FAILED\. 0 passed; 1 failed; 0 ignored;", log, re.MULTILINE
        )
        and not re.search(r"^error\[|could not compile", log, re.MULTILINE)
    )


def selftest():
    script = (ROOT / "scripts/ci/run-ledger-integration.sh").read_text()
    plant = re.search(r"PLANT_ORIGINAL='(.*?)'\nPLANT_TEXT=", script, re.DOTALL)[1]
    source = (ROOT / "crates/gateway/src/db/audit_chain_state.rs").read_text()
    failures = []
    if source.count(plant) != 1:
        failures.append("mutation must match exactly one canonical insert")
    cleanup = re.search(r"cleanup\(\) \{\n(.*?)\n\}", script, re.DOTALL)[0]
    with tempfile.TemporaryDirectory() as td:
        calls = Path(td) / "calls"
        pg_id, ch_id = "a" * 64, "b" * 64
        pg_file, ch_file = Path(td) / "pg.cid", Path(td) / "ch.cid"
        pg_file.write_text(pg_id)
        ch_file.write_text(ch_id)
        # A failed start can still create a container. Only captured IDs prove
        # ownership; a name collision must never authorize removing that name.
        shell = (
            "set -e; STARTED_PG=0; STARTED_CH=0; PG_CONTAINER=foreign-pg; CH_CONTAINER=foreign-ch; "
            "OWNED_WT=''; WT_PARENT=''; "
            'docker() { echo "$*" >> "$CALL_LOG"; [ "$3" != "$FAIL_ID" ]; };\n'
            + cleanup
            + "\ncleanup\n"
        )
        import os

        subprocess.run(
            ["bash", "-c", shell],
            env={
                **os.environ,
                "CALL_LOG": str(calls),
                "FAIL_ID": pg_id,
                "PG_CID_FILE": str(pg_file),
                "CH_CID_FILE": str(ch_file),
                "CONTAINER_DIR": td,
            },
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        recorded = calls.read_text() if calls.exists() else ""
        if pg_id not in recorded or ch_id not in recorded or "foreign-" in recorded:
            failures.append(
                "cleanup must use both captured IDs even after failed startup/removal"
            )
    with tempfile.TemporaryDirectory() as td:
        docker = Path(td) / "docker"
        docker.write_text("#!/bin/sh\nexit 1\n")
        docker.chmod(0o755)
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("BASH_ENV", "ENV") and not k.startswith("BASH_FUNC_")
        }
        env["PATH"] = td + os.pathsep + env.get("PATH", "")
        absent = subprocess.run(
            ["bash", str(ROOT / "scripts/ci/run-ledger-integration.sh")],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if (
            absent.returncode != 3
            or "CANNOT DETERMINE" not in absent.stdout + absent.stderr
        ):
            failures.append("missing Docker must not report successful ledger proof")
    sample = (
        f"test audit::tests::{TEST} ... FAILED\n"
        "assertion `left == right` failed\n"
        "  left: (None, None, 0)\n right: (Some(0), Some(4), 5)\n"
        "test result: FAILED. 0 passed; 1 failed; 0 ignored; 400 filtered out;\n"
    )
    cases = [
        ("canonical-row assertion", sample, 101, True),
        (
            "compiler error",
            "error[E0308]: mismatched types\ncould not compile gateway",
            101,
            False,
        ),
        ("zero tests", "test result: ok. 0 passed; 0 failed; 0 ignored;", 0, False),
        (
            "unrelated panic",
            sample.replace("left: (None, None, 0)", "connection refused"),
            101,
            False,
        ),
        ("wrong test", sample.replace(TEST, "some_other_test"), 101, False),
        ("killed test", sample, 137, False),
        ("success", sample, 0, False),
    ]
    for label, log, code, expected in cases:
        if bool(discriminating_failure(log, code)) != expected:
            failures.append(label)
    if failures:
        print("FAIL:", "; ".join(failures))
        return 1
    print(
        f"ledger runner selftest: exact plant and {len(cases)} result-classification cases, owned cleanup and missing-Docker refusal passed"
    )
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--log", type=Path)
    p.add_argument("--exit-code", type=int)
    args = p.parse_args()
    if args.selftest:
        return selftest()
    if args.log is None or args.exit_code is None:
        p.error("--log and --exit-code are required")
    if not discriminating_failure(args.log.read_text(), args.exit_code):
        print(
            "CANNOT DETERMINE: expected canonical-row assertion did not fail; see preserved log"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
