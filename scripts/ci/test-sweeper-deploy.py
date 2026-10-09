#!/usr/bin/env python3
"""Offline tests of the production entrypoint and source archive (no deploy)."""

import hashlib
import os
import re
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def entrypoint():
    compose = (ROOT / "infra/prod/docker-compose.yml").read_text()
    service = compose.split("  clickhouse:\n", 1)[1].split("\n  nats:", 1)[0]
    block = re.search(r"      - \|\n((?:        .*\n)+)", service)
    if block is None:
        return "exec /entrypoint.sh"  # The image default before the startup guard.
    return "".join(line[8:] for line in block[1].splitlines(keepends=True)).replace(
        "$$", "$"
    )


def archive_command():
    script = (ROOT / "scripts/deploy/gateway.sh").read_text()
    match = re.search(
        r"^source_archive\(\) \{\n.*?^\}", script, re.MULTILINE | re.DOTALL
    )
    if match:
        return match[0] + '\nsource_archive "$1"'
    return next(
        line for line in script.splitlines() if line.startswith("tar czf ")
    ).replace("/tmp/gw-src.tgz", '"$1"')


class DeploySecurity(unittest.TestCase):
    def test_secret_shape(self):
        # Replace ONLY the exec target: a sentinel proves the guard allowed startup.
        script = entrypoint().replace("exec /entrypoint.sh", "echo ENTRYPOINT_REACHED")
        for value in (
            None,
            "",
            "a" * 47,
            "a" * 49,
            "G" * 48,
            "a" * 47 + "\n",
            "a" * 48,
        ):
            env = dict(os.environ)
            env.pop("CLICKHOUSE_SWEEPER_PASSWORD", None)
            if value is not None:
                env["CLICKHOUSE_SWEEPER_PASSWORD"] = value
            result = subprocess.run(
                ["sh", "-ec", script],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            with self.subTest(value=value):
                self.assertEqual(
                    result.returncode == 0,
                    value == "a" * 48,
                    result.stdout + result.stderr,
                )
                self.assertEqual(
                    "ENTRYPOINT_REACHED" in result.stdout, value == "a" * 48
                )

    def test_preflight_refuses_bad_file_or_missing_live_user(self):
        script = (ROOT / "scripts/deploy/gateway.sh").read_text()
        match = re.search(
            r"^sweeper_preflight\(\) \{\n.*?^\}", script, re.MULTILINE | re.DOTALL
        )
        function = match[0] if match else "sweeper_preflight() { :; }"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            secret = root / "infra/prod/.env.sweeper"
            secret.parent.mkdir(parents=True)
            docker = root / "docker"
            # One shim, dispatched on the probe: inspect → entrypoint; SHOW USERS →
            # the user list; the empty-password login → its rc; the sha256 probe → hash.
            docker.write_text(
                "#!/bin/sh\n"
                'case "$1" in inspect) printf "%s\\n" "$PROOF_ENTRYPOINT"; exit 0;; esac\n'
                'case "$*" in\n'
                '  *"SHOW USERS"*) printf "%s\\n" "$PROOF_USERS"; exit "$PROOF_DOCKER_RC";;\n'
                '  *"--user tl_sweeper --password  --query"*) exit "$PROOF_EMPTY_RC";;\n'
                '  *sha256sum*) printf "%s  -\\n" "$PROOF_LIVE_HASH"; exit 0;;\n'
                "esac\nexit 1\n"
            )
            guarded = (
                '["/bin/sh","-ec","… REFUSE: CLICKHOUSE_SWEEPER_PASSWORD must be …"]'
            )
            good_hash = hashlib.sha256(b"a" * 48).hexdigest()
            docker.chmod(0o755)
            valid = "CLICKHOUSE_SWEEPER_PASSWORD=" + "a" * 48 + "\n"
            base = {"ep": guarded, "empty_rc": "1", "live": good_hash}
            cases = [
                (None, "tl_sweeper", "0", {}, False),
                ("", "tl_sweeper", "0", {}, False),
                (valid.replace("a" * 48, "bad"), "tl_sweeper", "0", {}, False),
                (valid + "EXTRA=x\n", "tl_sweeper", "0", {}, False),
                (valid + valid, "tl_sweeper", "0", {}, False),
                (valid, "tl_gateway", "0", {}, False),
                (valid, "tl_sweeper_backup", "0", {}, False),
                (valid, "tl_sweeper", "1", {}, False),
                # H-A (2026-09-30): users file hot-reloaded into the OLD, unguarded
                # container — tl_sweeper exists but the container was never recreated.
                (
                    valid,
                    "tl_gateway\ntl_sweeper",
                    "0",
                    {"ep": '["/entrypoint.sh"]'},
                    False,
                ),
                # ... and it logs in with an EMPTY password.
                (valid, "tl_gateway\ntl_sweeper", "0", {"empty_rc": "0"}, False),
                # the running secret is not the file's (a rotated file, not recreated).
                (
                    valid,
                    "tl_gateway\ntl_sweeper",
                    "0",
                    {"live": hashlib.sha256(b"").hexdigest()},
                    False,
                ),
                (valid, "tl_gateway\ntl_sweeper", "0", {}, True),
            ]
            for content, users, rc, over, accepted in cases:
                probe = {**base, **over}
                if content is None:
                    secret.unlink(missing_ok=True)
                else:
                    secret.write_text(content)
                env = dict(
                    os.environ,
                    APP_DIR=td,
                    PATH=td + ":" + os.environ["PATH"],
                    PROOF_USERS=users,
                    PROOF_DOCKER_RC=rc,
                    PROOF_ENTRYPOINT=probe["ep"],
                    PROOF_EMPTY_RC=probe["empty_rc"],
                    PROOF_LIVE_HASH=probe["live"],
                )
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        function + '\nssh_node() { bash -c "$1"; }\nsweeper_preflight',
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                with self.subTest(content=content, users=users, rc=rc, over=over):
                    self.assertEqual(
                        result.returncode == 0, accepted, result.stdout + result.stderr
                    )
                    self.assertNotIn("a" * 48, result.stdout + result.stderr)
        self.assertIn("sweeper_preflight || die ", script)
        self.assertLess(
            script.index("sweeper_preflight || die "),
            script.index("source_archive /tmp/gw-src.tgz"),
        )

    def test_users_proof_cache_covers_script_dependencies(self):
        gate = (ROOT / "scripts/verify-all.sh").read_text()
        line = next(
            line
            for line in gate.splitlines()
            if 'run_cached "clickhouse per-service grants' in line
        )
        inputs = line.split('"')[3].split()
        for path in (
            "scripts/ops/tenant-purge.sh",
            "scripts/ci/check-orphan-sweep-covers-purge.py",
            "scripts/ci/check-banned-patterns.py",
            "scripts/ci/test-sweeper-deploy.py",
            "scripts/deploy/gateway.sh",
        ):
            self.assertIn(path, inputs)

    def test_archive_keeps_example_only(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # Populate every source operand without reading any real env file.
            command = archive_command()
            for path in [
                ".dockerignore",
                "Cargo.toml",
                "Cargo.lock",
                "pnpm-lock.yaml",
                "osv-scanner.toml",
                ".grype.yaml",
                "crates/x",
                "packages/verifier-rust/x",
                "apps/web/db/migrations/x",
                "apps/web/db/kya_catalog.v1.json",
                "apps/web/db/plans.v3.json",
                "apps/web/db/usage_conventions.v1.json",
                "infra/prod/.env",
                "infra/prod/.env.sweeper",
                "infra/prod/.env.bak.anchorproof",
                "infra/prod/.env.example",
                "infra/prod/.env.example.bak",
                "infra/prod/.env.[backup]",
                "infra/self-host/.env",
                "infra/prod/.envrc",
                "infra/prod/docker-compose.yml",
            ]:
                file = root / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text("fixture")
            archive = root / "source.tgz"
            subprocess.run(
                ["bash", "-ec", command, "proof", str(archive)], cwd=root, check=True
            )
            with tarfile.open(archive) as tar:
                names = tar.getnames()
            self.assertIn("infra/prod/.env.example", names)
            self.assertEqual(
                [n for n in names if n.startswith("infra/prod/.env")],
                ["infra/prod/.env.example"],
            )


if __name__ == "__main__":
    unittest.main()
