"""Offline contract tests for the affected-code gate."""

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCOPE = ROOT / "scripts/ci/lean-scope.py"
STAMP = ROOT / "scripts/ci/check-verify-stamp.sh"
PROMOTION = ROOT / "scripts/ci/check-promotion-readiness.py"
AUDIT_GUARD = ROOT / "scripts/ci/check-gate-runner-semantics.py"
EXPORT = ROOT / "scripts/export/build-public-export.sh"


def load_scope():
    spec = importlib.util.spec_from_file_location("lean_scope", SCOPE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_promotion():
    spec = importlib.util.spec_from_file_location("promotion", PROMOTION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def metadata():
    return {
        "workspace_members": ["core 0.1.0", "leaf 0.1.0", "consumer 0.1.0"],
        "packages": [
            {
                "id": "core 0.1.0",
                "name": "core",
                "manifest_path": "/repo/crates/core/Cargo.toml",
            },
            {
                "id": "leaf 0.1.0",
                "name": "leaf",
                "manifest_path": "/repo/crates/leaf/Cargo.toml",
            },
            {
                "id": "consumer 0.1.0",
                "name": "consumer",
                "manifest_path": "/repo/crates/consumer/Cargo.toml",
            },
        ],
        "resolve": {
            "nodes": [
                {"id": "core 0.1.0", "deps": []},
                {"id": "leaf 0.1.0", "deps": [{"pkg": "core 0.1.0"}]},
                {"id": "consumer 0.1.0", "deps": [{"pkg": "leaf 0.1.0"}]},
            ]
        },
    }


class ScopeTests(unittest.TestCase):
    def test_leaf_reverse_closure(self):
        scope = load_scope().classify(
            ["crates/leaf/src/lib.rs"], metadata(), Path("/repo")
        )
        self.assertEqual(scope["rust"], ["consumer", "leaf"])
        self.assertTrue(scope["export_compile"])

    def test_export_transform_selects_compile(self):
        scope = load_scope().classify(
            ["scripts/export/build-public-export.sh"], metadata(), Path("/repo")
        )
        self.assertTrue(scope["export_compile"])

    def test_shared_forces_workspace(self):
        scope = load_scope().classify(
            ["crates/core/src/lib.rs"], metadata(), Path("/repo"), shared={"core"}
        )
        self.assertEqual(scope["rust"], ["consumer", "core", "leaf"])

    def test_lock_forces_workspace(self):
        scope = load_scope().classify(["Cargo.lock"], metadata(), Path("/repo"))
        self.assertEqual(scope["rust"], ["consumer", "core", "leaf"])

    def test_docs_only_scope(self):
        scope = load_scope().classify(["docs/guide.md"], metadata(), Path("/repo"))
        self.assertEqual(scope["rust"], [])
        self.assertFalse(scope["node"])
        self.assertTrue(scope["publication"])

    def test_fixture_owner_scope(self):
        scope = load_scope().classify(
            ["crates/leaf/tests/data/input.fixture"], metadata(), Path("/repo")
        )
        self.assertEqual(scope["rust"], ["consumer", "leaf"])

    def test_web_reverse_dependents(self):
        scope = load_scope().classify(
            ["packages/ui/src/button.ts"], metadata(), Path("/repo")
        )
        self.assertTrue(scope["node"])
        self.assertEqual(scope["node_filter"], "...[HEAD]")

    def test_unclassified_path_fails_broad(self):
        scope = load_scope().classify(["odd/new.binary"], metadata(), Path("/repo"))
        self.assertEqual(scope["rust"], ["consumer", "core", "leaf"])
        self.assertTrue(scope["node"])

    def test_metadata_failure_fails_broad(self):
        scope = load_scope().classify(["crates/leaf/src/lib.rs"], None, Path("/repo"))
        self.assertTrue(scope["rust_all"])
        self.assertEqual(scope["rust"], ["workspace"])
        self.assertFalse(scope["metadata_ok"])

    def test_python_package_scope(self):
        for path in (
            "packages/sdk-python/src/tracelane/__init__.py",
            "packages/verifier-python/tests/test_verify.py",
            "ml/train.py",
            "pyproject.toml",
            "pytest.ini",
        ):
            with self.subTest(path=path):
                scope = load_scope().classify([path], metadata(), Path("/repo"))
                self.assertTrue(scope["python"])

    def test_rust_member_under_packages(self):
        data = metadata()
        data["workspace_members"].append("verifier 0.1.0")
        data["packages"].append(
            {
                "id": "verifier 0.1.0",
                "name": "verifier",
                "manifest_path": "/repo/packages/verifier-rust/Cargo.toml",
            }
        )
        data["resolve"]["nodes"].append({"id": "verifier 0.1.0", "deps": []})
        scope = load_scope().classify(
            ["packages/verifier-rust/src/lib.rs"], data, Path("/repo")
        )
        self.assertEqual(scope["rust"], ["verifier"])
        self.assertFalse(scope["node"])

    def test_metadata_failure_under_packages_refuses_scope(self):
        scope = load_scope().classify(
            ["packages/verifier-rust/src/lib.rs"], None, Path("/repo")
        )
        self.assertFalse(scope["metadata_ok"])
        self.assertTrue(scope["rust_all"])

    def test_multiple_push_bases_select_broad_pnpm(self):
        scope = load_scope().classify(
            ["packages/ui/src/button.ts"], metadata(), Path("/repo"), multi_base=True
        )
        self.assertTrue(scope["node_all"])
        self.assertEqual(scope["node_filter"], "")

    def test_mode_only_runs_exec_guard(self):
        scope = load_scope().classify(
            ["scripts/demo.sh"], metadata(), Path("/repo"), mode_only=True
        )
        self.assertFalse(scope["node"])
        self.assertEqual(scope["rust"], [])
        self.assertTrue(scope["exec_bits"])

    def test_unknown_crate_selects_workspace(self):
        scope = load_scope().classify(
            ["crates/missing/src/lib.rs"], metadata(), Path("/repo")
        )
        self.assertTrue(scope["rust_all"])

    def test_unknown_fixture_selects_broad(self):
        scope = load_scope().classify(
            ["unowned/test.fixture"], metadata(), Path("/repo")
        )
        self.assertTrue(scope["rust_all"])
        self.assertTrue(scope["node_all"])

    def test_empty_diff_keeps_publication(self):
        scope = load_scope().classify([], metadata(), Path("/repo"))
        self.assertTrue(scope["publication"])
        self.assertEqual(scope["rust"], [])


class StampTests(unittest.TestCase):
    def test_exact_tree_stamp_reused(self):
        with tempfile.TemporaryDirectory() as tmp:
            stamp = Path(tmp) / "stamp"
            stamp.write_text("0 abc pre-push\n")
            result = subprocess.run(
                ["bash", str(STAMP), "--check-file", str(stamp), "abc", "pre-push"],
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_stale_stamp_not_reused(self):
        with tempfile.TemporaryDirectory() as tmp:
            stamp = Path(tmp) / "stamp"
            for line in ("1 abc pre-push\n", "0 old pre-push\n", "0 abc full\n"):
                stamp.write_text(line)
                result = subprocess.run(
                    ["bash", str(STAMP), "--check-file", str(stamp), "abc", "pre-push"],
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0, line)

    def test_pre_push_refuses_dirty_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "scripts").mkdir()
            (root / ".githooks").mkdir()
            (root / ".githooks/pre-push").write_bytes(
                (ROOT / ".githooks/pre-push").read_bytes()
            )
            (root / "scripts/verify-all.sh").write_text(
                "#!/bin/sh\necho 'GATE PASS fake'\n"
            )
            (root / "dirty.txt").write_text("uncommitted")
            result = subprocess.run(
                ["bash", ".githooks/pre-push"],
                cwd=root,
                input="",
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("dirty checkout", result.stderr)

    def test_pre_push_refuses_gate_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "scripts").mkdir()
            (root / ".githooks").mkdir()
            (root / ".githooks/pre-push").write_bytes(
                (ROOT / ".githooks/pre-push").read_bytes()
            )
            (root / "scripts/verify-all.sh").write_text(
                "#!/bin/sh\necho changed > mutated.txt\necho 'GATE PASS fake'\n"
            )
            env = {
                **os.environ,
                "GIT_AUTHOR_NAME": "Probe",
                "GIT_AUTHOR_EMAIL": "probe@example.invalid",
                "GIT_COMMITTER_NAME": "Probe",
                "GIT_COMMITTER_EMAIL": "probe@example.invalid",
            }
            subprocess.run(["git", "add", "."], cwd=root, check=True, env=env)
            subprocess.run(
                ["git", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "probe"],
                cwd=root,
                check=True,
                env=env,
            )
            # The full gate is opt-in since the founder ruling of 2026-10-12 (the hook's own
            # comment); without the opt-in this test never reached the gate and read exit 0.
            result = subprocess.run(
                ["bash", ".githooks/pre-push"],
                cwd=root,
                input="",
                capture_output=True,
                text=True,
                check=False,
                env={**os.environ, "TRACELANE_PUSH_GATE": "1"},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("dirty checkout after gate", result.stderr)


class PromotionTests(unittest.TestCase):
    def test_confidential_doc_halts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / "README.md").write_text(
                "<!-- tracelane:classification: CONFIDENTIAL -->\n"
            )
            allowed, errors = load_promotion().check(root)
            self.assertFalse(allowed)
            self.assertIn("CONFIDENTIAL", str(errors))

    def test_restricted_doc_halts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / "README.md").write_text(
                "<!-- tracelane:classification: RESTRICTED -->\n"
            )
            allowed, errors = load_promotion().check(root)
            self.assertFalse(allowed)
            self.assertIn("RESTRICTED", str(errors))

    def test_body_yaml_is_not_classification(self):
        self.assertIsNone(
            load_promotion().classification("# A note\nclassification: PUBLIC\n")
        )

    def test_export_defaults_to_current_checkout(self):
        source_line = next(
            line for line in EXPORT.read_text().splitlines() if line.startswith("SRC=")
        )
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q", tmp], check=True)
            env = dict(os.environ)
            env.pop("SRC", None)
            result = subprocess.run(
                ["bash", "-c", source_line + '; printf "%s" "$SRC"'],
                cwd=tmp,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, tmp)


class ServiceRunnerTests(unittest.TestCase):
    def run_fake_suites(self, persistent_failure=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "scripts/ci").mkdir(parents=True)
            (root / "scripts/ci/run-service-suites.sh").write_bytes(
                (ROOT / "scripts/ci/run-service-suites.sh").read_bytes()
            )
            names = (
                "run-postgres-integration.sh",
                "run-clickhouse-integration.sh",
                "run-ledger-integration.sh",
                "check-clickhouse-users.sh",
                "check-nats-auth.sh",
            )
            for name in names:
                script = "#!/bin/sh\nexit 0\n"
                if name == names[0]:
                    script = (
                        "#!/bin/sh\ntest -f tried && exit 1\ntouch tried\nexit 1\n"
                        if persistent_failure
                        else "#!/bin/sh\ntest -f tried && exit 0\ntouch tried\nexit 1\n"
                    )
                (root / "scripts/ci" / name).write_text(script)
            docker = root / "docker"
            docker.write_text("#!/bin/sh\nexit 0\n")
            docker.chmod(0o755)
            env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}"}
            return subprocess.run(
                ["bash", "scripts/ci/run-service-suites.sh"],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

    def test_retry_reports_flaky(self):
        result = self.run_fake_suites()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("FLAKY service: postgres api key mint", result.stdout)

    def test_two_failures_refuse(self):
        result = self.run_fake_suites(persistent_failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL service: postgres api key mint", result.stderr)


class AuditGuardTests(unittest.TestCase):
    def test_critical_audit_and_mute_precondition(self):
        result = subprocess.run(
            ["python3", str(AUDIT_GUARD)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_audit_guard_selftest(self):
        result = subprocess.run(
            ["python3", str(AUDIT_GUARD), "--selftest"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class InnerLoopTests(unittest.TestCase):
    def test_fixture_path_runs_owner_crate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts/dev").mkdir(parents=True)
            (root / "crates/leaf/tests").mkdir(parents=True)
            (root / "crates/leaf/Cargo.toml").write_text(
                '[package]\nname = "leaf"\nversion = "0.1.0"\n'
            )
            (root / "crates/leaf/tests/input.fixture").write_text("sample")
            (root / "scripts/dev/t").write_bytes((ROOT / "scripts/dev/t").read_bytes())
            fake = root / "cargo"
            fake.write_text('#!/bin/sh\necho "$@" >> "$TEST_LOG"\n')
            fake.chmod(0o755)
            log = root / "commands"
            env = {
                **os.environ,
                "PATH": f"{root}:{os.environ['PATH']}",
                "TEST_LOG": str(log),
            }
            result = subprocess.run(
                [
                    "python3",
                    str(root / "scripts/dev/t"),
                    "crates/leaf/tests/input.fixture",
                ],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("test -p leaf", log.read_text())

    def test_unknown_target_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts/dev").mkdir(parents=True)
            (root / "scripts/dev/t").write_bytes((ROOT / "scripts/dev/t").read_bytes())
            result = subprocess.run(
                ["python3", str(root / "scripts/dev/t"), "missing"],
                cwd=root,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
