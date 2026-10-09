"""Isolated behavioral tests for build governance; no repository index mutation."""

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).with_name("check-spec-governance.py")
spec = importlib.util.spec_from_file_location("spec_governance", MODULE)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def complete():
    sections = "\n".join(
        "## " + h + "\nConcrete decision with an explicit reason.\n"
        for h in (*guard.SECTIONS[:-2], guard.SECTIONS[-1], guard.SECTIONS[-2])
    )
    for direction in ("Positive", "Negative"):
        sections += (
            "\n### "
            + direction
            + "\n| Case | Expected | Test name/path |\n|---|---|---|\n"
        )
        for i in range(10):
            sections += f"| {direction} case {i} | observed result {i} | `tests/test_x.py::test_{direction.lower()}_{i}` |\n"
    return sections


class GovernanceTests(unittest.TestCase):
    def test_complete_sections(self):
        self.assertEqual(guard.validate(complete(), False, {}), [])

    def test_ten_rows_each(self):
        self.assertEqual(guard.validate(complete(), False, {}), [])

    def test_missing_design(self):
        self.assertTrue(
            guard.validate(
                complete().replace("## Design & alternatives", "## unrelated"),
                False,
                {},
            )
        )

    def test_empty_comment_section(self):
        text = complete().replace(
            "Concrete decision with an explicit reason.", "<!-- looks filled -->", 1
        )
        self.assertTrue(guard.validate(text, False, {}))

    def test_bare_todo(self):
        text = complete().replace(
            "Concrete decision with an explicit reason.", "**TODO**", 1
        )
        self.assertTrue(guard.validate(text, False, {}))

    def test_nine_positive_rows(self):
        text = "\n".join(
            l for l in complete().splitlines() if "test_positive_9" not in l
        )
        self.assertTrue(guard.validate(text, False, {}))

    def test_nine_negative_rows(self):
        text = "\n".join(
            l for l in complete().splitlines() if "test_negative_9" not in l
        )
        self.assertTrue(guard.validate(text, False, {}))

    def test_built_missing_test(self):
        self.assertTrue(guard.validate(complete(), True, {}))

    def test_built_named_tests(self):
        source = "\n".join(
            f"def test_{d}_{i}(): pass"
            for d in ("positive", "negative")
            for i in range(10)
        )
        self.assertEqual(
            guard.validate(complete(), True, {"tests/test_x.py": source}), []
        )

    def test_comment_is_not_definition(self):
        self.assertTrue(
            guard.validate(complete(), True, {"tests/test_x.py": complete()})
        )

    def test_rust_doc_backtick_does_not_hide_real_test(self):
        source = "/// An unmatched ` in a doc comment\n#[test]\nfn real_test() {}\n"
        self.assertTrue(guard.definition(source, "real_test", "src/eval.rs"))

    def test_duplicate_rows_block(self):
        text = complete().replace("test_positive_9", "test_positive_8")
        self.assertTrue(guard.validate(text, False, {}))

    def test_old_built_legacy(self):
        self.assertFalse(guard.required("2026-10-07", "BUILT", False))

    def test_active_complete_spec(self):
        self.assertTrue(guard.required("2020-01-01", "IN-PROGRESS", False))

    def test_changed_spec_required(self):
        self.assertTrue(guard.required("2020-01-01", "BUILT", True))

    def test_after_cutoff_required(self):
        self.assertTrue(guard.required("2026-10-09", "BUILT", False))

    def test_cutoff_is_inclusive(self):
        self.assertTrue(guard.required("2026-10-08", "BUILT", False))

    def test_invalid_date_blocks(self):
        self.assertTrue(guard.required("", "BUILT", False))

    def test_path_escape_blocks(self):
        text = complete().replace("tests/test_x.py", "../tests/test_x.py")
        self.assertTrue(
            guard.validate(
                text, True, {"../tests/test_x.py": "def test_positive_0(): pass"}
            )
        )


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.run_git("init", "-q")

    def run_git(self, *args):
        subprocess.run(
            ["git", "-C", str(self.root), *args],
            env=self.env,
            check=True,
            capture_output=True,
        )

    def test_staged_valid_worktree_invalid(self):
        p = self.root / "evidence.py"
        p.write_text("def test_real(): pass")
        self.run_git("add", "evidence.py")
        p.write_text("broken worktree")
        from unittest.mock import patch

        with patch.dict(os.environ, self.env, clear=True):
            self.assertIn("test_real", guard.Snapshot(self.root)["evidence.py"])

    def test_untracked_evidence_absent(self):
        (self.root / "report.md").write_text("report")
        from unittest.mock import patch

        with patch.dict(os.environ, self.env, clear=True):
            self.assertNotIn("report.md", guard.Snapshot(self.root))

    def test_symlink_evidence_rejected(self):
        (self.root / "report.md").symlink_to("/etc/passwd")
        self.run_git("add", "report.md")
        from unittest.mock import patch

        with (
            patch.dict(os.environ, self.env, clear=True),
            self.assertRaises(ValueError),
        ):
            guard.Snapshot(self.root)["report.md"]

    def test_worktree_cannot_rescue_index(self):
        p = self.root / "evidence.py"
        p.write_text("invalid staged evidence")
        self.run_git("add", "evidence.py")
        p.write_text("def test_real(): pass")
        from unittest.mock import patch

        with patch.dict(os.environ, self.env, clear=True):
            self.assertFalse(
                guard.definition(guard.Snapshot(self.root)["evidence.py"], "test_real")
            )


class RoadmapTests(unittest.TestCase):
    def test_grouped_ids_keep_built_state(self):
        self.assertEqual(
            guard.roadmap_rows("| `B-1/B-2` | **BUILT** | proof |"),
            {"B-1": ["**BUILT**"], "B-2": ["**BUILT**"]},
        )

    def test_historical_quote_not_current_state(self):
        self.assertEqual(
            guard.roadmap_rows("> historical: | `B-1` | **BUILT** | proof |"), {}
        )


class CriticalFreshnessTests(unittest.TestCase):
    """Critical health must reflect observable drift rather than reassuring labels."""

    def setUp(self):
        import datetime
        import json

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.today = datetime.date(2026, 10, 8)
        module = Path(__file__).with_name("check-doc-freshness.py")
        spec = importlib.util.spec_from_file_location(
            "critical_freshness_tests", module
        )
        self.freshness = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.freshness)
        self.write(
            "scripts/ci/doc-freshness-policy.json",
            json.dumps({"max_age_days": 30, "artifacts": {"AGENTS.md": {}}}),
        )

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def agent_health(self):
        return next(
            row
            for row in self.freshness.critical_artifacts(self.root, now=self.today)
            if row["path"] == "AGENTS.md"
        )

    def test_critical_recent_verification_is_green(self):
        self.write("AGENTS.md", "Verified-against-code: 2026-10-01\nRules.\n")
        self.assertEqual(self.agent_health()["status"], "green")

    def test_critical_expired_verification_is_red(self):
        self.write("AGENTS.md", "Verified-against-code: 2026-08-01\nRules.\n")
        self.assertEqual(self.agent_health()["status"], "red")

    def test_critical_missing_verification_is_explicit_unknown(self):
        self.write("AGENTS.md", "Rules with no verification evidence.\n")
        result = self.agent_health()
        self.assertEqual(result["status"], "amber")
        self.assertIn("CANNOT DETERMINE", str(result["details"]))

    def test_critical_age_limit_comes_from_policy(self):
        import json

        self.write("AGENTS.md", "Verified-against-code: 2026-10-01\nRules.\n")
        self.write(
            "scripts/ci/doc-freshness-policy.json",
            json.dumps(
                {"max_age_days": 30, "artifacts": {"AGENTS.md": {"max_age_days": 3}}}
            ),
        )
        self.assertEqual(self.agent_health()["status"], "red")

    def test_inventory_health_detects_manual_generated_view_drift(self):
        module = Path(__file__).resolve().parents[1] / "docs/build-inventory.py"
        spec = importlib.util.spec_from_file_location("inventory_health_tests", module)
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        roadmap = "| `OBS-01` | **BUILT** | Observe | proof.py:1 | design |\n"
        self.write("docs/runbook/ROADMAP.md", roadmap)
        generated = builder.render(roadmap, {})
        self.write("docs/inventory/README.md", generated)
        self.assertTrue(self.freshness.inventory_health(self.root)["matches"])
        self.write(
            "docs/inventory/README.md",
            generated + "Manual claim with GENERATED marker retained.\n",
        )
        self.assertFalse(self.freshness.inventory_health(self.root)["matches"])

    def test_inventory_missing_source_is_explicit_unknown(self):
        self.write(
            "docs/inventory/README.md", "GENERATED — edit docs/runbook/ROADMAP.md\n"
        )
        result = self.freshness.inventory_health(self.root)
        self.assertIsNone(result["matches"])
        self.assertIn("CANNOT DETERMINE", result["unknown"])

    def provider_fixture(self):
        self.write(
            "crates/gateway/providers.tsv",
            "id\turl\n"
            + "".join(
                f"provider{i}\thttps://example.invalid/{i}\n" for i in range(100)
            ),
        )
        self.write(
            "crates/gateway/src/providers/mod.rs",
            "pub struct ProviderRegistry {\n"
            + "".join(f"    pub adapter{i}: NativeProvider,\n" for i in range(4))
            + "}\n",
        )
        self.write(
            "apps/docs/providers.mdx",
            "# Providers\n104 providers.\n",  # provider-count-exempt: planted wrong-count fixture
        )

    def test_provider_health_parses_documented_count(self):
        self.provider_fixture()
        result = self.freshness.provider_health(self.root)
        self.assertEqual(result["total"], 104)
        self.assertEqual(result["documented_total"], 104)
        self.assertTrue(result["matches"])
        self.write(
            "apps/docs/providers.mdx",
            "# Providers\n999 providers.\n",  # provider-count-exempt: planted wrong-count fixture
        )
        result = self.freshness.provider_health(self.root)
        self.assertEqual(result["documented_total"], 999)
        self.assertFalse(result["matches"])

    def test_provider_absent_documented_count_is_explicit_unknown(self):
        self.provider_fixture()
        self.write("apps/docs/providers.mdx", "# Providers\nA supported catalog.\n")
        result = self.freshness.provider_health(self.root)
        self.assertIsNone(result["matches"])
        self.assertIn("CANNOT DETERMINE", result["unknown"])


class SignalsHonestyTests(unittest.TestCase):
    """Exercise the existing gather entrypoint with real mutated source files."""

    def setUp(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        actual_root = Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location(
            "signals_behavior_tests", actual_root / "scripts/ops/eng-signals.py"
        )
        self.signals = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.signals)
        original_load = self.signals.load

        def fixture_load(path, name):
            if "check-spec-governance" in path:
                return SimpleNamespace(
                    check=lambda staged: ([], 0, 0), roadmap_rows=guard.roadmap_rows
                )
            if "skill-compliance" in path:
                return SimpleNamespace(
                    measure=lambda: {"since": "2026-10-08", "skills": {}}
                )
            with patch.object(self.signals, "ROOT", actual_root):
                return original_load(path, name)

        for target in (
            patch.object(self.signals, "ROOT", self.root),
            patch.object(self.signals, "load", fixture_load),
            patch.object(
                self.signals,
                "command",
                lambda *args, **kwargs: {"exit": 0, "output": ""},
            ),
        ):
            target.start()
            self.addCleanup(target.stop)
        self.write(
            "docs/runbook/ROADMAP.md",
            "| `OBS-01` | **BUILT** | Observe | proof.py:1 | spec |\n",
        )
        self.write(
            "docs/inventory/README.md",
            "GENERATED — edit docs/runbook/ROADMAP.md\nMANUAL DRIFT\n",
        )
        self.write(
            "docs/" + "trackers/" + "FOUNDER" + "_ACTIONS.md",
            "No outstanding fixture actions.\n",
        )
        self.write(
            "crates/gateway/providers.tsv",
            "id\turl\n"
            + "".join(f"p{i}\thttps://example.invalid/{i}\n" for i in range(187)),
        )
        self.write(
            "crates/gateway/src/providers/mod.rs",
            "pub struct ProviderRegistry {\n"
            + "".join(f"    pub adapter{i}: NativeProvider,\n" for i in range(6))
            + "}\n",
        )
        self.write(
            "apps/docs/providers.mdx",
            "# Providers\n999 providers.\n",  # provider-count-exempt: planted wrong-count fixture
        )
        self.write(
            "scripts/ci/doc-freshness-policy.json",
            '{"max_age_days":30,"artifacts":{"AGENTS.md":{}}}',
        )
        self.write("AGENTS.md", "No verification evidence.\n")

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def test_signals_inventory_marker_does_not_hide_drift(self):
        result = self.signals.gather(cheap=True)["inventory"]
        self.assertEqual(result.get("matches"), False, result)

    def test_signals_provider_claim_is_compared_to_actual_document(self):
        result = self.signals.gather(cheap=True)["providers"]
        self.assertEqual(result.get("documented_total"), 999, result)
        self.assertEqual(result.get("matches"), False, result)

    def test_signals_surface_critical_artifact_unknown(self):
        data = self.signals.gather(cheap=True)
        artifacts = data.get("critical_artifacts", [])
        self.assertTrue(
            any(
                row["path"] == "AGENTS.md"
                and row["status"] == "amber"
                and "CANNOT DETERMINE" in str(row["details"])
                for row in artifacts
            ),
            "Missing verification must appear as a per-artifact unknown, not disappear",
        )
