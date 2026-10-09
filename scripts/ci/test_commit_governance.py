"""Staged commit evidence tests."""

import importlib.util
import unittest
from pathlib import Path

commit_spec = importlib.util.spec_from_file_location(
    "commit_governance", Path(__file__).with_name("check-commit-governance.py")
)
commit_guard = importlib.util.module_from_spec(commit_spec)
commit_spec.loader.exec_module(commit_guard)


class CommitTests(unittest.TestCase):
    def test_feature_subject_spec_ids(self):
        self.assertEqual(
            commit_guard.feature_spec_ids(
                "feat(WEB-REV-01): implement A13 and GOV-01; B-542 context"
            ),
            ["WEB-REV-01", "A13", "GOV-01"],
        )
        self.assertEqual(
            commit_guard.feature_spec_ids("docs: explain GOV-01"), ["GOV-01"]
        )

    def check(
        self,
        message="chore: update\n\nSkills: test-driven-development\n",
        changed=(),
        files=None,
        added="",
        public_errors=(),
    ):
        return commit_guard.evaluate(
            message, changed, files or {}, {p: added for p in changed}, public_errors
        )

    def test_skills_trailer(self):
        self.assertEqual(self.check(), [])

    def test_missing_skills(self):
        self.assertTrue(self.check("chore: update"))

    def test_skills_in_body_blocks(self):
        self.assertTrue(self.check("chore: update\n\nSkills: tdd\n\nordinary body"))

    def test_staged_report(self):
        self.assertEqual(
            self.check(
                "fix: auth\n\nSkills: security-and-hardening\nSecurity-Review: review.md",
                ["src/auth.rs"],
                {"review.md": "# Review\nNo blocking findings after concrete probes."},
            ),
            [],
        )

    def test_unstaged_report(self):
        self.assertTrue(
            self.check(
                "fix: auth\n\nSkills: security-and-hardening\nSecurity-Review: review.md",
                ["src/auth.rs"],
            )
        )

    def test_review_path_escape(self):
        self.assertTrue(
            self.check(
                "fix: auth\n\nSkills: security-and-hardening\nSecurity-Review: ../review.md",
                ["src/auth.rs"],
                {"../review.md": "fake"},
            )
        )

    def test_red_test_in_diff(self):
        self.assertEqual(
            self.check(
                "fix(B-123): reject invalid key\n\nSkills: test-driven-development\nRed-Test: test_reject",
                ["tests/test_auth.py"],
                {"tests/test_auth.py": "def test_reject(): pass"},
                "def test_reject(): pass",
            ),
            [],
        )

    def test_red_test_absent_diff(self):
        self.assertTrue(
            self.check(
                "fix(B-123): reject invalid key\n\nSkills: test-driven-development\nRed-Test: test_reject",
                added="",
            )
        )

    def test_red_test_comment_blocks(self):
        self.assertTrue(
            self.check(
                "fix(B-123): reject invalid key\n\nSkills: test-driven-development\nRed-Test: test_reject",
                added="# test_reject",
            )
        )

    def test_docstring_only_change_is_not_red_test(self):
        before = 'def test_complete_sections():\n    """old description"""\n    assert True\n'
        after = 'def test_complete_sections():\n    """new description"""\n    assert True\n'
        self.assertEqual(
            commit_guard.test_definition(
                before, "test_complete_sections", "tests/test_x.py"
            ),
            commit_guard.test_definition(
                after, "test_complete_sections", "tests/test_x.py"
            ),
        )

    def test_dependency_review(self):
        self.assertEqual(
            self.check(
                "chore: dependencies\n\nSkills: code-review-and-quality\nDep-Review: reviewed ownership and lockfile changes",
                ["Cargo.lock"],
            ),
            [],
        )

    def test_missing_dependency_review(self):
        self.assertTrue(self.check(changed=["Cargo.lock"]))

    def test_public_copy_checked(self):
        self.assertEqual(
            self.check(
                "docs: wording\n\nSkills: public-copy\nPublic-Copy: checked",
                public_errors=[],
            ),
            [],
        )

    def test_public_copy_cannot_hide_failure(self):
        self.assertTrue(
            self.check(
                "docs: wording\n\nSkills: public-copy\nPublic-Copy: checked",
                public_errors=["banned claim"],
            )
        )

    def test_duplicate_skills_blocks(self):
        self.assertTrue(self.check("chore: update\n\nSkills: one\nSkills: two"))

    def test_empty_skills_blocks(self):
        self.assertTrue(self.check("chore: update\n\nSkills: "))


class OverrideTests(unittest.TestCase):
    def test_logged_override(self):
        result = commit_guard.override_message(
            "chore: emergency", "Founder emergency: restore the broken hook"
        )
        self.assertIn("Governance-Override: Founder emergency", result)

    def test_unlogged_override(self):
        with self.assertRaises(ValueError):
            commit_guard.override_message("message", "")

    def test_override_newline_blocks(self):
        with self.assertRaises(ValueError):
            commit_guard.override_message(
                "message", "long enough reason for bypass\nSkills: fake"
            )

    def test_public_scope(self):
        files = {
            "scripts/export/export-allow.txt": "docs\nREADME.md\n",
            "scripts/export/export-deny.txt": "docs/internal\n",
        }
        self.assertEqual(
            commit_guard.public_paths(
                ["README.md", "docs/" + "internal/private.md", "apps/site/index.astro"],
                files,
            ),
            ["README.md", "apps/site/index.astro"],
        )

    def test_public_copy_planted_claim_blocks(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "README.md": "Our ledger is tamper-proof.",
        }
        self.assertTrue(commit_guard.public_copy(["README.md"], files))

    def test_public_copy_clean_accepts(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "README.md": "Our ledger is tamper-evident.",
        }
        self.assertEqual(commit_guard.public_copy(["README.md"], files), [])

    def test_svg_text_planted_claim_blocks(self):
        files = {
            "scripts/export/export-allow.txt": "apps/docs\n",
            "scripts/export/export-deny.txt": "docs/internal\n",
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg xmlns="http://www.w3.org/2000/svg"><text>tamper-proof</text></svg>',
        }
        paths = commit_guard.public_paths(["apps/docs/images/claim.svg"], files)
        self.assertEqual(paths, ["apps/docs/images/claim.svg"])
        self.assertTrue(commit_guard.public_copy(paths, files))

    def test_svg_tspan_planted_claim_blocks(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg xmlns="http://www.w3.org/2000/svg"><text>tamper-<tspan>proof</tspan></text></svg>',
        }
        self.assertTrue(commit_guard.public_copy(["apps/docs/images/claim.svg"], files))

    def test_svg_entity_encoded_claim_blocks(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg xmlns="http://www.w3.org/2000/svg"><text>tamper&#45;proof</text></svg>',
        }
        self.assertTrue(commit_guard.public_copy(["apps/docs/images/claim.svg"], files))

    def test_svg_line_break_cannot_split_a_banned_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\nreliable | 100%[[:space:]]*reliable | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg xmlns="http://www.w3.org/2000/svg"><text>100%&#10;reliable</text></svg>',
        }
        self.assertTrue(commit_guard.public_copy(["apps/docs/images/claim.svg"], files))

    def test_svg_sibling_text_keeps_document_order(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\nreliable | 100%[[:space:]]*reliable | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg xmlns="http://www.w3.org/2000/svg"><text x="0">100%</text><text x="60">reliable</text></svg>',
        }
        self.assertTrue(commit_guard.public_copy(["apps/docs/images/claim.svg"], files))

    def test_svg_sibling_text_can_form_one_hyphenated_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text x="0">tamper-</text><text x="70">proof</text></svg>',
        }
        self.assertTrue(commit_guard.public_copy(["apps/docs/images/claim.svg"], files))

    def test_svg_tspan_position_can_form_spaced_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\nreliable | 100% reliable | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text>100%<tspan x="60">reliable</tspan></text></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_mixed_tspan_boundaries_can_form_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\nreliable | 100% reliable | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text>100%<tspan x="60">re</tspan><tspan>liable</tspan></text></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_mixed_sibling_boundaries_can_form_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\nreliable | 100% reliable | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text y="20">100%</text><text y="20">re</text><text y="20">liable</text></svg>',
        }
        self.assertTrue(commit_guard.public_copy(["apps/docs/images/claim.svg"], files))

    def test_svg_equivalent_numeric_rows_cannot_split_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\nreliable | 100% reliable | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text y="20">100%</text><text y="20.0">re</text><text y="20.00">liable</text></svg>',
        }
        self.assertTrue(commit_guard.public_copy(["apps/docs/images/claim.svg"], files))

    def test_svg_unitless_and_px_rows_cannot_split_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\nreliable | 100% reliable | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text y="20">100%</text><text y="20px">re</text><text y="20.00px">liable</text></svg>',
        }
        self.assertTrue(commit_guard.public_copy(["apps/docs/images/claim.svg"], files))

    def test_svg_default_y_and_zero_rows_cannot_split_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\nreliable | 100% reliable | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text>100%</text><text y="0">re</text><text y="0px">liable</text></svg>',
        }
        self.assertTrue(commit_guard.public_copy(["apps/docs/images/claim.svg"], files))

    def test_svg_dy_positioning_blocks_scan(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text dy="20">clean</text></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_nested_tspan_y_positioning_blocks_scan(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\nreliable | 100% reliable | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text y="20">100%</text><text y="40"><tspan y="20">re</tspan></text><text y="20">liable</text></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_horizontal_order_cannot_hide_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\nreliable | 100% reliable | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text x="30" y="20">re</text><text x="0" y="20">100%</text><text x="42" y="20">liable</text></svg>',
        }
        self.assertTrue(commit_guard.public_copy(["apps/docs/images/claim.svg"], files))

    def test_svg_dx_positioning_blocks_scan(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\nreliable | 100% reliable | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text x="0" dx="30" y="20">re</text><text x="30" dx="-30" y="20">100%</text><text x="42" y="20">liable</text></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_nested_tspan_x_positioning_blocks_scan(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text>clean<tspan x="30">copy</tspan></text></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_baseline_shift_blocks_scan(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\nreliable | 100% reliable | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text x="0" y="20">100%</text><text x="30" y="40" baseline-shift="20">re</text><text x="42" y="20">liable</text></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_hidden_descendant_cannot_interrupt_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text>tamper-<tspan display="none">x</tspan>proof</text></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_zero_size_descendant_cannot_interrupt_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text>tamper-<tspan font-size="0">x</tspan>proof</text></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_zero_size_text_with_exponent_blocks_scan(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text>tamper-</text><text font-size="0e0">x</text><text>proof</text></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_title_descendant_cannot_interrupt_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": "<svg><text>tamper-<title>x</title>proof</text></svg>",
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_foreign_namespace_tspan_cannot_interrupt_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg xmlns="http://www.w3.org/2000/svg"><text>tamper-<tspan xmlns="urn:hidden">x</tspan>proof</text></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_invisible_compressed_tspan_cannot_interrupt_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text>tamper-<tspan fill="none" textLength="0.001" lengthAdjust="spacingAndGlyphs">x</tspan>proof</text></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_transparent_hex_tspan_cannot_interrupt_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text>tamper-<tspan fill="#00000000">x</tspan>proof</text></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_zero_width_character_cannot_split_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": "<svg><text>tamper-&#x200b;proof</text></svg>",
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_soft_hyphen_cannot_split_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": "<svg><text>tamper-&#xad;proof</text></svg>",
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_nonspacing_unicode_cannot_split_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": "<svg><text>tamper-&#x17b4;proof</text></svg>",
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_hangul_choseong_filler_cannot_split_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": "<svg><text>tamper-&#x115f;proof</text></svg>",
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_hangul_compatibility_filler_cannot_split_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": "<svg><text>tamper-&#x3164;proof</text></svg>",
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_bidi_override_cannot_reverse_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text direction="rtl" unicode-bidi="bidi-override">foorp-repmat</text></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_subpixel_y_values_cannot_split_visible_row(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\nreliable | 100% reliable | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text x="10" y="40">100%</text><text x="100" y="40.00000001">re</text><text x="136.125" y="40.00000002">liable</text></svg>',
        }
        self.assertTrue(commit_guard.public_copy(["apps/docs/images/claim.svg"], files))

    def test_svg_scaled_viewbox_cannot_split_visible_row(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\nreliable | 100% reliable | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg width="400" height="80" viewBox="0 0 40000 8000"><text x="1000" y="4000">100%</text><text x="10000" y="4002">re</text><text x="13612.5" y="4004">liable</text></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_event_handler_cannot_reveal_hidden_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg onload="document.getElementById(\'filler\').remove()"><text>tamper-<tspan id="filler">x</tspan>proof</text></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_staggered_rows_cannot_split_visible_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\nreliable | 100% reliable | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg width="400" height="100" font-size="30" font-family="monospace"><text x="10" y="40">100%</text><text x="100" y="42">re</text><text x="136" y="44">liable</text></svg>',
        }
        self.assertTrue(commit_guard.public_copy(["apps/docs/images/claim.svg"], files))

    def test_svg_letter_spacing_cannot_hide_descendant(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text>tamper-<tspan fill="#fff" letter-spacing="-18.0615234375">x</tspan>proof</text></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_conditional_tspan_cannot_interrupt_claim(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text>tamper-<tspan requiredExtensions="urn:unsupported">x</tspan>proof</text></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_set_animation_cannot_hide_claim_fragment(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text>tamper-<tspan id="x">x</tspan>proof</text><set href="#x" attributeName="display" to="none"/></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_anchor_can_reverse_visual_order(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text x="100" y="30">proof</text><text x="100" y="30" text-anchor="end">tamper-</text></svg>',
        }
        self.assertTrue(commit_guard.public_copy(["apps/docs/images/claim.svg"], files))

    def test_svg_nested_viewport_blocks_scan(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><svg x="30" y="10"><text y="10">clean</text></svg></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_stylesheet_blocks_scan(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><style>.raised {transform:translateY(-20px)}</style><text class="raised">clean</text></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_unsupported_y_unit_blocks_scan(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": '<svg><text y="20em">clean</text></svg>',
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_expansion_budget_blocks_before_large_allocation(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.svg": "<svg><text y='20'>"
            + "x" * 4_000
            + "</text>"
            + "".join(f"<text y='20'>{char}</text>" for char in "abcdefghijkl")
            + "</svg>",
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/claim.svg"], files)

    def test_svg_uppercase_extension_is_scanned(self):
        files = {
            "scripts/export/export-allow.txt": "apps/docs\n",
            "scripts/export/export-deny.txt": "docs/internal\n",
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/claim.SVG": "<svg><text>tamper-proof</text></svg>",
        }
        paths = commit_guard.public_paths(["apps/docs/images/claim.SVG"], files)
        self.assertEqual(paths, ["apps/docs/images/claim.SVG"])
        self.assertTrue(commit_guard.public_copy(paths, files))

    def test_svg_excessive_nesting_blocks_before_text_extraction(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/deep.svg": "<svg>"
            + "<text>x" * 70
            + "</text>" * 70
            + "</svg>",
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/deep.svg"], files)

    def test_svg_oversize_blocks_instead_of_skipping_copy(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/large.svg": "<svg><text>"
            + "x" * 1_000_001
            + "</text></svg>",
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/large.svg"], files)

    def test_svg_clean_text_accepts(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/clean.svg": '<svg xmlns="http://www.w3.org/2000/svg"><text>tamper-evident</text></svg>',
        }
        self.assertEqual(
            commit_guard.public_copy(["apps/docs/images/clean.svg"], files), []
        )

    def test_svg_non_text_attribute_does_not_count_as_copy(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/clean.svg": '<svg xmlns="http://www.w3.org/2000/svg"><path id="tamper-proof"/><text>tamper-evident</text></svg>',
        }
        self.assertEqual(
            commit_guard.public_copy(["apps/docs/images/clean.svg"], files), []
        )

    def test_svg_malformed_blocks(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ntamper-proof | tamper-proof | reason\n<!-- NEVER-SAY-AGAIN:END -->",
            "apps/docs/images/broken.svg": "<svg><text>clean",
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["apps/docs/images/broken.svg"], files)


class ReviewRegressionTests(unittest.TestCase):
    def test_documentation_cannot_supply_red_test(self):
        msg = "fix(B-123): guard\n\nSkills: tdd\nRed-Test: test_fake"
        body = "```python\ndef test_fake(): pass\n```"
        self.assertTrue(
            commit_guard.evaluate(
                msg, ["docs/note.md"], {"docs/note.md": body}, {"docs/note.md": body}
            )
        )

    def test_python_docstring_is_not_test(self):
        self.assertFalse(
            commit_guard.governance.definition(
                '"""\ndef test_fake(): pass\n"""', "test_fake", "test_x.py"
            )
        )

    def test_byok_provider_keys_requires_review(self):
        self.assertTrue(
            commit_guard.evaluate(
                "fix: keys\n\nSkills: tdd",
                ["crates/gateway/src/db/provider_keys.rs"],
                {},
                {},
            )
        )

    def test_malformed_public_rule_blocks(self):
        files = {
            "docs/reference/NEVER_SAY_AGAIN.md": "<!-- NEVER-SAY-AGAIN:BEGIN -->\ngood | banned | reason\nbad rule\n<!-- NEVER-SAY-AGAIN:END -->",
            "README.md": "clean",
        }
        with self.assertRaises(ValueError):
            commit_guard.public_copy(["README.md"], files)


class FinalReviewRegressionTests(unittest.TestCase):
    def test_template_literal_is_not_test(self):
        source = 'const example = `\ntest("test_fake", () => {});\n`;'
        self.assertFalse(
            commit_guard.governance.definition(source, "test_fake", "fake.test.ts")
        )

    def test_actual_javascript_test_is_definition(self):
        self.assertTrue(
            commit_guard.governance.definition(
                'test("test_real", () => {});', "test_real", "real.test.ts"
            )
        )

    def test_rust_raw_string_is_not_definition(self):
        source = 'let x = r#"\nfn test_fake() {}\n"#;'
        self.assertFalse(
            commit_guard.governance.definition(source, "test_fake", "fake.rs")
        )


class GovfixTests(unittest.TestCase):
    def test_codex_and_arbitrary_feature_subjects(self):
        for subject in (
            "codex GOV-9999: add reviewer probe",
            "repair GOV-9999 contract",
        ):
            self.assertEqual(commit_guard.feature_spec_ids(subject), ["GOV-9999"])

    def test_comment_naming_existing_test_is_not_red_evidence(self):
        self.assertTrue(
            commit_guard.evaluate(
                "fix(B-123): regression\n\nSkills: test-driven-development\nRed-Test: test_complete_sections",
                ["test_example.py"],
                {
                    "test_example.py": "def test_complete_sections(): pass\n# test_complete_sections"
                },
                {"test_example.py": "# test_complete_sections"},
            )
        )

    def test_rust_function_without_test_attribute_is_not_red_evidence(self):
        source = "fn test_reject() {}"
        self.assertTrue(
            commit_guard.evaluate(
                "fix(B-123): regression\n\nSkills: test-driven-development\nRed-Test: test_reject",
                ["example.rs"],
                {"example.rs": source},
                {"example.rs": source},
            )
        )

    def test_skip_preflight_still_runs_spec_governance(self):
        import os
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
            env["TRACELANE_SKIP_PREFLIGHT"] = "1"
            subprocess.run(["git", "init", "-q", tmp], env=env, check=True)
            for name in (
                "check-agent-claims.py",
                "build-doc-index.py",
                "build-surface-index.py",
                "check-inventory-generated.py",
            ):
                p = root / "scripts/ci" / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("")
            (root / "scripts/ci/check-spec-governance.py").write_text(
                "raise SystemExit(1)"
            )
            (root / ".githooks").mkdir()
            (root / ".githooks/check-commit-author.sh").write_text("exit 0")
            hook = Path(__file__).resolve().parents[2] / ".githooks/pre-commit"
            result = subprocess.run(
                ["bash", str(hook)],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_skills_cover_internal_html_and_signal_producer(self):
        spec = importlib.util.spec_from_file_location(
            "skills", Path(__file__).resolve().parents[1] / "ops/skill-compliance.py"
        )
        skills = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(skills)
        self.assertTrue(
            skills.eligible(
                "frontend-ui-engineering",
                "fix page",
                ["docs/internal/ENG-SIGNALS.html"],
            )
        )
        self.assertIn("observability-and-instrumentation", skills.SKILLS)
        self.assertTrue(
            skills.eligible(
                "observability-and-instrumentation",
                "fix signals",
                ["scripts/ops/eng-signals.py"],
            )
        )
        self.assertFalse(
            skills.eligible(
                "observability-and-instrumentation",
                "fix parser",
                ["scripts/docs/parser.py"],
            )
        )

    def test_commented_rust_attribute_blocks(self):
        for source in (
            "// #[test]\nfn test_reject() {}",
            "/* #[test]\nfn test_reject() {} */\nfn test_reject() {}",
        ):
            self.assertFalse(
                commit_guard.changed_test_definition(source, "test_reject", "x.rs")
            )

    def test_modified_test_body_is_evidence(self):
        self.assertEqual(
            commit_guard.evaluate(
                "fix(B-123): regression\n\nSkills: tdd\nRed-Test: test_reject",
                ["x.py"],
                {"x.py": "def test_reject():\n    assert False\n"},
                {"x.py": "    assert False"},
                before={"x.py": "def test_reject():\n    pass\n"},
            ),
            [],
        )

    def test_comments_inside_existing_rust_and_js_tests_are_not_changes(self):
        for path, old, new in (
            (
                "x.rs",
                "#[test]\nfn test_reject() { assert!(false); }",
                "#[test]\nfn test_reject() {\n// test_reject\n assert!(false); }",
            ),
            (
                "x.ts",
                'test("test_reject", () => { expect(false); });',
                'test("test_reject", () => {\n// test_reject\n expect(false); });',
            ),
        ):
            self.assertTrue(
                commit_guard.evaluate(
                    "fix(B-123): regression\n\nSkills: tdd\nRed-Test: test_reject",
                    [path],
                    {path: new},
                    {path: "// test_reject"},
                    before={path: old},
                )
            )

    def test_codex_html_feature_without_spec_is_refused_by_cli(self):
        import os
        import shutil
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
            env.pop("TRACELANE_GOVERNANCE_OVERRIDE", None)
            for filename in ("check-commit-governance.py", "check-spec-governance.py"):
                target = root / "scripts/ci" / filename
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(Path(__file__).with_name(filename), target)
            (root / "scripts/export").mkdir()
            (root / "scripts/export/export-allow.txt").write_text("docs\n")
            (root / "scripts/export/export-deny.txt").write_text("docs/internal\n")

            def git(*args):
                return subprocess.run(
                    ["git", *args], cwd=root, env=env, check=True, capture_output=True
                )

            git("init", "-q")
            (root / "docs/runbook").mkdir(parents=True)
            (root / "docs/runbook/ROADMAP.md").write_text(
                "| `GOV-01` | BUILT | Existing | proof | spec |\n"
            )
            git("add", "scripts/export", "docs/runbook/ROADMAP.md")
            git(
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.com",
                "commit",
                "-qm",
                "fixture",
            )
            (root / "page.html").write_text("<h1>Feature</h1>")
            git("add", "page.html")
            message = root / "message"
            message.write_text(
                "codex GOV-9999: add reviewer probe\n\nSkills: frontend-ui-engineering\n"
            )
            result = subprocess.run(
                [
                    "python3",
                    str(root / "scripts/ci/check-commit-governance.py"),
                    "--msg-file",
                    str(message),
                ],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("GOV-9999", result.stdout + result.stderr)
