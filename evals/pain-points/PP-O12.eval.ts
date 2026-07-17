import { describe, it } from "vitest";
import { expect } from "../src/harness.js";
import fs from "node:fs";
import path from "node:path";

/**
 * PP-O12 — Apache 2.0 + public licensing pledge
 *
 * Competitor behavior: Langfuse changed from MIT to BSL/ELv2 in October 2024
 * — a retroactive license change that locked out existing self-hosters.
 * PostHog (Apache 2.0) and OpenReplay (ELv2 core + AGPL) have complex
 * dual-license models. Customers cannot plan around licenses that can change.
 *
 * Pain: Enterprise procurement requires stable licenses. A license change
 * forces re-evaluation, legal review, and potentially ripping out tooling.
 * The uncertainty has a real cost even if the license never actually changes.
 *
 * Tracelane fix: Apache 2.0 + LICENSE-PLEDGE.md. The pledge commits to
 * never changing the license, with a BSL trigger clause that activates
 * if a hyperscaler captures >5% of Tracelane's revenue. This makes the
 * commitment credible — it has teeth if violated.
 *
 * Eval design:
 * - Read LICENSE and assert Apache 2.0
 * - Read LICENSE-PLEDGE.md and assert the non-revocation commitment
 * - Assert the pledge mentions the BSL trigger clause
 *
 */
describe("PP-O12: Apache 2.0 + public licensing pledge", () => {
  const repoRoot = path.resolve(__dirname, "../../");

  it("LICENSE is Apache 2.0 full text", () => {
    const license = fs.readFileSync(path.join(repoRoot, "LICENSE"), "utf8");
    expect(license).toContain("Apache License");
    expect(license).toContain("Version 2.0");
    expect(license).toContain("http://www.apache.org/licenses/LICENSE-2.0");
  });

  it("LICENSE-PLEDGE.md exists with non-revocation commitment", () => {
    const pledge = fs.readFileSync(
      path.join(repoRoot, "LICENSE-PLEDGE.md"),
      "utf8"
    );
    // Must contain some commitment language
    expect(pledge.toLowerCase()).toMatch(/pledge|commit|never/);
  });

  it("LICENSE-PLEDGE.md references BSL trigger clause", () => {
    const pledge = fs.readFileSync(
      path.join(repoRoot, "LICENSE-PLEDGE.md"),
      "utf8"
    );
    // The BSL trigger makes the pledge credible
    expect(pledge).toMatch(/BSL|Business Source|hyperscaler|trigger/i);
  });

  it("AI_DISCLOSURE.md acknowledges Claude Code co-authorship", () => {
    const disclosure = fs.readFileSync(
      path.join(repoRoot, "AI_DISCLOSURE.md"),
      "utf8"
    );
    expect(disclosure).toMatch(/claude|anthropic/i);
  });
});
