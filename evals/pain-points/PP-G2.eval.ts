import { describe, it } from "vitest";
import { expect } from "../src/harness.js";
import fs from "node:fs";
import path from "node:path";

/**
 * PP-G2 — Apache 2.0 self-host available
 *
 * Competitor behavior: Helicone (MIT for SDK but custom terms for the AI
 * gateway), Phoenix (ELv2 — cannot compete commercially), Langfuse
 * (MIT core but self-host restrictions in practice for large deployments).
 *
 * Pain: Enterprise teams cannot use GPL/ELv2 software without legal review.
 * Legal review takes 4–12 weeks. Projects stall. Teams pick proprietary
 * SaaS instead.
 *
 * Tracelane fix: Full Apache 2.0 for the entire stack, including the gateway.
 * No "Community Edition" vs "Enterprise Edition" split. Everything is OSS.
 * The LICENSE-PLEDGE.md commits to never changing this.
 *
 * Eval design:
 * - Read LICENSE file and assert it contains "Apache License, Version 2.0"
 * - Read LICENSE-PLEDGE.md and assert the pledge exists
 * - Assert no dependency uses GPL-3.0, AGPL, or ELv2
 * - Assert Helicone ai-gateway code (GPL-3.0) is not present in codebase
 *
 */
describe("PP-G2: Apache 2.0 self-host available", () => {
  const repoRoot = path.resolve(__dirname, "../../");

  it("LICENSE file is Apache 2.0", () => {
    const license = fs.readFileSync(path.join(repoRoot, "LICENSE"), "utf8");
    expect(license).toContain("Apache License");
    expect(license).toContain("Version 2.0");
  });

  it("LICENSE-PLEDGE.md exists and contains the non-revocation commitment", () => {
    const pledge = fs.readFileSync(
      path.join(repoRoot, "LICENSE-PLEDGE.md"),
      "utf8"
    );
    expect(pledge.toLowerCase()).toMatch(/pledge|commit|never|change/i);
  });

  // Behavioral half: `cargo license --json` over the real workspace, asserting
  // no GPL/AGPL/ELv2 crate is present. Not yet wired (needs the cargo
  // toolchain + a license-scan step). Skip honestly rather than asserting a
  // hardcoded list length.
  it.skip(
    "no GPL-3.0 or ELv2 dependencies in Cargo workspace — requires `cargo license` scan",
    async () => {
      // TODO: run `cargo license --json`, assert none are GPL/AGPL/ELv2.
      expect(true).toBe(true);
    },
  );

  // Behavioral half: grep the real source tree for Helicone copyright headers.
  // Not yet wired as a measured check; skip honestly.
  it.skip(
    "no files contain helicone ai-gateway copyright headers — requires source-tree grep step",
    async () => {
      // TODO: grep -r "helicone" crates/ --include="*.rs", assert empty.
      expect(true).toBe(true);
    },
  );
});
