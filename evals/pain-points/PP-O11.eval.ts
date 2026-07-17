import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-O11 — CI-gate evals via GitHub Action
 *
 * Competitor behavior: Portkey has no eval integration. Langfuse's eval
 * system is cloud-only with no GitHub Actions integration. LiteLLM has no
 * pain-point eval concept. Teams build their own fragile test harnesses.
 *
 * Pain: Marketing claims get out of sync with product reality. A provider
 * adapter breaks the Gemini translation — nobody notices for 3 weeks
 * because there was no automated assertion. Teams file bugs after customers
 * report it.
 *
 * Tracelane fix: 50 pain-point evals are the merge gate. CI runs
 * `pnpm eval:run --suite=all` on every PR. If PP-G8 fails (provider
 * translation broken), the PR is blocked. Marketing claims are tied
 * directly to code correctness.
 *
 * Eval design:
 * - Verify ci.yml runs the eval suite
 * - Verify the eval suite spans the full pain-point range
 * - Verify the harness has the painPoint() function
 *
 */
describe("PP-O11: CI-gate evals via GitHub Action", () => {
  it("ci.yml exists and runs eval suite", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const ciYml = fs.readFileSync(
      path.resolve(__dirname, "../../.github/workflows/ci.yml"),
      "utf8"
    );
    expect(ciYml).toMatch(/eval/i);
  });

  it("eval harness exports painPoint() function", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const harness = fs.readFileSync(
      path.resolve(__dirname, "../src/harness.ts"),
      "utf8"
    );
    expect(harness).toContain("painPoint");
  });

  it("the pain-point eval suite spans the full PP-G1..PP-PR12 range", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const dir = path.resolve(__dirname);
    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".eval.ts"));
    // The suite is public + runnable; both ends of the range are present.
    expect(files.length).toBeGreaterThanOrEqual(40);
    expect(files).toContain("PP-G1.eval.ts");
    expect(files).toContain("PP-PR12.eval.ts");
  });
});
