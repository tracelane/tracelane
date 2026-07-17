import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-G6 — Public eval suite + aggressive issue triage
 *
 * Competitor behavior: Helicone's eval suite is not public. LangSmith does
 * not publish benchmarks. Braintrust publishes marketing claims but not
 * runnable evals. When bugs are filed, response time is days-to-weeks with
 * no public SLA.
 *
 * Pain: Developers can't verify claims independently. "Is the 5K RPS claim
 * actually tested? Is it on their hardware or mine?" Support tickets disappear
 * into black holes. No visibility into product roadmap or fix timelines.
 *
 * Tracelane fix: All 50 pain-point evals are public and runnable. CI
 * results are public. Issues are triaged within 24h with public labels.
 * Marketing claims on the website are auto-gated by the eval results.
 *
 * Eval: Verify the eval suite infrastructure exists and is wired to CI.
 *
 * Linked: PP-G6
 */
describe("PP-G6: Public eval suite + aggressive issue triage", () => {
  it("eval pain-points directory contains multiple eval files", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const dir = path.resolve(__dirname);
    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".eval.ts"));
    // At least 20 evals written by Week 6
    expect(files.length).toBeGreaterThanOrEqual(20);
  });

  it("CI workflow includes eval-suite job", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const ci = fs.readFileSync(
      path.resolve(__dirname, "../../.github/workflows/ci.yml"),
      "utf8"
    );
    expect(ci).toContain("eval-suite");
    expect(ci).toContain("eval:run");
  });

  it("the public eval suite is discoverable and includes the headline evals", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const dir = path.resolve(__dirname);
    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".eval.ts"));
    // The pain-point evals are public + runnable; the headline ones are present.
    expect(files.length).toBeGreaterThanOrEqual(40);
    expect(files).toContain("PP-G3.eval.ts");
    expect(files).toContain("PP-PR1.eval.ts");
  });
});
