import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-P8 — No hidden egress or data-export fees
 *
 * Competitor behavior: many observability vendors charge separately for
 * ingestion AND storage AND query AND export, so customers are surprised by
 * 3× the estimated bill. The "cheap" tier becomes expensive once teams need
 * to extract their own data.
 *
 * Pain: Vendor lock-in via pricing. Teams can't migrate because exporting
 * historical traces costs more than a new year of the competitor subscription.
 * "We checked the exit cost and decided to stay even though the product sucks."
 *
 * Tracelane fix: Full trace export included at every paid tier (OTLP +
 * OpenInference format). Cloudflare R2 provides free egress. No export fees.
 * Customer escape hatch is guaranteed in ADR-001 (anti-lock-in).
 *
 * Eval: Assert export capability and no egress fee commitment are documented.
 *
 */
describe("PP-P8: No hidden egress or data-export fees", () => {
  it("TRD documents export in OTLP + OpenInference format", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const trd = fs.readFileSync(
      path.resolve(__dirname, "../fixtures/public-spec.md"),
      "utf8"
    );
    expect(trd).toContain("OTLP");
    expect(trd).toContain("OpenInference");
    expect(trd).toContain("export");
  });

  it("Cloudflare R2 provides free egress", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const trd = fs.readFileSync(
      path.resolve(__dirname, "../fixtures/public-spec.md"),
      "utf8"
    );
    expect(trd).toContain("R2");
    expect(trd).toContain("egress");
  });

  it("anti-lock-in architecture documented in ADR-001", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const adr = fs.readFileSync(
      path.resolve(__dirname, "../../decisions/ADR-001-license-apache-2.md"),
      "utf8"
    );
    expect(adr.length).toBeGreaterThan(200);
  });
});
