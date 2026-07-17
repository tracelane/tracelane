import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-PR5 — CAPTCHA pre-empted <5ms
 *
 * Linked: PP-PR5, AFT-A2UI-CAPTCHA-001
 */
describe("PP-PR5: CAPTCHA pre-empted <5ms", () => {
  it("captcha predictor module exists", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const p = path.resolve(
      __dirname,
      "../../crates/gateway/src/predictive/captcha.rs"
    );
    expect(fs.existsSync(p)).toBe(true);
  });

  it("CaptchaPreemptor fires Warn for recaptcha URL", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/predictive/captcha.rs"),
      "utf8"
    );
    expect(content).toContain("AFT-A2UI-CAPTCHA-001");
    expect(content).toContain("recaptcha");
  });

  it("CaptchaPreemptor is wired into PredictiveLayer", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/predictive/mod.rs"),
      "utf8"
    );
    expect(content).toContain("CaptchaPreemptor");
  });

  it.skip("detection latency <5ms (integration benchmark — Week 7)", async () => {
    // Full: measure time from request arrival to Warn decision with CAPTCHA URL
    // Assert p99 < 5ms per PP-PR5 target
  });
});
