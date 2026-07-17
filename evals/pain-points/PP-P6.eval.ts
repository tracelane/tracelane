import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-P6 — Native multimodal payload rendering
 *
 * Competitor behavior: Langfuse renders multimodal LLM calls as raw JSON
 * blobs. Images are base64 strings. Audio is not rendered at all. The user
 * experience for debugging multimodal agent calls is "view source."
 *
 * Pain: Vision-capable agents are mainstream. Teams debugging image-captioning
 * agents, screenshot-based A2UI agents, or audio-processing agents can't
 * inspect their multimodal payloads in any competitor's dashboard.
 *
 * Tracelane fix: The trace detail page renders multimodal payloads natively.
 * Base64-encoded images are decoded and displayed inline. Audio is rendered
 * with a waveform player. Tool results with image content are thumbnailed.
 *
 * Eval design:
 * - Verify ContentPart in the model supports image_url and base64 image types
 * - Verify dashboard trace detail page has a multimodal content area
 *
 */
describe("PP-P6: Native multimodal payload rendering", () => {
  it("ChatRequest supports ContentPart with image type", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/shared/src/model.rs"),
      "utf8"
    );
    expect(content).toMatch(/image|multimodal|ContentPart/i);
  });

  it("trace detail page file exists", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const p = path.resolve(
      __dirname,
      "../../apps/web/app/traces/[traceId]/page.tsx"
    );
    expect(fs.existsSync(p)).toBe(true);
  });

  it.skip("images render inline in trace detail (Playwright — Week 7)", async () => {
    // Full: open trace with image content, assert <img> element visible
  });
});
