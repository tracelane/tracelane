/**
 * `EVL-03` §2/§3 — `buildPromptVersionPayload`, the pure builder for the body
 * Codex's save-as-version dialog posts to the EXISTING
 * `POST /api/prompts/[name]/versions` (no new route). Precise contract (§3):
 * `{content: <system text, variables UNRENDERED>, model_pin: <column 1's
 * model>, template_variables: variablesIn(system)}` — content is byte-equal
 * to the system field, never trimmed or rendered (proof #6).
 */
import { describe, expect, it } from "vitest";
import { buildPromptVersionPayload } from "./playground-prompt-version";

describe("buildPromptVersionPayload — accepts a real draft", () => {
	it("builds {content, model_pin, template_variables} from the system field verbatim", () => {
		const result = buildPromptVersionPayload({
			system: "You are a support agent for {{product}}.\n\nBe concise.",
			model: "claude-sonnet-4-6",
		});
		expect(result).toEqual({
			ok: true,
			payload: {
				content: "You are a support agent for {{product}}.\n\nBe concise.",
				model_pin: "claude-sonnet-4-6",
				template_variables: ["product"],
			},
		});
	});

	it("does not trim or otherwise alter the system text — byte-equal (proof #6)", () => {
		const withPadding = "  leading and trailing whitespace kept  ";
		const result = buildPromptVersionPayload({
			system: withPadding,
			model: "gpt-4o",
		});
		expect(result.ok).toBe(true);
		expect(result.ok && result.payload.content).toBe(withPadding);
	});

	it("returns an empty template_variables array when the system has none", () => {
		const result = buildPromptVersionPayload({
			system: "You are a helpful assistant.",
			model: "gpt-4o",
		});
		expect(result.ok).toBe(true);
		expect(result.ok && result.payload.template_variables).toEqual([]);
	});

	it("trims only the MODEL id, never the content", () => {
		const result = buildPromptVersionPayload({
			system: "system text",
			model: "  gpt-4o  ",
		});
		expect(result.ok).toBe(true);
		expect(result.ok && result.payload.model_pin).toBe("gpt-4o");
	});
});

describe("buildPromptVersionPayload — must-reject", () => {
	it("refuses an empty system field — nothing to save", () => {
		const result = buildPromptVersionPayload({ system: "", model: "gpt-4o" });
		expect(result).toEqual({
			ok: false,
			error: "the system prompt is empty — nothing to save",
		});
	});

	it("refuses a whitespace-only system field", () => {
		const result = buildPromptVersionPayload({
			system: "   \n\t  ",
			model: "gpt-4o",
		});
		expect(result.ok).toBe(false);
	});

	it("refuses an empty/blank model — column 1 must have one selected", () => {
		const result = buildPromptVersionPayload({ system: "text", model: "  " });
		expect(result).toEqual({
			ok: false,
			error: "select a model for column 1 before saving",
		});
	});
});
