import { describe, expect, it } from "vitest";
import { pickDefaultTaraModel } from "./models";

describe("pickDefaultTaraModel", () => {
	it("returns null for zero connected providers (the no-provider state)", () => {
		expect(pickDefaultTaraModel([])).toBeNull();
	});

	it("returns null when every connected provider is one Tara has no model for", () => {
		expect(
			pickDefaultTaraModel(["cohere", "azure", "some-obscure-provider"]),
		).toBeNull();
	});

	it("prefers anthropic over openai when both are connected", () => {
		expect(pickDefaultTaraModel(["openai", "anthropic"])).toEqual({
			providerId: "anthropic",
			model: "claude-haiku-4-5-20251001",
		});
	});

	it("falls back to openai when anthropic is not connected", () => {
		expect(pickDefaultTaraModel(["openai"])).toEqual({
			providerId: "openai",
			model: "gpt-4o-mini",
		});
	});
});
