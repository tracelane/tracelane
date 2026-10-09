import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";

// Upstream https://www.promptfoo.dev/config-schema.json, retrieved 2026-09-30.
// Rust's regression_promptfoo_matches_upstream_schema_fixture pins this fixture
// to actual exporter output. Next already bundles this draft-07 validator.
const require = createRequire(import.meta.url);
const { validate } = require("next/dist/compiled/schema-utils3") as {
	validate: (schema: unknown, value: unknown) => void;
};
const fixtureRoot = new URL(
	"../../../crates/gateway/tests/fixtures/",
	import.meta.url,
);
const schema = JSON.parse(
	readFileSync(new URL("promptfoo-config-schema.json", fixtureRoot), "utf8"),
);
const fixture = JSON.parse(
	readFileSync(new URL("regression-promptfoo.json", fixtureRoot), "utf8"),
);

describe("regression export against Promptfoo's upstream schema", () => {
	it("accepts the actual Rust export shape", () => {
		expect(() => validate(schema, fixture)).not.toThrow();
	});
	it("rejects an invalid prompt field rather than treating any JSON as a fixture", () => {
		const bad = structuredClone(fixture);
		bad.prompts = 42;
		expect(() => validate(schema, bad)).toThrow();
	});
});
