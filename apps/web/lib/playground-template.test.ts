/**
 * `EVL-03` §2 — `variablesIn` / `render`, the ONE variable-templating
 * implementation shared by the playground route (rendering before dispatch)
 * and the save-as-version payload (`playground-prompt-version.ts`,
 * `template_variables: variablesIn(system)`). Syntax: `{{name}}`, `name` =
 * `[A-Za-z_][A-Za-z0-9_]{0,127}` (spec table, row 4).
 */
import { describe, expect, it } from "vitest";
import { render, variablesIn } from "./playground-template";

describe("variablesIn", () => {
	it("finds every distinct {{name}} token, in first-seen order", () => {
		expect(variablesIn("Hi {{name}}, your order {{order_id}} shipped")).toEqual(
			["name", "order_id"],
		);
	});

	it("de-duplicates a repeated variable", () => {
		expect(variablesIn("{{x}} and {{x}} again")).toEqual(["x"]);
	});

	it("returns an empty array when there are no variables", () => {
		expect(variablesIn("no placeholders here")).toEqual([]);
	});

	it("rejects a name starting with a digit — not a valid identifier", () => {
		expect(variablesIn("{{1abc}}")).toEqual([]);
	});

	it("rejects an empty {{}} and a name with a hyphen", () => {
		expect(variablesIn("{{}} {{order-id}}")).toEqual([]);
	});

	it("accepts underscores and digits after the first character", () => {
		expect(variablesIn("{{a_b2}}")).toEqual(["a_b2"]);
	});
});

describe("render", () => {
	it("substitutes every variable it is given a value for", () => {
		const { rendered, missing } = render("Hi {{name}}, order {{order_id}}", {
			name: "Ava",
			order_id: "A-1042",
		});
		expect(rendered).toBe("Hi Ava, order A-1042");
		expect(missing).toEqual([]);
	});

	it("leaves an unfilled variable as the literal token and reports it missing", () => {
		const { rendered, missing } = render("Hi {{name}}, {{missing_var}}", {
			name: "Ava",
		});
		expect(rendered).toBe("Hi Ava, {{missing_var}}");
		expect(missing).toEqual(["missing_var"]);
	});

	it("reports each distinct missing variable once even if repeated", () => {
		const { missing } = render("{{x}} {{x}} {{y}}", {});
		expect(missing).toEqual(["x", "y"]);
	});

	it("renders text with no variables unchanged", () => {
		const { rendered, missing } = render("no placeholders", {});
		expect(rendered).toBe("no placeholders");
		expect(missing).toEqual([]);
	});

	it("treats an empty-string value as FILLED, not missing", () => {
		const { rendered, missing } = render("[{{x}}]", { x: "" });
		expect(rendered).toBe("[]");
		expect(missing).toEqual([]);
	});
});
