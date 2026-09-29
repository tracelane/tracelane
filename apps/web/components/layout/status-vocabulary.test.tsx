import { StatusBadge } from "@tracelanedev/ui";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
it.each([
	["ok", "OK"],
	["OK", "OK"],
	["success", "OK"],
	["needs_review", "Needs review"],
	["half_open", "Half open"],
	["not_judged", "Not judged"],
])("uses the canonical spelling for %s", (status, label) => {
	expect(renderToStaticMarkup(<StatusBadge status={status} />)).toContain(
		`>${label}<`,
	);
});
