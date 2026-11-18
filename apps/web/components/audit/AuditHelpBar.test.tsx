import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { AuditHelpBar } from "./AuditHelpBar";

it("explains the bounded verification scope and does not invent a successful verdict", () => {
	const html = renderToStaticMarkup(h(AuditHelpBar, { exportEntitled: false }));
	expect(html).toContain("How to interpret this verification");
	expect(html).toContain(
		"only the rows counted above, the newest in the read window",
	);
	expect(html).toContain("Gateway-admitted audit events");
	expect(html).toContain("unavailable read");
	expect(html).not.toContain("Evidence handbook (PDF)");
	expect(html).toContain(
		"Exporting a range for the documented offline verifier requires the Enterprise plan.",
	);
	expect(html).not.toContain("workspace verified");
});

it("shows the existing export handbook only when entitled", () => {
	const html = renderToStaticMarkup(h(AuditHelpBar, { exportEntitled: true }));
	expect(html).toContain("Evidence handbook (PDF)");
	expect(html).toContain("/api/audit/handbook");
	expect(html).toContain(
		"Use the documented offline verifier with an exported audit range and the appropriate trust key.",
	);
	expect(html).not.toContain("requires the Enterprise plan");
});
