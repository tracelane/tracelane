import { StatCard } from "@tracelanedev/ui";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
it.each(["default", "action", "inverse"] as const)(
	"shows a failing number on %s cards",
	(variant) => {
		const html = renderToStaticMarkup(
			<StatCard label="Errors" value="2" tone="danger" variant={variant} />,
		);
		expect(html).toMatch(/class="[^"]*text-danger-ink[^"]*">2</);
	},
);
it("keeps an untoned action card neutral instead of borrowing selection styling", () => {
	const html = renderToStaticMarkup(
		<StatCard label="Requests" value="12" variant="action" />,
	);
	expect(html).not.toContain("bg-action-soft");
	expect(html).not.toContain("border-action-line");
});
