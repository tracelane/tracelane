import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import Page from "./page";
it("distinguishes purge eligibility from completed deletion and retained data", () => {
	const html = renderToStaticMarkup(<Page />);
	expect(html).not.toContain("permanent deletion within 30 days");
	expect(html).toContain("eligible for purge");
	expect(html).toContain("30-day grace period by default");
	expect(html).toContain("Audit records and backups");
	expect(html).toContain('href="/sign-out"');
});
