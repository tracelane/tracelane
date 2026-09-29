import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import Page from "./legal/[doc]/page";
it.each(["privacy", "terms", "dpa"])(
	"renders an honest interim page for the unpublished %s document",
	async (doc) => {
		const html = renderToStaticMarkup(
			await Page({ params: Promise.resolve({ doc }) }),
		);
		expect(html).toContain("being finalised");
		expect(html).toContain('href="/support"');
		for (const href of ["/privacy", "/terms", "/dpa"]) {
			expect(html).toContain(`href="${href}"`);
		}
		expect(html).toContain("sign-in required");
		expect(html).not.toContain("DRAFT");
		expect(html).not.toMatch(/\[[\s\S]*?\]/);
		expect(html).not.toContain("GOVERNING LAW");
	},
);
it("keeps unknown documents unavailable", async () => {
	await expect(
		Page({ params: Promise.resolve({ doc: "unknown" }) }),
	).rejects.toThrow("not_found");
});

it.each(["privacy", "terms", "dpa"])(
	"the bare /%s URL serves the same safe interim state",
	async (doc) => {
		const pages = {
			privacy: () => import("./privacy/page"),
			terms: () => import("./terms/page"),
			dpa: () => import("./dpa/page"),
		};
		const module = await pages[doc as keyof typeof pages]();
		expect(renderToStaticMarkup(await module.default())).toContain(
			"being finalised",
		);
	},
);
