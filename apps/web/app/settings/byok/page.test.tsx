import { renderToStaticMarkup } from "react-dom/server";
import { expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ entitled: false }));
vi.mock("@/lib/auth", () => ({
	requireSession: async () => ({ tenantId: "org_cmk_copy" }),
}));
vi.mock("@/db", () => ({
	db: {
		select: () => ({
			from: () => ({
				where: () => ({ limit: async () => [{ id: "tenant", plan: "free" }] }),
			}),
		}),
	},
}));
vi.mock("@/lib/entitlements", () => ({
	resolveEntitlements: async () => ({ byok_cmk: h.entitled }),
}));
vi.mock("@/components/settings/ByokKeyManager", () => ({
	ByokKeyManager: () => <div>Key registry controls</div>,
}));
import ByokPage from "./page";

it("explains the registry limitation before offering an upgrade", async () => {
	h.entitled = false;
	const html = renderToStaticMarkup(await ByokPage());
	expect(html).toContain(
		"Registration does not enable customer-managed encryption",
	);
	expect(html).not.toContain("Customer-managed encryption is available");
	expect(html).toContain('href="/settings/billing"');
	expect(html).not.toContain("Key registry controls");
});

it("keeps the enforcement disclaimer alongside the entitled registry", async () => {
	h.entitled = true;
	const html = renderToStaticMarkup(await ByokPage());
	expect(html).toContain("Registered now · enforcement in a later release");
	expect(html).toContain("not yet enforcing");
	expect(html).toContain("Key registry controls");
});
