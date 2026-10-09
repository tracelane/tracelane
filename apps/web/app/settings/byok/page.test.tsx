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

it("distinguishes the registry from gateway KMS before offering an upgrade", async () => {
	h.entitled = false;
	const html = renderToStaticMarkup(await ByokPage());
	expect(html).toContain("gateway customer KMS configuration");
	expect(html).toContain("does not configure KMS encryption");
	expect(html).toContain('href="/settings/billing"');
	expect(html).not.toContain("Key registry controls");
});

it("explains the gateway KMS setup alongside the entitled registry", async () => {
	h.entitled = true;
	const html = renderToStaticMarkup(await ByokPage());
	expect(html).toContain("Fingerprint registry · separate from gateway KMS");
	expect(html).toContain("through the gateway security API");
	expect(html).toContain("Key registry controls");
});
