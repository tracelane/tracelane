import { PGlite } from "@electric-sql/pglite";
import { drizzle } from "drizzle-orm/pglite";
import { Children, type ReactNode, isValidElement } from "react";
import { afterAll, beforeAll, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ db: null as unknown }));
vi.mock("@/db", () => ({
	get db() {
		return h.db;
	},
}));
vi.mock("@/lib/auth", () => ({
	requireSession: async () => ({ tenantId: "org-test" }),
}));
vi.mock("@/lib/metrics/fetch", () => ({}));
import DashboardPage from "./page";

let pg: PGlite;
beforeAll(async () => {
	pg = new PGlite();
	h.db = drizzle(pg);
	await pg.exec(`CREATE TABLE tenants (id uuid, workos_org_id text);
		CREATE TABLE api_keys (tenant_id uuid, revoked_at timestamptz);
		INSERT INTO tenants VALUES ('00000000-0000-0000-0000-000000000001', 'org-test');`);
});
afterAll(async () => pg.close());

function findBanner(node: ReactNode): (() => Promise<ReactNode>) | undefined {
	for (const child of Children.toArray(node)) {
		if (!isValidElement<{ children?: ReactNode }>(child)) continue;
		if (
			typeof child.type === "function" &&
			child.type.name === "NoApiKeysBanner"
		) {
			return child.type as () => Promise<ReactNode>;
		}
		const found = findBanner(child.props.children);
		if (found) return found;
	}
}

it("counts grace-period keys as active and excludes retired and foreign keys", async () => {
	const page = await DashboardPage({ searchParams: Promise.resolve({}) });
	const banner = findBanner(page);
	expect(banner).toBeDefined();
	if (!banner) throw new Error("dashboard lost its active-key banner");
	await pg.exec(`INSERT INTO api_keys VALUES
		('00000000-0000-0000-0000-000000000001', now() + interval '1 hour');`);
	expect(
		await banner(),
		"a grace-period key must hide the no-active-keys panel",
	).toBeNull();
	await pg.exec(`UPDATE api_keys SET revoked_at = now();
		INSERT INTO api_keys VALUES ('00000000-0000-0000-0000-000000000002', NULL);`);
	expect(await banner()).not.toBeNull();
	await pg.exec(
		`UPDATE api_keys SET revoked_at = NULL WHERE tenant_id = '00000000-0000-0000-0000-000000000001';`,
	);
	expect(await banner()).toBeNull();
});
