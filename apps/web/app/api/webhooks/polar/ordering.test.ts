import crypto from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import * as schema from "@/db/schema";
import { PGlite } from "@electric-sql/pglite";
import { type PgliteDatabase, drizzle } from "drizzle-orm/pglite";
import { migrate } from "drizzle-orm/pglite/migrator";
import type { NextRequest } from "next/server";
import { afterAll, beforeAll, beforeEach, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	db: null as PgliteDatabase<typeof schema> | null,
}));
vi.mock("@/db", () => ({
	get db() {
		return h.db;
	},
}));
import { migrationSqlForTestDb } from "@/lib/test-migration-sql";
import { POST } from "./route";

const SECRET = "polar_whs_ordering_test_only";
const TENANT = "11111111-2222-4333-8444-555555555555";
const T1 = "2026-10-10T00:00:00.000Z";
const T2 = "2026-10-11T00:00:00.000Z";
let pg: PGlite;

function request(
	id: string,
	sub: string,
	key: string,
	at: string,
	status = "active",
) {
	const body = JSON.stringify({
		type: "subscription.updated",
		timestamp: at,
		data: {
			id: sub,
			customer_id: "cust_ordering",
			customer: { external_id: TENANT },
			status,
			modified_at: at,
			product: {
				organization_id: "org_ordering",
				metadata: { lookup_key: key },
			},
		},
	});
	const ts = String(Math.floor(Date.now() / 1000));
	const sig = crypto
		.createHmac("sha256", SECRET)
		.update(`${id}.${ts}.${body}`)
		.digest("base64");
	return {
		headers: new Headers({
			"webhook-id": id,
			"webhook-timestamp": ts,
			"webhook-signature": `v1,${sig}`,
		}),
		text: async () => body,
	} as unknown as NextRequest;
}
async function state() {
	const result = await pg.query<{
		plan: string;
		polar_subscription_id: string | null;
		annual_pair: schema.AnnualPairJson | null;
		polar_subscription_modified_at: Date;
		plan_lookup_key: string;
	}>(
		"SELECT t.plan, t.polar_subscription_id, t.annual_pair, t.polar_subscription_modified_at, w.plan_lookup_key FROM tenants t LEFT JOIN workspace_entitlements w ON w.tenant_id=t.id WHERE t.id=$1",
		[TENANT],
	);
	return result.rows[0];
}
beforeAll(async () => {
	vi.stubEnv("POLAR_WEBHOOK_SECRET", SECRET);
	vi.stubEnv("POLAR_EXPECTED_ORGANIZATION_ID", "org_ordering");
	vi.stubEnv("POLAR_WORKER_TOKEN", "");
	pg = new PGlite();
	h.db = drizzle(pg, { schema });
	const folder = path.resolve("db/migrations");
	await migrate(h.db, { migrationsFolder: folder });
	const journal = JSON.parse(
		readFileSync(path.join(folder, "meta/_journal.json"), "utf8"),
	) as { entries: { tag: string }[] };
	const names = new Set(journal.entries.map((e) => `${e.tag}.sql`));
	for (const file of readdirSync(folder)
		.filter((f) => f.endsWith(".sql") && !names.has(f))
		.sort()) {
		await pg.exec(
			migrationSqlForTestDb(readFileSync(path.join(folder, file), "utf8")),
		);
	}
	await pg.exec(
		"INSERT INTO plan_entitlements(plan_lookup_key) VALUES ('free_v1'), ('team_v1'), ('builder_v1') ON CONFLICT DO NOTHING",
	);
});
beforeEach(async () => {
	await pg.exec(
		"TRUNCATE webhook_events, workspace_entitlements; DELETE FROM tenants;",
	);
	await pg.query(
		"INSERT INTO tenants(id, workos_org_id, plan, price_protected_until) VALUES ($1, 'org_ordering', 'free', '2027-01-01')",
		[TENANT],
	);
});
afterAll(async () => {
	await pg?.close();
	vi.unstubAllEnvs();
});

it("annual_pair_accepts_older_event_from_other_half", async () => {
	expect(
		(await POST(request("usage", "sub_usage", "team_v1_usage_month", T2)))
			.status,
	).toBe(200);
	expect(
		(await POST(request("base", "sub_base", "team_v1_base_year", T1))).status,
	).toBe(200);
	const row = await state();
	expect(row?.annual_pair?.base?.id).toBe("sub_base");
	expect(row?.annual_pair?.usage?.id).toBe("sub_usage");
	expect(row?.plan).toBe("team");
	expect(row?.plan_lookup_key).toBe("team_v1");
});
it("revoking_superseded_subscription_preserves_current_plan", async () => {
	expect((await POST(request("current", "sub_B", "team_v1", T1))).status).toBe(
		200,
	);
	expect(
		(await POST(request("old-revoked", "sub_A", "team_v1", T2, "revoked")))
			.status,
	).toBe(200);
	const row = await state();
	expect(row?.plan).toBe("team");
	expect(row?.polar_subscription_id).toBe("sub_B");
	expect(row?.plan_lookup_key).toBe("team_v1");
});
it("concurrent_older_event_cannot_overwrite_newer_state", async () => {
	let release = () => {};
	let paused = () => {};
	const wait = new Promise<void>((resolve) => {
		release = resolve;
	});
	const entered = new Promise<void>((resolve) => {
		paused = resolve;
	});
	const query = pg.query.bind(pg);
	let held = false;
	const spy = vi
		.spyOn(pg, "query")
		.mockImplementation(async (text, params, options) => {
			if (!held && /update "tenants"/i.test(text)) {
				held = true;
				paused();
				await wait;
			}
			return query(text, params, options);
		});
	const older = POST(request("older", "sub_one", "builder_v1", T1));
	await entered;
	try {
		expect(
			(await POST(request("newer", "sub_one", "team_v1", T2))).status,
		).toBe(200);
	} finally {
		release();
	}
	const res = await older;
	spy.mockRestore();
	if (res.status === 503)
		expect(
			(await POST(request("older", "sub_one", "builder_v1", T1))).status,
		).toBe(200);
	const row = await state();
	expect(row?.plan).toBe("team");
	expect(
		new Date(row?.polar_subscription_modified_at ?? "").toISOString(),
	).toBe(T2);
	expect(row?.plan_lookup_key).toBe("team_v1");
});

it("revoking_superseded_monthly_subscription_preserves_current_annual_pair", async () => {
	await POST(request("usage-new", "sub_usage_B", "team_v1_usage_month", T1));
	await POST(request("base-new", "sub_base_B", "team_v1_base_year", T1));
	expect((await state())?.plan).toBe("team");
	expect(
		(await POST(request("monthly-old", "sub_A", "team_v1", T2, "revoked")))
			.status,
	).toBe(200);
	expect((await state())?.plan).toBe("team");
	expect((await state())?.plan_lookup_key).toBe("team_v1");
});

it("same_half_stale_event_cannot_resurrect_a_revoked_half", async () => {
	await POST(request("base-first", "base", "team_v1_base_year", T1));
	await POST(request("usage-first", "usage", "team_v1_usage_month", T1));
	await POST(
		request("usage-revoke", "usage", "team_v1_usage_month", T2, "revoked"),
	);
	expect((await state())?.plan).toBe("free");
	expect(
		(await POST(request("usage-stale", "usage", "team_v1_usage_month", T1)))
			.status,
	).toBe(200);
	expect((await state())?.plan).toBe("free");
	expect((await state())?.annual_pair?.usage?.status).toBe("revoked");
});

it("entitlement_failure_rolls_back_tenant_state_and_remains_retryable", async () => {
	await pg.exec(
		"DELETE FROM plan_entitlements WHERE plan_lookup_key='builder_v1'",
	);
	const result = await POST(
		request("rollback", "sub_rollback", "builder_v1", T1),
	);
	expect(result.status).toBe(503);
	expect((await state())?.plan).toBe("free");
	expect(
		(
			await pg.query(
				"SELECT event_id FROM webhook_events WHERE event_id='rollback'",
			)
		).rows,
	).toHaveLength(0);
	await pg.exec(
		"INSERT INTO plan_entitlements(plan_lookup_key) VALUES ('builder_v1')",
	);
	expect(
		(await POST(request("rollback", "sub_rollback", "builder_v1", T1))).status,
	).toBe(200);
	expect((await state())?.plan_lookup_key).toBe("builder_v1");
	expect(
		await (
			await POST(request("rollback", "sub_rollback", "builder_v1", T1))
		).json(),
	).toMatchObject({ duplicate: true });
});

it("stale_monthly_event_does_not_replace_current_annual_pair", async () => {
	await POST(request("usage-new", "sub_usage_B", "team_v1_usage_month", T2));
	await POST(request("base-new", "sub_base_B", "team_v1_base_year", T2));
	expect((await state())?.plan).toBe("team");
	expect(
		(await POST(request("monthly-stale", "sub_A", "team_v1", T1))).status,
	).toBe(200);
	expect((await state())?.plan).toBe("team");
});

it("revoking_superseded_annual_subscription_preserves_current_monthly_plan", async () => {
	await POST(request("monthly-current", "sub_B", "team_v1", T1));
	expect(
		(
			await POST(
				request("annual-old", "sub_A", "team_v1_base_year", T2, "revoked"),
			)
		).status,
	).toBe(200);
	const row = await state();
	expect(row?.plan).toBe("team");
	expect(row?.polar_subscription_id).toBe("sub_B");
	expect(row?.plan_lookup_key).toBe("team_v1");
});

it("concurrent_annual_halves_remain_retryable_and_both_survive", async () => {
	const query = pg.query.bind(pg);
	let intercepted = false;
	const spy = vi
		.spyOn(pg, "query")
		.mockImplementation(async (text, params, options) => {
			if (!intercepted && /update "tenants"/i.test(text)) {
				intercepted = true;
				expect(
					(
						await POST(
							request("usage-race", "usage", "team_v1_usage_month", T2),
						)
					).status,
				).toBe(200);
			}
			return query(text, params, options);
		});
	const first = await POST(
		request("base-race", "base", "team_v1_base_year", T1),
	);
	spy.mockRestore();
	expect(first.status).toBe(503);
	expect(
		(
			await pg.query(
				"SELECT event_id FROM webhook_events WHERE event_id='base-race'",
			)
		).rows,
	).toHaveLength(0);
	expect(
		(await POST(request("base-race", "base", "team_v1_base_year", T1))).status,
	).toBe(200);
	const row = await state();
	expect(row?.annual_pair?.base?.id).toBe("base");
	expect(row?.annual_pair?.usage?.id).toBe("usage");
	expect(row?.plan).toBe("team");
	expect(row?.plan_lookup_key).toBe("team_v1");
	expect(
		new Date(row?.polar_subscription_modified_at ?? "").toISOString(),
	).toBe(T2);
});

it("older_annual_event_cannot_replace_newer_monthly_subscription", async () => {
	await POST(request("monthly-newer", "sub_B", "team_v1", T2));
	expect(
		(await POST(request("annual-older", "sub_A", "team_v1_usage_month", T1)))
			.status,
	).toBe(200);
	const row = await state();
	expect(row?.plan).toBe("team");
	expect(row?.polar_subscription_id).toBe("sub_B");
	expect(row?.plan_lookup_key).toBe("team_v1");
});
