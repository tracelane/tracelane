/**
 * E2E-only in-process database (hero launch-gate coverage).
 *
 * The dashboard's `@/db` client uses `@neondatabase/serverless` (neon-http over
 * HTTPS) — a plain Postgres won't talk to it, and there is no seeded Neon in CI,
 * so the L16 webServer used to crash on `DATABASE_URL is not set` and time out.
 * This module stands up a REAL Postgres engine IN PROCESS (PGlite, WASM — already
 * a devDependency, used by the pglite guard test) with the REAL Drizzle schema +
 * migrations + a minimal seed, and stashes it on `globalThis`. `@/db` reads it in
 * E2E mode. NO Neon, NO docker, NO API key, NO CI service.
 *
 * Prod-safety: everything here is gated on `e2eAuthEnabled()` (dev/test-only,
 * boot-crashes a prod build that carries the flag). `instrumentation.ts` calls
 * `setupE2EDb()` once at server boot; a production build never imports PGlite
 * (the import lives here and in instrumentation, both behind the gate).
 */

import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import * as schema from "@/db/schema";
import { E2E_TEST_TENANT_ID, e2eAuthEnabled } from "@/lib/e2e-auth";
import { PGlite } from "@electric-sql/pglite";
import { drizzle } from "drizzle-orm/pglite";
import { migrate } from "drizzle-orm/pglite/migrator";

type E2EDatabase = ReturnType<typeof drizzle<typeof schema>>;

/** Global-registry symbol shared with `db/index.ts` (both call `Symbol.for`, no
 * import coupling — so `db/index.ts` never pulls this PGlite module into the prod
 * graph). The true prod-safety anchor is that this handle's ONLY writer is the
 * `e2eAuthEnabled()`-gated `setupE2EDb` below. */
const GLOBAL_KEY = Symbol.for("tracelane.e2e.db");
type Holder = { [k: symbol]: E2EDatabase | undefined };

/** Internal tenant UUID for the disposable workspace. MUST differ from
 * `E2E_TEST_TENANT_ID` — migration 0003 CHECKs `tenants.id <> e2e-disposable`.
 * The bypass session's `tenantId` (= `E2E_TEST_TENANT_ID`) is matched against
 * `tenants.workos_org_id`, so that column carries the disposable id. */
const E2E_INTERNAL_TENANT_ID = "00000000-0000-4000-8000-00000000e2db";

/**
 * Create-or-return the in-process E2E database. Idempotent (memoised on
 * `globalThis`). No-op (returns `null`) when the e2e bypass is off.
 */
export async function setupE2EDb(): Promise<E2EDatabase | null> {
	if (!e2eAuthEnabled()) return null;
	const holder = globalThis as unknown as Holder;
	if (holder[GLOBAL_KEY]) return holder[GLOBAL_KEY];

	const pg = new PGlite();
	const db = drizzle(pg, { schema });
	const folder = path.join(process.cwd(), "db/migrations");

	// Journaled migrations (0000–0008) via the drizzle migrator…
	await migrate(db, { migrationsFolder: folder });
	// …then the hand-written non-journaled migrations (0009+) in order, so the
	// engine schema matches schema.ts (same pattern the pglite guard test uses).
	const journaled = new Set<string>(
		(
			JSON.parse(
				readFileSync(path.join(folder, "meta", "_journal.json"), "utf-8"),
			) as { entries: { tag: string }[] }
		).entries.map((e) => e.tag),
	);
	const nonJournaled = readdirSync(folder)
		.filter((f) => f.endsWith(".sql"))
		.filter((f) => !journaled.has(f.replace(/\.sql$/, "")))
		.sort();
	for (const file of nonJournaled) {
		await pg.exec(readFileSync(path.join(folder, file), "utf-8"));
	}

	// Seed plan_entitlements (mirror of db/seed.mjs / the pglite guard test) +
	// the disposable tenant on the Team plan, so authed pages resolve + render.
	await db.insert(schema.planEntitlements).values([
		{
			planLookupKey: "free_v1",
			seatCapIncluded: 1,
			seatCapMax: 1,
			retentionDays: 7,
			traceQuotaMonthly: 10_000,
			gatewayQuotaMonthly: 10_000,
			overageHardCapMultiplier: "1.0",
			overagePricePer10kUsd: "0.00",
			fFullCapture: false,
		},
		{
			planLookupKey: "team_v1",
			seatCapIncluded: 10,
			seatCapMax: 25,
			retentionDays: 90,
			traceQuotaMonthly: 1_000_000,
			gatewayQuotaMonthly: 1_000_000,
			overageHardCapMultiplier: "5.0",
			overagePricePer10kUsd: "1.20",
			fFullCapture: false,
			fPromptPromotionWrite: true,
		},
	]);
	await pg.query(
		'insert into "tenants" ("id", "workos_org_id", "plan") values ($1, $2, $3)',
		[E2E_INTERNAL_TENANT_ID, E2E_TEST_TENANT_ID, "team"],
	);

	holder[GLOBAL_KEY] = db;
	return db;
}
