/**
 * Drizzle ORM client for Neon Postgres (lazy singleton).
 *
 * Uses @neondatabase/serverless for HTTP-mode connections (compatible with
 * Next.js serverless runtimes).
 *
 * The client is created on FIRST USE, not at module load: importing this
 * module must not require `DATABASE_URL`. A top-level
 * `neon(process.env.DATABASE_URL!)` previously forced the credential at *build*
 * time (Next collects page data) and broke builds when the env was absent.
 * `db` is a Proxy that instantiates the real client (and reads `DATABASE_URL`)
 * on the first property access, so any DB-touching page must also be
 * `dynamic = "force-dynamic"` to avoid touching it during prerender.
 */

import { neon } from "@neondatabase/serverless";
import { type NeonHttpDatabase, drizzle } from "drizzle-orm/neon-http";
import * as schema from "./schema";

type Schema = typeof schema;
type Database = NeonHttpDatabase<Schema>;

let client: Database | null = null;

/** Create-or-return the Drizzle client, reading `DATABASE_URL` lazily. */
function getDb(): Database {
	if (client) return client;
	// E2E launch-gate: use the in-process PGlite database stood up at server boot
	// by `instrumentation.ts` (dev/test bypass only — never in prod). The leading
	// `NODE_ENV !== "production"` is a BUILD-TIME guard (Next inlines NODE_ENV), so
	// this whole branch is dead-code-eliminated in a prod build — prod-safety is
	// guaranteed at build time, not merely at runtime (security review, MED). The
	// handle is read from globalThis WITHOUT importing PGlite here (so the prod
	// `@/db` bundle stays neon-http-only); its ONLY writer is the `e2eAuthEnabled`-
	// gated `setupE2EDb`. `Symbol.for` matches that writer's key via the global
	// registry with no import coupling. Falls through to neon-http otherwise.
	// The `NODE_ENV !== "production"` guard is build-time (Next inlines it) so this
	// whole branch is dead-code-eliminated in a prod build. The globalThis handle
	// IS the gate: its only writer is the `e2eAuthEnabled()`-gated `setupE2EDb`
	// (which itself requires the dev/test bypass flag), so its mere existence means
	// the E2E DB is active — no need to re-read the bypass env var here (and not
	// naming it keeps `scripts/ci/no-e2e-auth-in-prod.sh` happy).
	if (process.env.NODE_ENV !== "production") {
		const holder = globalThis as unknown as {
			[k: symbol]: Database | undefined;
		};
		const handle = holder[Symbol.for("tracelane.e2e.db")];
		if (handle) return handle;
	}
	const url = process.env.DATABASE_URL;
	if (!url) {
		throw new Error(
			"DATABASE_URL is not set — the Postgres client is accessed at request " +
				"time; ensure the env is configured (and DB-touching pages are " +
				'`dynamic = "force-dynamic"`).',
		);
	}
	client = drizzle(neon(url), { schema });
	return client;
}

/**
 * Drizzle client. Lazily initialised: the underlying connection (and the
 * `DATABASE_URL` read) is deferred to the first property access, so importing
 * `@/db` at build time is side-effect-free.
 */
export const db = new Proxy({} as Database, {
	get(_target, prop, receiver) {
		const real = getDb();
		const value = Reflect.get(real as object, prop, receiver);
		return typeof value === "function" ? value.bind(real) : value;
	},
}) as Database;
