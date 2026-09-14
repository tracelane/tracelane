/**
 * GET /api/health/deep — DATA-path health, not just "the route responds".
 *
 * ## Why this exists (green-while-broken health control)
 *
 * A naive `/health` 200 is green-while-broken: the Worker returns the app shell
 * with a 200 and THEN fails the server-side data load, so an HTTP-200 monitor
 * passes while every authenticated page is dead. That is exactly how the
 * Neon Frankfurt migration broke `/audit`, `/prompts`, and `/settings/api-keys`
 * silently (the web `DATABASE_URL` still pointed at the decommissioned Singapore
 * project) — nobody knew until the founder clicked.
 *
 * This endpoint instead EXERCISES the two data dependencies every authenticated
 * page relies on and fails (503) the moment either is unhealthy:
 *   - **Neon (Postgres):** the SAME `select … from tenants` read that
 *     `upsertTenantId` / `getAuditAccess` / `PromoteGateBanner` do first on every
 *     `@/db` page. A stale/dead `DATABASE_URL` fails HERE, exactly as it did on
 *     the broken pages — so a monitor pinging this endpoint catches class.
 *   - **Gateway (ClickHouse-backed reads):** the gateway `/health` the dashboard
 *     / SLO / traces surfaces depend on.
 *
 * Green here ⟺ both data tiers are healthy ⟺ the authenticated pages render. A
 * true browser-level page assertion (a seeded-session Playwright monitor) is the
 * heavier V1.1 upgrade; this covers the failure mode that actually shipped.
 *
 * Monitor-agnostic by design (fits ADR-061 zero-third-party just as well as a
 * Better Stack HTTP monitor): point any uptime check at this URL and alert on a
 * non-200. Optionally gate it with `HEALTH_CHECK_TOKEN` (sent as
 * `x-health-token`) so it is not a public probe surface.
 */

import { db } from "@/db";
import { tenants } from "@/db/schema";
import { gatewayBaseUrl } from "@/lib/gateway";
import { causeLine } from "@/lib/redact-cause";
import { sql } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

// Reads the DB + gateway at request time — never prerender / cache.
export const dynamic = "force-dynamic";

/** One dependency's result: "ok" or "fail: <short reason>" (never a secret). */
type CheckResult = "ok" | `fail: ${string}`;

/**
 * Log the REAL cause where only we can see it, while the response stays coarse.
 * The redaction + withhold logic lives in `@/lib/redact-cause` so it can carry a
 * test that proves the credential does not survive — see that file for the why.
 */
function logCause(dep: string, err: unknown): void {
	console.error(causeLine(dep, err, process.env.DATABASE_URL));
}

/** Coarse, secret-free failure CLASS — never raw driver text, which can name
 * dependency hostnames (e.g. the Neon endpoint) on this probe surface.
 *
 * This is what the RESPONSE carries. `logCause` above is what the WORKER LOG
 * carries — the two are deliberately different resolutions. */
function reason(err: unknown): string {
	const msg = err instanceof Error ? err.message : String(err);
	if (/getaddrinfo|ENOTFOUND|EAI_AGAIN|dns/i.test(msg)) return "dns";
	if (/ECONNREFUSED|ECONNRESET|EPIPE|socket|network/i.test(msg)) return "conn";
	if (/timeout|timed out|abort/i.test(msg)) return "timeout";
	if (/password|auth|SASL|permission|denied/i.test(msg)) return "auth";
	return "error";
}

/** Real Neon read — the exact first read every `@/db` authenticated page does.
 *
 * Also returns the compute's Postgres UPTIME (NEON-TO-ZERO 3b, founder 2026-09-03):
 * `pg_postmaster_start_time()` resets when the Neon compute resumes from suspend,
 * so a small uptime at the hourly canary is evidence the compute was Idle between
 * wakes, and an uptime that keeps growing hour over hour is a PIN — the canary
 * pages on that. One extra scalar on a query this route already pays for. */
async function checkNeon(): Promise<{
	result: CheckResult;
	uptimeSecs: number | null;
}> {
	try {
		// Parameterised Drizzle query (no raw SQL); existence probe, returns no
		// tenant data. Mirrors the `select … from tenants` that broke in.
		await db.select({ id: tenants.id }).from(tenants).limit(1);
		let uptimeSecs: number | null = null;
		try {
			const rows = await db.execute(
				sql`select extract(epoch from now() - pg_postmaster_start_time())::int as uptime_secs`,
			);
			const v = (rows as unknown as { rows?: Array<{ uptime_secs?: unknown }> })
				.rows?.[0]?.uptime_secs;
			uptimeSecs =
				typeof v === "number"
					? v
					: typeof v === "string"
						? Number.parseInt(v, 10)
						: null;
			if (uptimeSecs !== null && !Number.isFinite(uptimeSecs))
				uptimeSecs = null;
		} catch (err) {
			// The uptime is a sentinel input, not a health verdict: its absence is
			// reported as null, never as a failed data tier.
			logCause("neon_uptime", err);
		}
		return { result: "ok", uptimeSecs };
	} catch (err) {
		logCause("neon", err);
		return { result: `fail: ${reason(err)}`, uptimeSecs: null };
	}
}

/** Real gateway reachability — the ClickHouse-backed read tier the dashboard uses. */
async function checkGateway(): Promise<CheckResult> {
	try {
		const res = await fetch(`${gatewayBaseUrl()}/health`, {
			cache: "no-store",
			signal: AbortSignal.timeout(5000),
		});
		return res.ok ? "ok" : `fail: gateway /health ${res.status}`;
	} catch (err) {
		logCause("gateway", err);
		return `fail: ${reason(err)}`;
	}
}

export async function GET(req: NextRequest): Promise<NextResponse> {
	// Shared-secret gate so this is not a public probe/DoS surface. Unset in
	// dev = open; in PRODUCTION an unset token fails CLOSED — this endpoint
	// exercises (and reports on) the data tier (2026-07-22 audit).
	const expected = process.env.HEALTH_CHECK_TOKEN;
	if (process.env.NODE_ENV === "production" && !expected) {
		return NextResponse.json({ error: "unauthorized" }, { status: 401 });
	}
	if (expected && req.headers.get("x-health-token") !== expected) {
		return NextResponse.json({ error: "unauthorized" }, { status: 401 });
	}

	// `?neon=skip` — the 15-minute watchdog passes this so its probe does not wake the
	// Neon compute four times an hour (founder, 2026-09-03: NEON-COMPUTE-PIN; cost wins
	// with zero users). The hourly canary still probes Neon for real. A skipped leg is
	// reported as "skipped", never as "ok", so a reader cannot mistake it for a pass.
	const skipNeon = new URL(req.url).searchParams.get("neon") === "skip";
	const [neonProbe, gateway] = await Promise.all([
		skipNeon
			? Promise.resolve({ result: "skipped" as const, uptimeSecs: null })
			: checkNeon(),
		checkGateway(),
	]);
	const neon = neonProbe.result;
	// `neon_uptime_secs` is null when the leg was skipped or the scalar could not
	// be read — a reader must treat null as CANNOT DETERMINE, not as zero.
	const checks = { neon, gateway, neon_uptime_secs: neonProbe.uptimeSecs };
	const ok = (neon === "ok" || neon === "skipped") && gateway === "ok";

	// 503 on any failure so a plain HTTP-status monitor fires — the check ASSERTS
	// the data path, it does not merely confirm the route responds.
	return NextResponse.json(
		{ ok, checks, ts: new Date().toISOString() },
		{ status: ok ? 200 : 503, headers: { "cache-control": "no-store" } },
	);
}
