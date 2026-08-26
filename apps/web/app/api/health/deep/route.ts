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

/** Real Neon read — the exact first read every `@/db` authenticated page does. */
async function checkNeon(): Promise<CheckResult> {
	try {
		// Parameterised Drizzle query (no raw SQL); existence probe, returns no
		// tenant data. Mirrors the `select … from tenants` that broke in.
		await db.select({ id: tenants.id }).from(tenants).limit(1);
		return "ok";
	} catch (err) {
		logCause("neon", err);
		return `fail: ${reason(err)}`;
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

	const [neon, gateway] = await Promise.all([checkNeon(), checkGateway()]);
	const checks = { neon, gateway };
	const ok = neon === "ok" && gateway === "ok";

	// 503 on any failure so a plain HTTP-status monitor fires — the check ASSERTS
	// the data path, it does not merely confirm the route responds.
	return NextResponse.json(
		{ ok, checks, ts: new Date().toISOString() },
		{ status: ok ? 200 : 503, headers: { "cache-control": "no-store" } },
	);
}
