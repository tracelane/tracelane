/**
 * GET /api/version — the deployed build, readable by anyone.
 *
 * Founder, 2026-09-14: "Give web and site a version marker a read-only check can
 * fetch. Both deploys are REPORTED rather than VERIFIED only because neither
 * serves its SHA." `scripts/deploy/web.sh` bakes `NEXT_PUBLIC_BUILD_SHA` (and
 * `NEXT_PUBLIC_BUILD_AT`) into the bundle at build time — a `NEXT_PUBLIC_*`
 * value is constant-folded, so this answers with the bytes that were built, not
 * with whatever the runtime happens to hold (apps/web/CLAUDE.md, B-139) — and
 * its post-deploy Proof V fetches this route and compares it to the commit it
 * just shipped.
 *
 * Deliberately unauthenticated (the middleware only manages sessions for API
 * routes; nothing here reads one) and `no-store`, so an edge never answers for
 * a build it no longer serves. A commit SHA of a private repository reveals
 * nothing a caller can act on.
 */

import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export function GET(): NextResponse {
	return NextResponse.json(
		{
			sha: process.env.NEXT_PUBLIC_BUILD_SHA ?? null,
			built_at: process.env.NEXT_PUBLIC_BUILD_AT ?? null,
			surface: "web",
		},
		{ headers: { "cache-control": "no-store" } },
	);
}
