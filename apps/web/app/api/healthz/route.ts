/**
 * GET /api/healthz — unauthenticated liveness + gateway-reachability probe.
 *
 * Point an uptime monitor (Better Stack) at this. It catches the exact class
 * that killed checkout: a misconfigured `NEXT_PUBLIC_GATEWAY_URL` makes
 * `gatewayBaseUrl()` throw (→ "misconfigured") or the Worker's fetch fail
 * (→ "unreachable"), so a dropped/wrong gateway URL trips this to 503 at deploy
 * time instead of surfacing as a user's dead button (the internal
 * checkout CSP / gateway-URL incident review).
 */

import { gatewayBaseUrl } from "@/lib/gateway";
import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function GET(): Promise<NextResponse> {
	let base: string | null = null;
	let gateway: "ok" | "unreachable" | "misconfigured";
	try {
		base = gatewayBaseUrl(); // throws if NEXT_PUBLIC_GATEWAY_URL is unset/invalid
		const res = await fetch(`${base}/health`, {
			signal: AbortSignal.timeout(5000),
		});
		gateway = res.ok ? "ok" : "unreachable";
	} catch {
		gateway = base ? "unreachable" : "misconfigured";
	}

	const healthy = gateway === "ok";
	// The "misconfigured" enum already carries the diagnostic signal — never
	// echo the gateway base URL itself on a public probe (2026-07-22 audit).
	return NextResponse.json(
		{ status: healthy ? "ok" : "degraded", gateway },
		{ status: healthy ? 200 : 503 },
	);
}
