/**
 * PUT /api/billing/ceiling — proxies `PUT /v1/billing/ceiling` (spec
 * `BILL-01` §2.6, `admin` scope). Body `{ usd: number|null, overflow_mode }`.
 *
 * Admin-gated at BOTH layers: this route refuses a non-admin caller before
 * ever reaching the gateway (spec §4 "Permission-denied": a member can VIEW
 * usage; the ceiling control is disabled for them), and the gateway itself
 * re-checks the `admin` scope — a UI-only gate is not a gate.
 */

import { canAdmin, requireGatewayToken, requireSession } from "@/lib/auth";
import { gatewayBaseUrl } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

interface CeilingBody {
	usd: number | null;
	overflow_mode: "auto_age" | "auto_overage";
}

function isValidBody(v: unknown): v is CeilingBody {
	if (typeof v !== "object" || v === null) return false;
	const b = v as Record<string, unknown>;
	const usdOk = b.usd === null || (typeof b.usd === "number" && b.usd >= 0);
	const modeOk =
		b.overflow_mode === "auto_age" || b.overflow_mode === "auto_overage";
	return usdOk && modeOk;
}

export async function PUT(req: NextRequest): Promise<NextResponse> {
	const session = await requireSession();
	if (!canAdmin(session.role)) {
		return NextResponse.json(
			{ error: "workspace admins can change this" },
			{ status: 403 },
		);
	}

	let body: unknown;
	try {
		body = await req.json();
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}
	if (!isValidBody(body)) {
		return NextResponse.json(
			{ error: "invalid ceiling body" },
			{ status: 422 },
		);
	}

	const { token } = await requireGatewayToken();
	const base = gatewayBaseUrl();

	try {
		const upstream = await fetch(`${base}/v1/billing/ceiling`, {
			method: "PUT",
			headers: {
				"content-type": "application/json",
				authorization: `Bearer ${token}`,
			},
			body: JSON.stringify(body),
		});
		if (!upstream.ok) {
			return NextResponse.json(
				{ error: "could not update the spend ceiling" },
				{ status: upstream.status >= 500 ? 502 : upstream.status },
			);
		}
		const data = await upstream.json();
		return NextResponse.json(data);
	} catch {
		return NextResponse.json(
			{ error: "could not update the spend ceiling" },
			{ status: 502 },
		);
	}
}
