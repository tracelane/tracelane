/**
 * Proxy for one-click tool approval (/B).
 *
 * Forwards only `{tool_name, def_hash}`. The gateway pins the hash it reads back
 * from `observed_tools`, so the value here is a selector, not an input — a hash
 * the gateway never computed matches nothing and writes nothing. There is
 * deliberately no `caps` field anywhere on this path: approve cannot move
 * capabilities, and the gateway rejects a caps field outright.
 */

import { GatewayError, gatewayPost } from "@/lib/gateway";
import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
	let body: unknown;
	try {
		body = await req.json();
	} catch {
		return NextResponse.json({ error: "invalid_json" }, { status: 400 });
	}
	const { tool_name, def_hash } = (body ?? {}) as Record<string, unknown>;
	if (typeof tool_name !== "string" || typeof def_hash !== "string") {
		return NextResponse.json(
			{ error: "tool_name and def_hash are required" },
			{ status: 400 },
		);
	}

	try {
		// Only these two fields are forwarded — anything else the browser sent is
		// dropped here rather than relayed, so the gateway's deny_unknown_fields
		// rejection can never be triggered by a stray UI field.
		const out = await gatewayPost<{ approved: boolean }>(
			"/v1/guardrails/tool-pins/approve",
			{ tool_name, def_hash },
		);
		return NextResponse.json(out);
	} catch (err) {
		if (err instanceof GatewayError) {
			if (err.status === 403) {
				return NextResponse.json(
					{ error: "role_forbidden", required_role: "owner" },
					{ status: 403 },
				);
			}
			if (err.status === 404) {
				return NextResponse.json(
					{ error: "no_such_observed_definition" },
					{ status: 404 },
				);
			}
			return NextResponse.json(
				{ error: "upstream_error", status: err.status },
				{ status: err.status },
			);
		}
		return NextResponse.json({ error: "unexpected" }, { status: 500 });
	}
}
