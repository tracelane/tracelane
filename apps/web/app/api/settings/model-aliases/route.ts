/**
 * GWY-27 — the workspace's own model aliases (`specs/GWY-27-model-aliases.md`).
 *
 * GET    /api/settings/model-aliases                → {items, max, can_edit}
 * PUT    /api/settings/model-aliases {alias, target_model, create?}
 * DELETE /api/settings/model-aliases?alias=<alias>
 *
 * Thin proxy to the gateway's `/v1/model-aliases`, which owns validation (only it
 * knows the routing map) and the owner-only write gate. The WorkOS access token is
 * forwarded as Bearer; the tenant is derived from it by the gateway, never sent here.
 *
 * Unlike the provider-key proxy, the gateway's 400/404/409 bodies are passed through:
 * they are our own typed codes (`unroutable_target`, `alias_exists`, …) carrying only
 * the model name the user typed, and the form shows them at the field (spec §4).
 */

import { requireGatewayToken } from "@/lib/auth";
import { gatewayResponse } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

const PASS_THROUGH = new Set([400, 404, 409, 503]);

async function relay(upstream: Response): Promise<NextResponse> {
	if (upstream.status === 204) return new NextResponse(null, { status: 204 });
	if (upstream.ok) return NextResponse.json(await upstream.json());
	if (upstream.status === 403) {
		// The gateway's role gate: pass its typed shape so the UI renders a locked
		// state, never "failed to load".
		const body = (await upstream.json().catch(() => ({}))) as {
			required_role?: string;
		};
		return NextResponse.json(
			{ error: "role_forbidden", required_role: body.required_role ?? "owner" },
			{ status: 403 },
		);
	}
	if (PASS_THROUGH.has(upstream.status)) {
		const body = (await upstream.json().catch(() => ({}))) as {
			error?: unknown;
			message?: unknown;
		};
		return NextResponse.json(
			{
				error: typeof body.error === "string" ? body.error : "request_failed",
				message: typeof body.message === "string" ? body.message : undefined,
			},
			{ status: upstream.status },
		);
	}
	return NextResponse.json(
		{ error: "model aliases unavailable" },
		{ status: upstream.status >= 500 ? 502 : upstream.status },
	);
}

export async function GET(): Promise<NextResponse> {
	const upstream = await gatewayResponse("/v1/model-aliases");
	return relay(upstream);
}

export async function PUT(req: NextRequest): Promise<NextResponse> {
	// Auth first (unchanged order): an unauthenticated caller is redirected
	// before any body validation. `gatewayResponse` reuses the memoized token.
	await requireGatewayToken();
	let body: { alias?: unknown; target_model?: unknown; create?: unknown };
	try {
		body = (await req.json()) as typeof body;
	} catch {
		return NextResponse.json({ error: "invalid_body" }, { status: 400 });
	}
	const alias = typeof body.alias === "string" ? body.alias.trim() : "";
	const target =
		typeof body.target_model === "string" ? body.target_model.trim() : "";
	if (!alias || !target) {
		return NextResponse.json(
			{ error: "invalid_body", message: "alias and target model are required" },
			{ status: 400 },
		);
	}
	const upstream = await gatewayResponse("/v1/model-aliases", {
		method: "PUT",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({
			alias,
			target_model: target,
			create: body.create === true,
		}),
	});
	return relay(upstream);
}

export async function DELETE(req: NextRequest): Promise<NextResponse> {
	// Auth first (unchanged order): an unauthenticated caller is redirected
	// before any body validation. `gatewayResponse` reuses the memoized token.
	await requireGatewayToken();
	const alias = req.nextUrl.searchParams.get("alias")?.trim() ?? "";
	if (!alias) {
		return NextResponse.json({ error: "invalid_query" }, { status: 400 });
	}
	const upstream = await gatewayResponse(
		`/v1/model-aliases?alias=${encodeURIComponent(alias)}`,
		{ method: "DELETE" },
	);
	return relay(upstream);
}
