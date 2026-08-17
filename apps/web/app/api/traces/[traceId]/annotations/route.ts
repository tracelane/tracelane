/**
 * OBS-18 — annotations on one trace. Thin proxy to the gateway.
 *
 * GET    /api/traces/[traceId]/annotations  → list
 * POST   /api/traces/[traceId]/annotations  → upsert this author's verdict
 * DELETE /api/traces/[traceId]/annotations  → remove this author's verdict
 *
 * The gateway owns the store, the tenant resolution and the role gate. This
 * route deliberately re-validates NOTHING: one validator, at the enforcement
 * point. A second copy here would drift from it, and the drift would be silent.
 *
 * A 403 (viewer tried to write) keeps its status and body rather than becoming
 * a generic failure — an opaque "couldn't save" for what is really "your role
 * cannot do this" is the role-403 defect that has already cost a debugging
 * session once.
 */

import {
	GatewayError,
	gatewayDelete,
	gatewayGet,
	gatewayPost,
} from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

export type Annotation = {
	trace_id: string;
	/** `""` = the whole trace. */
	span_id: string;
	label: "good" | "bad" | "needs_review";
	note: string;
	author_sub: string;
	created_at: string;
	updated_at: string;
};

/** Pass a gateway error through with its meaning intact. */
function passthrough(err: unknown): NextResponse {
	if (err instanceof GatewayError) {
		if (err.status >= 500) {
			return NextResponse.json(
				{ error: "unavailable", reason: "gateway_unreachable" },
				{ status: 502 },
			);
		}
		return NextResponse.json(
			{ error: err.message || "request_failed" },
			{ status: err.status },
		);
	}
	throw err;
}

export async function GET(
	_req: NextRequest,
	ctx: { params: Promise<{ traceId: string }> },
): Promise<NextResponse> {
	const { traceId } = await ctx.params;
	try {
		return NextResponse.json(
			await gatewayGet<Annotation[]>(
				`/v1/traces/${encodeURIComponent(traceId)}/annotations`,
			),
		);
	} catch (err) {
		return passthrough(err);
	}
}

export async function POST(
	req: NextRequest,
	ctx: { params: Promise<{ traceId: string }> },
): Promise<NextResponse> {
	const { traceId } = await ctx.params;
	let body: { label?: string; note?: string; spanId?: string };
	try {
		body = await req.json();
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}
	try {
		return NextResponse.json(
			await gatewayPost<Annotation>(
				`/v1/traces/${encodeURIComponent(traceId)}/annotations`,
				{
					label: body.label,
					...(body.note ? { note: body.note } : {}),
					// camelCase in, snake_case out — the gateway's body type has no
					// serde rename, so `spanId` would be silently ignored and every
					// span-level flag would land as a trace-level one.
					...(body.spanId ? { span_id: body.spanId } : {}),
				},
			),
		);
	} catch (err) {
		return passthrough(err);
	}
}

export async function DELETE(
	req: NextRequest,
	ctx: { params: Promise<{ traceId: string }> },
): Promise<NextResponse> {
	const { traceId } = await ctx.params;
	// `span_id` travels as a QUERY param so the existing `gatewayDelete` helper
	// (which sends no body but does carry auth correctly) can be reused. The
	// alternative — a body-carrying DELETE — meant hand-rolling the auth header
	// here, i.e. a second copy of the one thing that must not drift.
	const spanId = req.nextUrl.searchParams.get("spanId") ?? "";
	const qs = spanId ? `?span_id=${encodeURIComponent(spanId)}` : "";
	try {
		await gatewayDelete(
			`/v1/traces/${encodeURIComponent(traceId)}/annotations${qs}`,
		);
		return new NextResponse(null, { status: 204 });
	} catch (err) {
		return passthrough(err);
	}
}
