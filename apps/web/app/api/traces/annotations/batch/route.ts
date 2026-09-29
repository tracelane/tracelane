/**
 * OBS-56 — bulk trace-level flag. Thin proxy to the gateway's
 * `POST /v1/annotations/batch`.
 *
 * The gateway owns the store, the tenant resolution, the role gate and the
 * `bulk_trace_action_max` cap. This route re-validates NOTHING — one
 * validator, at the enforcement point (the same discipline
 * `[traceId]/annotations/route.ts` documents for the single-trace path).
 *
 * A non-2xx keeps its status and body: a role-403 or a `400 bulk_too_large`
 * collapsing into a generic failure is the exact defect the single-trace
 * proxy's own comment warns about.
 */

import { GatewayError, gatewayPost } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

export type BatchAnnotationResult = {
	written: number;
	refused: { trace_id: string; reason: string }[];
};

function passthrough(err: unknown): NextResponse {
	if (err instanceof GatewayError) {
		if (err.status >= 500) {
			return NextResponse.json(
				{ error: "unavailable", reason: "gateway_unreachable" },
				{ status: 502 },
			);
		}
		return NextResponse.json(
			err.body ?? { error: err.message || "request_failed" },
			{
				status: err.status,
			},
		);
	}
	throw err;
}

export async function POST(req: NextRequest): Promise<NextResponse> {
	let body: { trace_ids?: string[]; label?: string; note?: string };
	try {
		body = await req.json();
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}
	try {
		return NextResponse.json(
			await gatewayPost<BatchAnnotationResult>("/v1/annotations/batch", {
				trace_ids: body.trace_ids,
				label: body.label,
				...(body.note ? { note: body.note } : {}),
			}),
		);
	} catch (err) {
		return passthrough(err);
	}
}
