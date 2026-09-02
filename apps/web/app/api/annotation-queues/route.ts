/**
 * EVL-29 — golden-case authoring queues. Thin proxy to the gateway.
 *
 * GET  /api/annotation-queues  → list this workspace's queues
 * POST /api/annotation-queues  → create one
 *
 * This route re-validates NOTHING: one validator, at the enforcement point. The
 * gateway owns tenant resolution, the role gate, the `f_annotation_queues`
 * entitlement and the whole rubric schema. A second copy here would drift, and
 * the drift would be silent.
 *
 * Types and the error passthrough live in `./shared` — a route module may only
 * export route fields, so a helper exported from here breaks `next build`.
 */

import { gatewayGet, gatewayPost } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";
import { type AnnotationQueue, passthrough } from "./shared";

export async function GET(): Promise<NextResponse> {
	try {
		return NextResponse.json(
			await gatewayGet<{ queues: AnnotationQueue[]; max_queues: number }>(
				"/v1/annotation-queues",
			),
		);
	} catch (err) {
		return passthrough(err);
	}
}

export async function POST(req: NextRequest): Promise<NextResponse> {
	let body: unknown;
	try {
		body = await req.json();
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}
	try {
		// Forwarded VERBATIM. The gateway's body type uses snake_case with
		// `deny_unknown_fields`, so re-shaping here would either drop a field
		// silently or be rejected — both worse than passing the author's
		// object through to the one validator that owns it.
		return NextResponse.json(
			await gatewayPost<AnnotationQueue>("/v1/annotation-queues", body),
			{ status: 201 },
		);
	} catch (err) {
		return passthrough(err);
	}
}
