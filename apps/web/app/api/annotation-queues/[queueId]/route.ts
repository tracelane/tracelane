/**
 * EVL-29 — one queue. PATCH only: rename, re-filter, re-rubric, archive.
 *
 * There is deliberately **no DELETE**, at every layer. A review's `queue_id` is
 * a foreign key into this table, so a hard delete would either dangle it or
 * cascade away the reviews — and a review is the record of a human judgement
 * (`CLAUDE.md` §19, supersession never silent deletion). Archiving is the
 * retirement path: `{"archived": true}`.
 */

import { gatewayPatch } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";
import { type AnnotationQueue, passthrough } from "../shared";

export async function PATCH(
	req: NextRequest,
	ctx: { params: Promise<{ queueId: string }> },
): Promise<NextResponse> {
	const { queueId } = await ctx.params;
	let body: unknown;
	try {
		body = await req.json();
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}
	try {
		return NextResponse.json(
			await gatewayPatch<AnnotationQueue>(
				`/v1/annotation-queues/${encodeURIComponent(queueId)}`,
				body,
			),
		);
	} catch (err) {
		return passthrough(err);
	}
}
