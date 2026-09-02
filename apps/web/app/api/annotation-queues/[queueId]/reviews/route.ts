/**
 * EVL-29 — THE ONE ACTION.
 *
 * One POST submits the reviewer's rubric AND creates the dataset item carrying
 * their answer as its `expected_output`. There is no second call and there must
 * never be one: if closing the loop took two requests, a failure between them
 * would leave a trace that had left the queue without becoming a test case.
 *
 * The gateway performs the dataset write FIRST and the annotation row LAST, so
 * a `dataset_write_failed` here means **nothing was recorded** and the trace is
 * still in the queue — which is why the client may safely retry, and why the
 * error copy says so.
 */

import { gatewayPost } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";
import { passthrough } from "../../shared";

export type ReviewResponse = {
	annotation: {
		trace_id: string;
		span_id: string;
		label: string;
		note: string;
		author_sub: string;
		created_at: string;
		updated_at: string;
	};
	dataset_id: string;
	item_id: string;
	/** True when the source span was already in the dataset; the reference is
	 * still written onto the existing item rather than duplicating it. */
	deduped: boolean;
	expected_output: string;
};

export async function POST(
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
			await gatewayPost<ReviewResponse>(
				`/v1/annotation-queues/${encodeURIComponent(queueId)}/reviews`,
				body,
			),
			{ status: 201 },
		);
	} catch (err) {
		return passthrough(err);
	}
}
