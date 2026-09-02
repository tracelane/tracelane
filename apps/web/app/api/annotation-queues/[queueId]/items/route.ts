/**
 * EVL-29 — the queue's unreviewed candidates.
 *
 * **This is a LIVE QUERY, not a stored list** (founder ruling R221.1): queue
 * membership is a saved filter evaluated at read time, never materialised. A
 * materialised queue is a second copy of a judgement that goes stale the moment
 * a threshold moves, and we would then own reconciliation between the queue and
 * the scores it came from. The accepted cost, knowingly taken, is that a
 * reviewer's list is a live query — so this route is `no-store` by way of the
 * gateway helper and the page must not cache it.
 *
 * The response carries `scan_exhausted` / `scan_truncated` alongside the items
 * because a short page has two very different meanings — "that is all there is"
 * versus "we stopped looking" — and a reviewer who cannot tell them apart will
 * believe an empty queue.
 */

import { gatewayGet } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";
import { passthrough } from "../../shared";

export type QueueItem = {
	trace_id: string;
	span_id: string;
	/** Absent for a source that carries no score — never rendered as 0. */
	score?: number;
	verdict?: string;
	reason?: string;
	occurred_at: string;
};

export type QueueItemsResponse = {
	queue_id: string;
	items: QueueItem[];
	scan_exhausted: boolean;
	scan_truncated: boolean;
	pages_scanned: number;
	max_pages: number;
};

export async function GET(
	req: NextRequest,
	ctx: { params: Promise<{ queueId: string }> },
): Promise<NextResponse> {
	const { queueId } = await ctx.params;
	const limit = req.nextUrl.searchParams.get("limit");
	const qs = limit ? `?limit=${encodeURIComponent(limit)}` : "";
	try {
		return NextResponse.json(
			await gatewayGet<QueueItemsResponse>(
				`/v1/annotation-queues/${encodeURIComponent(queueId)}/items${qs}`,
			),
		);
	} catch (err) {
		return passthrough(err);
	}
}
