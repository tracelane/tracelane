/**
 * `EVL-29` — the reviewer, for one queue.
 *
 * Server Component that loads the queue and its **live** candidate list, then
 * hands both to the client panel that performs the one action.
 *
 * ## The list is a query, not a table
 *
 * Founder ruling R221.1: queue membership is a saved filter evaluated at READ
 * TIME, never materialised. `force-dynamic` is therefore load-bearing rather
 * than cautious — a cached page would show a reviewer a queue that no longer
 * reflects the scores it came from, which is exactly the drift the ruling
 * exists to prevent.
 *
 * ## States
 *
 * | State | What the reviewer sees |
 * |---|---|
 * | not entitled (`403`) | the locked page, HTTP 200 |
 * | no such / archived queue (`404`/`409`) | "this queue is not available", not a crash |
 * | read failed | "could not load", explicitly NOT "nothing to review" |
 * | empty | told whether the scan was EXHAUSTED or TRUNCATED — those mean different things |
 * | populated | the review panel |
 */

import type { QueueItemsResponse } from "@/app/api/annotation-queues/[queueId]/items/route";
import type { AnnotationQueue } from "@/app/api/annotation-queues/shared";
import { ReviewPanel } from "@/components/review/ReviewPanel";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { EmptyState } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = { title: "Review — Tracelane" };
/** R221.1: membership is a live query. A cached page defeats the ruling. */
export const dynamic = "force-dynamic";

type Load =
	| { kind: "ok"; queue: AnnotationQueue; items: QueueItemsResponse }
	| { kind: "locked" }
	| { kind: "missing" }
	| { kind: "failed" };

async function load(queueId: string): Promise<Load> {
	let queues: { queues: AnnotationQueue[] };
	try {
		queues = await gatewayGet<{ queues: AnnotationQueue[] }>(
			"/v1/annotation-queues",
		);
	} catch (err) {
		if (err instanceof GatewayError && err.status === 403)
			return { kind: "locked" };
		return { kind: "failed" };
	}
	const queue = queues.queues.find((q) => q.id === queueId);
	if (!queue) return { kind: "missing" };
	try {
		const items = await gatewayGet<QueueItemsResponse>(
			`/v1/annotation-queues/${encodeURIComponent(queueId)}/items`,
		);
		return { kind: "ok", queue, items };
	} catch (err) {
		if (
			err instanceof GatewayError &&
			(err.status === 404 || err.status === 409)
		)
			return { kind: "missing" };
		return { kind: "failed" };
	}
}

export default async function ReviewQueuePage(ctx: {
	params: Promise<{ queueId: string }>;
}) {
	const { queueId } = await ctx.params;
	const res = await load(queueId);

	if (res.kind === "locked") {
		return (
			<main className="p-8">
				<EmptyState
					title="Review queues aren't included in this plan"
					description="A reviewer answers a rubric once and that answer becomes a graded test case in the same action."
				/>
				<p className="mt-4 text-sm">
					<Link className="underline" href="/settings/billing">
						See plans →
					</Link>
				</p>
			</main>
		);
	}
	if (res.kind === "missing") {
		return (
			<main className="p-8">
				<EmptyState
					title="This queue is not available"
					description="It may have been archived, or it belongs to another workspace."
				/>
				<p className="mt-4 text-sm">
					<Link className="underline" href="/review">
						All review queues →
					</Link>
				</p>
			</main>
		);
	}
	if (res.kind === "failed") {
		return (
			<main className="p-8">
				<EmptyState
					title="We could not load this queue"
					description="This is a read failure, not an empty queue — nothing has been reviewed or lost. Retry in a moment."
				/>
			</main>
		);
	}

	const { queue, items } = res;
	return (
		<main className="p-8 space-y-6">
			<div>
				<h1 className="text-2xl font-semibold">{queue.name}</h1>
				<p className="text-sm opacity-70">
					Answers to <code>{queue.expected_output_field}</code> become the
					expected output of a new case in this queue&rsquo;s dataset.
				</p>
			</div>
			<ReviewPanel
				queue={queue}
				items={items.items}
				scanTruncated={items.scan_truncated}
				scanExhausted={items.scan_exhausted}
			/>
		</main>
	);
}
