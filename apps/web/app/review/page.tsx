/**
 * `EVL-29` — golden-case authoring queues, listed.
 *
 * Server Component, following the `EVL-02` experiments page exactly: the four
 * states are told apart, and **entitlement is decided by the GATEWAY**, never
 * re-derived here. A second resolver in `apps/web` would eventually disagree
 * with the gateway's cache, silently, in the direction that grants.
 *
 * | State | What decides it | What the user sees |
 * |---|---|---|
 * | **Not entitled** | gateway answers `403 entitlement_required` | an HTTP **200** locked page naming the feature and the upgrade path — never a bare 403 |
 * | **Read failed** | the request threw for any other reason | "We could not load your queues" — NOT "you have none" |
 * | **Empty, no dataset** | no queues AND no datasets | "You need a dataset first", with the reason ON the disabled button: a queue REQUIRES a target dataset (R222), so it is genuinely uncreatable |
 * | **Empty, has datasets** | no queues | "No queues yet" |
 * | **Populated** | rows | the table |
 *
 * ## Why "you need a dataset first" is a real precondition, not a nicety
 *
 * `annotation_queues.default_dataset_id` is **NOT NULL** at the schema (founder
 * ruling R222, migration 0033). A queue cannot exist without a target, because
 * "the loop closes by construction" is only true if the field cannot be absent.
 * So this page must not offer a create button it knows will fail.
 *
 * ## Not in the nav yet, on purpose
 *
 * The `BUILD_RUNBOOK.md` S3 rule that `/experiments` records: the nav entry
 * goes in only after a real review has produced rows on prod. Until then this
 * route exists for direct-URL access and `no-stranded-routes.test.ts` carries
 * the reason.
 */

import type { AnnotationQueue } from "@/app/api/annotation-queues/shared";
import { formatDateTimeUtc } from "@/lib/format-date";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { EmptyState } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = { title: "Review queues — Tracelane" };

type QueueListResponse = { queues: AnnotationQueue[]; max_queues: number };
type DatasetListResponse = {
	datasets: { dataset_id: string; name: string }[];
};

/** Distinguishes NOT-ENTITLED from READ-FAILED from EMPTY. Collapsing those is
 * the defect where a customer on the wrong plan is told their data is empty. */
type Load =
	| { kind: "ok"; data: QueueListResponse }
	| { kind: "locked" }
	| { kind: "failed" };

async function loadQueues(): Promise<Load> {
	try {
		return {
			kind: "ok",
			data: await gatewayGet<QueueListResponse>("/v1/annotation-queues"),
		};
	} catch (err) {
		if (err instanceof GatewayError && err.status === 403)
			return { kind: "locked" };
		return { kind: "failed" };
	}
}

async function loadDatasets(): Promise<DatasetListResponse | null> {
	try {
		return await gatewayGet<DatasetListResponse>("/v1/datasets");
	} catch {
		return null;
	}
}

function sourceLabel(q: AnnotationQueue): string {
	const s = q.filter.source;
	switch (s.kind) {
		case "online_eval_score":
			return `Judge score ≤ ${s.max_score}${s.rubric ? ` · ${s.rubric}` : ""}`;
		case "trace_error":
			return "Errored traces";
		case "needs_review":
			return "Flagged needs_review";
		default:
			// The source union is CLOSED, so this is unreachable today. It exists
			// because TypeScript cannot prove the switch returns on every path
			// without it, and because a future source added to the Rust enum
			// should render as its own kind rather than crash the list.
			return (s as { kind: string }).kind;
	}
}

export default async function ReviewQueuesPage() {
	const load = await loadQueues();

	if (load.kind === "locked") {
		return (
			<main className="p-8">
				<h1 className="text-2xl font-semibold">Review queues</h1>
				<EmptyState
					title="Review queues aren't included in this plan"
					description="A review queue turns low-scoring production traces into graded test cases: a reviewer answers a rubric once, and that answer becomes a dataset item's expected output in the same action."
				/>
				<p className="mt-4 text-sm">
					<Link className="underline" href="/settings/billing">
						See plans →
					</Link>
				</p>
			</main>
		);
	}

	if (load.kind === "failed") {
		return (
			<main className="p-8">
				<h1 className="text-2xl font-semibold">Review queues</h1>
				<EmptyState
					title="We could not load your review queues"
					description="This is a problem reading them, not an empty list — your queues are unaffected. Retry in a moment."
				/>
			</main>
		);
	}

	const { queues } = load.data;

	if (queues.length === 0) {
		const datasets = await loadDatasets();
		// `null` = the dataset read FAILED. Treating that as "no datasets" would
		// tell the user to create something they may already have.
		const hasDatasets = datasets ? datasets.datasets.length > 0 : true;
		return (
			<main className="p-8">
				<h1 className="text-2xl font-semibold">Review queues</h1>
				<EmptyState
					title={
						hasDatasets ? "No review queues yet" : "You need a dataset first"
					}
					description={
						hasDatasets
							? "A queue is a saved filter over your traces — for example, every trace the online-eval judge scored below 0.5. A reviewer works the queue, answers your rubric, and each answer becomes a graded case in a dataset."
							: "Every review queue writes into a target dataset, and that target is required — it is what makes the review loop close. Create a dataset, then come back."
					}
				/>
			</main>
		);
	}

	return (
		<main className="p-8 space-y-6">
			<h1 className="text-2xl font-semibold">Review queues</h1>
			<div className="overflow-x-auto">
				<table className="w-full text-sm">
					<thead>
						<tr className="text-left border-b">
							<th className="py-2 pr-4">Queue</th>
							<th className="py-2 pr-4">Source</th>
							<th className="py-2 pr-4">Window</th>
							<th className="py-2 pr-4">Reference field</th>
							<th className="py-2 pr-4">Created</th>
						</tr>
					</thead>
					<tbody>
						{queues.map((q) => (
							<tr key={q.id} className="border-b last:border-0">
								<td className="py-2 pr-4">
									{q.archived_at ? (
										<span className="opacity-60">{q.name} (archived)</span>
									) : (
										<Link className="underline" href={`/review/${q.id}`}>
											{q.name}
										</Link>
									)}
								</td>
								<td className="py-2 pr-4">{sourceLabel(q)}</td>
								<td className="py-2 pr-4">{q.filter.window_hours}h</td>
								<td className="py-2 pr-4">
									<code>{q.expected_output_field}</code>
								</td>
								<td className="py-2 pr-4">{formatDateTimeUtc(q.created_at)}</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>
		</main>
	);
}
