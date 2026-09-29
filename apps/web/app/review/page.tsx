import { PageHeader } from "@tracelanedev/ui";
import { TBody, TH, THead, TR, Table } from "@tracelanedev/ui";
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
 * ## The "New queue" affordance (added 2026-09-07 — a founder finding, not new scope)
 *
 * `specs/EVL-29-golden-case-authoring-queues.md:400` specified this control —
 * "**Create queue** disables at 50 with…" — back when this page was first built
 * (2026-08-29), and its own §8 wireframe drew `[ + New queue ]` in the header. It
 * shipped read-only: `POST /v1/annotation-queues` existed end to end at the
 * gateway and the Next.js proxy, and nothing in `apps/web` ever called it — the
 * only way to create a queue was `curl`. `NewQueueDialog` (rendered from BOTH the
 * header, always, and the empty state's primary action) closes that gap. It is
 * disabled — never hidden — whenever this page already knows the create would
 * fail: no datasets (R222), the dataset read itself failing (so the target
 * cannot be verified), or the workspace already at `max_queues` (`crates/gateway/
 * src/annotation_routes.rs:644`, `MAX_QUEUES = 50` today, read from the list
 * response rather than hard-coded here).
 *
 * Per-row **Archive** / **Un-archive** (`QueueRow`) closes the matching gap on
 * `PATCH /v1/annotation-queues/{id}` — see that file's header for why archiving,
 * not a full edit form, is what shipped.
 *
 * ## Not in the nav yet, on purpose
 *
 * The `BUILD_RUNBOOK.md` S3 rule that `/experiments` records: the nav entry
 * goes in only after a real review has produced rows on prod. Until then this
 * route exists for direct-URL access and `no-stranded-routes.test.ts` carries
 * the reason.
 */

import type { AnnotationQueue } from "@/app/api/annotation-queues/shared";
import {
	type DatasetOption,
	NewQueueDialog,
} from "@/components/review/NewQueueDialog";
import { QueueRow } from "@/components/review/QueueRow";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { EmptyState } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";
import type { ReactNode } from "react";

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

/**
 * The single place that decides why "New queue" is disabled, or that it is not.
 * `datasets === null` means the dataset READ failed — treated as "cannot verify
 * a target exists" rather than "there are none", which is the more honest
 * refusal (R222 requires a REAL target, and an unconfirmed one is not that).
 */
function createDisabledReason(
	datasets: DatasetListResponse | null,
	atCap: boolean,
	activeCount: number,
): ReactNode | null {
	if (datasets === null) {
		return "We couldn't confirm your datasets — reload and try again.";
	}
	if (datasets.datasets.length === 0) {
		return (
			<>
				A queue writes into a dataset, and every review lands in it — so a queue
				cannot exist without one. Creating a dataset is not in the app yet; the
				API accepts one today at <code>POST /v1/datasets</code>. This button
				turns on as soon as you have one.
			</>
		);
	}
	if (atCap) {
		// The real ACTIVE count (B-520), never `max_queues` — the list response
		// includes archived rows (ordered NULLS FIRST, filling the remainder of
		// its 50-row LIMIT), so `queues.length` can equal `max_queues` while the
		// tenant has far fewer active queues than that, and the gateway's own
		// create cap (`crates/gateway/src/annotation_routes.rs:644`) counts
		// active queues only.
		return `You have ${activeCount} active queues (the maximum). Archive one to create another.`;
	}
	return null;
}

export default async function ReviewQueuesPage() {
	const load = await loadQueues();

	if (load.kind === "locked") {
		return (
			<div className="p-8">
				<PageHeader title={<>Review queues</>} />
				<EmptyState
					title="Review queues aren't included in this plan"
					description="A review queue turns low-scoring production traces into graded test cases: a reviewer answers a rubric once, and that answer becomes a dataset item's expected output in the same action."
				/>
				<p className="mt-4 text-sm">
					<Link className="underline" href="/settings/billing">
						See plans →
					</Link>
				</p>
			</div>
		);
	}

	// Loaded once for every entitled branch below — the header's "New queue"
	// affordance needs to know the tenant's datasets whether or not the queue
	// list itself loaded.
	const datasetsResp = await loadDatasets();
	const datasetOptions: DatasetOption[] = datasetsResp?.datasets ?? [];

	if (load.kind === "failed") {
		return (
			<div className="p-8 space-y-6">
				<div className="flex items-center justify-between gap-3">
					<PageHeader title={<>Review queues</>} />
					<NewQueueDialog
						datasets={datasetOptions}
						disabledReason={createDisabledReason(datasetsResp, false, 0)}
					/>
				</div>
				<EmptyState
					title="We could not load your review queues"
					description="This is a problem reading them, not an empty list — your queues are unaffected. Retry in a moment."
				/>
			</div>
		);
	}

	const { queues, max_queues } = load.data;

	if (queues.length === 0) {
		// `null` = the dataset read FAILED. Treating that as "no datasets" would
		// tell the user to create something they may already have.
		const hasDatasets = datasetsResp ? datasetsResp.datasets.length > 0 : true;
		const disabledReason = createDisabledReason(datasetsResp, false, 0);
		return (
			<div className="p-8 space-y-6">
				<div className="flex items-center justify-between gap-3">
					<PageHeader title={<>Review queues</>} />
					<NewQueueDialog
						datasets={datasetOptions}
						disabledReason={disabledReason}
					/>
				</div>
				<EmptyState
					title={
						hasDatasets ? "No review queues yet" : "You need a dataset first"
					}
					description={
						hasDatasets
							? "A queue is a saved filter over your traces — for example, every trace the online-eval judge scored below 0.5. A reviewer works the queue, answers your rubric, and each answer becomes a graded case in a dataset."
							: "Every review queue writes into a target dataset, and that target is required — it is what makes the review loop close. Create a dataset, then come back."
					}
					action={
						<NewQueueDialog
							datasets={datasetOptions}
							disabledReason={disabledReason}
							label="Create queue"
							size="lg"
						/>
					}
				/>
			</div>
		);
	}

	// B-520: `queues` is the raw list response, which includes ARCHIVED rows
	// (ordered NULLS FIRST, filling the remainder of the 50-row LIMIT after
	// every active one) — the gateway's own create cap
	// (`crates/gateway/src/annotation_routes.rs:644`) counts active queues
	// only, so the cap check and the message it renders must too.
	const activeCount = queues.filter((q) => !q.archived_at).length;
	const atCap = activeCount >= max_queues;
	const disabledReason = createDisabledReason(datasetsResp, atCap, activeCount);

	return (
		<div className="p-8 space-y-6">
			<div className="flex items-center justify-between gap-3">
				<PageHeader title={<>Review queues</>} />
				<NewQueueDialog
					datasets={datasetOptions}
					disabledReason={disabledReason}
				/>
			</div>
			<div className="overflow-x-auto">
				<Table className="w-full text-sm">
					<THead>
						<TR className="text-left border-b">
							<TH className="py-2 pr-4">Queue</TH>
							<TH className="py-2 pr-4">Source</TH>
							<TH className="py-2 pr-4">Window</TH>
							<TH className="py-2 pr-4">Reference field</TH>
							<TH className="py-2 pr-4">Created</TH>
							<TH className="py-2 pr-4">Actions</TH>
						</TR>
					</THead>
					<TBody>
						{queues.map((q) => (
							<QueueRow key={q.id} queue={q} sourceLabel={sourceLabel(q)} />
						))}
					</TBody>
				</Table>
			</div>
		</div>
	);
}
