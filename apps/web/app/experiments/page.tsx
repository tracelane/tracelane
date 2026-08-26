/**
 * `EVL-02` — experiments, listed.
 *
 * Server Component. Replaces the `<ComingSoon/>` stub that stood here while the
 * feature did not exist.
 *
 * ## The four states this page has to tell apart
 *
 * | State | What decides it | What the user sees |
 * |---|---|---|
 * | **Not entitled** | the gateway answers `403 entitlement_required` | an HTTP **200** locked page naming what the feature does and where to upgrade — never a bare 403 error page |
 * | **Empty, no dataset** | the experiments list is empty AND the datasets list is empty | "You need a dataset first", and **New experiment disabled with that reason ON the button** |
 * | **Empty, has datasets** | the experiments list is empty | "No experiments yet", button enabled |
 * | **Populated** | rows | the table |
 *
 * **Entitlement is decided by the GATEWAY, not by a second resolver here.** The
 * gateway's entitlement cache is the authority (and it fails CLOSED on an absent
 * control plane); re-deriving the same answer from `apps/web`'s Postgres reader
 * would be a second resolution path, and the two would eventually disagree —
 * silently, in the direction that grants.
 *
 * ## Not in the nav yet, on purpose
 *
 * `docs/runbook/BUILD_RUNBOOK.md`'s **S3** serialization point: the nav entry is
 * added only after a real run has produced rows on prod. Until then the route
 * exists for direct-URL access and `no-stranded-routes.test.ts` carries the
 * reason.
 */

import type {
	ExperimentListResponse,
	ExperimentSummary,
} from "@/app/api/experiments/route";
import {
	type DatasetOption,
	NewExperimentDialog,
	type PromptOption,
} from "@/components/experiments/NewExperimentDialog";
import { formatDateTimeUtc } from "@/lib/format-date";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { EmptyState } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = { title: "Experiments — Tracelane" };

type DatasetListResponse = {
	datasets: { dataset_id: string; name: string; items: number | null }[];
};

/** `null` means the read FAILED — distinct from an empty list, and the page must
 * not turn "we could not ask" into "you have none". */
async function safeList<T>(path: string): Promise<T | null> {
	try {
		return await gatewayGet<T>(path);
	} catch {
		return null;
	}
}

export default async function ExperimentsPage() {
	let data: ExperimentListResponse;
	try {
		data = await gatewayGet<ExperimentListResponse>("/v1/experiments?limit=25");
	} catch (err) {
		const status = err instanceof GatewayError ? err.status : 0;
		if (status === 403) {
			// LOCKED, at HTTP 200. A hidden route that 403s is the invisible-
			// entitlement bug; locked-with-a-reason is discoverable.
			return (
				<main className="mx-auto max-w-3xl px-6 py-10">
					<h1 className="t-h1 mb-6">Experiments</h1>
					<EmptyState
						title="Experiments aren't included in this plan"
						description="An experiment runs one frozen dataset against two to four prompt versions or models, then shows you exactly which items got worse — not that an average moved."
					/>
					<p className="mt-4 text-sm">
						<Link className="underline" href="/settings/billing">
							See plans →
						</Link>
					</p>
				</main>
			);
		}
		return (
			<main className="mx-auto max-w-3xl px-6 py-10">
				<h1 className="t-h1 mb-6">Experiments</h1>
				<EmptyState
					title="Couldn't load experiments"
					description="The gateway couldn't be reached. Nothing is wrong with your experiments — try again."
				/>
			</main>
		);
	}

	// The two lists the create dialog needs. Fetched here rather than by the
	// client so the browser makes no gateway call of its own, and read with
	// `safeList` so a failure renders as "we could not check" instead of as
	// "you have none" — the zero-vs-unknown rule, applied to a precondition.
	const [datasetsRes, promptsRes] = await Promise.all([
		safeList<DatasetListResponse>("/v1/datasets?limit=100"),
		safeList<PromptOption[]>("/v1/prompts"),
	]);
	const datasets: DatasetOption[] = datasetsRes?.datasets ?? [];
	const prompts: PromptOption[] = promptsRes ?? [];

	const disabledReason =
		datasetsRes === null || promptsRes === null
			? "Couldn't check your datasets and prompts just now — reload to try again."
			: datasets.length === 0
				? "Create a dataset first — an experiment runs a frozen set of cases."
				: prompts.length === 0
					? "Create a prompt first — an experiment compares versions of one prompt."
					: null;

	return (
		<main className="p-6">
			<div className="mb-4 flex flex-wrap items-start justify-between gap-3">
				<h1 className="t-h1">Experiments</h1>
				<NewExperimentDialog
					datasets={datasets}
					prompts={prompts}
					disabledReason={disabledReason}
				/>
			</div>

			{data.experiments.length === 0 ? (
				<EmptyState
					title="No experiments yet"
					description="An experiment runs a dataset against 2–4 arms and diffs the results, so a change ships only when it measurably wins."
				/>
			) : (
				<>
					<div className="overflow-x-auto">
						<table className="w-full text-sm">
							<thead>
								<tr className="border-line border-b text-left">
									<th className="px-3 py-1.5">Name</th>
									<th className="px-3 py-1.5">Dataset</th>
									<th className="px-3 py-1.5 text-right">Arms</th>
									<th className="px-3 py-1.5 text-right">Items</th>
									<th className="px-3 py-1.5">Status</th>
									<th className="px-3 py-1.5">Created</th>
								</tr>
							</thead>
							<tbody>
								{data.experiments.map((e: ExperimentSummary) => (
									<tr key={e.experiment_id} className="border-line border-b">
										<td className="px-3 py-2">
											<Link
												className="underline"
												href={`/experiments/${encodeURIComponent(e.experiment_id)}`}
											>
												{e.name || "(unnamed)"}
											</Link>
										</td>
										<td className="px-3 py-2 font-mono text-2xs text-ink-3">
											{e.dataset_id.slice(0, 8)}…
										</td>
										<td
											className="px-3 py-2 text-right"
											style={{ fontVariantNumeric: "tabular-nums" }}
										>
											{e.arms}
										</td>
										<td
											className="px-3 py-2 text-right"
											style={{ fontVariantNumeric: "tabular-nums" }}
										>
											{e.item_count}
										</td>
										<td className="px-3 py-2">{e.status}</td>
										<td className="px-3 py-2 text-ink-3">
											{formatDateTimeUtc(
												new Date(e.created_at_ms).toISOString(),
											)}
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
					{/* NEVER a silent stop. A list that ends without saying whether more
					    exists is the CSV lesson `specs/README.md` records. */}
					<p className="mt-3 text-ink-3 text-xs">
						showing {data.experiments.length}
						{data.next_cursor
							? " — more available; pagination lands with the next page control"
							: ` of ${data.experiments.length}`}
					</p>
				</>
			)}
		</main>
	);
}
