import { fmtCount } from "@tracelanedev/ui";
import { PageHeader } from "@tracelanedev/ui";
import { StatusBadge } from "@tracelanedev/ui";
import { TBody, TD, TH, THead, TR, Table } from "@tracelanedev/ui";
import { ObjectSurface } from "@tracelanedev/ui";
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
import { getListPageSettings } from "@/lib/list-page-settings";
import { EmptyState } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = { title: "Experiments — Tracelane" };

type DatasetListResponse = {
	next_cursor: string | null;
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

export default async function ExperimentsPage({
	searchParams,
}: { searchParams: Promise<{ cursor?: string; dataset_cursor?: string }> }) {
	const { cursor, dataset_cursor } = await searchParams;
	const settings = await getListPageSettings();
	const pageHref = (experimentCursor?: string, choiceCursor?: string) => {
		const params = new URLSearchParams();
		if (experimentCursor) params.set("cursor", experimentCursor);
		if (choiceCursor) params.set("dataset_cursor", choiceCursor);
		return `/experiments${params.size ? `?${params}` : ""}`;
	};
	const query = `limit=${settings.sizes.experiments}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`;
	const retryHref = pageHref(cursor, dataset_cursor);
	let data: ExperimentListResponse;
	try {
		data = await gatewayGet<ExperimentListResponse>(`/v1/experiments?${query}`);
	} catch (err) {
		const status = err instanceof GatewayError ? err.status : 0;
		if (status === 403) {
			// LOCKED, at HTTP 200. A hidden route that 403s is the invisible-
			// entitlement bug; locked-with-a-reason is discoverable.
			return (
				<div className="mx-auto max-w-3xl px-6 py-10">
					<PageHeader title={<>Experiments</>} />
					<EmptyState
						title="Experiments aren't included in this plan"
						description="An experiment runs one frozen dataset against two to four prompt versions or models, then shows you exactly which items got worse — not that an average moved."
					/>
					<p className="mt-4 text-sm">
						<Link className="underline" href="/settings/billing">
							See plans →
						</Link>
					</p>
				</div>
			);
		}
		return (
			<div className="mx-auto max-w-3xl px-6 py-10">
				<PageHeader title={<>Experiments</>} />
				<EmptyState
					title="Couldn't load experiments"
					description="The gateway couldn't be reached. Nothing is wrong with your experiments — try again."
					action={
						<a className="underline" href={retryHref}>
							Retry
						</a>
					}
				/>
				{cursor && (
					<Link
						className="underline"
						href={pageHref(undefined, dataset_cursor)}
					>
						First page
					</Link>
				)}
			</div>
		);
	}

	// The two lists the create dialog needs. Fetched here rather than by the
	// client so the browser makes no gateway call of its own, and read with
	// `safeList` so a failure renders as "we could not check" instead of as
	// "you have none" — the zero-vs-unknown rule, applied to a precondition.
	const [datasetsRes, promptsRes] = await Promise.all([
		safeList<DatasetListResponse>(
			`/v1/datasets?limit=${settings.sizes.experiment_datasets}${dataset_cursor ? `&cursor=${encodeURIComponent(dataset_cursor)}` : ""}`,
		),
		safeList<PromptOption[]>("/v1/prompts"),
	]);
	const datasets: DatasetOption[] = datasetsRes?.datasets ?? [];
	const prompts: PromptOption[] = promptsRes ?? [];

	const disabledReason =
		datasetsRes === null || promptsRes === null
			? "Couldn't check your datasets and prompts just now — reload to try again."
			: datasets.length === 0
				? dataset_cursor
					? "No datasets on this choice page — return to the first dataset choices."
					: "Create a dataset first — an experiment runs a frozen set of cases."
				: prompts.length === 0
					? "Create a prompt first — an experiment compares versions of one prompt."
					: null;

	return (
		<div className="p-6">
			<div className="mb-4 flex flex-wrap items-start justify-between gap-3">
				<PageHeader title={<>Experiments</>} />
				<NewExperimentDialog
					key={dataset_cursor ?? "first-dataset-page"}
					datasets={datasets}
					prompts={prompts}
					disabledReason={disabledReason}
				/>
			</div>

			{settings.defaulted && (
				<p className="mb-3 text-sm text-ink-2">List settings unavailable.</p>
			)}
			<nav
				aria-label="Dataset choices"
				className="mb-4 flex flex-wrap gap-3 text-sm"
			>
				{datasetsRes && (
					<span>Dataset choices: {datasets.length} on this page.</span>
				)}
				{dataset_cursor && (
					<Link className="underline" href={pageHref(cursor)}>
						First dataset choices
					</Link>
				)}
				{datasetsRes?.next_cursor && (
					<Link
						className="underline"
						href={pageHref(cursor, datasetsRes.next_cursor)}
					>
						Next dataset choices
					</Link>
				)}
			</nav>
			{data.experiments.length === 0 ? (
				<EmptyState
					title={cursor ? "No experiments on this page" : "No experiments yet"}
					description={
						cursor
							? "Return to the first page to see your latest experiments."
							: "An experiment runs a dataset against 2–4 arms and diffs the results, so a change ships only when it measurably wins."
					}
				/>
			) : (
				<>
					<div className="overflow-x-auto">
						<Table className="w-full text-sm">
							<THead>
								<TR className="border-line border-b text-left">
									<TH className="px-3 py-1.5">Name</TH>
									<TH className="px-3 py-1.5">Dataset</TH>
									<TH className="px-3 py-1.5 text-right">Arms</TH>
									<TH className="px-3 py-1.5 text-right">Items</TH>
									<TH className="px-3 py-1.5">Status</TH>
									<TH className="px-3 py-1.5">Created</TH>
									<TH className="px-3 py-2">
										<span className="sr-only">Object actions</span>
									</TH>
								</TR>
							</THead>
							<TBody>
								{data.experiments.map((e: ExperimentSummary) => (
									<ObjectSurface
										key={e.experiment_id}
										objectId={e.experiment_id}
										title={e.name || "Unnamed experiment"}
										href={`/experiments/${encodeURIComponent(e.experiment_id)}`}
										fields={[
											{ label: "Dataset", value: e.dataset_id },
											{ label: "Arms", value: fmtCount(e.arms) },
											{ label: "Cases", value: fmtCount(e.item_count) },
											{ label: "Status", value: e.status },
										]}
										links={[
											{
												label: "Open dataset",
												href: `/datasets/${encodeURIComponent(e.dataset_id)}`,
											},
										]}
										className="border-line border-b"
									>
										<TD className="px-3 py-2">
											<Link
												className="underline"
												href={`/experiments/${encodeURIComponent(e.experiment_id)}`}
											>
												{e.name || "(unnamed)"}
											</Link>
										</TD>
										<TD className="px-3 py-2 font-mono text-2xs text-ink-3">
											{e.dataset_id.slice(0, 8)}…
										</TD>
										<TD
											className="px-3 py-2 text-right"
											style={{ fontVariantNumeric: "tabular-nums" }}
										>
											{e.arms}
										</TD>
										<TD
											className="px-3 py-2 text-right"
											style={{ fontVariantNumeric: "tabular-nums" }}
										>
											{e.item_count}
										</TD>
										<TD className="px-3 py-2">
											<StatusBadge status={e.status} />
										</TD>
										<TD className="px-3 py-2 text-ink-3">
											{formatDateTimeUtc(
												new Date(e.created_at_ms).toISOString(),
											)}
										</TD>
									</ObjectSurface>
								))}
							</TBody>
						</Table>
					</div>
					<p className="mt-3 text-ink-3 text-xs">
						Showing {data.experiments.length} on this page
					</p>
				</>
			)}
			<nav
				aria-label="Experiment pages"
				className="mt-4 flex flex-wrap gap-4 text-sm"
			>
				{cursor && (
					<Link
						className="underline"
						href={pageHref(undefined, dataset_cursor)}
					>
						First page
					</Link>
				)}
				{data.next_cursor && (
					<Link
						className="underline"
						href={pageHref(data.next_cursor, dataset_cursor)}
					>
						Next page →
					</Link>
				)}
			</nav>
		</div>
	);
}
