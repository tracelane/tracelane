import { canAdmin, requireSession } from "@/lib/auth";
import { formatDateTimeUtc } from "@/lib/format-date";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { getListPageSettings } from "@/lib/list-page-settings";
import { PageHeader } from "@tracelanedev/ui";
import { TBody, TD, TH, THead, TR, Table } from "@tracelanedev/ui";
import { ObjectSurface } from "@tracelanedev/ui";
import { EmptyState } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";
import { DatasetAction } from "./DatasetAction";
import { DeleteDatasetButton } from "./[id]/DeleteDatasetButton";

export const metadata: Metadata = { title: "Datasets — Tracelane" };

/** One row, exactly as `dataset_routes.rs`'s `DatasetDto` serializes it.
 * `items` / `with_reference` / `from_traces` are `Option<u64>` server-side —
 * `null` means the per-dataset count query FAILED, and must render as "—",
 * never a fabricated `0` (the zero-vs-unknown rule the server comment states
 * verbatim: "on an evidence product it is the expensive one"). There is no
 * `updated_at_ms` field — the DTO does not carry one, so this page does not
 * invent an "Updated" column. */
type DatasetRow = {
	dataset_id: string;
	name: string;
	description: string;
	created_at_ms: number;
	created_by: string;
	items: number | null;
	with_reference: number | null;
	from_traces: number | null;
};

type DatasetListResponse = {
	datasets: DatasetRow[];
	next_cursor: string | null;
	total: number | null;
};

/** Distinguishes NOT-ENTITLED from READ-FAILED from EMPTY — collapsing those
 * is the defect where a customer on the wrong plan is told their data is
 * empty (the same `Load` shape `/review` uses). */
type Load =
	| { kind: "ok"; data: DatasetListResponse }
	| { kind: "locked" }
	| { kind: "failed" };

async function loadDatasets(limit: number, cursor?: string): Promise<Load> {
	try {
		return {
			kind: "ok",
			data: await gatewayGet<DatasetListResponse>(
				`/v1/datasets?limit=${limit}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
			),
		};
	} catch (err) {
		if (err instanceof GatewayError && err.status === 403) {
			return { kind: "locked" };
		}
		return { kind: "failed" };
	}
}

/** `null` (failed count) renders as an em dash, never `0`. */
function formatCount(n: number | null): string {
	return n === null ? "—" : String(n);
}

export default async function DatasetsPage({
	searchParams,
}: { searchParams: Promise<{ cursor?: string }> }) {
	const session = await requireSession();
	const canWrite = canAdmin(session.role);
	const cursor = (await searchParams)?.cursor;
	const settings = await getListPageSettings();
	const load = await loadDatasets(settings.sizes.datasets, cursor);

	if (load.kind === "locked") {
		return (
			<div className="mx-auto max-w-3xl px-6 py-10">
				<PageHeader title={<>Datasets</>} />
				<EmptyState
					title="Datasets aren't included in this plan"
					description="A dataset is a curated, labeled set of real traces — replay it against a prompt or model change to catch regressions before they reach production."
				/>
				<p className="mt-4 text-sm">
					<Link className="underline" href="/settings/billing">
						See plans →
					</Link>
				</p>
			</div>
		);
	}

	if (load.kind === "failed") {
		return (
			<div className="mx-auto max-w-3xl px-6 py-10">
				<PageHeader title={<>Datasets</>} />
				<EmptyState
					title="Couldn't load datasets"
					description="The gateway couldn't be reached. Nothing is wrong with your datasets — try again."
					action={
						<a
							className="underline"
							href={
								cursor
									? `/datasets?cursor=${encodeURIComponent(cursor)}`
									: "/datasets"
							}
						>
							Retry
						</a>
					}
				/>
				{cursor && (
					<Link className="underline" href="/datasets">
						First page
					</Link>
				)}
			</div>
		);
	}

	const { datasets, next_cursor } = load.data;

	return (
		<div className="p-6">
			<div className="mb-4 flex flex-wrap items-start justify-between gap-3">
				<PageHeader title={<>Datasets</>} />
				<DatasetAction />
			</div>

			{settings.defaulted && (
				<p className="mb-3 text-sm text-ink-2">List settings unavailable.</p>
			)}
			{datasets.length === 0 ? (
				<EmptyState
					title={cursor ? "No datasets on this page" : "No datasets yet"}
					description={
						cursor
							? "Return to the first page to see your latest datasets."
							: "A dataset is a curated, labeled set of real traces you replay against a prompt or model change. Create a dataset here, then add cases from a production trace."
					}
				/>
			) : (
				<>
					<div className="overflow-x-auto">
						<Table className="w-full text-sm">
							<THead>
								<TR className="border-line border-b text-left">
									<TH className="px-3 py-1.5">Name</TH>
									<TH className="px-3 py-1.5 text-right">Items</TH>
									<TH className="px-3 py-1.5 text-right">With reference</TH>
									<TH className="px-3 py-1.5 text-right">From traces</TH>
									<TH className="px-3 py-1.5">Created</TH>
									<TH>Actions</TH>
									<TH className="px-3 py-2">
										<span className="sr-only">Object actions</span>
									</TH>
								</TR>
							</THead>
							<TBody>
								{datasets.map((d) => (
									<ObjectSurface
										key={d.dataset_id}
										objectId={d.dataset_id}
										title={d.name || "Unnamed dataset"}
										href={`/datasets/${encodeURIComponent(d.dataset_id)}`}
										fields={[
											{ label: "Description", value: d.description || "—" },
											{ label: "Items", value: formatCount(d.items) },
											{
												label: "With reference",
												value: formatCount(d.with_reference),
											},
											{
												label: "From traces",
												value: formatCount(d.from_traces),
											},
										]}
										links={[
											{
												label: "Manage cases",
												href: `/datasets/${encodeURIComponent(d.dataset_id)}`,
											},
										]}
										className="border-line border-b"
									>
										<TD className="px-3 py-2">
											<Link
												className="underline"
												href={`/datasets/${d.dataset_id}`}
											>
												{d.name || "(unnamed)"}
											</Link>
										</TD>
										<TD
											className="px-3 py-2 text-right"
											style={{ fontVariantNumeric: "tabular-nums" }}
										>
											{formatCount(d.items)}
										</TD>
										<TD
											className="px-3 py-2 text-right"
											style={{ fontVariantNumeric: "tabular-nums" }}
										>
											{formatCount(d.with_reference)}
										</TD>
										<TD
											className="px-3 py-2 text-right"
											style={{ fontVariantNumeric: "tabular-nums" }}
										>
											{formatCount(d.from_traces)}
										</TD>
										<TD className="px-3 py-2 text-ink-3">
											{formatDateTimeUtc(
												new Date(d.created_at_ms).toISOString(),
											)}
										</TD>
										<TD>
											<DeleteDatasetButton
												datasetId={d.dataset_id}
												datasetName={d.name}
												canWrite={canWrite}
											/>
										</TD>
									</ObjectSurface>
								))}
							</TBody>
						</Table>
					</div>
					<p className="mt-3 text-ink-3 text-xs">
						Showing {datasets.length} on this page
					</p>
				</>
			)}
			<nav
				aria-label="Dataset pages"
				className="mt-4 flex flex-wrap gap-4 text-sm"
			>
				{cursor && (
					<Link className="underline" href="/datasets">
						First page
					</Link>
				)}
				{next_cursor && (
					<Link
						className="underline"
						href={`/datasets?cursor=${encodeURIComponent(next_cursor)}`}
					>
						Next page →
					</Link>
				)}
			</nav>
		</div>
	);
}
