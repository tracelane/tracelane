import { ObjectPageCommands } from "@/components/command-palette/object-commands";
import { ReadFailure } from "@/components/empty-states/ReadFailure";
import {
	NewExperimentDialog,
	type PromptOption,
} from "@/components/experiments/NewExperimentDialog";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import Link from "next/link";
import { DeleteDatasetButton } from "./DeleteDatasetButton";
import { ImportJsonlForm } from "./ImportJsonlForm";

import { canAdmin, requireSession } from "@/lib/auth";
import { getListPageSettings } from "@/lib/list-page-settings";
import { PageHeader } from "@tracelanedev/ui";
import type { DatasetItem, DatasetLimits } from "../management";
import { ownerReason } from "../management";
import { DatasetItems } from "./DatasetItems";
import { NewCaseForm } from "./NewCaseForm";
export default async function DatasetPage({
	params,
	searchParams,
}: {
	params: Promise<{ id: string }>;
	searchParams?: Promise<{ cursor?: string }>;
}) {
	const session = await requireSession();
	const canWrite = canAdmin(session.role);
	const settings = await getListPageSettings();
	const { id } = await params;
	const cursor = (await searchParams)?.cursor;
	try {
		const [dataset, data] = await Promise.all([
			gatewayGet<{
				name: string;
				description: string;
				items: number | null;
				with_reference: number | null;
				from_traces: number | null;
				limits: DatasetLimits;
			}>(`/v1/datasets/${encodeURIComponent(id)}`),
			gatewayGet<{
				items: DatasetItem[];
				next_cursor: string | null;
				total: number | null;
			}>(
				`/v1/datasets/${encodeURIComponent(id)}/items?limit=${settings.sizes.dataset_items}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
			),
		]);
		// Creating an experiment is optional: a failed prompt read must not hide cases.
		let promptStatus: number | null = null;
		const prompts = await gatewayGet<PromptOption[]>("/v1/prompts").catch(
			(error) => {
				promptStatus = error instanceof GatewayError ? error.status : 503;
				return null;
			},
		);
		const disabledReason =
			prompts == null
				? promptStatus === 401
					? "Sign in again to load prompt choices."
					: promptStatus === 403
						? "Access denied for prompt choices — ask a workspace owner to check your access."
						: "Couldn't load prompts — reload to try again."
				: prompts.length === 0
					? "Create a prompt first — an experiment compares versions of one prompt."
					: dataset.items === 0
						? "Add cases to this dataset before starting an experiment."
						: null;
		return (
			<div className="space-y-4 p-6">
				<ObjectPageCommands
					copyHref={`/datasets/${encodeURIComponent(id)}`}
					commands={[
						{
							id: "dataset-export",
							label: "Export JSONL",
							href: `/api/datasets/${encodeURIComponent(id)}/export?format=jsonl`,
							group: "action",
						},
					]}
				/>
				<Link href="/datasets" className="underline">
					Datasets
				</Link>
				<PageHeader
					title={dataset.name}
					description={dataset.description}
					actions={
						<>
							<NewCaseForm
								datasetId={id}
								limits={dataset.limits}
								canWrite={canWrite}
							/>
							<ImportJsonlForm
								datasetId={id}
								limits={dataset.limits}
								items={dataset.items}
								canWrite={canWrite}
							/>
							<a
								className="rounded-control border border-line px-4 py-2 text-sm"
								href={`/api/datasets/${encodeURIComponent(id)}/export?format=jsonl`}
							>
								Export JSONL
							</a>
							<DeleteDatasetButton
								datasetId={id}
								datasetName={dataset.name}
								canWrite={canWrite}
							/>
							<NewExperimentDialog
								datasets={[
									{
										dataset_id: id,
										name: dataset.name,
										items: dataset.items ?? null,
									},
								]}
								prompts={prompts ?? []}
								disabledReason={disabledReason}
							/>
						</>
					}
				/>
				{!canWrite && <p className="text-sm text-ink-2">{ownerReason}</p>}
				<p className="text-sm">
					Items {dataset.items ?? "—"} · With reference{" "}
					{dataset.with_reference ?? "—"} · From traces{" "}
					{dataset.from_traces ?? "—"}
					{dataset.items != null &&
						dataset.limits &&
						` · ${Math.max(0, dataset.limits.items_max - dataset.items)} slots left`}
				</p>

				{promptStatus !== null && (
					<ReadFailure
						status={promptStatus}
						resource="prompts"
						retryHref={`/datasets/${encodeURIComponent(id)}`}
					/>
				)}

				<p className="text-sm text-ink-2">
					Use{" "}
					<Link className="underline" href="/review">
						review queues
					</Link>{" "}
					to collect reference answers for this dataset, or{" "}
					<Link className="underline" href="/prompts">
						author a prompt
					</Link>{" "}
					to evaluate.
				</p>
				{data.items.length === 0 ? (
					<div className="rounded-card border border-line p-6">
						<p>{cursor ? "No items on this page" : "No cases yet"}</p>
						{!cursor && (
							<p className="mt-2 text-sm text-ink-2">
								Choose New case or Import JSONL above, or{" "}
								<Link className="underline" href="/traces">
									open a trace → Add to dataset
								</Link>
								.
							</p>
						)}
					</div>
				) : (
					<DatasetItems
						datasetId={id}
						items={data.items}
						limits={dataset.limits}
						canWrite={canWrite}
					/>
				)}
				<p className="text-sm text-ink-2">
					Showing {data.items.length} on this page
					{data.total != null && ` · ${data.total} total`}
				</p>
				{cursor && (
					<Link
						className="mr-4 underline"
						href={`/datasets/${encodeURIComponent(id)}`}
					>
						First page
					</Link>
				)}

				{data.next_cursor && (
					<Link
						className="underline"
						href={`/datasets/${encodeURIComponent(id)}?cursor=${encodeURIComponent(data.next_cursor)}`}
					>
						Next page
					</Link>
				)}
			</div>
		);
	} catch (err) {
		const message =
			err instanceof GatewayError && err.status < 500
				? typeof err.body?.message === "string"
					? err.body.message
					: err.status === 404
						? "Dataset not found in this workspace."
						: "This workspace cannot access this dataset."
				: "Could not load dataset. Try again.";
		return (
			<div className="p-6">
				<Link href="/datasets">Datasets</Link>
				<p role="alert">{message}</p>
				<Link
					className="underline"
					href={`/datasets/${encodeURIComponent(id)}`}
				>
					Retry
				</Link>
				{err instanceof GatewayError && err.status === 403 && (
					<Link className="ml-4 underline" href="/settings/billing">
						See plans
					</Link>
				)}
			</div>
		);
	}
}
