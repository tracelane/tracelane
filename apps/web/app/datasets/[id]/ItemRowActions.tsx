"use client";
import { apiFetchRaw } from "@/lib/api-fetch";
import {
	Button,
	ConfirmDialog,
	Dialog,
	ObjectActions,
	usePeek,
} from "@tracelanedev/ui";
import { useRouter } from "next/navigation";
import { useState } from "react";
import {
	type DatasetLimits,
	bytes,
	datasetResponse,
	ownerReason,
	parseMetadata,
} from "../management";
import { NewCaseForm } from "./NewCaseForm";
export function ItemRowActions({
	datasetId,
	itemId,
	expectedOutput,
	metadata = {},
	input,
	system,
	name,
	limits,
	canWrite = false,
}: {
	datasetId: string;
	itemId: string;
	expectedOutput: string | null;
	metadata?: Record<string, unknown>;
	input?: unknown;
	system?: unknown;
	name?: string;
	limits?: DatasetLimits;
	canWrite?: boolean;
}) {
	const router = useRouter();
	const [peek, setPeek] = usePeek("case");
	const [reference, setReference] = useState(expectedOutput ?? "");
	const [meta, setMeta] = useState(JSON.stringify(metadata, null, 2));
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [deleting, setDeleting] = useState(false);
	let validation = "";
	try {
		parseMetadata(meta);
	} catch {
		validation = "Metadata must be a JSON object.";
	}
	if (limits && bytes(reference) > limits.expected_output_bytes_max)
		validation = "Expected output exceeds the byte limit.";
	if (limits && bytes(meta) > limits.metadata_bytes_max)
		validation = "Metadata exceeds the byte limit.";
	async function save() {
		if (validation || !canWrite || !limits || busy) return;
		setBusy(true);
		setError("");
		try {
			await datasetResponse(
				await apiFetchRaw(
					`/api/datasets/${encodeURIComponent(datasetId)}/items/${encodeURIComponent(itemId)}`,
					{
						method: "PATCH",
						headers: { "content-type": "application/json" },
						body: JSON.stringify({
							expected_output: reference,
							metadata: parseMetadata(meta),
						}),
					},
				),
			);
			setPeek(null);
			router.refresh();
		} catch (e) {
			setError(e instanceof Error ? e.message : "Could not save. Retry.");
		} finally {
			setBusy(false);
		}
	}
	async function remove() {
		if (!canWrite || busy) return;
		setBusy(true);
		setError("");
		try {
			await datasetResponse(
				await apiFetchRaw(
					`/api/datasets/${encodeURIComponent(datasetId)}/items/${encodeURIComponent(itemId)}`,
					{ method: "DELETE" },
				),
			);
			setDeleting(false);
			setPeek(null);
			router.refresh();
		} catch (e) {
			setError(e instanceof Error ? e.message : "Could not delete. Retry.");
		} finally {
			setBusy(false);
		}
	}
	function edit() {
		setReference(expectedOutput ?? "");
		setMeta(JSON.stringify(metadata, null, 2));
		setError("");
		setPeek(itemId);
	}
	return (
		<div className="flex items-center gap-1">
			<Button
				size="sm"
				disabled={!canWrite}
				title={!canWrite ? ownerReason : undefined}
				onClick={edit}
			>
				Edit case
			</Button>
			<ObjectActions
				label="Case actions"
				actions={[
					{
						label: "Edit case",
						onSelect: edit,
						disabled: !canWrite,
						reason: ownerReason,
					},
					{
						label: "Delete case",
						onSelect: () => {
							setError("");
							setDeleting(true);
						},
						danger: true,
						disabled: !canWrite,
						reason: ownerReason,
					},
				]}
			/>
			<Dialog
				drawer
				title={name || "Edit case"}
				open={peek === itemId}
				onClose={() => setPeek(null)}
				busy={busy}
			>
				<div className="space-y-4">
					<p className="text-sm text-ink-2">
						Input and name are immutable. Duplicate this case to change them.
					</p>
					<details>
						<summary>Input (read-only)</summary>
						<pre className="whitespace-pre-wrap break-words">
							{JSON.stringify({ input, system }, null, 2)}
						</pre>
					</details>
					<label className="block">
						Expected output
						<textarea
							aria-label="Expected output"
							value={reference}
							onChange={(e) => setReference(e.target.value)}
							rows={6}
							className="mt-2 w-full rounded-control border border-line bg-surface p-2"
						/>
					</label>
					<p className="text-xs text-ink-2">
						{bytes(reference)} /{" "}
						{limits?.expected_output_bytes_max ?? "unknown"} bytes
					</p>
					<label className="block">
						Metadata JSON
						<textarea
							aria-label="Metadata JSON"
							value={meta}
							onChange={(e) => setMeta(e.target.value)}
							rows={4}
							className="mt-2 w-full rounded-control border border-line bg-surface p-2 font-mono"
						/>
					</label>
					<p className="text-xs text-ink-2">
						{bytes(meta)} / {limits?.metadata_bytes_max ?? "unknown"} bytes
					</p>
					{validation && (
						<p role="alert" className="text-danger-ink">
							{validation}
						</p>
					)}
					{error && (
						<p role="alert" className="text-danger-ink">
							{error}
						</p>
					)}
					{!limits && (
						<p role="alert">
							Limits could not be loaded. Reload before saving.
						</p>
					)}
					<Button
						variant="primary"
						disabled={busy || !canWrite || !!validation || !limits}
						onClick={() => void save()}
					>
						{busy ? "Saving…" : "Save"}
					</Button>
					<NewCaseForm
						originalItemId={itemId}
						datasetId={datasetId}
						limits={limits}
						canWrite={canWrite}
						initial={{
							name: name ?? "",
							input,
							system,
							expected_output: reference,
							metadata,
						}}
						label="Duplicate as new case"
					/>
				</div>
			</Dialog>
			<ConfirmDialog
				open={deleting}
				onClose={() => setDeleting(false)}
				onConfirm={() => void remove()}
				title="Delete case"
				busy={busy}
				error={error}
			>
				<p>
					This case leaves the dataset. Frozen snapshots and past experiment
					results are kept. This cannot be undone.
				</p>
			</ConfirmDialog>
		</div>
	);
}
