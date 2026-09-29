"use client";
import { useObjectCommands } from "@/components/command-palette/object-commands";
import { apiFetchRaw } from "@/lib/api-fetch";
import { Button, Dialog } from "@tracelanedev/ui";
import { useRouter } from "next/navigation";
import { useRef, useState } from "react";
import {
	type DatasetLimits,
	type ImportResult,
	bytes,
	datasetResponse,
	ownerReason,
	parseMetadata,
} from "../management";
export function NewCaseForm({
	datasetId,
	limits,
	canWrite,
	initial,
	originalItemId,
	label = "New case",
}: {
	datasetId: string;
	limits?: DatasetLimits;
	canWrite: boolean;
	initial?: {
		name: string;
		input: unknown;
		system?: unknown;
		expected_output: string;
		metadata: Record<string, unknown>;
	};
	label?: string;
	originalItemId?: string;
}) {
	const trigger = useRef<HTMLButtonElement>(null);
	useObjectCommands(
		canWrite && !!limits && !originalItemId
			? [
					{
						id: "dataset-new-case",
						label: "New case",
						href: "",
						group: "action",
						onSelect: () => trigger.current?.click(),
					},
				]
			: [],
	);
	const router = useRouter();
	const [deleteOriginal, setDeleteOriginal] = useState(false);
	const [deleteResult, setDeleteResult] = useState("");
	const [open, setOpen] = useState(false);
	const [name, setName] = useState(initial?.name ?? "");
	const [input, setInput] = useState(
		JSON.stringify(initial?.input ?? [{ role: "user", content: "" }], null, 2),
	);
	const [system, setSystem] = useState(JSON.stringify(initial?.system ?? null));
	const [reference, setReference] = useState(initial?.expected_output ?? "");
	const [metadata, setMetadata] = useState(
		JSON.stringify(initial?.metadata ?? {}, null, 2),
	);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [result, setResult] = useState<ImportResult | null>(null);
	async function submit() {
		if (busy || !canWrite || !limits) return;
		setError("");
		try {
			const messages = JSON.parse(input);
			if (!Array.isArray(messages) || messages.length === 0)
				throw new Error("Input must be a non-empty messages array.");
			const sys = JSON.parse(system);
			const meta = parseMetadata(metadata);
			if (bytes(input) + bytes(system) > limits.item_input_bytes_max)
				throw new Error("Input and system exceed the byte limit.");
			if (
				bytes(reference) > limits.expected_output_bytes_max ||
				bytes(metadata) > limits.metadata_bytes_max
			)
				throw new Error("Reference or metadata exceeds the byte limit.");
			setBusy(true);
			const body = JSON.stringify({
				name,
				input: messages,
				system: sys,
				expected_output: reference || null,
				metadata: meta,
			});
			const r = await datasetResponse<ImportResult>(
				await apiFetchRaw(
					`/api/datasets/${encodeURIComponent(datasetId)}/import?format=jsonl`,
					{
						method: "POST",
						headers: { "content-type": "application/x-ndjson" },
						body,
					},
				),
			);
			setResult(r);
			if (deleteOriginal && originalItemId && r.added > 0) {
				try {
					await datasetResponse(
						await apiFetchRaw(
							`/api/datasets/${encodeURIComponent(datasetId)}/items/${encodeURIComponent(originalItemId)}`,
							{ method: "DELETE" },
						),
					);
					setDeleteResult("Original case deleted.");
				} catch (e) {
					setDeleteResult(
						`New case added; original was not deleted: ${e instanceof Error ? e.message : "request failed"}`,
					);
				}
			} else if (deleteOriginal)
				setDeleteResult("Original kept because no new case was added.");
			router.refresh();
		} catch (e) {
			setError(e instanceof Error ? e.message : "Could not add case. Retry.");
		} finally {
			setBusy(false);
		}
	}
	const field =
		"mt-1 w-full rounded-control border border-line bg-surface p-2 text-sm";
	return (
		<>
			<Button
				ref={trigger}
				disabled={!canWrite || !limits}
				title={
					!canWrite ? ownerReason : !limits ? "Limits unavailable" : undefined
				}
				onClick={() => {
					setOpen(true);
					setResult(null);
					setError("");
				}}
			>
				{label}
			</Button>
			<Dialog
				open={open}
				drawer
				title={label}
				onClose={() => setOpen(false)}
				busy={busy}
			>
				<form
					className="space-y-3"
					onSubmit={(e) => {
						e.preventDefault();
						void submit();
					}}
				>
					<label className="block">
						Case name
						<input
							className={field}
							value={name}
							onChange={(e) => setName(e.target.value)}
						/>
					</label>
					<label className="block">
						Input messages JSON
						<textarea
							className={field}
							rows={6}
							value={input}
							onChange={(e) => setInput(e.target.value)}
						/>
					</label>
					<label className="block">
						System JSON
						<textarea
							className={field}
							value={system}
							onChange={(e) => setSystem(e.target.value)}
						/>
					</label>
					<label className="block">
						Reference answer
						<textarea
							className={field}
							value={reference}
							onChange={(e) => setReference(e.target.value)}
						/>
					</label>
					<label className="block">
						Case metadata JSON
						<textarea
							className={field}
							value={metadata}
							onChange={(e) => setMetadata(e.target.value)}
						/>
					</label>
					{originalItemId && (
						<label className="flex gap-2">
							<input
								type="checkbox"
								checked={deleteOriginal}
								onChange={(e) => setDeleteOriginal(e.target.checked)}
							/>
							Then delete the original case (cannot be undone)
						</label>
					)}
					{deleteResult && <p aria-live="polite">{deleteResult}</p>}
					{error && (
						<p role="alert" className="text-danger-ink">
							{error}
						</p>
					)}
					{result && (
						<div aria-live="polite">
							{result.added === 0 && result.deduped === 1
								? "No change — an identical case already exists"
								: `Added ${result.added} · Already present ${result.deduped} · Rejected ${result.rejected_count}`}
							<ul>
								{result.rejected.map((r) => (
									<li key={r.line}>{r.reason}</li>
								))}
							</ul>
						</div>
					)}
					<Button type="submit" variant="primary" disabled={busy}>
						{busy ? "Adding…" : "Add case"}
					</Button>
				</form>
			</Dialog>
		</>
	);
}
