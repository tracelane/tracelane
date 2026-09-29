"use client";
import { useObjectCommands } from "@/components/command-palette/object-commands";
import { downloadText } from "@/components/trace-viewer/TraceBulkBar";
import { apiFetchRaw } from "@/lib/api-fetch";
import { fmtBytes, fmtCount } from "@/lib/metrics/format";
import { Button, Dialog } from "@tracelanedev/ui";
import { useRouter } from "next/navigation";
import { useRef, useState } from "react";
import {
	type DatasetLimits,
	type ImportResult,
	datasetResponse,
	ownerReason,
} from "../management";
export function ImportJsonlForm({
	datasetId,
	limits,
	items,
	canWrite = false,
}: {
	datasetId: string;
	limits?: DatasetLimits;
	items?: number | null;
	canWrite?: boolean;
}) {
	const trigger = useRef<HTMLButtonElement>(null);
	useObjectCommands(
		canWrite && !!limits
			? [
					{
						id: "dataset-import",
						label: "Import JSONL",
						href: "",
						group: "action",
						onSelect: () => trigger.current?.click(),
					},
				]
			: [],
	);
	const router = useRouter();
	const [open, setOpen] = useState(false);
	const [file, setFile] = useState<{
		name: string;
		size: number;
		text: string;
		lines: number;
	} | null>(null);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [result, setResult] = useState<ImportResult | null>(null);
	const headroom =
		items == null || !limits ? null : Math.max(0, limits.items_max - items);
	const refusal =
		file && limits
			? file.size > limits.import_bytes_max
				? `File is ${fmtBytes(file.size)}; limit is ${fmtBytes(limits.import_bytes_max)}.`
				: headroom !== null && file.lines > headroom
					? `This file has ${fmtCount(file.lines)} cases; ${fmtCount(headroom)} slots left.`
					: null
			: null;
	async function submit() {
		if (busy || !file || refusal || !canWrite || !limits) return;
		setBusy(true);
		setError("");
		try {
			const data = await datasetResponse<ImportResult>(
				await apiFetchRaw(
					`/api/datasets/${encodeURIComponent(datasetId)}/import?format=jsonl`,
					{
						method: "POST",
						headers: { "content-type": "application/x-ndjson" },
						body: file.text,
					},
				),
			);
			setResult(data);
			setFile(null);
			router.refresh();
		} catch (e) {
			setError(e instanceof Error ? e.message : "Could not import. Retry.");
		} finally {
			setBusy(false);
		}
	}
	return (
		<>
			<Button
				ref={trigger}
				disabled={!canWrite || !limits}
				title={!canWrite ? ownerReason : undefined}
				onClick={() => setOpen(true)}
			>
				Import JSONL
			</Button>
			<Dialog
				open={open}
				onClose={() => setOpen(false)}
				title="Import JSONL"
				busy={busy}
			>
				<div className="space-y-4">
					<label className="block">
						JSONL file
						<input
							type="file"
							accept=".jsonl,application/x-ndjson,text/plain"
							disabled={busy}
							onChange={async (e) => {
								const chosen = e.target.files?.[0];
								setResult(null);
								setError("");
								setFile(null);
								if (!chosen) return;
								if (limits && chosen.size > limits.import_bytes_max) {
									setError(
										`File is ${fmtBytes(chosen.size)}; limit is ${fmtBytes(limits.import_bytes_max)}.`,
									);
									return;
								}
								try {
									const text = (await chosen.text()).replace(/^\uFEFF/, "");
									setFile({
										name: chosen.name,
										size: chosen.size,
										text,
										lines: text.split(/\r?\n/).filter((line) => line.trim())
											.length,
									});
								} catch {
									setError("Could not read this file.");
								}
							}}
						/>
					</label>
					{file && (
						<p>
							{file.name} · {fmtBytes(file.size)} · {fmtCount(file.lines)}{" "}
							non-blank lines ·{" "}
							{headroom == null ? "unknown" : fmtCount(headroom)} slots left
						</p>
					)}
					{refusal && (
						<p role="alert" className="text-danger-ink">
							Nothing was imported. {refusal}
						</p>
					)}
					{error && (
						<p role="alert" className="text-danger-ink">
							{error}
						</p>
					)}
					<Button
						variant="primary"
						disabled={busy || !file || !!refusal}
						onClick={() => void submit()}
					>
						{busy ? "Importing…" : "Import"}
					</Button>
					{result && (
						<div aria-live="polite">
							<p>
								Added {result.added} · Already present {result.deduped} ·
								Rejected {result.rejected_count}
							</p>
							{result.rejected.length > 0 && (
								<>
									<ul className="my-3 space-y-2">
										{result.rejected.map((r) => (
											<li key={r.line}>
												Line {r.line}: {r.reason}
											</li>
										))}
									</ul>
									<Button
										onClick={() =>
											downloadText(
												result.rejected
													.map((r) => `Line ${r.line}: ${r.reason}`)
													.join("\n"),
												"rejected-lines.txt",
												"text/plain",
											)
										}
									>
										Download rejected lines
									</Button>
								</>
							)}
						</div>
					)}
				</div>
			</Dialog>
		</>
	);
}
