"use client";
import { Modal } from "@/components/Modal";
import { useObjectCommands } from "@/components/command-palette/object-commands";
import { apiFetchRaw } from "@/lib/api-fetch";
import { useInputCapture } from "@/lib/use-input-capture";
import { Button } from "@tracelanedev/ui";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useId, useState } from "react";
import { CaptureNotice } from "./CaptureNotice";

type Dataset = { dataset_id: string; name: string };
async function response(res: Response) {
	const data = await res.json();
	if (!res.ok)
		throw new Error(
			data.message ?? data.error ?? `Request refused (${res.status})`,
		);
	return data;
}
export function DatasetAction({
	traceId,
	spanId,
	primary = false,
	contentUnavailable = false,
}: {
	traceId?: string;
	spanId?: string;
	primary?: boolean;
	contentUnavailable?: boolean;
}) {
	const router = useRouter();
	const captureOff = useInputCapture(Boolean(traceId)) === false;
	const id = useId();
	const [open, setOpen] = useState(false);
	const [datasets, setDatasets] = useState<Dataset[]>([]);
	const [cursor, setCursor] = useState<string | null>(null);
	const [selected, setSelected] = useState("");
	const [name, setName] = useState("");
	const [loading, setLoading] = useState(false);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [success, setSuccess] = useState<Dataset | null>(null);
	async function load(next?: string) {
		setLoading(true);
		setError("");
		try {
			const data = await response(
				await apiFetchRaw(
					next
						? `/api/datasets?cursor=${encodeURIComponent(next)}`
						: "/api/datasets",
				),
			);
			setDatasets((old) => (next ? [...old, ...data.datasets] : data.datasets));
			setCursor(data.next_cursor);
		} catch (e) {
			setError(e instanceof Error ? e.message : "Could not load datasets.");
		} finally {
			setLoading(false);
		}
	}
	async function submit(e: React.FormEvent) {
		e.preventDefault();
		if (captureOff || busy) return;
		setBusy(true);
		setError("");
		try {
			let target = datasets.find((d) => d.dataset_id === selected);
			if (!target) {
				const created = await response(
					await apiFetchRaw("/api/datasets", {
						method: "POST",
						headers: { "content-type": "application/json" },
						body: JSON.stringify({ name: name.trim() }),
					}),
				);
				target = { dataset_id: created.dataset_id, name: name.trim() };
				// Keep the created dataset selected if copying fails: retry must not create another.
				setDatasets((old) => [...old, target as Dataset]);
				setSelected(target.dataset_id);
			}
			if (traceId && spanId) {
				// The caller already picked the span — unambiguous, single-item route.
				await response(
					await apiFetchRaw(
						`/api/datasets/${encodeURIComponent(target.dataset_id)}/items`,
						{
							method: "POST",
							headers: { "content-type": "application/json" },
							body: JSON.stringify({ trace_id: traceId, span_id: spanId }),
						},
					),
				);
			} else if (traceId) {
				// `OBS-56` S4 — the trace-header case (no span). B-582: the single-item
				// route requires span_id and this button used to send `{trace_id}`
				// alone, so it could only ever 400 `span_id_required` and was removed.
				// The batch route resolves the trace's ONE content-bearing span
				// server-side, refusing rather than guessing when there isn't exactly
				// one — the same discipline the single-item route already holds.
				const result = await response(
					await apiFetchRaw(
						`/api/datasets/${encodeURIComponent(target.dataset_id)}/items/batch`,
						{
							method: "POST",
							headers: { "content-type": "application/json" },
							body: JSON.stringify({ traces: [{ trace_id: traceId }] }),
						},
					),
				);
				if (result.added === 0 && result.deduped === 0) {
					throw new Error(
						result.refused?.[0]?.message ?? "Could not add this trace.",
					);
				}
			}
			setSuccess(target);
			setOpen(false);
			router.refresh();
		} catch (e) {
			setError(e instanceof Error ? e.message : "Could not save dataset.");
		} finally {
			setBusy(false);
		}
	}
	function showDialog() {
		setOpen(true);
		setError("");
		setSuccess(null);
		if (traceId) void load();
	}
	useObjectCommands(
		traceId
			? [
					{
						id: spanId ? "span-add-dataset" : "trace-add-dataset",
						label: spanId ? "Add selected span to dataset" : "Add to dataset",
						href: "",
						group: "action",
						onSelect: showDialog,
					},
				]
			: [],
	);
	return (
		<>
			<Button
				variant={primary && !captureOff ? "primary" : "secondary"}
				type="button"
				size="sm"
				onClick={showDialog}
			>
				{traceId ? "Add to dataset" : "New dataset"}
			</Button>
			{success && (
				<output>
					{traceId ? "Case saved in " : "Created "}
					<Link className="underline" href={`/datasets/${success.dataset_id}`}>
						{success.name}
					</Link>
				</output>
			)}
			{open && (
				<Modal
					title={traceId ? "Add to dataset" : "New dataset"}
					onClose={() => {
						if (!busy) setOpen(false);
					}}
					dismissable={!busy}
				>
					<form className="space-y-4" onSubmit={submit}>
						{captureOff && <CaptureNotice />}
						{!captureOff && contentUnavailable && (
							<p className="text-sm text-ink-2">
								This turn has no prompt text available to copy. The gateway will
								check whether the selected trace has recorded input.
							</p>
						)}
						{traceId && (
							<>
								<p className="text-sm text-ink-2">
									Copies recorded input from{" "}
									{spanId
										? "this span"
										: "a content-bearing span in this trace"}
									. Expected output is not captured; add a reviewed reference in
									the review workflow.
								</p>
								<label className="block" htmlFor={`${id}-dataset`}>
									Dataset
								</label>
								<select
									className="w-full border border-line bg-surface p-2"
									id={`${id}-dataset`}
									value={selected}
									onChange={(e) => setSelected(e.target.value)}
									disabled={busy || loading}
								>
									<option value="">Create new dataset</option>
									{datasets.map((d) => (
										<option key={d.dataset_id} value={d.dataset_id}>
											{d.name}
										</option>
									))}
								</select>
								{loading && <output>Loading datasets…</output>}
								{cursor && (
									<Button
										type="button"
										variant="ghost"
										disabled={loading || busy}
										onClick={() => void load(cursor)}
									>
										Load more datasets
									</Button>
								)}
							</>
						)}
						{!selected && (
							<>
								<label className="block" htmlFor={`${id}-name`}>
									Dataset name
								</label>
								<input
									className="w-full border border-line bg-surface p-2"
									id={`${id}-name`}
									required
									value={name}
									disabled={busy}
									onChange={(e) => setName(e.target.value)}
								/>
							</>
						)}
						{error && <p role="alert">{error}</p>}
						<Button
							type="submit"
							disabled={
								captureOff || busy || loading || (!selected && !name.trim())
							}
						>
							{busy ? "Saving…" : traceId ? "Save case" : "Create dataset"}
						</Button>
						<Button
							type="button"
							variant="ghost"
							disabled={busy}
							onClick={() => setOpen(false)}
						>
							Cancel
						</Button>
					</form>
				</Modal>
			)}
		</>
	);
}
