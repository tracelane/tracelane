"use client";
import { CaptureNotice } from "@/app/datasets/CaptureNotice";
import { ownerReason } from "@/app/datasets/management";
import { type BatchAnnotationLabel, flagTracesBatch } from "@/lib/annotations";
import { ApiError, apiFetchRaw } from "@/lib/api-fetch";
import { useInputCapture } from "@/lib/use-input-capture";
import { Button, Dialog } from "@tracelanedev/ui";
import { type ReactNode, useState } from "react";
import { bulkRefusal, traceRefusals } from "./bulk-refusals";
type Refusal = { trace_id: string; reason: string; message?: string };
type Dataset = { dataset_id: string; name: string };
export function BulkTraceWrites({
	ids,
	viewerRole,
	onSelection,
	onBusy,
	children,
}: {
	children?: ReactNode;
	ids: string[];
	viewerRole?: string | null;
	onSelection: (ids: string[]) => void;
	onBusy: (busy: boolean) => void;
}) {
	const [mode, setMode] = useState<"flag" | "dataset" | null>(null);
	const [busy, setBusy] = useState(false);
	const [loading, setLoading] = useState(false);
	const [label, setLabel] = useState<BatchAnnotationLabel>("bad");
	const [note, setNote] = useState("");
	const [datasets, setDatasets] = useState<Dataset[]>([]);
	const [cursor, setCursor] = useState<string | null>(null);
	const [dataset, setDataset] = useState("");
	const [headroom, setHeadroom] = useState<number | null>(null);
	const [name, setName] = useState("");
	const [error, setError] = useState("");
	const [result, setResult] = useState<{
		text: string;
		refused: Refusal[];
	} | null>(null);
	const owner = viewerRole === "owner" || viewerRole === "admin";
	const captureOff = useInputCapture(owner && ids.length > 0) === false;
	const canFlag = owner || viewerRole === "member";
	function lock(value: boolean) {
		setBusy(value);
		onBusy(value);
	}
	async function response(res: Response) {
		const data = await res.json();
		if (!res.ok) {
			const refusal = bulkRefusal(data.error, data.max);
			if (refusal) throw new Error(refusal);
			if (data.error === "entitlement_required")
				throw new Error(
					"Datasets aren't included in this plan. See plans in Settings → Billing.",
				);
			if (res.status === 403) throw new Error(ownerReason);
			throw new Error(
				data.message ?? data.error ?? "Could not load datasets. Retry.",
			);
		}
		return data;
	}
	async function loadDatasets(next?: string) {
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
			setCursor(data.next_cursor ?? null);
		} catch (e) {
			setError(
				e instanceof Error ? e.message : "Could not load datasets. Retry.",
			);
		} finally {
			setLoading(false);
		}
	}
	async function choose(id: string) {
		setDataset(id);
		setHeadroom(null);
		if (!id) return;
		setLoading(true);
		setError("");
		try {
			const data = await response(
				await apiFetchRaw(`/api/datasets/${encodeURIComponent(id)}`),
			);
			setHeadroom(
				typeof data.items === "number" &&
					typeof data.limits?.items_max === "number"
					? Math.max(0, data.limits.items_max - data.items)
					: null,
			);
		} catch (e) {
			setError(
				e instanceof Error ? `${e.message} Slots unknown.` : "Slots unknown.",
			);
		} finally {
			setLoading(false);
		}
	}
	async function create() {
		if (captureOff || busy || !name.trim()) return;
		lock(true);
		setError("");
		try {
			const data = await response(
				await apiFetchRaw("/api/datasets", {
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify({ name: name.trim() }),
				}),
			);
			setDatasets((old) => [...old, data]);
			setName("");
			await choose(data.dataset_id);
		} catch (e) {
			setError(
				e instanceof Error ? e.message : "Could not create dataset. Retry.",
			);
		} finally {
			lock(false);
		}
	}
	async function submit() {
		if (busy || (mode === "dataset" && captureOff)) return;
		lock(true);
		setError("");
		try {
			if (mode === "flag") {
				const data = await flagTracesBatch(ids, label, note);
				setResult({
					text: `Flagged ${data.written} · Refused ${data.refused.length}`,
					refused: data.refused,
				});
				onSelection(data.refused.map((r) => r.trace_id));
			} else {
				const res = await apiFetchRaw(
					`/api/datasets/${encodeURIComponent(dataset)}/items/batch`,
					{
						method: "POST",
						headers: { "content-type": "application/json" },
						body: JSON.stringify({
							traces: ids.map((trace_id) => ({ trace_id })),
						}),
					},
				);
				const data = await res.json();
				if (!res.ok) {
					const refusal = bulkRefusal(data.error, data.max);
					if (refusal) throw new Error(refusal);
					if (res.status === 422)
						throw new Error(
							"Nothing was added — this workspace does not record prompt text",
						);
					if (data.error === "dataset_full")
						throw new Error(
							`Nothing was added — ${ids.length} selected, ${data.headroom} slots left`,
						);
					if (data.error === "entitlement_required")
						throw new Error(
							"Datasets aren't included in this plan. See plans in Settings → Billing.",
						);
					if (res.status === 403) throw new Error(ownerReason);
					throw new Error(
						res.status >= 500
							? "Nothing was changed — the service did not answer. Retry."
							: (data.message ??
									data.error ??
									`Request refused (${res.status})`),
					);
				}
				setResult({
					text: `Added ${data.added} · Already in dataset ${data.deduped} · Refused ${data.refused_count}`,
					refused: data.refused,
				});
				onSelection(data.refused.map((r: Refusal) => r.trace_id));
			}
			setMode(null);
		} catch (e) {
			setError(
				e instanceof ApiError && bulkRefusal(e.message, e.body?.max)
					? (bulkRefusal(e.message, e.body?.max) ?? "Request refused. Retry.")
					: e instanceof ApiError && e.status === 403
						? "Viewers can't flag traces"
						: e instanceof ApiError && e.status >= 500
							? "Nothing was changed — the service did not answer. Retry."
							: e instanceof Error
								? e.message
								: "Nothing was changed — the service did not answer. Retry.",
			);
		} finally {
			lock(false);
		}
	}
	return (
		<>
			{ids.length > 0 && (
				<div
					aria-label="Selected trace actions"
					className="sticky bottom-3 z-20 m-3 flex flex-wrap items-center gap-2 rounded-control border border-line-2 bg-surface p-3 shadow-overlay"
				>
					{children}
					<Button
						disabled={busy || !canFlag}
						title={!canFlag ? "Viewers can't flag traces" : undefined}
						onClick={() => {
							setError("");
							setMode("flag");
						}}
					>
						Flag selected
					</Button>
					<Button
						disabled={busy || !owner}
						title={!owner ? ownerReason : undefined}
						onClick={() => {
							setError("");
							setMode("dataset");
							setDataset("");
							setHeadroom(null);
							void loadDatasets();
						}}
					>
						Add selected to dataset
					</Button>
				</div>
			)}
			{result && (
				<section
					aria-live="polite"
					className="m-3 space-y-2 rounded-card border border-line bg-surface p-4"
				>
					<div className="flex items-center justify-between">
						<p className="font-semibold">{result.text}</p>
						<Button variant="ghost" onClick={() => setResult(null)}>
							Dismiss result
						</Button>
					</div>
					{result.refused.length > 0 && (
						<details open>
							<summary>Refused traces</summary>
							<ul className="space-y-2 pt-2">
								{result.refused.map((r) => (
									<li key={r.trace_id} className="text-sm">
										<a
											className="underline"
											href={`/traces/${encodeURIComponent(r.trace_id)}`}
										>
											{r.trace_id}
										</a>{" "}
										—{" "}
										{traceRefusals[r.reason] ??
											"This trace could not be processed. Retry or open the trace for details."}
										{!traceRefusals[r.reason] && (
											<small className="block text-ink-2">
												Code: {r.reason}
											</small>
										)}
									</li>
								))}
							</ul>
						</details>
					)}
				</section>
			)}
			<Dialog
				open={mode !== null}
				title={
					mode === "flag" ? "Flag selected traces" : "Add traces to dataset"
				}
				onClose={() => setMode(null)}
				busy={busy}
			>
				<div className="space-y-4">
					{mode === "dataset" && captureOff && <CaptureNotice />}
					<p className="text-sm">
						{ids.length} selected
						{mode === "dataset"
							? headroom === null
								? " · slots unknown"
								: ` · ${headroom} slots left`
							: ""}
					</p>
					{mode === "flag" ? (
						<>
							<label className="block">
								Flag
								<select
									className="ml-3 rounded-control border border-line bg-surface p-2"
									value={label}
									onChange={(e) =>
										setLabel(e.target.value as BatchAnnotationLabel)
									}
									disabled={busy}
								>
									{["good", "bad", "needs_review"].map((value) => (
										<option key={value} value={value}>
											{value.replaceAll("_", " ")}
										</option>
									))}
								</select>
							</label>
							<label className="block">
								Note (optional)
								<textarea
									className="mt-2 w-full rounded-control border border-line bg-surface p-2"
									value={note}
									onChange={(e) => setNote(e.target.value)}
									disabled={busy}
								/>
							</label>
						</>
					) : (
						<>
							<label className="block">
								Dataset
								<select
									className="mt-2 w-full rounded-control border border-line bg-surface p-2"
									value={dataset}
									disabled={busy || loading}
									onChange={(e) => void choose(e.target.value)}
								>
									<option value="">Choose a dataset</option>
									{datasets.map((d) => (
										<option key={d.dataset_id} value={d.dataset_id}>
											{d.name}
										</option>
									))}
								</select>
							</label>
							{loading && <p aria-live="polite">Loading datasets…</p>}
							{cursor && (
								<Button
									disabled={loading || busy}
									onClick={() => void loadDatasets(cursor)}
								>
									More datasets
								</Button>
							)}
							<details>
								<summary>Create a dataset</summary>
								<label className="block">
									New dataset name
									<input
										className="mt-2 w-full rounded-control border border-line bg-surface p-2"
										value={name}
										onChange={(e) => setName(e.target.value)}
										disabled={busy}
									/>
								</label>
								<Button
									disabled={captureOff || busy || !name.trim()}
									onClick={() => void create()}
								>
									Create dataset
								</Button>
							</details>
							{headroom !== null && ids.length > headroom && (
								<p className="text-warn-ink">
									Nothing will be added — select fewer traces or choose a
									dataset with enough slots.
								</p>
							)}
						</>
					)}
					{error && (
						<p role="alert" className="text-danger-ink">
							{error}
						</p>
					)}
					{mode === "dataset" && error && (
						<Button
							disabled={busy || loading}
							onClick={() => void loadDatasets()}
						>
							Retry datasets
						</Button>
					)}
					<Button
						variant="primary"
						disabled={
							busy ||
							loading ||
							(mode === "dataset" &&
								(captureOff ||
									!dataset ||
									(headroom !== null && ids.length > headroom)))
						}
						onClick={() => void submit()}
					>
						{busy ? "Working…" : mode === "flag" ? "Apply flag" : "Add traces"}
					</Button>
				</div>
			</Dialog>
		</>
	);
}
