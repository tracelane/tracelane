"use client";

import { nextFilterParams } from "@/app/traces/filter-params";
import { Button, SegmentedControl, cn } from "@tracelanedev/ui";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

// Only the dimensions the gateway /v1/traces endpoint genuinely filters on are
// rendered here — no dead chips. status→has_error, model, time→since, latency→
// min_latency_ms, signature_id (the §2 read-path dims). provider / cost
// thresholds are V1.1 (need a write-path MV change — not cleanly read-path).
const STATUS = [
	{ value: "", label: "All" },
	{ value: "ok", label: "OK" },
	{ value: "error", label: "Error" },
] as const;
const RANGE = [
	{ value: "1h", label: "1h" },
	{ value: "24h", label: "24h" },
	{ value: "7d", label: "7d" },
	{ value: "30d", label: "30d" },
	{ value: "all", label: "All time" },
] as const;
const GROUPS = [
	{ value: "", label: "None" },
	{ value: "model", label: "Model" },
	{ value: "operation", label: "Operation" },
	{ value: "status", label: "Status" },
] as const;

/**
 * Removable chip for an active text filter. Chip fill = `--action-soft`, text =
 * `--ink`.
 *
 * The old note here justified the ink text as "never action-ink — Lava is CTA-only".
 * There is no Lava: `--lava-*` is deleted and `--action-ink` now IS `--ink`, so the
 * two are the same value and the warning describes a distinction the palette no
 * longer draws. What still holds, and is the reason worth keeping, is that a
 * SELECTED filter is not an action — it is a state — so it gets the quiet well fill
 * and body ink rather than any emphasis treatment.
 */
function FilterChip({
	label,
	onRemove,
}: {
	label: string;
	onRemove: () => void;
}) {
	return (
		<span className="inline-flex items-center gap-1 rounded-md border border-action-line bg-action-soft px-2 py-0.5 text-2xs font-semibold text-ink">
			{label}
			<button
				type="button"
				aria-label={`Remove ${label} filter`}
				onClick={onRemove}
				className="ml-0.5 rounded text-ink-3 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
			>
				×
			</button>
		</span>
	);
}

/**
 * Trace-list filter bar. URL-encoded state (shareable, back-button-able);
 * every change resets the keyset cursor and re-runs the server fetch.
 *
 * Status / model / time-range / latency / signature_id each map 1:1 to a real
 * /v1/traces param that reaches the ClickHouse WHERE. Group-by is folded into
 * the same control row (was a separate server-rendered div in page.tsx) and
 * drives the /v1/traces/groups endpoint instead of the list.
 *
 * Active text filters render as removable chips (`--action-soft` fill + `--action-line`
 * border) to match the §4 chip grammar; inputs appear when the filter is clear.
 * Status, range and group are three instances of the shared <SegmentedControl>
 * primitive — they used to be three renders of a local `segment()` helper that
 * painted the active option as a solid ink pill, which is how one filter row
 * ended up carrying five of them.
 */
export function FilterBar() {
	const router = useRouter();
	const pathname = usePathname();
	const sp = useSearchParams();
	const status = sp.get("status") ?? "";
	// No range param defaults to 1h (fast) — the page's rangeSince mirrors this;
	// "All time" is the explicit opt-out (range=all).
	const range = sp.get("range") ?? "1h";
	const group = sp.get("group") ?? "";
	const [model, setModel] = useState(sp.get("model") ?? "");
	const [latency, setLatency] = useState(sp.get("min_latency_ms") ?? "");
	const [signature, setSignature] = useState(sp.get("signature_id") ?? "");

	const setParam = useCallback(
		(key: string, value: string) => {
			// nextFilterParams also clears a stale since/until window when a range
			// PRESET is picked — otherwise the server's `sp.since ?? rangeSince(range)`
			// keeps the old window and the preset shows rows outside the picked range.
			const qs = nextFilterParams(sp, key, value);
			router.replace(qs ? `${pathname}?${qs}` : pathname);
		},
		[sp, pathname, router],
	);

	// debounce the model input → URL (exact match, per the gateway `model = ?`).
	useEffect(() => {
		const id = setTimeout(() => {
			if ((sp.get("model") ?? "") !== model.trim())
				setParam("model", model.trim());
		}, 350);
		return () => clearTimeout(id);
	}, [model, setParam, sp]);

	// debounce the latency floor (ms) → URL; the gateway converts ms → duration_us.
	useEffect(() => {
		const id = setTimeout(() => {
			if ((sp.get("min_latency_ms") ?? "") !== latency.trim())
				setParam("min_latency_ms", latency.trim());
		}, 350);
		return () => clearTimeout(id);
	}, [latency, setParam, sp]);

	// debounce the signature_id filter → URL (tenant-scoped spans subquery, §2).
	useEffect(() => {
		const id = setTimeout(() => {
			if ((sp.get("signature_id") ?? "") !== signature.trim())
				setParam("signature_id", signature.trim());
		}, 350);
		return () => clearTimeout(id);
	}, [signature, setParam, sp]);

	// The default 1h range isn't a "custom" filter — only a non-default range
	// counts toward showing "Clear all".
	const active = Boolean(
		status ||
			(range && range !== "1h") ||
			model ||
			latency ||
			signature ||
			group,
	);

	const inputCls =
		"h-8 rounded-lg border border-line bg-surface px-2.5 text-sm text-ink placeholder:text-ink-3 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring";

	return (
		<div className="mb-4 flex flex-wrap items-center gap-2">
			{/* Status */}
			<SegmentedControl
				label="Trace status"
				value={status}
				options={STATUS}
				onChange={(v) => setParam("status", v)}
			/>

			{/* Time range */}
			<SegmentedControl
				label="Time range"
				value={range}
				options={RANGE}
				onChange={(v) => setParam("range", v)}
			/>

			{/* Model — chip when active, input when clear */}
			{model ? (
				<FilterChip
					label={`model: ${model}`}
					onRemove={() => {
						setModel("");
						setParam("model", "");
					}}
				/>
			) : (
				<input
					value={model}
					onChange={(e) => setModel(e.target.value)}
					placeholder="model (exact)…"
					aria-label="Filter by model"
					className={cn(inputCls, "w-44")}
				/>
			)}

			{/* Latency floor — chip when active, input when clear */}
			{latency ? (
				<FilterChip
					label={`latency ≥ ${latency}ms`}
					onRemove={() => {
						setLatency("");
						setParam("min_latency_ms", "");
					}}
				/>
			) : (
				<input
					type="number"
					min={0}
					inputMode="numeric"
					value={latency}
					onChange={(e) => setLatency(e.target.value)}
					placeholder="latency ≥ ms"
					aria-label="Filter by minimum latency in milliseconds"
					className={cn(inputCls, "w-32")}
				/>
			)}

			{/* Signature ID — chip when active, input when clear */}
			{signature ? (
				<FilterChip
					label={`sig: ${signature.length > 12 ? `${signature.slice(0, 12)}…` : signature}`}
					onRemove={() => {
						setSignature("");
						setParam("signature_id", "");
					}}
				/>
			) : (
				<input
					value={signature}
					onChange={(e) => setSignature(e.target.value)}
					placeholder="signature id…"
					aria-label="Filter by failure-signature id"
					className={cn(inputCls, "w-44")}
				/>
			)}

			{active && (
				<Button
					variant="ghost"
					size="sm"
					onClick={() => {
						setModel("");
						setLatency("");
						setSignature("");
						router.replace(pathname);
					}}
				>
					Clear all
				</Button>
			)}

			{/*
			 * The hairline separator that used to sit HERE is deleted. It marked the
			 * boundary between the filters and the group control while both were on one
			 * line — but the row wraps, and once the group control moved to line two the
			 * separator was stranded as a floating tick at the right end of line one,
			 * dividing nothing from nothing. A separator that survives the wrap of the
			 * thing it separates is worse than none, and the wrap is now the boundary.
			 */}

			{/*
			 * Group-by. THE LABEL AND ITS CONTROL ARE ONE FLEX ITEM, and that is a
			 * layout fix, not decoration: as two siblings in the wrapping row they
			 * were separable, and at 1440px the row broke exactly between them —
			 * "Group" stranded at the right end of line one, its segments at the left
			 * end of line two, reading as a heading for the wrong thing. Wrapping the
			 * pair in its own `inline-flex` makes them wrap TOGETHER or not at all.
			 * Found by rendering the page; the JSX looked fine.
			 */}
			<span className="inline-flex items-center gap-2">
				<span className="t-metric-label">Group</span>
				<SegmentedControl
					label="Group by"
					value={group}
					options={GROUPS}
					onChange={(v) => setParam("group", v)}
				/>
			</span>
		</div>
	);
}
