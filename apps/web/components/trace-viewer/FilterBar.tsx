"use client";

import { Button, cn } from "@tracelanedev/ui";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

// Only the dimensions the gateway /v1/traces endpoint genuinely filters on are
// rendered here — no dead chips. status→has_error, model, time→since, latency→
// min_latency_ms, signature_id (the §2 read-path dims). provider / cost
// thresholds are V1.1 (need a write-path MV change — not cleanly read-path).
const STATUS = [
	{ v: "", l: "All" },
	{ v: "ok", l: "OK" },
	{ v: "error", l: "Error" },
] as const;
const RANGE = [
	{ v: "1h", l: "1h" },
	{ v: "24h", l: "24h" },
	{ v: "7d", l: "7d" },
	{ v: "30d", l: "30d" },
	{ v: "all", l: "All time" },
] as const;
const GROUPS = [
	{ v: "", l: "None" },
	{ v: "model", l: "Model" },
	{ v: "operation", l: "Operation" },
	{ v: "status", l: "Status" },
] as const;

/**
 * Removable chip for an active text filter. Chip bg = accent-soft (per the
 * design-system "chip bg" token role); text = ink (never accent-ink — Lava is
 * CTA-only, not a selected-state color).
 */
function FilterChip({
	label,
	onRemove,
}: {
	label: string;
	onRemove: () => void;
}) {
	return (
		<span className="inline-flex items-center gap-1 rounded-md border border-accent-line bg-accent-soft px-2 py-0.5 text-[11px] font-semibold text-ink">
			{label}
			<button
				type="button"
				aria-label={`Remove ${label} filter`}
				onClick={onRemove}
				className="ml-0.5 rounded text-ink-3 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
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
 * Active text filters render as removable chips (accent-soft bg + accent-line
 * border) to match the §4 chip grammar; inputs appear when the filter is clear.
 * Segment controls (status, range, group) show their active option inline.
 */
export function FilterBar() {
	const router = useRouter();
	const pathname = usePathname();
	const sp = useSearchParams();
	const status = sp.get("status") ?? "";
	// No range param defaults to 24h (fast) — the page's rangeSince mirrors this;
	// "All time" is the explicit opt-out (range=all).
	const range = sp.get("range") ?? "24h";
	const group = sp.get("group") ?? "";
	const [model, setModel] = useState(sp.get("model") ?? "");
	const [latency, setLatency] = useState(sp.get("min_latency_ms") ?? "");
	const [signature, setSignature] = useState(sp.get("signature_id") ?? "");

	const setParam = useCallback(
		(key: string, value: string) => {
			const next = new URLSearchParams(sp.toString());
			if (value) next.set(key, value);
			else next.delete(key);
			next.delete("cursor"); // any filter change resets pagination
			const qs = next.toString();
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

	/**
	 * Segment control — a pill-group where one option is active. Active option
	 * gets accent-soft bg with ink text (NOT accent-ink text — Lava is CTA only,
	 * not a selected-state color).
	 */
	const segment = (
		key: string,
		current: string,
		opts: ReadonlyArray<{ v: string; l: string }>,
	) => (
		<div className="inline-flex rounded-lg border border-line bg-surface p-0.5">
			{opts.map((o) => (
				<button
					key={o.v || "all"}
					type="button"
					onClick={() => setParam(key, o.v)}
					className={cn(
						"rounded-md px-2.5 py-1 text-[12.5px] transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal",
						current === o.v
							? "bg-accent-soft text-ink"
							: "text-ink-2 hover:text-ink",
					)}
				>
					{o.l}
				</button>
			))}
		</div>
	);

	// The default 24h range isn't a "custom" filter — only a non-default range
	// counts toward showing "Clear all".
	const active = Boolean(
		status ||
			(range && range !== "24h") ||
			model ||
			latency ||
			signature ||
			group,
	);

	const inputCls =
		"h-8 rounded-lg border border-line bg-surface px-2.5 text-[13px] text-ink outline-none placeholder:text-ink-3 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal";

	return (
		<div className="mb-4 flex flex-wrap items-center gap-2">
			{/* Status */}
			{segment("status", status, STATUS)}

			{/* Time range */}
			{segment("range", range, RANGE)}

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

			{/* Visual separator before group control */}
			<span className="mx-1 h-4 w-px bg-line" aria-hidden="true" />

			{/* Group by — folded into the same control row (was a separate div in page.tsx) */}
			<span className="text-[10px] font-semibold uppercase tracking-wide text-ink-3">
				Group
			</span>
			{segment("group", group, GROUPS)}
		</div>
	);
}
