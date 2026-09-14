"use client";

import { nextFilterParams } from "@/app/traces/filter-params";
import { Button, SegmentedControl, cn } from "@tracelanedev/ui";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";

// Only the dimensions the gateway /v1/traces endpoint genuinely filters on are
// rendered here — no dead chips. status→has_error, model, time→since, latency→
// min_latency_ms, signature_id, q (the §2 read-path dims). provider / cost
// thresholds are V1.1 (need a write-path MV change — not cleanly read-path).

/**
 * OBS-01. Tied to the gateway's own `ngrambf_v1(4, …)` skip index, not a UI
 * preference — `crates/gateway/src/trace_reads.rs` `MIN_SEARCH_TERM` /
 * `validate_search_term`. A shorter term is REJECTED there (400), never
 * silently scanned, so the client-side gate here exists only to avoid firing
 * a request that is guaranteed to 400 — the gateway stays the one place the
 * rule is enforced.
 */
const MIN_SEARCH_TERM = 4;
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
	// OBS-20: URL-derived, not local state — nothing in this bar SETS it.
	const endUser = sp.get("end_user") ?? "";
	const [q, setQ] = useState(sp.get("q") ?? "");
	const searchRef = useRef<HTMLInputElement>(null);

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

	// `q` does NOT debounce-as-typed like model/latency/signature above — it
	// submits on Enter only (OBS-01 §2). Firing a request per keystroke below
	// the 4-char minimum would just accumulate 400s from the gateway; explicit
	// submit is also what lets "type `/`, type a term, press Enter" read as one
	// deliberate action rather than a moving-target debounce.
	//
	// Still resync FROM the URL when it changes out from under us (Clear all,
	// the browser back button, a bare `?q=` typed by hand) — otherwise the box
	// would show stale text after either.
	useEffect(() => {
		setQ(sp.get("q") ?? "");
	}, [sp]);

	// `/` focuses the search box, unless focus is already inside a form control
	// (typing a literal `/` into the model filter must not get hijacked).
	useEffect(() => {
		function onKeyDown(e: KeyboardEvent) {
			if (e.key !== "/") return;
			const el = document.activeElement as HTMLElement | null;
			const tag = el?.tagName;
			if (
				tag === "INPUT" ||
				tag === "TEXTAREA" ||
				tag === "SELECT" ||
				el?.isContentEditable
			) {
				return;
			}
			e.preventDefault();
			searchRef.current?.focus();
		}
		window.addEventListener("keydown", onKeyDown);
		return () => window.removeEventListener("keydown", onKeyDown);
	}, []);

	const qTrimmed = q.trim();
	const qTooShort = qTrimmed.length > 0 && qTrimmed.length < MIN_SEARCH_TERM;

	function submitSearch() {
		if (qTrimmed.length === 0) {
			setParam("q", "");
			return;
		}
		// Below the minimum: the hint is already visible: refuse to submit
		// rather than fire a request the gateway will 400 anyway.
		if (qTooShort) return;
		setParam("q", qTrimmed);
	}

	function handleSearchKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
		if (e.key === "Enter") {
			e.preventDefault();
			submitSearch();
		} else if (e.key === "Escape") {
			setQ("");
			setParam("q", "");
			e.currentTarget.blur();
		}
	}

	// The default 1h range isn't a "custom" filter — only a non-default range
	// counts toward showing "Clear all".
	const active = Boolean(
		status ||
			(range && range !== "1h") ||
			model ||
			latency ||
			signature ||
			sp.get("q") ||
			endUser ||
			group,
	);

	const inputCls =
		"h-8 rounded-lg border border-line bg-surface px-2.5 text-sm text-ink placeholder:text-ink-3 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring";

	return (
		<div className="mb-4 flex flex-wrap items-center gap-2">
			{/* OBS-01 full-text search — span name + attributes, ngram-indexed on the
			    gateway (`crates/gateway/src/trace_reads.rs:1849`). Submits on Enter,
			    not on every keystroke (see the `q` effect above); Esc clears. */}
			<div className="flex flex-col">
				<input
					ref={searchRef}
					type="search"
					value={q}
					onChange={(e) => setQ(e.target.value)}
					onKeyDown={handleSearchKeyDown}
					placeholder="search span names and attributes… (/)"
					aria-label="Search span names and attributes"
					title="Substring match. Case-sensitive, except a plain lowercase term also matches raw case. Minimum 4 characters."
					className={cn(inputCls, "w-64")}
				/>
				{qTooShort && (
					<span className="mt-0.5 text-2xs text-ink-3">
						4 characters minimum
					</span>
				)}
			</div>

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

			{/* OBS-20 — chip only, never an input. You reach this filter by clicking
			    a user on /sessions or on a trace, not by typing an opaque id from
			    memory; an empty text box inviting you to guess one would be a
			    dead chip. Clearable like every other. */}
			{endUser && (
				<FilterChip
					label={`user: ${endUser.length > 16 ? `${endUser.slice(0, 16)}…` : endUser}`}
					onRemove={() => setParam("end_user", "")}
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
						setQ("");
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
