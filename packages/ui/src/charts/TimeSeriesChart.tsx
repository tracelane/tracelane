"use client";

import {
	type KeyboardEvent,
	type PointerEvent,
	useCallback,
	useEffect,
	useId,
	useMemo,
	useRef,
	useState,
} from "react";
import { cn } from "../lib/cn";
import { fmtDurMs } from "../lib/fmt-dur";
import { TimeRuler } from "../signature/TimeRuler";

/**
 * TimeSeriesChart — the ONE interactive time-series chart (DSH-11 §3b).
 *
 * Bars per bucket, one to three series, a hover crosshair with a tooltip that
 * states the bucket's UTC bounds and every visible series' exact value, keyboard
 * navigation, a legend that toggles series, click-through on a bucket, and
 * brush-to-zoom that hands the caller a `[since, until)` snapped to bucket edges.
 * The shared `TimeRuler` is its x-axis, inset to the plot, so the app keeps ONE
 * time axis (ADR-074 §7).
 *
 * WHAT IT REPLACES AND WHY. `Lollipop`, `LatencyTimeline` and `BarChart` were
 * server-rendered SVGs stretched with `preserveAspectRatio="none"`, so every axis
 * label was distorted at any width but the viewBox's, their only hover detail was a
 * native `<title>`, and only one of the three could be clicked. This component is
 * measured in PIXELS (`ResizeObserver`) and draws text in DOM units, so nothing
 * stretches; it is the first client component among the charts because hover,
 * keyboard and brush need state.
 *
 * HONEST BY CONSTRUCTION, the same rules the old charts carried:
 *  · bars, never lines — every series is a bucket, and a line invents values
 *    between buckets that were never measured;
 *  · a `null` value is a GAP (nothing drawn), never a zero;
 *  · a PARTIAL edge bucket (the window's bound falls inside it) draws de-emphasised
 *    and the tooltip says which part of the bucket the number covers;
 *  · the y-axis ceiling is a nice number over the VISIBLE series only;
 *  · emphasis is weight (opacity), never hue; colour is data (`danger` for errors).
 *
 * NO DEPENDENCY. ~400 lines of platform: pointer events, one ResizeObserver, one
 * absolutely positioned tooltip inside the figure — no portal, no filter, no
 * gradient, no shadow beyond `--shadow-overlay`, and the only transition is opacity.
 *
 * FRAMEWORK-FREE. The package has no `next` dependency, so navigation is injected:
 * `onNavigate(href)` (the app passes `router.push`) with `location.assign` as the
 * fallback, and the app injects its own formatter so the number in the tooltip is
 * formatted by the registry's rule, not a second one here.
 */

export type ChartTone = "data" | "second" | "danger" | "ok" | "warn";
export type ChartMark = "bar" | "band" | "tick" | "line" | "area";
export type ChartValueKind =
	| "count"
	| "tokens"
	| "percent"
	| "duration_ms"
	| "currency"
	| "ratio";

export interface ChartBucket {
	t: number;
	tEnd: number;
	partial: boolean;
}

export interface ChartSeriesInput {
	id: string;
	label: string;
	kind: ChartValueKind;
	tone?: ChartTone;
	mark?: ChartMark;
	values: readonly (number | null)[];
}

export interface TimeSeriesChartProps {
	buckets: readonly ChartBucket[];
	series: readonly ChartSeriesInput[];
	/** Per-bucket sample size, shown in the tooltip as `n`. */
	n?: readonly (number | null)[];
	/** Accessible name. Required — a chart with no name is unreadable to a screen reader. */
	label: string;
	/** Plot height in px (the axis strip is added). Default 160. */
	height?: number;
	/** Formatter for tooltip and axis values. Defaults to a compact built-in. */
	format?: (kind: ChartValueKind, v: number) => string;
	/** Click-through for a bucket. Return `undefined` for no link. */
	hrefFor?: (index: number) => string | undefined;
	/** Soft navigation (the app's `router.push`). Falls back to `location.assign`. */
	onNavigate?: (href: string) => void;
	/** Brush-to-zoom: called with the selection snapped to bucket edges. */
	onBrush?: (sinceMs: number, untilMs: number) => void;
	/** Show the legend (series toggles). Default: when more than one series. */
	legend?: boolean;
	className?: string;
}

const Y_GUTTER = 44;
const AXIS_H = 26;
const MIN_BRUSH_PX = 4;

const FILL: Record<ChartTone, string> = {
	data: "fill-chart-primary",
	second: "fill-chart-secondary",
	danger: "fill-danger",
	ok: "fill-ok",
	warn: "fill-warn",
};
/* DSH-14 (founder 2026-09-04, ADR-074 A4-4): QUANTILES and RATES draw as a LINE
   (optionally with a soft area under it); COUNTS stay bars. A line is drawn
   through the bucket centres and breaks at a null bucket rather than bridging
   it — a gap is "no traffic", never a value. */
const STROKE: Record<ChartTone, string> = {
	data: "stroke-chart-primary",
	second: "stroke-chart-secondary",
	danger: "stroke-danger",
	ok: "stroke-ok",
	warn: "stroke-warn",
};
function linePath(
	values: readonly (number | null)[],
	xc: (i: number) => number,
	yOf: (v: number) => number,
): string {
	let d = "";
	let open = false;
	values.forEach((v, i) => {
		if (v == null) {
			open = false;
			return;
		}
		d += `${open ? "L" : "M"}${xc(i).toFixed(1)},${yOf(v).toFixed(1)} `;
		open = true;
	});
	return d.trim();
}
function areaPath(
	values: readonly (number | null)[],
	xc: (i: number) => number,
	yOf: (v: number) => number,
	base: number,
): string {
	// one closed polygon per contiguous run of values
	const runs: number[][] = [];
	let cur: number[] = [];
	values.forEach((v, i) => {
		if (v == null) {
			if (cur.length) runs.push(cur);
			cur = [];
		} else cur.push(i);
	});
	if (cur.length) runs.push(cur);
	return runs
		.map((run) => {
			const top = run
				.map(
					(i, k) =>
						`${k ? "L" : "M"}${xc(i).toFixed(1)},${yOf(values[i] as number).toFixed(1)}`,
				)
				.join(" ");
			const last = run[run.length - 1] ?? 0;
			const first = run[0] ?? 0;
			return `${top} L${xc(last).toFixed(1)},${base} L${xc(first).toFixed(1)},${base} Z`;
		})
		.join(" ");
}
const SWATCH: Record<ChartTone, string> = {
	data: "bg-chart-primary",
	second: "bg-chart-secondary",
	danger: "bg-danger",
	ok: "bg-ok",
	warn: "bg-warn",
};

function defaultFormat(kind: ChartValueKind, v: number): string {
	switch (kind) {
		case "duration_ms":
			return fmtDurMs(v);
		case "percent":
			return `${v.toFixed(2)}%`;
		case "currency":
			return `$${v.toFixed(v >= 1 ? 2 : 4)}`;
		case "ratio":
			return `${v.toFixed(2)}×`;
		case "tokens":
			return v >= 1_000_000
				? `${(v / 1_000_000).toFixed(1)}M`
				: v >= 1_000
					? `${(v / 1_000).toFixed(1)}K`
					: String(Math.round(v));
		default:
			return Math.round(v).toLocaleString("en-US");
	}
}

/** 1/2/5 × 10ⁿ ceiling so the gridline labels read as round numbers. */
function niceCeil(v: number): number {
	if (!(v > 0)) return 1;
	const pow = 10 ** Math.floor(Math.log10(v));
	const n = v / pow;
	const step = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10;
	return step * pow;
}

function pad(n: number): string {
	return String(n).padStart(2, "0");
}

/** `14:25–14:30 UTC` · `Sep 1 14:00 – Sep 2 02:00 UTC` (crosses a day). */
function fmtBounds(t: number, tEnd: number): string {
	const a = new Date(t);
	const b = new Date(tEnd);
	const sameDay =
		a.getUTCFullYear() === b.getUTCFullYear() &&
		a.getUTCMonth() === b.getUTCMonth() &&
		a.getUTCDate() === b.getUTCDate();
	const MON = [
		"Jan",
		"Feb",
		"Mar",
		"Apr",
		"May",
		"Jun",
		"Jul",
		"Aug",
		"Sep",
		"Oct",
		"Nov",
		"Dec",
	];
	const day = (d: Date) => `${MON[d.getUTCMonth()]} ${d.getUTCDate()}`;
	const hm = (d: Date) => `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
	return sameDay
		? `${day(a)} ${hm(a)}–${hm(b)} UTC`
		: `${day(a)} ${hm(a)} – ${day(b)} ${hm(b)} UTC`;
}

export function TimeSeriesChart({
	buckets,
	series,
	n,
	label,
	height = 120, // A4-7 density (2026-09-04): 140 → 120
	format = defaultFormat,
	hrefFor,
	onNavigate,
	onBrush,
	legend,
	className,
}: TimeSeriesChartProps) {
	const rootRef = useRef<HTMLDivElement>(null);
	const [width, setWidth] = useState(0);
	const [hidden, setHidden] = useState<ReadonlySet<string>>(() => new Set());
	const [active, setActive] = useState<number | null>(null);
	const [pointer, setPointer] = useState<{ x: number; y: number } | null>(null);
	const [brush, setBrush] = useState<{ x0: number; x1: number } | null>(null);
	const brushStart = useRef<number | null>(null);
	const tipId = useId();

	// Measure ONCE per resize — the plot is drawn in pixels, so text never stretches.
	useEffect(() => {
		const el = rootRef.current;
		if (!el) return;
		const ro = new ResizeObserver((entries) => {
			for (const e of entries) setWidth(Math.floor(e.contentRect.width));
		});
		ro.observe(el);
		setWidth(Math.floor(el.getBoundingClientRect().width));
		return () => ro.disconnect();
	}, []);

	const visible = useMemo(
		() => series.filter((s) => !hidden.has(s.id)),
		[series, hidden],
	);
	const count = buckets.length;
	const plotW = Math.max(0, width - Y_GUTTER);
	const slot = count > 0 ? plotW / count : 0;
	const gap = Math.min(slot * 0.3, 6);
	const barW = Math.max(slot - gap, 1);

	const ceiling = useMemo(() => {
		let max = 0;
		for (const s of visible)
			for (const v of s.values) if (v != null && v > max) max = v;
		return niceCeil(max * 1.05);
	}, [visible]);
	const yOf = (v: number) => height - (v / ceiling) * height;
	const xOf = (i: number) => Y_GUTTER + i * slot;

	const hasData = series.some((s) => s.values.some((v) => v != null));
	const bandSeries = visible.filter((s) => s.mark === "band");
	const tickSeries = visible.filter((s) => s.mark === "tick");
	const barSeries = visible.filter((s) => (s.mark ?? "bar") === "bar");
	const lineSeries = visible.filter(
		(s) => s.mark === "line" || s.mark === "area",
	);
	const showLegend = legend ?? series.length > 1;

	const bucketAt = useCallback(
		(clientX: number): number | null => {
			const el = rootRef.current;
			if (!el || slot <= 0) return null;
			const x = clientX - el.getBoundingClientRect().left - Y_GUTTER;
			const i = Math.floor(x / slot);
			return i >= 0 && i < count ? i : null;
		},
		[slot, count],
	);

	const navigate = (i: number) => {
		const href = hrefFor?.(i);
		if (!href) return;
		if (onNavigate) onNavigate(href);
		else window.location.assign(href);
	};

	const onPointerMove = (e: PointerEvent<HTMLDivElement>) => {
		const el = rootRef.current;
		if (!el) return;
		const rect = el.getBoundingClientRect();
		const x = e.clientX - rect.left;
		setPointer({ x, y: e.clientY - rect.top });
		setActive(bucketAt(e.clientX));
		if (brushStart.current !== null) {
			setBrush({ x0: brushStart.current, x1: x });
		}
	};
	const onPointerLeave = () => {
		if (brushStart.current === null) {
			setActive(null);
			setPointer(null);
		}
	};
	const onPointerDown = (e: PointerEvent<HTMLDivElement>) => {
		if (e.button !== 0) return;
		const el = rootRef.current;
		if (!el) return;
		brushStart.current = e.clientX - el.getBoundingClientRect().left;
		el.setPointerCapture(e.pointerId);
	};
	const onPointerUp = (e: PointerEvent<HTMLDivElement>) => {
		const el = rootRef.current;
		const start = brushStart.current;
		brushStart.current = null;
		setBrush(null);
		if (!el || start === null) return;
		const rect = el.getBoundingClientRect();
		const end = e.clientX - rect.left;
		if (Math.abs(end - start) < MIN_BRUSH_PX) {
			// A click, not a drag.
			const i = bucketAt(e.clientX);
			if (i !== null) navigate(i);
			return;
		}
		if (!onBrush || slot <= 0) return;
		const lo = Math.max(
			0,
			Math.min(count - 1, Math.floor((Math.min(start, end) - Y_GUTTER) / slot)),
		);
		const hi = Math.max(
			0,
			Math.min(count - 1, Math.floor((Math.max(start, end) - Y_GUTTER) / slot)),
		);
		if (hi - lo < 1) return; // fewer than two buckets — nothing to zoom to
		const a = buckets[lo];
		const b = buckets[hi];
		if (a && b) onBrush(a.t, b.tEnd);
	};

	const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
		if (count === 0) return;
		if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
			e.preventDefault();
			const delta = e.key === "ArrowRight" ? 1 : -1;
			setActive((cur) => {
				const next = cur === null ? (delta > 0 ? 0 : count - 1) : cur + delta;
				return Math.max(0, Math.min(count - 1, next));
			});
			setPointer(null);
		} else if (e.key === "Enter" && active !== null) {
			e.preventDefault();
			navigate(active);
		} else if (e.key === "Escape") {
			setActive(null);
			setPointer(null);
			setBrush(null);
			brushStart.current = null;
		}
	};

	const activeBucket = active !== null ? buckets[active] : undefined;
	const tooltipLeft = (() => {
		if (active === null || width === 0) return 0;
		const cx = pointer ? pointer.x : xOf(active) + slot / 2;
		// Keep the tooltip inside the figure: flip to the left past the midpoint.
		return cx > width / 2
			? Math.max(0, cx - 232)
			: Math.min(width - 232, cx + 12);
	})();

	if (!hasData || count === 0) {
		return (
			<div
				className={cn(
					"flex items-center justify-center rounded-lg border border-line border-dashed text-ink-3 text-xs",
					className,
				)}
				style={{ height: height + AXIS_H }}
			>
				No data in this range
			</div>
		);
	}

	const first = buckets[0];
	const last = buckets[count - 1];

	return (
		<figure className={cn("m-0 w-full", className)} aria-label={label}>
			{/* The plot is ONE focusable widget (role=application): arrow keys move the
			    active bucket, Enter drills through, Escape clears. A per-bar tab stop
			    would be up to 96 stops, which is worse for a keyboard user, not better. */}
			<div
				ref={rootRef}
				role="application"
				aria-roledescription="time series chart"
				aria-label={label}
				aria-describedby={active !== null ? tipId : undefined}
				// biome-ignore lint/a11y/noNoninteractiveTabindex: one tab stop for the whole plot; arrow keys / Enter / Escape are handled on it (see above).
				tabIndex={0}
				onPointerMove={onPointerMove}
				onPointerLeave={onPointerLeave}
				onPointerDown={onPointerDown}
				onPointerUp={onPointerUp}
				onKeyDown={onKeyDown}
				className="relative select-none focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
				style={{
					touchAction: "none",
					cursor: hrefFor ? "pointer" : "crosshair",
				}}
			>
				{width > 0 && (
					<svg
						width={width}
						height={height + 2}
						role="img"
						aria-label={label}
						className="block overflow-visible"
					>
						<title>{label}</title>
						{/* gridlines + y labels — in DOM pixels, never stretched */}
						{[0, 0.5, 1].map((f) => {
							const y = yOf(ceiling * f);
							return (
								<g key={f}>
									<line
										x1={Y_GUTTER}
										x2={width}
										y1={y}
										y2={y}
										className="stroke-chart-grid"
										strokeWidth={1}
										strokeDasharray={f === 0 ? undefined : "2 3"}
									/>
									<text
										x={Y_GUTTER - 8}
										y={y + (f === 1 ? 9 : 3)}
										textAnchor="end"
										/* design-constraint-ok: SVG user-space font size on an axis label, not a DOM font size — same carve-out BarChart / LatencyTimeline record */
										className="fill-ink-3 font-mono text-[10px]"
										style={{ fontVariantNumeric: "tabular-nums" }}
									>
										{f === 0
											? "0"
											: format(visible[0]?.kind ?? "count", ceiling * f)}
									</text>
								</g>
							);
						})}

						{/* crosshair on the active bucket — a class toggle, not a redraw */}
						{activeBucket && active !== null && (
							<rect
								x={xOf(active)}
								y={0}
								width={slot}
								height={height}
								className="fill-ink opacity-[0.06]"
							/>
						)}

						{/* DSH-14: area fills first (under everything), lines last (over the bars). */}
						{lineSeries
							.filter((s) => s.mark === "area")
							.map((s) => (
								<path
									key={`area-${s.id}`}
									d={areaPath(s.values, (i) => xOf(i) + slot / 2, yOf, height)}
									className={cn(FILL[s.tone ?? "data"], "opacity-15")}
								/>
							))}
						{buckets.map((b, i) => {
							const x = xOf(i) + gap / 2;
							const partialCls = b.partial ? "opacity-45" : "opacity-80";
							const activeCls = active === i ? "opacity-100" : partialCls;
							return (
								<g key={b.t} className="transition-opacity duration-150">
									{barSeries.map((s) => {
										const v = s.values[i];
										if (v == null) return null;
										const h = v > 0 ? Math.max(height - yOf(v), 1.5) : 0;
										return (
											<rect
												key={s.id}
												x={x}
												y={height - h}
												width={barW}
												height={h}
												rx={Math.min(1.5, barW / 2)}
												className={cn(FILL[s.tone ?? "data"], activeCls)}
											/>
										);
									})}
									{bandSeries.length > 0 &&
										(() => {
											const vals = bandSeries
												.map((s) => s.values[i])
												.filter((v): v is number => v != null);
											if (vals.length === 0) return null;
											const top = yOf(Math.max(...vals));
											const bottom = yOf(Math.min(...vals));
											return (
												<rect
													x={x}
													y={top}
													width={barW}
													height={Math.max(bottom - top, 1.5)}
													rx={Math.min(2, barW / 2)}
													className={cn(
														FILL[bandSeries[0]?.tone ?? "second"],
														active === i
															? "opacity-45"
															: b.partial
																? "opacity-15"
																: "opacity-25",
													)}
												/>
											);
										})()}
									{tickSeries.map((s) => {
										const v = s.values[i];
										if (v == null) return null;
										return (
											<rect
												key={s.id}
												x={x}
												y={yOf(v) - 1}
												width={barW}
												height={2}
												rx={1}
												className={cn(FILL[s.tone ?? "data"], activeCls)}
											/>
										);
									})}
								</g>
							);
						})}

						{lineSeries.map((s) => (
							<path
								key={`line-${s.id}`}
								d={linePath(s.values, (i) => xOf(i) + slot / 2, yOf)}
								fill="none"
								strokeWidth={s.tone === "second" ? 1.5 : 2}
								strokeLinejoin="round"
								strokeLinecap="round"
								className={cn(
									STROKE[s.tone ?? "data"],
									s.tone === "second" ? "opacity-80" : "opacity-95",
								)}
							/>
						))}
						{lineSeries.map((s) =>
							active != null && s.values[active] != null ? (
								<circle
									key={`dot-${s.id}`}
									cx={xOf(active) + slot / 2}
									cy={yOf(s.values[active] as number)}
									r={3}
									className={cn(FILL[s.tone ?? "data"])}
								/>
							) : null,
						)}
						{/* brush selection */}
						{brush && (
							<rect
								x={Math.min(brush.x0, brush.x1)}
								y={0}
								width={Math.abs(brush.x1 - brush.x0)}
								height={height}
								className="fill-ink opacity-10 stroke-ink-2"
								strokeWidth={1}
							/>
						)}
					</svg>
				)}

				{/* the ONE time axis, inset to the plot */}
				{first && last && (
					<div style={{ marginLeft: Y_GUTTER }}>
						<TimeRuler
							startMs={first.t}
							endMs={last.tEnd}
							ticks={5}
							mode="absolute"
						/>
					</div>
				)}

				{/* tooltip: exact values + UTC bounds; absolutely positioned inside the figure */}
				{activeBucket && active !== null && (
					<div
						id={tipId}
						role="tooltip"
						className="pointer-events-none absolute top-1 z-30 w-56 rounded-lg border border-line bg-surface px-2.5 py-2 text-2xs text-ink-2 shadow-[var(--shadow-overlay)]"
						style={{ left: tooltipLeft }}
					>
						<div
							className="font-mono text-ink"
							style={{ fontVariantNumeric: "tabular-nums" }}
						>
							{fmtBounds(activeBucket.t, activeBucket.tEnd)}
						</div>
						{activeBucket.partial && (
							<div className="text-ink-3">
								partial bucket — the window edge falls inside it
							</div>
						)}
						<dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5">
							{visible.map((s) => {
								const v = s.values[active];
								return (
									<div key={s.id} className="contents">
										<dt className="flex items-center gap-1.5 text-ink-3">
											<span
												className={cn(
													"inline-block h-1.5 w-1.5 rounded-sm",
													SWATCH[s.tone ?? "data"],
												)}
												aria-hidden
											/>
											{s.label}
										</dt>
										<dd
											className="text-right font-mono text-ink"
											style={{ fontVariantNumeric: "tabular-nums" }}
										>
											{v == null ? "—" : format(s.kind, v)}
										</dd>
									</div>
								);
							})}
							{n?.[active] != null && (
								<>
									<dt className="text-ink-3">n</dt>
									<dd
										className="text-right font-mono text-ink-2"
										style={{ fontVariantNumeric: "tabular-nums" }}
									>
										{Math.round(n[active] ?? 0).toLocaleString("en-US")}
									</dd>
								</>
							)}
						</dl>
						{hrefFor?.(active) && (
							<div className="mt-1 text-ink-3">
								click · Enter — open these traces
							</div>
						)}
					</div>
				)}
			</div>

			{showLegend && (
				<figcaption className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-2xs text-ink-3">
					{series.map((s) => {
						const off = hidden.has(s.id);
						return (
							<button
								key={s.id}
								type="button"
								aria-pressed={!off}
								onClick={() =>
									setHidden((cur) => {
										const next = new Set(cur);
										if (next.has(s.id)) next.delete(s.id);
										else if (next.size < series.length - 1) next.add(s.id);
										return next;
									})
								}
								className={cn(
									"inline-flex items-center gap-1.5 rounded px-1 py-0.5 transition-opacity focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring",
									off ? "opacity-40 line-through" : "hover:text-ink",
								)}
							>
								<span
									className={cn(
										"inline-block h-2 w-3 rounded-sm",
										SWATCH[s.tone ?? "data"],
									)}
									aria-hidden
								/>
								{s.label}
							</button>
						);
					})}
					<span className="ml-auto">
						{onBrush ? "drag to zoom · " : ""}hover or ← → for values · gaps =
						no traffic
					</span>
				</figcaption>
			)}
		</figure>
	);
}
