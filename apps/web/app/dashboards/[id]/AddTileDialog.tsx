"use client";

/**
 * AddTileDialog — two compact, inline client forms: "Add tile" (a metric +
 * shape composition) and "Add section divider" (spec §9, 2026-09-07 — a pure
 * layout tile, no metric). They are DELIBERATELY separate actions, not one
 * form with a "type" toggle: a divider is never a metric+shape combination,
 * and burying it inside the metric picker would put a `metric_id` select in
 * front of a control that has none.
 *
 * "Add tile": four closed lists — metric_id (from the registry), shape
 * (stat/series/breakdown), dimension (optional, closed set), width AND
 * height. Submits a POST to /api/dashboards/[id]/tiles.
 *
 * Both forms are DELIBERATELY NOT a modal — they expand inline so the user
 * can see what's being configured in context. A modal blocks the grid;
 * inline does not.
 *
 * Width/height defaults follow the SHAPE (`SHAPE_SIZE_DEFAULTS`) — a stat is a
 * number, a series is a chart, and the founder's report (2026-09-07: "the graph
 * wasn't visible at all") is exactly what a bad default here reproduces. The
 * live preview renders the actual proportion and the actual pixel height so a
 * customer sees the choice before committing to it, not just its label.
 */

import { allMetrics } from "@/lib/metrics/registry";
import {
	CHART_HEIGHT_PX,
	DIVIDER_METRIC_ID,
	DIVIDER_SHAPE,
	SHAPE_SIZE_DEFAULTS,
	STAT_MIN_HEIGHT_PX,
	type TileHeight,
	type TileWidth,
	heightPxFor,
	tileSupport,
} from "@/lib/metrics/tile-support";
import { useRouter } from "next/navigation";
import { useState } from "react";

// Every registry metric that supports at least one tile shape — derived, never hand-listed.
// The first build hand-listed 18 ids and 13 of them did not exist in the registry, so 13 of
// 18 picker choices answered 422 (verifier, 2026-09-05).
const METRIC_OPTIONS: { id: string; label: string }[] = allMetrics()
	.filter((m) => {
		const sup = tileSupport(m.id);
		return sup.stat || sup.series || sup.breakdownDimensions.length > 0;
	})
	.map((m) => ({ id: m.id, label: m.label }));

function shapesFor(metricId: string): Array<"stat" | "series" | "breakdown"> {
	const sup = tileSupport(metricId);
	const out: Array<"stat" | "series" | "breakdown"> = [];
	if (sup.stat) out.push("stat");
	if (sup.series) out.push("series");
	if (sup.breakdownDimensions.length > 0) out.push("breakdown");
	return out;
}

const SHAPE_OPTIONS = [
	{ value: "stat", label: "Stat (single number)" },
	{ value: "series", label: "Series (time chart)" },
	{ value: "breakdown", label: "Breakdown (top-N table)" },
];

const DIMENSION_OPTIONS = [
	{ value: "", label: "— none —" },
	{ value: "model", label: "Model" },
	{ value: "provider", label: "Provider" },
	{ value: "api_key", label: "API key" },
	{ value: "status", label: "Status" },
	{ value: "operation", label: "Operation" },
	{ value: "decision", label: "Decision" },
	{ value: "rail", label: "Rail" },
];

const WIDTH_OPTIONS: { value: TileWidth; label: string }[] = [
	{ value: 4, label: "1/3 width (4 cols)" },
	{ value: 6, label: "Half width (6 cols)" },
	{ value: 12, label: "Full width (12 cols)" },
];

const HEIGHT_OPTIONS: { value: TileHeight; label: string }[] = [
	{ value: "compact", label: "Compact" },
	{ value: "regular", label: "Regular" },
	{ value: "tall", label: "Tall" },
];

interface Props {
	dashboardId: string;
}

type Mode = "closed" | "metric" | "divider";

export function AddTileDialog({ dashboardId }: Props) {
	const router = useRouter();
	const [mode, setMode] = useState<Mode>("closed");
	const [metricId, setMetricId] = useState(
		METRIC_OPTIONS[0]?.id ?? "llm_calls",
	);
	const [shape, setShape] = useState<"stat" | "series" | "breakdown">("stat");
	const [dimension, setDimension] = useState("");
	const [width, setWidth] = useState<TileWidth>(SHAPE_SIZE_DEFAULTS.stat.width);
	const [height, setHeight] = useState<TileHeight>(
		SHAPE_SIZE_DEFAULTS.stat.height,
	);
	const [title, setTitle] = useState("");
	const [adding, setAdding] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const [dividerLabel, setDividerLabel] = useState("");
	const [addingDivider, setAddingDivider] = useState(false);
	const [dividerError, setDividerError] = useState<string | null>(null);

	/** Switch shape (from either the metric or shape select) and reset width/height
	 * to that shape's sensible default — a series-only metric picked after a stat
	 * should not inherit the stat's compact 4-col default and reproduce the exact
	 * "too slim to see" bug this feature exists to fix. */
	function applyShape(next: "stat" | "series" | "breakdown") {
		setShape(next);
		const d = SHAPE_SIZE_DEFAULTS[next];
		setWidth(d.width);
		setHeight(d.height);
	}

	async function handleAdd(e: React.FormEvent) {
		e.preventDefault();
		setAdding(true);
		setError(null);
		try {
			const res = await fetch(`/api/dashboards/${dashboardId}/tiles`, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					metric_id: metricId,
					shape,
					dimension: dimension || null,
					width,
					height,
					title: title.trim() || null,
				}),
			});
			if (!res.ok) {
				const body = (await res.json()) as { error?: string };
				setError(body.error ?? "Failed to add tile");
				return;
			}
			setMode("closed");
			setTitle("");
			router.refresh();
		} catch {
			setError("Network error — try again");
		} finally {
			setAdding(false);
		}
	}

	/** Divider tiles carry no width/height/dimension — the server forces
	 * width=12, height="compact" (spec §9); this form sends only the label. */
	async function handleAddDivider(e: React.FormEvent) {
		e.preventDefault();
		setAddingDivider(true);
		setDividerError(null);
		try {
			const res = await fetch(`/api/dashboards/${dashboardId}/tiles`, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					metric_id: DIVIDER_METRIC_ID,
					shape: DIVIDER_SHAPE,
					title: dividerLabel.trim() || null,
				}),
			});
			if (!res.ok) {
				const body = (await res.json()) as { error?: string };
				setDividerError(body.error ?? "Failed to add divider");
				return;
			}
			setMode("closed");
			setDividerLabel("");
			router.refresh();
		} catch {
			setDividerError("Network error — try again");
		} finally {
			setAddingDivider(false);
		}
	}

	if (mode === "closed") {
		return (
			<div className="flex flex-wrap items-center gap-2">
				<button
					type="button"
					onClick={() => setMode("metric")}
					className="inline-flex items-center gap-2 rounded-[var(--radius-control)] border border-dashed border-line px-4 py-2 text-sm text-ink-3 transition-colors hover:border-line-2 hover:text-ink-2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
				>
					<span aria-hidden="true">+</span> Add tile
				</button>
				<button
					type="button"
					onClick={() => setMode("divider")}
					className="inline-flex items-center gap-2 rounded-[var(--radius-control)] border border-dashed border-line px-4 py-2 text-sm text-ink-3 transition-colors hover:border-line-2 hover:text-ink-2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
				>
					<span aria-hidden="true">+</span> Add section divider
				</button>
			</div>
		);
	}

	if (mode === "divider") {
		return (
			<div className="stat-tile p-4">
				<form
					onSubmit={handleAddDivider}
					className="flex flex-col gap-4 sm:max-w-md"
				>
					<div className="flex items-center justify-between">
						<p className="t-metric-label">Add a section divider</p>
						<button
							type="button"
							onClick={() => setMode("closed")}
							className="text-xs text-ink-3 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-focus-ring"
						>
							Cancel
						</button>
					</div>
					<p className="text-xs text-ink-3">
						A full-width strip that starts a new row — every tile added after it
						lines up flush-left, regardless of what came before.
					</p>
					<div className="flex flex-col gap-1.5">
						<label htmlFor="divider-label" className="text-xs text-ink-2">
							Label (optional)
						</label>
						<input
							id="divider-label"
							type="text"
							value={dividerLabel}
							onChange={(e) => setDividerLabel(e.target.value)}
							placeholder="e.g. Latency, Cost"
							maxLength={60}
							className="rounded-[var(--radius-control)] border border-line bg-surface px-3 py-1.5 text-sm text-ink placeholder:text-ink-3 focus:border-action"
						/>
					</div>
					{/* Live preview: the actual full-width strip this will render as. */}
					<div className="flex flex-col gap-1.5">
						<span className="text-xs text-ink-2">Preview</span>
						<div className="flex items-center gap-3 rounded-[var(--radius-control)] border border-dashed border-line-2 bg-surface-2 p-2">
							{dividerLabel.trim() && (
								<span className="shrink-0 whitespace-nowrap text-xs font-medium uppercase tracking-wide text-ink-2">
									{dividerLabel.trim()}
								</span>
							)}
							<hr className="h-px flex-1 border-0 bg-line" />
						</div>
						<p className="text-2xs text-ink-3">Full width · fixed height</p>
					</div>
					{dividerError && (
						<p className="text-xs text-danger-ink">{dividerError}</p>
					)}
					<div className="flex justify-end">
						<button
							type="submit"
							disabled={addingDivider}
							className="rounded-[var(--radius-control)] bg-action px-4 py-2 text-sm font-medium text-action-on transition-colors hover:bg-action/90 disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
						>
							{addingDivider ? "Adding…" : "Add divider"}
						</button>
					</div>
				</form>
			</div>
		);
	}

	const previewPx = heightPxFor(shape, height);
	const previewMaxPx =
		shape === "stat" ? STAT_MIN_HEIGHT_PX.tall : CHART_HEIGHT_PX.tall;

	return (
		<div className="stat-tile p-4">
			<form onSubmit={handleAdd} className="flex flex-col gap-4">
				<div className="flex items-center justify-between">
					<p className="t-metric-label">Add a tile</p>
					<button
						type="button"
						onClick={() => setMode("closed")}
						className="text-xs text-ink-3 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-focus-ring"
					>
						Cancel
					</button>
				</div>

				<div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
					<div className="flex flex-col gap-1.5">
						<label htmlFor="tile-metric" className="text-xs text-ink-2">
							Metric
						</label>
						<select
							id="tile-metric"
							value={metricId}
							onChange={(e) => {
								const id = e.target.value;
								setMetricId(id);
								const allowed = shapesFor(id);
								if (!allowed.includes(shape)) applyShape(allowed[0] ?? "stat");
								setDimension("");
							}}
							className="rounded-[var(--radius-control)] border border-line bg-surface px-2 py-1.5 text-sm text-ink focus:border-action"
						>
							{METRIC_OPTIONS.map((m) => (
								<option key={m.id} value={m.id}>
									{m.label}
								</option>
							))}
						</select>
					</div>

					<div className="flex flex-col gap-1.5">
						<label htmlFor="tile-shape" className="text-xs text-ink-2">
							Shape
						</label>
						<select
							id="tile-shape"
							value={shape}
							onChange={(e) =>
								applyShape(e.target.value as "stat" | "series" | "breakdown")
							}
							className="rounded-[var(--radius-control)] border border-line bg-surface px-2 py-1.5 text-sm text-ink focus:border-action"
						>
							{SHAPE_OPTIONS.filter((s) =>
								shapesFor(metricId).includes(
									s.value as "stat" | "series" | "breakdown",
								),
							).map((s) => (
								<option key={s.value} value={s.value}>
									{s.label}
								</option>
							))}
						</select>
					</div>

					<div className="flex flex-col gap-1.5">
						<label htmlFor="tile-dimension" className="text-xs text-ink-2">
							Dimension (optional)
						</label>
						<select
							id="tile-dimension"
							value={dimension}
							onChange={(e) => setDimension(e.target.value)}
							className="rounded-[var(--radius-control)] border border-line bg-surface px-2 py-1.5 text-sm text-ink focus:border-action"
						>
							{DIMENSION_OPTIONS.filter(
								(d) =>
									d.value === "" ||
									(
										tileSupport(metricId)
											.breakdownDimensions as readonly string[]
									).includes(d.value),
							).map((d) => (
								<option key={d.value} value={d.value}>
									{d.label}
								</option>
							))}
						</select>
					</div>

					<div className="flex flex-col gap-1.5">
						<label htmlFor="tile-width" className="text-xs text-ink-2">
							Width
						</label>
						<select
							id="tile-width"
							value={width}
							onChange={(e) => setWidth(Number(e.target.value) as TileWidth)}
							className="rounded-[var(--radius-control)] border border-line bg-surface px-2 py-1.5 text-sm text-ink focus:border-action"
						>
							{WIDTH_OPTIONS.map((w) => (
								<option key={w.value} value={w.value}>
									{w.label}
								</option>
							))}
						</select>
					</div>

					<div className="flex flex-col gap-1.5">
						<label htmlFor="tile-height" className="text-xs text-ink-2">
							Height
						</label>
						<select
							id="tile-height"
							value={height}
							onChange={(e) => setHeight(e.target.value as TileHeight)}
							className="rounded-[var(--radius-control)] border border-line bg-surface px-2 py-1.5 text-sm text-ink focus:border-action"
						>
							{HEIGHT_OPTIONS.map((h) => (
								<option key={h.value} value={h.value}>
									{h.label}
								</option>
							))}
						</select>
					</div>

					<div className="flex flex-col gap-1.5">
						{/* Live preview — a proportional bar (width) plus a proportional
						    block (height, scaled against the largest possible tile) so the
						    customer sees the SHAPE of the choice, not just a label. Real
						    numbers (no fabricated data — spec §7): the exact col fraction
						    and the exact pixel height this tile will render at. */}
						<span className="text-xs text-ink-2">Preview</span>
						<div
							className="flex items-end rounded-[var(--radius-control)] border border-dashed border-line-2 bg-surface-2 p-2"
							style={{ height: 64 }}
						>
							<div
								className="rounded-[var(--radius-control)] border border-action-line bg-action-soft"
								style={{
									width: `${(width / 12) * 100}%`,
									height: `${Math.min(100, (previewPx / previewMaxPx) * 100)}%`,
									minHeight: 8,
								}}
							/>
						</div>
						<p className="text-2xs text-ink-3">
							{width === 12 ? "Full width" : `${width}/12 columns`} ·{" "}
							{previewPx}px {shape === "stat" ? "min-height" : "chart height"}
						</p>
					</div>
				</div>

				<div className="flex flex-col gap-1.5">
					<label htmlFor="tile-title" className="text-xs text-ink-2">
						Custom title (optional — defaults to metric name)
					</label>
					<input
						id="tile-title"
						type="text"
						value={title}
						onChange={(e) => setTitle(e.target.value)}
						placeholder="Leave blank to use the metric name"
						maxLength={60}
						className="rounded-[var(--radius-control)] border border-line bg-surface px-3 py-1.5 text-sm text-ink placeholder:text-ink-3 focus:border-action"
					/>
				</div>

				{error && <p className="text-xs text-danger-ink">{error}</p>}

				<div className="flex justify-end">
					<button
						type="submit"
						disabled={adding}
						className="rounded-[var(--radius-control)] bg-action px-4 py-2 text-sm font-medium text-action-on transition-colors hover:bg-action/90 disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
					>
						{adding ? "Adding…" : "Add tile"}
					</button>
				</div>
			</form>
		</div>
	);
}
