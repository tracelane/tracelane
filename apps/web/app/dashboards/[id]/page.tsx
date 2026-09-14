/**
 * /dashboards/[id] — a custom dashboard: a 12-column tile grid under RangeControl.
 *
 * Each tile is its own Suspense boundary with the existing skeletons. A slow tile
 * never blocks the others. Loading, empty, error, unknown-metric and
 * entitlement-blocked states are all first-class (spec §5).
 *
 * The window comes from the URL (same grammar as every other page):
 *   ?range=<preset>  |  ?since=<ISO>&until=<ISO>
 * No tile stores a window or a number — the dashboard is a saved question.
 *
 * Fan-out: tiles are rendered as individual RSC Suspense boundaries, each doing
 * its own fetch. No Promise.all in this file — React streams them concurrently.
 * check-page-fanout.py counts literal Promise.all blocks and finds 0 here, which
 * is correct: the per-tile Suspense model is the right pattern for a dynamic
 * tile count.
 *
 * tenant isolation: the id is looked up against the session's resolved tenant UUID.
 * A foreign id → 404 page (never exposes ownership).
 */

import { RangeControl } from "@/components/RangeControl";
import { MetricChart } from "@/components/metrics/MetricChart";
import { WindowNotice } from "@/components/metrics/WindowNotice";
import { db } from "@/db";
import { dashboardTiles, dashboards } from "@/db/schema";
import type { DashboardTile } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { availabilityTargetFor } from "@/lib/metrics/availability-target";
import { METRICS, type MetricId, metric } from "@/lib/metrics/registry";
import {
	type Limiter,
	STAT_MIN_HEIGHT_CLASS,
	type TileHeight,
	type TileWidth,
	heightPxFor,
	makeLimiter,
} from "@/lib/metrics/tile-support";
import { type TileDef, fetchTileData } from "@/lib/metrics/tiles";
import { type TimeRange, parseTimeRange } from "@/lib/metrics/time-range";
import { upsertTenantId } from "@/lib/tenant";
import { StatCard } from "@tracelanedev/ui";
import { and, eq } from "drizzle-orm";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { Suspense } from "react";
import { AddTileDialog } from "./AddTileDialog";
import { DividerTile } from "./DividerTile";
import { ShareButton } from "./ShareButton";
import { TileFrame } from "./TileFrame";
import { TileSkeleton } from "./TileSkeleton";

export const dynamic = "force-dynamic";

export async function generateMetadata({
	params,
}: {
	params: Promise<{ id: string }>;
}): Promise<Metadata> {
	const { id } = await params;
	const row = await db
		.select({ name: dashboards.name })
		.from(dashboards)
		.where(eq(dashboards.id, id))
		.limit(1);
	return { title: `${row[0]?.name ?? "Dashboard"} — Tracelane` };
}

interface Props {
	params: Promise<{ id: string }>;
	searchParams: Promise<{ range?: string; since?: string; until?: string }>;
}

export default async function DashboardPage({ params, searchParams }: Props) {
	const { id } = await params;
	const sp = await searchParams;
	const range = parseTimeRange(sp, { defaultPreset: "24h", nowMs: Date.now() });

	const session = await requireSession();
	// One render, at most 8 tile fetches in flight (spec §3). `check-page-fanout.py` counts
	// literal `Promise.all` blocks and cannot see per-tile Suspense fan-out, so the bound
	// lives here, in code, and is unit-tested — not asserted by the guard.
	const run = makeLimiter(8);
	const target = await availabilityTargetFor(session.tenantId);
	const tenantDbId = await upsertTenantId(session.tenantId);
	const canEdit =
		session.role === "owner" ||
		session.role === "admin" ||
		session.role === "member";

	// Verify this dashboard belongs to this tenant (404 on foreign id — never 403).
	const [dashboard] = await db
		.select()
		.from(dashboards)
		.where(and(eq(dashboards.id, id), eq(dashboards.tenantId, tenantDbId)))
		.limit(1);

	if (!dashboard) notFound();

	const tiles = await db
		.select()
		.from(dashboardTiles)
		.where(eq(dashboardTiles.dashboardId, id))
		.orderBy(dashboardTiles.position);

	return (
		<div className="space-y-8 px-1 py-2 sm:px-2 sm:py-4 lg:px-3">
			<header className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
				<div className="min-w-0 flex-1">
					<h1 className="t-h1 truncate">{dashboard.name}</h1>
					<p className="mt-1 text-xs text-ink-3">
						{tiles.length === 0
							? "No tiles yet"
							: `${tiles.length} tile${tiles.length === 1 ? "" : "s"}`}{" "}
						· {range.label}
					</p>
				</div>
				<div className="flex shrink-0 items-center gap-3">
					{canEdit && <ShareButton />}
					<RangeControl />
				</div>
			</header>

			<WindowNotice range={range} />

			{tiles.length === 0 ? (
				<EmptyTileSlot dashboardId={id} canEdit={canEdit} />
			) : (
				<div className="grid grid-cols-12 gap-4">
					{tiles.map((tile, idx) => {
						// A divider is pure layout — no metric, no fetch, no Suspense
						// boundary (there is nothing async to wait on). It counts
						// toward the 12-tile cap like any other tile (spec §9.5).
						if (tile.shape === "divider") {
							return (
								<TileFrame
									key={tile.id}
									dashboardId={id}
									tileId={tile.id}
									tileIndex={idx}
									totalTiles={tiles.length}
									canEdit={canEdit}
									initialWidth={12}
									initialHeight="compact"
									shape="divider"
								>
									<DividerTile
										dashboardId={id}
										tileId={tile.id}
										label={tile.title}
										canEdit={canEdit}
									/>
								</TileFrame>
							);
						}

						const tileShape = tile.shape as "stat" | "series" | "breakdown";
						const tileHeight = (tile.height as TileHeight) ?? "regular";
						return (
							<TileFrame
								key={tile.id}
								dashboardId={id}
								tileId={tile.id}
								tileIndex={idx}
								totalTiles={tiles.length}
								canEdit={canEdit}
								initialWidth={tile.width as TileWidth}
								initialHeight={tileHeight}
								shape={tileShape}
							>
								<Suspense
									fallback={
										<TileSkeleton shape={tileShape} height={tileHeight} />
									}
								>
									<TileContainer
										run={run}
										target={target}
										tile={tile}
										range={range}
									/>
								</Suspense>
							</TileFrame>
						);
					})}
					{canEdit && tiles.length < 12 && (
						<div className="col-span-12">
							<AddTileDialog dashboardId={id} />
						</div>
					)}
				</div>
			)}
		</div>
	);
}

/** Shown when there are no tiles — a dashed slot with an "Add tile" affordance. */
function EmptyTileSlot({
	dashboardId,
	canEdit,
}: { dashboardId: string; canEdit: boolean }) {
	return (
		<div className="flex flex-col items-center gap-4 rounded-[var(--radius-card)] border-2 border-dashed border-line-2 px-8 py-16 text-center">
			<p className="text-sm text-ink-2">This dashboard has no tiles yet.</p>
			{canEdit && <AddTileDialog dashboardId={dashboardId} />}
		</div>
	);
}

/** Async RSC: fetches tile data and renders the appropriate component. Resize
 * and move/remove controls live one level up, in `TileFrame` — a single
 * overlay for every branch below, rather than each shape wiring its own
 * (which is how the `stat` branch shipped with no `group` ancestor and its
 * controls never became visible on hover at all). */
async function TileContainer({
	tile,
	range,
	run,
	target,
}: {
	tile: DashboardTile;
	range: TimeRange;
	run: Limiter;
	target: number;
}) {
	const tileShape = tile.shape as "stat" | "series" | "breakdown";
	const tileHeight = (tile.height as TileHeight) ?? "regular";
	const tileDef: TileDef = {
		id: tile.id,
		metricId: tile.metricId,
		shape: tileShape,
		dimension: tile.dimension,
		filterDimension: tile.filterDimension,
		filterValue: tile.filterValue,
		title: tile.title,
	};

	const data = await fetchTileData(tileDef, range, { target, run });
	const title =
		tile.title ||
		(tile.metricId in METRICS
			? METRICS[tile.metricId as keyof typeof METRICS].label
			: tile.metricId);
	// Non-stat branches (including every error/empty state below) share one
	// min-height so a "tall" tile's error state is never a collapsed sliver —
	// an empty/error state is a first-class render, not an afterthought box.
	const shellHeightPx = heightPxFor(tileShape, tileHeight);

	// ── unknown metric ──────────────────────────────────────────────────────────
	if (data.kind === "unknown_metric") {
		return (
			<TileShell title={title} heightPx={shellHeightPx}>
				<p className="text-xs text-ink-2">
					This tile&apos;s metric no longer exists — remove it.
				</p>
			</TileShell>
		);
	}

	// ── unreachable (gateway error) ─────────────────────────────────────────────
	if (data.kind === "unreachable") {
		return (
			<TileShell title={title} heightPx={shellHeightPx}>
				<p className="text-xs text-ink-3">
					<span className="font-medium text-ink-2">{data.label}</span> — could
					not reach the gateway.
				</p>
			</TileShell>
		);
	}

	// ── entitlement blocked ─────────────────────────────────────────────────────
	if (data.kind === "entitlement_blocked") {
		return (
			<TileShell title={title} heightPx={shellHeightPx}>
				<p className="text-xs text-ink-2">
					Not on your plan.{" "}
					<a href="/settings/billing" className="text-action underline">
						Upgrade
					</a>
				</p>
			</TileShell>
		);
	}

	// ── unsupported shape ───────────────────────────────────────────────────────
	if (data.kind === "unsupported_shape") {
		return (
			<TileShell title={title} heightPx={shellHeightPx}>
				<p className="text-xs text-ink-3">{data.reason}</p>
			</TileShell>
		);
	}

	// ── stat tile ───────────────────────────────────────────────────────────────
	if (data.kind === "stat") {
		// `metric()` returns the `MetricDef` interface (optional `hint` / `floor`); indexing
		// `METRICS` directly yields the literal union, on which those fields do not exist.
		const def =
			tile.metricId in METRICS ? metric(tile.metricId as MetricId) : null;
		return (
			<StatCard
				className={STAT_MIN_HEIGHT_CLASS[tileHeight]}
				// A dashboard stat tile stretches to the tallest tile in its row
				// (grid `items-stretch`), so the default bottom-pushed value left the
				// number stranded at the foot of a mostly-empty card beside a chart.
				valueAlign="top"
				label={title}
				value={data.value}
				hint={def?.hint}
				sample={
					data.n !== null && def?.floor
						? {
								n: data.n,
								floor: typeof def.floor === "number" ? def.floor : 100,
							}
						: undefined
				}
			/>
		);
	}

	// ── series tile ─────────────────────────────────────────────────────────────
	if (data.kind === "series") {
		if (!data.data.hasData) {
			return (
				<TileShell title={title} heightPx={shellHeightPx}>
					<p className="text-xs text-ink-3">No data in this window.</p>
				</TileShell>
			);
		}
		return (
			<div className="stat-tile p-4" style={{ minHeight: shellHeightPx }}>
				<p className="t-metric-label mb-3">{title}</p>
				<MetricChart
					data={data.data}
					label={data.label}
					height={heightPxFor("series", tileHeight)}
					brush={false}
				/>
			</div>
		);
	}

	// ── breakdown tile ──────────────────────────────────────────────────────────
	if (data.kind === "breakdown") {
		return (
			<TileShell title={title} heightPx={shellHeightPx}>
				{data.rows.length === 0 ? (
					<p className="text-xs text-ink-3">No data in this window.</p>
				) : (
					<table className="w-full text-xs">
						<tbody>
							{data.rows.slice(0, 10).map((row) => (
								<tr
									key={row.key}
									className="border-b border-line last:border-0"
								>
									<td className="py-1.5 pr-4 text-ink-2 tabular-nums">
										{row.key || "(empty)"}
									</td>
									<td className="py-1.5 text-right font-medium text-ink tabular-nums">
										{typeof row.value === "number"
											? row.value.toLocaleString("en-US", {
													maximumFractionDigits: 2,
												})
											: "—"}
									</td>
								</tr>
							))}
						</tbody>
					</table>
				)}
			</TileShell>
		);
	}

	return null;
}

/** Generic tile shell with a title, sized to the tile's chosen height so an
 * error/empty/unsupported state is never a collapsed sliver. */
function TileShell({
	title,
	heightPx,
	children,
}: {
	title: string;
	heightPx: number;
	children: React.ReactNode;
}) {
	return (
		<div className="stat-tile p-4" style={{ minHeight: heightPx }}>
			<p className="t-metric-label mb-3">{title}</p>
			{children}
		</div>
	);
}

// ShareButton is a client component — see ShareButton.tsx
