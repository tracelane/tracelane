"use client";

/**
 * UsageBoard — `/settings/billing`'s usage section (spec §8 `#usage`).
 *
 * ONE gateway call per load (§2.5b): a single `useQuery` against
 * `/api/billing/usage`, a PURE PASSTHROUGH to the real
 * `GET /v1/billing/usage` (`crates/gateway/src/billing/usage.rs:110-181`).
 * The window breakdown and the ceiling write are SEPARATE, on-demand calls —
 * never fired on mount.
 *
 * The gateway sends no `state` field — `deriveUsageState` (lib/billing-usage.ts)
 * derives spec §4's seven states CLIENT-SIDE from the response + the fetch's
 * own success/failure. Loading is react-query's own `isLoading`, orthogonal
 * to the derived state. Permission-denied lives in `CeilingSheet` via
 * `canManage`, passed through from the server.
 */

import {
	type GatewayUsageResponse,
	METER_KEYS,
	type MeterKey,
	agedOutDays,
	deriveUsageState,
	formatCompactCount,
	formatGbAdaptive,
	formatGbUnit,
	formatMeterCaption,
	meterRateText,
	pctOf,
	warnLevel,
} from "@/lib/billing-usage";
import { formatDateTimeUtc } from "@/lib/format-date";
import { useQuery } from "@tanstack/react-query";
import { Badge, EmptyState, ErrorState } from "@tracelanedev/ui";
import { useState } from "react";
import { CeilingSheet } from "./CeilingSheet";
import { MeterTile } from "./MeterTile";
import { CeilingResolvedBanner, WarnBanner } from "./UsageBanner";
import { WindowBreakdown } from "./WindowBreakdown";

interface UsageFetchResult {
	httpOk: boolean;
	data: GatewayUsageResponse | null;
}

async function fetchUsage(): Promise<UsageFetchResult> {
	try {
		const res = await fetch("/api/billing/usage");
		if (!res.ok) return { httpOk: false, data: null };
		return { httpOk: true, data: (await res.json()) as GatewayUsageResponse };
	} catch {
		return { httpOk: false, data: null };
	}
}

// Six fixed, never-reordered slots — a stable key list sidesteps the
// index-as-key lint without pretending these have real identity.
const SKELETON_SLOTS = ["ingest", "hot", "cold", "series", "query", "evals"];

function SkeletonTiles() {
	return (
		<div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
			{SKELETON_SLOTS.map((slot) => (
				<div
					key={slot}
					className="h-28 animate-pulse rounded-[var(--radius-card)] border border-line bg-surface-2"
				/>
			))}
		</div>
	);
}

const METER_LABEL: Record<MeterKey, string> = {
	ingest: "Ingest",
	hot: "Hot window",
	series: "Series",
	query: "Query",
	cold: "Cold archive",
	evals: "Evaluations",
};

/** Ingest/hot are GB-shaped (adaptive decimals); series/query/evals are counts. */
const IS_GB_METER: Record<MeterKey, boolean> = {
	ingest: true,
	hot: true,
	series: false,
	query: false,
	cold: true,
	evals: false,
};

export function UsageBoard({
	plan: initialPlan,
	canManage,
	initialCeilingUsd,
	initialOverflowMode,
}: {
	plan: string;
	canManage: boolean;
	initialCeilingUsd: number | null;
	initialOverflowMode: "auto_age" | "auto_overage";
}) {
	const {
		data: result,
		isLoading,
		isError,
		refetch,
	} = useQuery({
		queryKey: ["billing-usage"],
		queryFn: fetchUsage,
	});
	const [showCeiling, setShowCeiling] = useState(false);
	// Only tracks a ceiling the USER just saved this session — otherwise the
	// live gateway response (or, before it loads, the server-rendered
	// Postgres value) is the source of truth, never a copy that can drift.
	const [savedCeiling, setSavedCeiling] = useState<{
		usd: number | null;
		mode: "auto_age" | "auto_overage";
	} | null>(null);
	const [showBreakdown, setShowBreakdown] = useState(false);

	if (isLoading) return <SkeletonTiles />;

	const httpOk = result?.httpOk ?? false;
	const data = result?.data ?? null;
	const state = deriveUsageState(data, httpOk);

	if (isError || state === "error") {
		return (
			<ErrorState
				title="Usage metering is unavailable"
				description="Your traces are still being recorded."
				action={
					<button
						type="button"
						onClick={() => refetch()}
						className="rounded border border-line bg-surface px-3 py-1.5 text-xs font-medium text-ink-2 transition-colors hover:border-line-2 hover:text-ink"
					>
						Retry
					</button>
				}
			/>
		);
	}

	if (state === "empty" || !data) {
		return (
			<EmptyState
				title="No usage yet — send a trace and it appears here within a minute."
				icon={
					<svg
						width="20"
						height="20"
						viewBox="0 0 24 24"
						fill="none"
						stroke="currentColor"
						strokeWidth={1.6}
						aria-hidden="true"
					>
						<circle cx="12" cy="12" r="9" />
						<path d="M12 7v5l3 2" />
					</svg>
				}
			/>
		);
	}

	const isFree = state === "not_entitled";
	const ceilingUsd = savedCeiling
		? savedCeiling.usd
		: (data.spend_ceiling_usd ?? initialCeilingUsd);
	const ceilingMode = savedCeiling
		? savedCeiling.mode
		: (data.overflow_mode ?? initialOverflowMode);

	// B-410: the gateway rates over the tenant's Polar cycle when one governs
	// (`period_start` set) and over the calendar month otherwise — the copy
	// names whichever window the numbers were actually rated over.
	const hasCycle = Boolean(data.period_start);
	const periodEndLabel = hasCycle ? "period end" : "month end";
	const tiles = METER_KEYS.filter((k) => k !== "cold").map((key) => {
		const block = data.meters[key];
		const pct = pctOf(block.used, block.included);
		const level = warnLevel(block.used, block.included, data.warn_pct);
		const isGb = IS_GB_METER[key];
		const formatUsed = isGb ? formatGbAdaptive : formatCompactCount;
		const caption = formatMeterCaption({
			used: block.used,
			included: block.included,
			unit: block.unit,
			usedFormat: formatUsed,
		});
		const partial = block.used === null;
		const projection =
			block.projection_month_end == null
				? "— not enough data yet"
				: `→ ${formatUsed(block.projection_month_end)}${block.unit ? ` ${block.unit}` : ""} by ${periodEndLabel}`;
		return {
			key,
			label: METER_LABEL[key],
			caption: partial ? "—" : caption,
			pct,
			level,
			overageUsd: block.overage_usd,
			projection: partial
				? `last computed ${block.last_computed_at ? formatDateTimeUtc(block.last_computed_at) : "unknown"}`
				: projection,
		};
	});

	const cold = data.meters.cold;
	// BILL-01 A5: cold now carries an included allowance on paid tiers, so it
	// gets the same used / included caption and warning bar as the other meters.
	const coldPct = pctOf(cold.used, cold.included);
	const coldLevel = warnLevel(cold.used, cold.included, data.warn_pct);
	const coldCaption =
		cold.used == null
			? "—"
			: cold.included == null
				? formatGbUnit(cold.used)
				: formatMeterCaption({
						used: cold.used,
						included: cold.included,
						unit: cold.unit,
						usedFormat: formatGbAdaptive,
					});
	const periodLabel = hasCycle
		? "Usage this billing period"
		: "Usage this month";

	// Worst-offending meter (for the banner), only among allowance-bearing meters.
	const worst = tiles.reduce<(typeof tiles)[number] | null>((acc, t) => {
		if (t.pct === null) return acc;
		if (!acc || (acc.pct ?? 0) < t.pct) return t;
		return acc;
	}, null);

	return (
		<div className="space-y-5">
			<div className="flex flex-wrap items-center justify-between gap-2">
				<h2 className="t-h1">{periodLabel}</h2>
				<span className="text-2xs text-ink-3">
					last computed {formatDateTimeUtc(data.computed_at)} · daily projection
				</span>
			</div>

			<div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
				{tiles.slice(0, 2).map((t) => (
					<MeterTile
						key={t.key}
						label={t.label}
						caption={t.caption}
						pct={t.pct}
						level={t.level}
						projection={t.projection}
					/>
				))}
				<MeterTile
					label={METER_LABEL.cold}
					caption={coldCaption}
					pct={coldPct}
					level={coldLevel}
					projection={
						cold.projection_month_end == null
							? "— not enough data yet"
							: `→ ${formatGbUnit(cold.projection_month_end)} by ${periodEndLabel}`
					}
					extra={
						cold.overage_usd != null
							? `$${cold.overage_usd.toFixed(2)} so far`
							: undefined
					}
				/>
				{tiles.slice(2).map((t) => (
					<MeterTile
						key={t.key}
						label={t.label}
						caption={t.caption}
						pct={t.pct}
						level={t.level}
						projection={t.projection}
					/>
				))}
			</div>

			{!isFree && worst && worst.level !== "ok" && (
				<WarnBanner
					meterLabel={worst.label}
					pct={worst.pct ?? 0}
					projectionText={worst.projection.replace(/^→ /, "projected ")}
					overageUsd={worst.overageUsd ?? data.projected_overage_usd}
					rateText={meterRateText(worst.key, data)}
					danger={worst.level === "danger"}
					onOpenBreakdown={() => setShowBreakdown((v) => !v)}
					onOpenCeiling={() => setShowCeiling(true)}
					ceilingUsd={ceilingUsd}
				/>
			)}

			{isFree && (
				<p className="text-xs text-ink-2">
					Free ages out — nothing is charged and nothing is blocked.
				</p>
			)}

			{/* Only rendered when the gateway reports the ceiling ACTUALLY fired
			    this period. `agedOutDays` is computed ONLY from two real gateway
			    numbers — never invented when `auto_age_window_days` is null. */}
			{data.ceiling_reached && (
				<CeilingResolvedBanner
					overflowMode={data.overflow_mode}
					agedOutDays={agedOutDays(data)}
					periodNoun={hasCycle ? "billing period" : "month"}
					onReview={() => setShowCeiling(true)}
				/>
			)}

			{/* The warn/danger banner above already carries its own "what's using
			    your window" + ceiling controls — this standalone row is the
			    quiet-state equivalent, so it only renders when that banner is not
			    already showing the same two affordances. */}
			{!isFree && !(worst && worst.level !== "ok") && (
				<div className="flex items-center justify-between">
					<button
						type="button"
						onClick={() => setShowBreakdown((v) => !v)}
						className="text-xs font-medium text-ink-2 underline underline-offset-2 hover:text-ink"
					>
						{showBreakdown ? "Hide" : "Show"} what&apos;s using your window
					</button>
					<span className="flex items-center gap-2 text-xs text-ink-2">
						Spend ceiling:{" "}
						{ceilingUsd === null ? (
							"OFF"
						) : (
							<Badge tone="action">${ceilingUsd}</Badge>
						)}
						<button
							type="button"
							onClick={() => setShowCeiling(true)}
							className="rounded border border-line bg-surface px-3 py-1.5 text-xs font-medium text-ink-2 transition-colors hover:border-line-2 hover:text-ink"
						>
							{ceilingUsd === null ? "Set a ceiling" : "Edit ceiling"}
						</button>
					</span>
				</div>
			)}

			{showBreakdown && <WindowBreakdown />}

			{showCeiling && (
				<CeilingSheet
					initialUsd={ceilingUsd}
					initialMode={ceilingMode}
					canManage={canManage}
					onClose={() => setShowCeiling(false)}
					onSaved={(usd, mode) => {
						setSavedCeiling({ usd, mode });
						setShowCeiling(false);
					}}
				/>
			)}
		</div>
	);
}
