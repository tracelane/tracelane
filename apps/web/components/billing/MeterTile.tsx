/**
 * MeterTile — one of the six usage meters on `/settings/billing` (spec
 * `BILL-01-metering-and-tiers.md` §8 `#usage`).
 *
 * Built on the shared `.stat-tile` surface (the same material `<StatCard>`
 * uses) rather than the primitive itself: a meter tile needs a progress bar
 * AND a projection line stacked under the value, and `<StatCard>`'s `sub`
 * slot renders inside a `<p>` — a block-level bar nested in a paragraph is
 * invalid HTML and an SSR/hydration risk. Same tokens, same radius, same
 * hairline; just laid out for two extra lines.
 *
 * Review note carried over from the wireframe: the value AND its unit render
 * as ONE string (`formatMeterCaption`) so the caption can never wrap the unit
 * onto its own line.
 */

import type { WarnLevel } from "@/lib/billing-usage";
import { cn } from "@tracelanedev/ui";

export interface MeterTileProps {
	label: string;
	/** Pre-formatted "182 / 300 GB" (or "0.9 GB" with no denominator). */
	caption: string;
	/** 0-999, or `null` when there is no allowance to compare against (custom/Enterprise). */
	pct: number | null;
	level: WarnLevel;
	/** "→ 268 GB by period end" (or "by month end" with no Polar cycle) — or a partial/unknown message. */
	projection: string;
	/** Cold's "$0.08 so far" secondary line (accrued spend, not a rate); omitted elsewhere. */
	extra?: string;
}

const FILL_COLOR: Record<WarnLevel, string | undefined> = {
	ok: undefined, // .bar-data's own --chart-primary
	warn: "var(--warn)",
	danger: "var(--danger)",
};

const PCT_TEXT_CLASS: Record<WarnLevel, string> = {
	ok: "text-ink-3",
	warn: "text-warn-ink font-medium",
	danger: "text-danger-ink font-medium",
};

export function MeterTile({
	label,
	caption,
	pct,
	level,
	projection,
	extra,
}: MeterTileProps) {
	return (
		<div
			className="stat-tile relative flex h-full flex-col gap-2 p-5"
			data-meter={label}
		>
			<span className="t-metric-label">{label}</span>
			<span className="t-metric-sm whitespace-nowrap tabular-nums">
				{caption}
			</span>
			{pct !== null && (
				<div className="h-1.5 overflow-hidden rounded-full bg-surface-2">
					<div
						className={cn("h-full rounded-full", level === "ok" && "bar-data")}
						style={{
							width: `${Math.min(100, pct)}%`,
							backgroundColor: FILL_COLOR[level],
						}}
					/>
				</div>
			)}
			<div className="mt-auto flex flex-wrap items-baseline gap-x-2 text-2xs">
				{pct !== null && (
					<span className={PCT_TEXT_CLASS[level]}>
						{pct}%{level === "danger" ? " ⚠" : level === "warn" ? " ⚠" : ""}
					</span>
				)}
				{extra && <span className="text-ink-3">{extra}</span>}
			</div>
			<span
				className={cn(
					"text-2xs",
					level === "warn" || level === "danger"
						? "text-warn-ink"
						: "text-ink-3",
				)}
			>
				{projection}
			</span>
		</div>
	);
}
