import type { ReactNode } from "react";
import { cn } from "../lib/cn";
import { MetricIcon, type MetricIconName } from "./MetricIcon";

/**
 * StatCard — the ONE premium metric tile shared across every dashboard surface
 * (Dashboard / SLO / Gateway / Guardrails / Signatures). A single component so
 * the metric row reads as one system, not five per-page reimplementations.
 *
 * Look (tasteful — NOT literal glass): a subtle surface→surface-2
 * gradient, a hairline border, and a soft 1px shadow give quiet elevation; the
 * `interactive` variant lifts 1px on hover for click-through tiles. Token-driven
 * (no hardcoded hex), theme-aware, and cheap to paint — no backdrop-blur/filter,
 * so a wall of these never costs a frame.
 */

export type StatTone = "default" | "ok" | "warn" | "danger";

/**
 * Card surface (app design system):
 *  - `default`  the standard elevated tile.
 *  - `inverse`  a dark card (near-black) with a lava value — the mockup's
 *               error-budget / burn-rate hero cards.
 *  - `action`   a lava-soft tinted card — the mockup's block-rate card.
 */
export type StatVariant = "default" | "inverse" | "action";

export interface StatCardProps {
	/** Micro uppercase label. */
	label: ReactNode;
	/** The metric — rendered large, tabular-nums, tone-colored. */
	value: ReactNode;
	/** Tone for the value (color + meaning; never color alone — pair with copy). Applies to the `default` variant. */
	tone?: StatTone;
	/** Card surface — see StatVariant. */
	variant?: StatVariant;
	/** Secondary line under the value (context / denominator / "1.0× = on pace"). */
	sub?: ReactNode;
	/** Native tooltip on the label (jargon → plain language) + a `?` affordance. */
	hint?: string;
	/** Optional monochrome metric-icon chip on the label row — the SAME shared
	 *  `MetricIcon` as the dashboard, so every surface reads as one system. */
	icon?: MetricIconName;
	/** Lift-on-hover + pointer — set when the tile is wrapped in a link/button (default variant). */
	interactive?: boolean;
	/**
	 * Period-over-period change. Rendered as a chip with an arrow AND a sign, never
	 * colour alone — `up` is not automatically good (a rising error rate is not a win),
	 * so the CALLER states the tone.
	 */
	delta?: { value: string; direction: "up" | "down" | "flat"; tone?: StatTone };
	/**
	 * Optional micro bar series behind the value — a shape for the trend, at a glance,
	 * without a second chart. BARS, not a sparkline: these are buckets (see BarChart).
	 * Values are normalised internally; pass raw numbers.
	 */
	spark?: readonly number[];
	className?: string;
}

const TONE: Record<StatTone, string> = {
	default: "text-ink",
	ok: "text-ok-ink",
	warn: "text-warn-ink",
	danger: "text-danger-ink",
};

export function StatCard({
	label,
	value,
	tone = "default",
	variant = "default",
	sub,
	hint,
	icon,
	interactive,
	delta,
	spark,
	className,
}: StatCardProps) {
	const isDefault = variant === "default";
	const card =
		variant === "inverse"
			? "rounded-lg border border-transparent bg-surface-inverse p-3"
			: variant === "action"
				? "rounded-lg border border-action-line bg-action-soft p-3"
				: "stat-tile p-3";
	const labelCls =
		variant === "action"
			? "text-action-ink"
			: isDefault
				? "text-ink-3"
				: "text-ink-inverse opacity-60";
	const valueCls =
		variant === "inverse"
			? // INK ON INK. This was `text-action`, which was correct while --action was
				// lava. ADR-074 remapped --action to the monochrome ink family, and
				// --surface-inverse is ALSO ink — so in LIGHT theme the value rendered
				// #0d0d0d on #0d0d0d: a 1:1 contrast ratio, completely invisible. Dark theme
				// was fine (light action on dark card), which is why it survived review and
				// shipped. The value on an inverse surface must use the token that EXISTS to
				// be legible on it.
				"text-ink-inverse"
			: variant === "action"
				? "text-action-ink"
				: TONE[tone];
	const subCls =
		variant === "action"
			? "text-action-ink opacity-80"
			: isDefault
				? "text-ink-3"
				: "text-ink-inverse opacity-60";

	return (
		// `flex h-full flex-col` is what makes a ROW of tiles align: the label row sits
		// at the top, the value block is pushed to a common baseline by `mt-auto`, and a
		// tile without a `sub` no longer floats its value halfway up while its neighbour
		// with a `sub` sits low. Grid `items-stretch` (StatGrid) supplies the equal height.
		<div
			className={cn(
				card,
				"flex h-full flex-col",
				isDefault && interactive && "stat-tile--interactive",
				className,
			)}
		>
			<div className="mb-0.5 flex items-center gap-1.5">
				{icon && (
					<MetricIcon name={icon} size={20} onInverse={variant === "inverse"} />
				)}
				<p
					className={cn(
						"flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wide",
						labelCls,
					)}
				>
					{label}
					{/* Real tooltip, not a native `title`: `title` never fires on touch
				    devices and lags ~1s on desktop, so the `?` looked dead. This shows
				    on hover, keyboard focus AND tap (focus-within). */}
					{hint && (
						<span className="group relative inline-flex">
							<button
								type="button"
								aria-label={hint}
								className="grid h-3.5 w-3.5 cursor-help place-items-center rounded-full border border-line-2 text-[8px] text-ink-3 transition-colors hover:border-ink-3 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
							>
								?
							</button>
							<span
								role="tooltip"
								className="pointer-events-none absolute left-1/2 top-full z-30 mt-1.5 w-56 -translate-x-1/2 rounded-lg border border-line bg-surface px-2.5 py-1.5 text-[11px] font-normal normal-case leading-snug tracking-normal text-ink-2 opacity-0 shadow-lg transition-opacity duration-100 group-hover:opacity-100 group-focus-within:opacity-100"
							>
								{hint}
							</span>
						</span>
					)}
				</p>
			</div>
			<div className="mt-auto">
				<div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
					<p className={cn("t-metric", valueCls)}>{value}</p>
					{delta && (
						<span
							className={cn(
								"inline-flex items-center gap-0.5 rounded-full px-1.5 py-0.5 font-mono text-[10px] leading-none",
								isDefault
									? `bg-surface-2 ${TONE[delta.tone ?? "default"]}`
									: "bg-white/10 text-ink-inverse",
							)}
							style={{ fontVariantNumeric: "tabular-nums" }}
						>
							<span aria-hidden="true">
								{delta.direction === "up"
									? "▲"
									: delta.direction === "down"
										? "▼"
										: "—"}
							</span>
							{delta.value}
						</span>
					)}
				</div>
				{spark && spark.length > 1 && (
					<Spark values={spark} inverse={!isDefault} />
				)}
				{/* Reserved line: keeps every tile in a row the same height even when
				    only some have a sub-line, without forcing callers to pass an empty
				    string. An `&nbsp;` would be a lie to a screen reader; this is not
				    rendered at all, it just holds the box. */}
				{sub ? (
					<p className={cn("mt-0.5 text-[11px]", subCls)}>{sub}</p>
				) : (
					<p aria-hidden="true" className="mt-0.5 h-[1.1em] text-[11px]" />
				)}
			</div>
		</div>
	);
}

/**
 * Micro bar series. Deliberately not a sparkline — the data are buckets, and a line
 * across buckets interpolates values that were never measured (see BarChart).
 */
function Spark({
	values,
	inverse,
}: { values: readonly number[]; inverse?: boolean }) {
	const max = Math.max(...values, 0) || 1;
	const n = values.length;
	return (
		<svg
			viewBox={`0 0 ${n * 3} 12`}
			height={12}
			width="100%"
			preserveAspectRatio="none"
			aria-hidden="true"
			className="mt-1.5 block max-w-[112px]"
		>
			{values.map((v, i) => {
				const h = Math.max((v / max) * 12, v > 0 ? 1 : 0);
				return (
					<rect
						key={`${i}:${v}`}
						x={i * 3}
						y={12 - h}
						width={2}
						height={h}
						className={
							inverse ? "fill-ink-inverse opacity-45" : "fill-ink-3 opacity-55"
						}
					/>
				);
			})}
		</svg>
	);
}
