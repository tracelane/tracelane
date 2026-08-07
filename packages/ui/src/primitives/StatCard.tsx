import type { ReactNode } from "react";
import { cn } from "../lib/cn";
import { MetricIcon, type MetricIconName } from "./MetricIcon";

/**
 * StatCard — the ONE premium metric tile shared across every dashboard surface
 * (Dashboard / SLO / Gateway / Guardrails / Signatures). A single component so
 * the metric row reads as one system, not five per-page reimplementations.
 *
 * Look (ADR-053 Neon, tasteful — NOT literal glass): a subtle surface→surface-2
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
 *  - `accent`   a lava-soft tinted card — the mockup's block-rate card.
 */
export type StatVariant = "default" | "inverse" | "accent";

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
	className,
}: StatCardProps) {
	const isDefault = variant === "default";
	const card =
		variant === "inverse"
			? "rounded-xl border border-transparent bg-surface-inverse p-4"
			: variant === "accent"
				? "rounded-xl border border-accent-line bg-accent-soft p-4"
				: "stat-tile p-4";
	const labelCls =
		variant === "accent"
			? "text-accent-ink"
			: isDefault
				? "text-ink-3"
				: "text-ink-inverse opacity-60";
	const valueCls =
		variant === "inverse"
			? "text-accent"
			: variant === "accent"
				? "text-accent-ink"
				: TONE[tone];
	const subCls =
		variant === "accent"
			? "text-accent-ink opacity-80"
			: isDefault
				? "text-ink-3"
				: "text-ink-inverse opacity-60";

	return (
		<div
			className={cn(
				card,
				isDefault && interactive && "stat-tile--interactive",
				className,
			)}
		>
			<div className="mb-1 flex items-center gap-2">
				{icon && (
					<MetricIcon name={icon} size={26} onInverse={variant === "inverse"} />
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
			<p className={cn("t-metric", valueCls)}>{value}</p>
			{sub && <p className={cn("mt-0.5 text-[11px]", subCls)}>{sub}</p>}
		</div>
	);
}
