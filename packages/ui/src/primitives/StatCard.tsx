import type { ReactNode } from "react";
import { cn } from "../lib/cn";

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

export interface StatCardProps {
	/** Micro uppercase label. */
	label: ReactNode;
	/** The metric — rendered large, tabular-nums, tone-colored. */
	value: ReactNode;
	/** Tone for the value (color + meaning; never color alone — pair with copy). */
	tone?: StatTone;
	/** Secondary line under the value (context / denominator / "1.0× = on pace"). */
	sub?: ReactNode;
	/** Native tooltip on the label (jargon → plain language) + a `?` affordance. */
	hint?: string;
	/** Lift-on-hover + pointer — set when the tile is wrapped in a link/button. */
	interactive?: boolean;
	className?: string;
}

const TONE: Record<StatTone, string> = {
	default: "text-ink",
	ok: "text-ok",
	warn: "text-warn",
	danger: "text-danger",
};

export function StatCard({
	label,
	value,
	tone = "default",
	sub,
	hint,
	interactive,
	className,
}: StatCardProps) {
	return (
		<div
			title={hint}
			className={cn(
				"stat-tile p-4",
				interactive && "stat-tile--interactive",
				className,
			)}
		>
			<p className="mb-1 flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wide text-ink-3">
				{label}
				{hint && (
					<span
						aria-hidden
						className="grid h-3 w-3 place-items-center rounded-full border border-line-2 text-[8px] text-ink-3"
					>
						?
					</span>
				)}
			</p>
			<p className={cn("text-2xl font-semibold tabular-nums", TONE[tone])}>
				{value}
			</p>
			{sub && <p className="mt-0.5 text-[11px] text-ink-3">{sub}</p>}
		</div>
	);
}
