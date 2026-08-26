import type { CSSProperties, ReactNode } from "react";
import { cn } from "../lib/cn";

/**
 * MetricIcon — the ONE monochrome icon chip shared across every metric card /
 * tile (Dashboard KPIs + section headers, then SLO / Gateway / Signatures /
 * Billing). A single component so the icon language reads as one system, not a
 * per-page snowflake.
 *
 * ── LOOK (P0.12) ────────────────────────────────────────────────────────────
 *
 * A `--surface-2` WELL with a single-colour line icon inside at stroke 1.6 —
 * thinned from 1.75 so the glyph reads lean rather than chunky at 13–18px. The
 * icon is `currentColor` = `--ink`, never grey; a greyed glyph read as disabled
 * next to the figure it labels. Both tokens flip with the theme, so the chip
 * inverts automatically.
 *
 * THE COLOUR NOTE IN THIS BLOCK WAS WRONG AND IS CORRECTED (2026-08-22). It said
 * "a circular soft-BLUE well (`--surface-2` = #eef3fa light)". `--surface-2` is
 * #f5f5f4 — a warm neutral — and has been since the P0 palette landed; #eef3fa
 * was the value under the retired tinted-slate system. The CODE was already
 * right (`bg-surface-2` + `currentColor` is exactly what P0.12 asks for); only
 * this comment still described a blue chip, which is precisely the doc-vs-code
 * defect CLAUDE.md §17 makes a bug. The stale sentence about lava rationing went
 * with it — lava is deleted from the system.
 *
 * SHAPE: a SQUIRCLE, not a circle, and the radius is PROPORTIONAL (30% of the
 * chip). The decision, since both are defensible:
 *   · The system's corner language is a generously rounded rectangle — 18px on
 *     cards, 8px on controls. A perfect circle belongs to neither family and
 *     reads as an avatar or a consumer-app badge sitting on an instrument panel.
 *   · A squircle presents more area at the same nominal size, so the glyph can
 *     stay at 50% and still read at 28px.
 *   · The radius is computed rather than a `rounded-*` utility BECAUSE the chip
 *     is sized in px: a fixed 8px radius is a near-circle at 18px and a hard
 *     square at 36px, i.e. a different shape at each call site. 30% holds one
 *     shape across the 18–36px range the app actually uses.
 * It is spent as an inline style for the same reason width/height are — the
 * component adds no new utility classes to the CSS bundle.
 *
 * On a dark CARD (the error-budget tile, which is `--surface-inverse` regardless
 * of theme) pass `onInverse` to flip the chip to a subtle white wash + inverse
 * ink so the icon still reads. `bg-white/10` is a translucent WASH rather than a
 * token because the system has no "well on an inverse surface" role: `--surface-2`
 * is a light grey in light theme and would paint a bright chip on a near-black
 * card. Stated here rather than left to be rediscovered.
 *
 * Icons are hand-authored inline SVG (24×24, stroke-only) — no icon-library
 * dependency, no bundle cost beyond the single glyph rendered. Decorative: the
 * chip always carries the card's real text label, so it is `aria-hidden`.
 *
 * @example
 *   <MetricIcon name="llm-calls" />                 // 36px KPI chip
 *   <MetricIcon name="time" size={28} />            // 28px section-header chip
 *   <MetricIcon name="error-budget" size={28} onInverse />  // on a dark card
 */

/** The metric each chip labels. One name per dashboard tile + the propagation set. */
export type MetricIconName =
	| "llm-calls"
	| "tokens"
	| "spend"
	| "time"
	| "traffic"
	| "latency"
	| "error-budget"
	| "request-flow"
	| "model-breakdown"
	| "agent-execution"
	| "failure-signatures"
	| "tool-usage"
	| "guardrail"
	| "provider";

/**
 * The inner geometry for each icon (the chip + <svg> wrapper is shared). Every
 * glyph is stroke-only on a 24×24 grid so a single `currentColor` colors it.
 */
const GLYPH: Record<MetricIconName, ReactNode> = {
	// waveform — LLM calls / signal volume
	"llm-calls": (
		<>
			<path d="M4 10v4" />
			<path d="M8 6v12" />
			<path d="M12 9v6" />
			<path d="M16 4v16" />
			<path d="M20 10v4" />
		</>
	),
	// stacked layers — tokens
	tokens: (
		<>
			<path d="M12 3 3 8l9 5 9-5-9-5Z" />
			<path d="M3 13l9 5 9-5" />
		</>
	),
	// dollar in a circle — spend
	spend: (
		<>
			<circle cx="12" cy="12" r="9" />
			<path d="M12 7v10" />
			<path d="M14.6 9.3c0-1-1.2-1.8-2.6-1.8s-2.6.8-2.6 1.9c0 2.6 5.2 1.4 5.2 4 0 1.1-1.2 1.9-2.6 1.9s-2.6-.8-2.6-1.8" />
		</>
	),
	// clock — where the time goes
	time: (
		<>
			<circle cx="12" cy="12" r="9" />
			<path d="M12 7v5l3.5 2" />
		</>
	),
	// line chart with axes — traffic over time
	traffic: (
		<>
			<path d="M4 4v16h16" />
			<path d="M7 14l3.5-4 3 2.5L21 8" />
		</>
	),
	// ecg pulse — latency
	latency: <path d="M3 12h4l2.5 6 4-13 2.5 7H21" />,
	// speedometer gauge + needle — error budget / burn
	"error-budget": (
		<>
			<path d="M4.5 17.5a8 8 0 1 1 15 0" />
			<path d="M12 17l3.5-3.5" />
		</>
	),
	// git-branch — request flow
	"request-flow": (
		<>
			<circle cx="6" cy="5" r="2" />
			<circle cx="6" cy="19" r="2" />
			<circle cx="18" cy="8" r="2" />
			<path d="M6 7v10" />
			<path d="M18 10a6 6 0 0 1-6 6H9" />
		</>
	),
	// concentric target rings — model breakdown
	"model-breakdown": (
		<>
			<circle cx="12" cy="12" r="9" />
			<circle cx="12" cy="12" r="5" />
			<circle cx="12" cy="12" r="1.5" />
		</>
	),
	// two nodes + connector — agent execution
	"agent-execution": (
		<>
			<rect x="3" y="4" width="6.5" height="6.5" rx="1.5" />
			<rect x="14.5" y="13.5" width="6.5" height="6.5" rx="1.5" />
			<path d="M9.5 7.25h4.25a3 3 0 0 1 3 3v3.25" />
		</>
	),
	// shield — failure signatures
	"failure-signatures": (
		<path d="M12 3l7.5 3v5.2c0 4.6-3.2 7.6-7.5 9.3-4.3-1.7-7.5-4.7-7.5-9.3V6l7.5-3Z" />
	),
	// package / box — tool usage
	"tool-usage": (
		<>
			<path d="M20.5 8 12 3.2 3.5 8v8L12 20.8 20.5 16Z" />
			<path d="M3.5 8 12 12.8 20.5 8" />
			<path d="M12 12.8V20.8" />
		</>
	),
	// shield with checkmark — guardrail activity
	guardrail: (
		<>
			<path d="M12 3l7.5 3v5.2c0 4.6-3.2 7.6-7.5 9.3-4.3-1.7-7.5-4.7-7.5-9.3V6l7.5-3Z" />
			<path d="M8.5 12l2.3 2.3 4.7-4.6" />
		</>
	),
	// server rack rows + status dots — provider health
	provider: (
		<>
			<rect x="3" y="4" width="18" height="6" rx="1.5" />
			<rect x="3" y="14" width="18" height="6" rx="1.5" />
			<path d="M7 7h.01" />
			<path d="M7 17h.01" />
		</>
	),
};

export interface MetricIconProps {
	/** Which metric the chip labels — picks the glyph. */
	name: MetricIconName;
	/** Chip diameter in px; the icon scales to half. Default 36 (KPI); use 28 for section headers. */
	size?: number;
	/** On a dark (`--surface-inverse`) card: flip the chip to a white wash + inverse ink. */
	onInverse?: boolean;
	className?: string;
}

/**
 * Renders the chip + line icon for a metric. Pure presentational, no state.
 * Size AND radius are inline styles (not arbitrary Tailwind values) so the
 * component adds no new utility classes to the CSS bundle — and so the corner
 * stays proportional to the chip at every call site (see the header).
 */
export function MetricIcon({
	name,
	size = 36,
	onInverse = false,
	className,
}: MetricIconProps) {
	const icon = Math.round(size * 0.5);
	return (
		<span
			aria-hidden="true"
			className={cn(
				"grid shrink-0 place-items-center",
				// The glyph is INK, never grey — a greyed glyph reads as disabled next
				// to the figure it labels. The chip is the system's inert WELL
				// (--surface-2, a warm neutral #f5f5f4), so the icon reads as a
				// deliberate mark on a container rather than a faded one.
				onInverse ? "bg-white/10 text-ink-inverse" : "bg-surface-2 text-ink",
				className,
			)}
			style={
				{
					width: size,
					height: size,
					borderRadius: Math.round(size * 0.3),
				} as CSSProperties
			}
		>
			<svg
				width={icon}
				height={icon}
				viewBox="0 0 24 24"
				fill="none"
				stroke="currentColor"
				strokeWidth={1.6}
				strokeLinecap="round"
				strokeLinejoin="round"
				role="presentation"
			>
				{GLYPH[name]}
			</svg>
		</span>
	);
}
