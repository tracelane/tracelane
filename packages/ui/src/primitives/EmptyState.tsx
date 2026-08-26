import type { ReactNode } from "react";
import { cn } from "../lib/cn";

export interface EmptyStateProps {
	/**
	 * A monochrome glyph. Rendered inside a `--surface-2` chip — the SAME inert
	 * well every other icon in the system sits in (P0.12), so an empty state is
	 * recognisably part of the app rather than a placeholder graphic.
	 */
	icon?: ReactNode;
	title: string;
	/** Guide the next action ("send your first trace →"), never a dead end. */
	description?: string;
	action?: ReactNode;
	/**
	 * A very subtle placeholder VISUALISATION of the shape that would be here —
	 * a ghosted axis, a few flat rows, an outline of the chart this card draws
	 * when it has data. Rendered behind the copy at low opacity and `aria-hidden`.
	 *
	 * THE CALLER SUPPLIES THE SHAPE, AND THAT IS A HARD BOUNDARY. This component
	 * will never synthesise one, because the only way to draw a convincing ghost
	 * chart from inside a primitive is to invent numbers, and a dashboard whose
	 * whole claim is full-fidelity capture cannot render fake data — not even at
	 * 10% opacity, not even labelled. Pass an empty grid, an axis, a silhouette;
	 * never a plausible series.
	 */
	ghost?: ReactNode;
	/**
	 * Tighter box for in-grid / no-data tiles (e.g. a dashboard card's "No tool
	 * calls yet"). Halves the vertical padding so an empty tile doesn't eat the
	 * frame; full-page first-run states keep the roomy default.
	 */
	compact?: boolean;
	/**
	 * `inline` — one muted line, left-aligned, NO centring, NO block.
	 *
	 * THE RULE, written here so nobody re-adds a frame "for consistency":
	 * AN EMPTY STATE INSIDE A BORDERED, TITLED CARD IS ALREADY FRAMED, AND A
	 * SECOND FRAME IS NOISE.
	 *
	 * Measured before this existed: 42 call sites, and a zero-traffic dashboard drew
	 * eight dashed boxes nested inside eight bordered cards that each already carried
	 * an icon and a title. Four other surfaces had quietly hand-rolled this exact
	 * muted line rather than use the primitive, which is the tell that the variant was
	 * missing rather than unwanted.
	 *
	 * WHAT CHANGED ON 2026-08-22, and why the rule above survives it: the FULL
	 * variant no longer draws a dashed box either (P0.9 — "empty states should not
	 * look like broken placeholders"), so neither variant frames itself now. The
	 * distinction is no longer border-vs-no-border, it is BLOCK vs LINE: `inline`
	 * costs one row inside a card that has its own title; the full variant is a
	 * centred block for a surface where the empty state IS the page.
	 *
	 * `compact` only tightens the padding; it does not collapse the block.
	 */
	inline?: boolean;
	className?: string;
}

/**
 * Empty state for any surface a user lands on before data. Their absence is the
 * #2 toy tell (after the filter bar) — every surface ships one.
 *
 * ── THE DASHED BOX IS GONE (P0.9, 2026-08-22) ───────────────────────────────
 *
 * The full variant rendered `rounded-xl border border-dashed border-line
 * bg-surface/40`. A dashed rectangle is the universal visual idiom for "content
 * failed to load" — it is what a broken image, an unmounted region and a
 * drag-and-drop target all look like — so the one screen a new user sees FIRST
 * was telling them the product was broken. The brief names it directly: do not
 * use large dashed rectangles everywhere.
 *
 * What replaces it is nothing: a calm centred block on the surface it already
 * sits on. An icon in the standard `--surface-2` chip, a statement in primary
 * ink at body size, an explanation in secondary ink at 12px on a ~50-character
 * measure, then the action. The hierarchy does the work the border was doing
 * badly, and the state reads as a considered screen rather than a hole.
 *
 * `bg-surface/40` went with it. A 40%-opaque white over an unknown parent is not
 * a colour anyone chose — on the canvas it is off-white, on a card it is
 * invisible, and inside a dark card it is a grey smear.
 */
export function EmptyState({
	icon,
	title,
	description,
	action,
	ghost,
	compact,
	inline,
	className,
}: EmptyStateProps) {
	if (inline) {
		// One line. No border, no background, no centring, no icon — the enclosing card
		// supplies all four. The description follows on the same line as a middot clause
		// rather than stacking, so an empty tile costs one row instead of a block.
		// `text-xs`, not `text-sm` (founder, 2026-08-18). At `sm` these explanations
		// wrapped to two full-width lines inside their card and read as the card's
		// CONTENT rather than as a placeholder for absent content — on a
		// zero-traffic dashboard that is nine cards all shouting. `[&_a]:text-xs`
		// pulls the trailing action link down with the sentence it sits in;
		// otherwise the link keeps the `text-sm` its call site sets and ends up
		// larger than the copy it follows.
		return (
			<p className={cn("text-xs text-ink-3 [&_a]:text-xs", className)}>
				{title}
				{description ? (
					<span className="text-ink-3"> · {description}</span>
				) : null}
				{action ? <span className="ml-2">{action}</span> : null}
			</p>
		);
	}
	return (
		<div
			className={cn(
				"relative flex flex-col items-center justify-center text-center",
				compact ? "gap-2 px-4 py-6" : "gap-3 px-6 py-10",
				className,
			)}
		>
			{/* The caller's placeholder shape, if it supplied one. Absolutely
			    positioned so it occupies no layout — an empty state must be the same
			    height with and without a ghost, or a grid of cards would jump as
			    individual tiles gained data. `opacity-10` is low enough that it reads
			    as texture rather than as content a user might try to read. */}
			{ghost && (
				<div
					aria-hidden="true"
					className="pointer-events-none absolute inset-0 flex items-center justify-center overflow-hidden opacity-10"
				>
					{ghost}
				</div>
			)}
			{/* `relative` lifts the copy above the ghost without a z-index scale. */}
			{icon && (
				<span
					aria-hidden="true"
					className="relative grid h-9 w-9 place-items-center rounded-xl bg-surface-2 text-ink-2"
				>
					{icon}
				</span>
			)}
			<div className="relative space-y-1">
				{/* A calm statement, in primary ink. The COPY is the caller's — this
				    component styles it and never rewrites it. */}
				<p className="text-sm font-medium text-ink">{title}</p>
				{description && (
					// `text-xs` + `max-w-xs`: ~50 characters a line, which is a
					// comfortable measure for two sentences of explanation. At `text-sm`
					// on `max-w-sm` this block read as body copy and competed with the
					// title above it.
					<p className="mx-auto max-w-xs text-xs text-ink-2">{description}</p>
				)}
			</div>
			{action && <div className="relative">{action}</div>}
		</div>
	);
}
