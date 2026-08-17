import type { ReactNode } from "react";
import { cn } from "../lib/cn";

export interface EmptyStateProps {
	icon?: ReactNode;
	title: string;
	/** Guide the next action ("send your first trace →"), never a dead end. */
	description?: string;
	action?: ReactNode;
	/**
	 * Tighter box for in-grid / no-data tiles (e.g. a dashboard card's "No tool
	 * calls yet"). Halves the vertical padding so an empty tile doesn't eat the
	 * frame; full-page first-run states keep the roomy default.
	 */
	compact?: boolean;
	/**
	 * `inline` — one muted line, left-aligned, NO border, NO centring.
	 *
	 * THE RULE, written here so nobody re-adds the border "for consistency":
	 * AN EMPTY STATE INSIDE A BORDERED, TITLED CARD IS ALREADY FRAMED, AND A SECOND
	 * DASHED FRAME IS NOISE. A full-page first-run state keeps the box, because there
	 * the box IS the frame — it is the only thing giving the message an edge.
	 *
	 * Measured before this existed: 42 call sites, and a zero-traffic dashboard drew
	 * eight dashed boxes nested inside eight bordered cards that each already carried
	 * an icon and a title. Four other surfaces had quietly hand-rolled this exact
	 * muted line rather than use the primitive, which is the tell that the variant was
	 * missing rather than unwanted.
	 *
	 * `compact` only halves the padding; it keeps the box. This removes it.
	 */
	inline?: boolean;
	className?: string;
}

/**
 * Empty state for any surface a user lands on before data. Their absence is the
 * #2 toy tell (after the filter bar) — every surface ships one.
 */
export function EmptyState({
	icon,
	title,
	description,
	action,
	compact,
	inline,
	className,
}: EmptyStateProps) {
	if (inline) {
		// One line. No border, no background, no centring, no icon — the enclosing card
		// supplies all four. The description follows on the same line as a middot clause
		// rather than stacking, so an empty tile costs one row instead of a block.
		return (
			<p className={cn("text-sm text-ink-3", className)}>
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
				"flex flex-col items-center justify-center rounded-xl border border-dashed border-line bg-surface/40 text-center",
				compact ? "gap-2 px-4 py-6" : "gap-3 px-6 py-12",
				className,
			)}
		>
			{icon && (
				<div className="text-ink-3" aria-hidden>
					{icon}
				</div>
			)}
			<div className="space-y-1">
				<p className="text-sm font-medium text-ink">{title}</p>
				{description && (
					<p className="mx-auto max-w-sm text-[13px] text-ink-2">
						{description}
					</p>
				)}
			</div>
			{action}
		</div>
	);
}
