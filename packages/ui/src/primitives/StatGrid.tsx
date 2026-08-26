import type { ReactNode } from "react";
import { cn } from "../lib/cn";

/**
 * StatGrid — the ONE layout for a row of metric tiles.
 *
 * WHY THIS EXISTS. Before it, every surface hand-wrote its own
 * `grid grid-cols-2 lg:grid-cols-4 gap-3` (and some `gap-4`, and one `md:grid-cols-3`),
 * so tiles were a different size and a different distance apart on Dashboard, SLO,
 * Gateway and Guardrails — five reimplementations of one row. The tiles themselves were
 * already shared via `StatCard`; the LAYOUT was not, which is why the surfaces still
 * failed to read as one system.
 *
 * `items-stretch` is the load-bearing part. Combined with `StatCard`'s `h-full flex-col`,
 * it is what makes values land on a common baseline across a row instead of drifting with
 * whichever tile happens to carry a sub-line.
 *
 * GROUPING IS A FIRST-CLASS ARGUMENT. A dashboard that shows twelve numbers in one
 * undifferentiated wall makes the reader do the grouping. `title` renders a section
 * label in the same grammar as the sidebar's groups, so related metrics read as
 * related — "Traffic", "Reliability", "Cost" — rather than as twelve equal facts.
 *
 * TWO SPACING/TYPE CHANGES ON 2026-08-22 (P0.8 / P0.15):
 *  · The group title is `.t-eyebrow` — the ONE definition of a section label
 *    (12px/600/0.10em uppercase on `--ink-2`). It was four inline utilities at
 *    11px/0.06em on `--ink-3`, i.e. a private near-copy of the eyebrow that drifted
 *    a size, a tracking step and a tone away from every other section label in the
 *    app. A type role that exists in two places is a type role that will disagree.
 *  · The tile gap is `gap-4`, not `gap-2`. P0.15 puts card gaps at 16–20px; at
 *    `gap-2` (8px) a 4-up row read as one segmented control rather than as four
 *    cards, which is most of why the metric strip looked cramped beside the 20px
 *    card padding inside each tile. The header-to-grid gap goes to `gap-3` with it,
 *    so the eyebrow has air under it instead of sitting on the first tile.
 */

export interface StatGridProps {
	children: ReactNode;
	/** Section label, rendered with `.t-eyebrow`. Omit for an ungrouped row. */
	title?: ReactNode;
	/** Optional right-aligned affordance on the group header (a link, a range control). */
	action?: ReactNode;
	/**
	 * Tiles per row at the widest breakpoint. Below `lg` the grid always steps down to
	 * 2 and then 1, because a 4-up row of metric tiles on a phone is four unreadable
	 * slivers. Default 4.
	 */
	cols?: 2 | 3 | 4 | 5 | 6;
	className?: string;
}

const COLS: Record<NonNullable<StatGridProps["cols"]>, string> = {
	2: "sm:grid-cols-2",
	3: "sm:grid-cols-2 lg:grid-cols-3",
	4: "sm:grid-cols-2 lg:grid-cols-4",
	5: "sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5",
	// 6 — for a dense metric strip. At 1440px a 3-up row of short tiles leaves most
	// of each tile empty to the right of its value; six squarer tiles carry the same
	// information in the same height and read as an instrument panel rather than
	// three billboards.
	6: "sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6",
};

export function StatGrid({
	children,
	title,
	action,
	cols = 4,
	className,
}: StatGridProps) {
	return (
		<section className={cn("flex flex-col gap-3", className)}>
			{(title || action) && (
				<div className="flex min-h-5 items-center justify-between gap-3">
					{title ? <h2 className="t-eyebrow">{title}</h2> : <span />}
					{action}
				</div>
			)}
			<div className={cn("grid items-stretch gap-4 grid-cols-1", COLS[cols])}>
				{children}
			</div>
		</section>
	);
}
