/**
 * Route-level loading skeleton for /slo — the shape the page actually lands in.
 *
 * IT MUST MIRROR THE REAL LAYOUT, which is the only reason to have one at all: a
 * skeleton that shapes nothing like the page it precedes is a flash of the wrong
 * furniture, and the reader watches the layout jump rather than fill in. This
 * tracks the P1 layout — an 8/4 split (two stacked metric strips beside the dark
 * burn-rate card), the disclosure strip, the latency card, then the table — and
 * it has to move whenever `page.tsx` moves.
 *
 * Every block carries `--radius-card`, the same radius `.stat-tile` and
 * `.surface-card` set, so the corners do not jump when the real cards land.
 */

import { Skeleton } from "@tracelanedev/ui";

export default function Loading() {
	return (
		<div className="space-y-8 px-1 py-2 sm:px-2 sm:py-4 lg:px-3">
			<Skeleton className="h-8 w-40" />
			<div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
				<div className="flex flex-col gap-4 lg:col-span-8">
					<Skeleton className="h-28 w-full rounded-[var(--radius-card)]" />
					<Skeleton className="h-28 w-full rounded-[var(--radius-card)]" />
				</div>
				<Skeleton className="h-60 w-full rounded-[var(--radius-card)] lg:col-span-4" />
			</div>
			<Skeleton className="h-11 w-full rounded-lg" />
			<Skeleton className="h-72 w-full rounded-[var(--radius-card)]" />
			<Skeleton className="h-56 w-full rounded-[var(--radius-card)]" />
		</div>
	);
}
