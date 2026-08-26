/**
 * Route-level loading skeleton for /audit. Unlike /traces and /slo, the audit
 * page awaits the gateway ledger export inline (no inner Suspense), so this is
 * the page's only loading feedback on navigation — the verify card + chain rows.
 *
 * The block that stands in for the verify CARD carries `--radius-card`, not
 * `rounded-xl`. A skeleton's whole job is to be the same shape as the thing that
 * replaces it; at 12px against the card's 16–20px the corner visibly popped on
 * every navigation.
 */

import { Skeleton } from "@tracelanedev/ui";

const ROWS = ["a", "b", "c", "d", "e", "f", "g", "h"];

export default function Loading() {
	return (
		<div className="mx-auto max-w-5xl p-6">
			<div className="mb-6">
				<Skeleton className="h-8 w-48" />
				<Skeleton className="mt-2 h-4 w-96 max-w-full" />
			</div>
			<Skeleton className="h-28 w-full rounded-[var(--radius-card)]" />
			<Skeleton className="mt-6 h-5 w-40" />
			<div className="mt-2 space-y-1.5">
				{ROWS.map((id) => (
					<Skeleton key={id} className="h-10 w-full" />
				))}
			</div>
		</div>
	);
}
