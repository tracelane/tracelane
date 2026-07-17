/**
 * Route-level loading skeleton for /audit. Unlike /traces and /slo, the audit
 * page awaits the gateway ledger export inline (no inner Suspense), so this is
 * the page's only loading feedback on navigation — the verify card + chain rows.
 */

import { Skeleton } from "@tracelanedev/ui";

const ROWS = ["a", "b", "c", "d", "e", "f", "g", "h"];

export default function Loading() {
	return (
		<main className="mx-auto max-w-5xl p-6">
			<div className="mb-6">
				<Skeleton className="h-8 w-48" />
				<Skeleton className="mt-2 h-4 w-96 max-w-full" />
			</div>
			<Skeleton className="h-28 w-full rounded-xl" />
			<Skeleton className="mt-6 h-5 w-40" />
			<div className="mt-2 space-y-1.5">
				{ROWS.map((id) => (
					<Skeleton key={id} className="h-10 w-full" />
				))}
			</div>
		</main>
	);
}
