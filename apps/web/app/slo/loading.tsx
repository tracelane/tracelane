/**
 * Route-level loading skeleton for /slo — the SLO summary cards + panel shell.
 */

import { Skeleton } from "@tracelanedev/ui";

const CARDS = ["a", "b", "c", "d"];

export default function Loading() {
	return (
		<main className="p-6">
			<Skeleton className="h-7 w-48" />
			<div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
				{CARDS.map((id) => (
					<Skeleton key={id} className="h-24 w-full rounded-xl" />
				))}
			</div>
			<Skeleton className="mt-4 h-64 w-full rounded-xl" />
		</main>
	);
}
