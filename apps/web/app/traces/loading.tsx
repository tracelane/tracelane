/**
 * Route-level loading skeleton for /traces — shows instantly on navigation
 * (the shell), while the page's inner Suspense streams the real rows.
 */

import { Skeleton } from "@tracelanedev/ui";

const ROWS = ["a", "b", "c", "d", "e", "f", "g", "h"];

export default function Loading() {
	return (
		<main className="p-6">
			<Skeleton className="h-7 w-40" />
			<Skeleton className="mt-4 h-10 w-full max-w-2xl" />
			<div className="mt-4 space-y-2">
				{ROWS.map((id) => (
					<Skeleton key={id} className="h-12 w-full" />
				))}
			</div>
		</main>
	);
}
