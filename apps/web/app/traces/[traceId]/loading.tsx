/**
 * Route-level loading skeleton for /traces/[traceId] — the trace-detail shell
 * (back link + transcript spine placeholder) while spans stream in.
 */

import { Skeleton } from "@tracelanedev/ui";

const SPANS = ["a", "b", "c", "d", "e", "f"];

export default function Loading() {
	return (
		<main className="p-6">
			<div className="mb-6 flex items-center gap-3">
				<Skeleton className="h-4 w-16" />
				<Skeleton className="h-6 w-64" />
			</div>
			<div className="space-y-1.5">
				{SPANS.map((id, i) => (
					<Skeleton
						key={id}
						className="h-9"
						style={{ width: `${92 - i * 9}%` }}
					/>
				))}
			</div>
		</main>
	);
}
