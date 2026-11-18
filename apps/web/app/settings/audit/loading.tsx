import { Card } from "@tracelanedev/ui";

export default function Loading() {
	return (
		<div aria-live="polite" aria-busy="true" className="space-y-6">
			<p className="text-sm text-ink-2">Loading audit keys…</p>
			<Card className="space-y-3 p-5" aria-hidden="true">
				<div className="h-4 w-1/2 animate-pulse rounded bg-surface-2" />
				<div className="h-12 animate-pulse rounded bg-surface-2" />
			</Card>
		</div>
	);
}
