"use client";
import { PageHeader } from "@tracelanedev/ui";

import { Button } from "@tracelanedev/ui";

export default function AuditError({
	reset,
}: { error: Error & { digest?: string }; reset: () => void }) {
	return (
		<section className="surface-card m-4 p-6" role="alert">
			<PageHeader title={<>Audit evidence is unavailable</>} />
			<p className="my-3 text-sm text-ink-2">
				The page could not finish loading. Ledger integrity is unknown here.
			</p>
			<div className="flex flex-wrap items-center gap-4">
				<Button onClick={reset}>Retry loading evidence</Button>
				<a href="/support" className="text-sm underline">
					Contact support
				</a>
			</div>
		</section>
	);
}
