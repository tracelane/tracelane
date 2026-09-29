/** Retains the existing component entry point for the workspace override state. */
export function AuditSalesSurface() {
	return (
		<section className="surface-card p-6" aria-live="polite">
			<h2 className="text-xl font-semibold">
				Ledger viewing is disabled for this workspace
			</h2>
			<p className="mt-3 max-w-2xl text-sm text-ink-2">
				Viewing and checking the ledger is included on every plan, but access is
				switched off here. No integrity verdict is available.
			</p>
			<a
				href="/support"
				className="mt-5 inline-block text-sm font-medium underline underline-offset-4"
			>
				Ask support about workspace access →
			</a>
		</section>
	);
}
