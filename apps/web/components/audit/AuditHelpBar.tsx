/** Supporting references, kept below the evidence and its next action. */
export function AuditHelpBar({ exportEntitled }: { exportEntitled: boolean }) {
	return (
		<nav
			aria-label="Audit help"
			className="flex flex-wrap gap-x-5 gap-y-3 text-xs text-ink-2"
		>
			<a
				className="underline underline-offset-4"
				href="https://docs.tracelane.dev/audit-ledger"
			>
				Verification guide ↗
			</a>
			<a className="underline underline-offset-4" href="/support">
				Get help with evidence
			</a>
			{exportEntitled && (
				<a className="underline underline-offset-4" href="/api/audit/handbook">
					Evidence handbook (PDF)
				</a>
			)}
		</nav>
	);
}
