/** Supporting references and verification-reading guidance, below the actual evidence. */
export function AuditHelpBar({ exportEntitled }: { exportEntitled: boolean }) {
	return (
		<div className="space-y-3">
			<details className="rounded-control border border-line bg-surface p-3 text-sm">
				<summary className="cursor-pointer font-medium text-ink">
					How to interpret this verification
				</summary>
				<div className="mt-3 space-y-2 text-ink-2">
					<p>
						<strong className="text-ink">1 · Check the scope.</strong> The
						displayed result covers only the rows counted above, the newest in
						the read window, not every agent action or the whole workspace.
					</p>
					<p>
						<strong className="text-ink">2 · Read the trust boundary.</strong>{" "}
						Examine the signing key and any platform-signed or unanchored
						ranges; a checkable chain is not a completeness guarantee.
					</p>
					<p>
						<strong className="text-ink">3 · Examine missing evidence.</strong>{" "}
						Gateway-admitted audit events are distinct from SDK/OTLP-only spans,
						which are captured but not ledger-chained.
					</p>
					<p>
						<strong className="text-ink">4 · Verify independently.</strong>{" "}
						{exportEntitled
							? "Use the documented offline verifier with an exported audit range and the appropriate trust key."
							: "Exporting a range for the documented offline verifier requires the Enterprise plan."}{" "}
						Never interpret an unavailable read as a successful check.
					</p>
					<p className="text-xs">
						This guide does not change, infer, or override the verifier's actual
						status, errors, coverage or entitlement decisions.
					</p>
				</div>
			</details>
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
					<a
						className="underline underline-offset-4"
						href="/api/audit/handbook"
					>
						Evidence handbook (PDF)
					</a>
				)}
			</nav>
		</div>
	);
}
