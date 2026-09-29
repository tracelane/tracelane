/** Scope follows gateway admission and the per-trace ledger membership read. */
export function LedgerCoverage() {
	return (
		<div
			className="mb-5 flex flex-wrap gap-x-6 gap-y-1 text-xs text-ink-2"
			aria-label="Ledger coverage"
		>
			<p>
				<strong className="font-medium text-ink">Chained:</strong>{" "}
				gateway-admitted calls and recorded guardrail verdicts.
			</p>
			<p>
				<strong className="font-medium text-ink">Captured, not chained:</strong>{" "}
				SDK/OTLP-only spans.
			</p>
		</div>
	);
}
