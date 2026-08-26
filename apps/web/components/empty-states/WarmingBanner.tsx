/**
 * WarmingBanner — shown when ClickHouse is unreachable (a connection failure),
 * which is distinct from the zero-data empty-state. It reassures that trace
 * storage is still coming online rather than surfacing the error card; pages
 * pair it with their normal empty-state below.
 *
 * Server component (static markup, no client state).
 */

export function WarmingBanner() {
	return (
		/*
		 * `--warn-soft` fill + `--warn-ink` text — the pair tokens.css defines as
		 * AA-cleared in both themes. It was `bg-warn/5` with `text-warn-ink/90`:
		 * a 5% wash of the FILL token over whatever happens to be behind it, and
		 * a 90% ink that is a colour nobody chose. `-soft` exists so a notice does
		 * not have to invent its own tint. Radius stays on the control band —
		 * this is a full-width notice strip, and a 18px card radius on a 44px-tall
		 * bar reads as a pill.
		 */
		<div className="mb-6 flex items-center gap-2 rounded-lg border border-warn/30 bg-warn-soft px-4 py-3 text-sm text-warn-ink">
			<svg
				aria-hidden="true"
				className="h-4 w-4 shrink-0"
				fill="none"
				viewBox="0 0 24 24"
				stroke="currentColor"
				strokeWidth={1.5}
			>
				<path
					strokeLinecap="round"
					strokeLinejoin="round"
					d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z"
				/>
			</svg>
			<span>
				Trace storage is warming up — your data will appear here shortly.
			</span>
		</div>
	);
}
