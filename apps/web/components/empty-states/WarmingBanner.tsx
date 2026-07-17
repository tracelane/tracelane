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
		<div className="mb-6 flex items-center gap-2 rounded-lg border border-warn/30 bg-warn/5 px-4 py-3 text-sm text-warn/90">
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
