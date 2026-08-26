/**
 * Trace-scoped 404 — rendered when the trace-detail page calls `notFound()`
 * (the gateway returned its tenant-safe 404 for a missing/foreign trace).
 * Existence never leaks: "missing" and "not your workspace" look identical.
 */

import Link from "next/link";

export default function TraceNotFound() {
	return (
		<div className="p-6">
			<div className="mx-auto max-w-md py-16 text-center">
				{/* `--ink-3`, matching the root 404. The numeral is decoration, not an
				    action and not a datum, so it takes the quietest tone and the
				    sentence beneath it leads. */}
				<p className="font-mono text-5xl font-semibold leading-none text-ink-3">
					404
				</p>
				<h1 className="t-h1 mt-3">Trace not found</h1>
				<p className="mt-1.5 text-sm text-ink-2">
					This trace doesn&apos;t exist, has expired, or isn&apos;t in your
					workspace.
				</p>
				<div className="mt-6">
					<Link
						href="/traces"
						className="inline-flex h-9 items-center rounded-lg border border-line bg-surface px-4 text-sm font-medium text-ink transition-colors hover:bg-surface-2"
					>
						← All traces
					</Link>
				</div>
			</div>
		</div>
	);
}
