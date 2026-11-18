/**
 * Existing, documented ways to capture a first trace. Do not claim gateway
 * routing alone captures nested planner/tool steps; SDK or OTLP does that.
 * SDK/OTLP-only spans are not automatically part of the signed gateway ledger.
 */
export const CONNECTION_PATHS = [
	{
		title: "Route an existing model client",
		href: "https://docs.tracelane.dev/quickstart",
		detail:
			"Use the examples above. Gateway routing records model calls without changing your LLM SDK.",
	},
	{
		title: "Instrument a Python agent",
		href: "https://docs.tracelane.dev/sdk-python",
		detail:
			"Initialize the Python SDK and instrument the agent steps you need. The key needs the ingest scope.",
	},
	{
		title: "Instrument a TypeScript agent",
		href: "https://docs.tracelane.dev/sdk-typescript",
		detail:
			"Initialize the TypeScript SDK to capture nested agent and tool spans beyond one model call.",
	},
	{
		title: "Use an existing OTLP exporter",
		href: "https://docs.tracelane.dev/sdk-python",
		detail:
			"For hosted workspaces, POST OTLP/HTTP to {gateway}/v1/traces with an ingest-scoped key. The Python SDK guide documents the hosted endpoint and key scope.",
	},
] as const;

export function ConnectionPathPicker() {
	return (
		<section
			className="space-y-3 border-t border-line pt-5"
			aria-labelledby="connection-path-title"
		>
			<div>
				<h3
					id="connection-path-title"
					className="text-sm font-semibold text-ink"
				>
					Want to capture more than a model call?
				</h3>
				<p className="mt-1 text-xs text-ink-2">
					The examples above route model calls through the gateway. Choose a
					setup guide if you already instrument your agent or send OTLP.
				</p>
			</div>
			<div className="grid gap-2 sm:grid-cols-2">
				{CONNECTION_PATHS.map((path) => (
					<a
						key={path.title}
						href={path.href}
						target="_blank"
						rel="noopener noreferrer"
						className="rounded-card border border-line bg-surface p-3 transition-colors hover:bg-surface-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
					>
						<span className="text-sm font-medium text-action-ink">
							{path.title} ↗
						</span>
						<span className="mt-1 block text-xs leading-relaxed text-ink-2">
							{path.detail}
						</span>
					</a>
				))}
			</div>
			<p className="text-xs text-ink-3">
				SDK/OTLP-only spans can be viewed as traces but are not automatically
				chained into the gateway-admitted audit ledger.
			</p>
		</section>
	);
}
