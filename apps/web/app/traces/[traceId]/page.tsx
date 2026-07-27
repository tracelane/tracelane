/**
 * Trace detail page — full-fidelity view of a single trace.
 *
 * Fetches all spans for the trace from ClickHouse and renders the
 * transcript-with-a-spine viewer (narrative order, color-coded span kinds,
 * the hash-chain thread, the seen-before signal) plus the span inspector
 * panel showing LLM attributes (model, token counts, and the real stored
 * `gen_ai_usage_cost` in USD) and guardrail interventions.
 *
 * Cost is read as-stored (the gateway derives it from the model price catalog
 * or a provider-reported cost); it is NEVER derived or fabricated on the
 * dashboard, and shows blank when the model isn't priced (V-1 honesty note).
 */

import { WarmingBanner } from "@/components/empty-states/WarmingBanner";
import { ChainStatusChip } from "@/components/trace-viewer/ChainStatusChip";
import { CopyButton } from "@/components/trace-viewer/CopyButton";
import { TraceDetailView } from "@/components/trace-viewer/TraceDetailView";
import type { Span } from "@/components/trace-viewer/types";
import { GatewayError, gatewayGetOrNull } from "@/lib/gateway";
import { EmptyState, Skeleton } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Suspense } from "react";

interface Props {
	params: Promise<{ traceId: string }>;
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
	const { traceId } = await params;
	return { title: `Trace ${traceId.slice(0, 8)}… — Tracelane` };
}

async function SpanData({ traceId }: { traceId: string }) {
	let spans: Span[];
	try {
		// gateway's 404 — the SAME response for "trace missing" and "not this
		// tenant's", so existence never leaks across tenants.
		const result = await gatewayGetOrNull<Span[]>(
			`/v1/traces/${encodeURIComponent(traceId)}/spans`,
		);
		if (result === null) {
			// Gateway 404 — the SAME response for "trace missing" and "not this
			// tenant's", so existence never leaks. A 404 page is consistent with
			// that (renders the [traceId] not-found.tsx).
			notFound();
		}
		spans = result;
	} catch (err) {
		// Gateway unreachable → warming banner instead of the error card.
		// Re-throw anything else (incl. NEXT_REDIRECT from the auth helper).
		if (err instanceof GatewayError) {
			return (
				<>
					<WarmingBanner />
					<EmptyState
						title="Waiting on trace storage"
						description="Spans will appear here once trace storage is reachable."
					/>
				</>
			);
		}
		throw err;
	}

	if (spans.length === 0) {
		// Trace exists (gateway returned 200 with []) but has no spans yet — an
		// empty state, NOT a 404 (which is the result === null path above).
		return (
			<EmptyState
				title="No spans for this trace yet"
				description="This trace exists but hasn't recorded any spans. They'll appear here as the agent runs."
			/>
		);
	}

	return <TraceDetailView spans={spans} />;
}

// Queries ClickHouse at request time — never prerender.
export const dynamic = "force-dynamic";

export default async function TraceDetailPage({ params }: Props) {
	const { traceId } = await params;

	return (
		<main className="p-6">
			<div className="mb-6 flex items-center gap-3">
				<Link
					href="/traces"
					className="shrink-0 text-sm text-ink-2 transition-colors hover:text-ink"
				>
					← Traces
				</Link>
				{/* Trace ID is a hex identifier — mono font is correct here. */}
				<h1 className="min-w-0 flex-1 truncate font-mono text-xl font-semibold text-ink">
					{traceId}
				</h1>
				<div className="flex shrink-0 items-center gap-1.5">
					{/* ChainStatusChip is async (server fetch). Suspense fallback is a
					    placeholder skeleton — sized to match the chip — so the header
					    layout does not reflow when the ledger status resolves. */}
					<Suspense fallback={<Skeleton className="h-6 w-40 rounded-md" />}>
						<ChainStatusChip traceId={traceId} />
					</Suspense>
					<CopyButton value={traceId} label="Copy ID" />
					<CopyButton copyLocation label="Copy link" />
				</div>
			</div>
			<Suspense
				fallback={
					<div className="space-y-1.5">
						<Skeleton className="h-9 w-[92%]" />
						<Skeleton className="h-9 w-[83%]" />
						<Skeleton className="h-9 w-[74%]" />
					</div>
				}
			>
				<SpanData traceId={traceId} />
			</Suspense>
		</main>
	);
}
