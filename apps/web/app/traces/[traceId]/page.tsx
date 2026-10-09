import { PageHeader } from "@tracelanedev/ui";
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

import { Providers } from "@/app/providers";
import { WarmingBanner } from "@/components/empty-states/WarmingBanner";
import { ChainStatusChip } from "@/components/trace-viewer/ChainStatusChip";
import { IncidentPanel } from "@/components/trace-viewer/IncidentPanel";
import { TraceDetailView } from "@/components/trace-viewer/TraceDetailView";
import { TraceFlagPanel } from "@/components/trace-viewer/TraceFlagPanel";
import { TraceHeaderActions } from "@/components/trace-viewer/TraceHeaderActions";
import type { Span } from "@/components/trace-viewer/types";
import { GatewayError, gatewayGet, gatewayGetOrNull } from "@/lib/gateway";
import { getListPageSettings } from "@/lib/list-page-settings";
import { fetchSignaturesFor } from "@/lib/metrics/fetch";
import { parseTimeRange } from "@/lib/metrics/time-range";
import { EmptyState, ErrorState, Skeleton } from "@tracelanedev/ui";
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
		// Gateway-proxied read (Option 1). A null result is the
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
			if (err.status === 403)
				return (
					<ErrorState
						title="You don't have access to trace data"
						description="Ask a workspace administrator for access."
					/>
				);
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

	// OBS-33: resolve the tenant's per-signature hit counts server-side and hand them
	// down. The badge reads "SEEN N×", which a user reads as "my workspace hit this N
	// times" — that number is `your_hits` from the gateway aggregate, NOT how many
	// signatures matched one span. Best-effort: a failure yields no counts and the
	// badge renders without one, because a wrong number on a trust surface is worse
	// than an absent one.
	let hitCounts: Record<string, number> | undefined;
	try {
		// The badge's window is the signatures page's default (30 d), through the
		// shared layer — never a second `Date.now() − 30 days` here.
		const sigWindow = parseTimeRange(
			{ range: "30d" },
			{ defaultPreset: "30d", nowMs: Date.now() },
		);
		const data = await fetchSignaturesFor(sigWindow);
		hitCounts = data
			? Object.fromEntries(
					data.signatures.map((s) => [s.signature_id, s.your_hits]),
				)
			: undefined;
	} catch {
		hitCounts = undefined;
	}
	const listSizes = (await getListPageSettings()).sizes;
	let minGenerationMs: number | undefined;
	try {
		const settings = await gatewayGet<{
			output_speed?: { min_generation_ms?: number };
		}>("/v1/gateway/settings");
		minGenerationMs = settings.output_speed?.min_generation_ms;
	} catch (error) {
		if (!(error instanceof GatewayError)) throw error;
	}

	return (
		<>
			<TraceDetailView
				traceId={traceId}
				spans={spans}
				hitCounts={hitCounts}
				toolPreviewLimit={listSizes.span_tool_names_preview}
				conversationLimit={listSizes.trace_conversation_messages}
				minGenerationMs={minGenerationMs}
			/>
			<Providers>
				<IncidentPanel traceId={traceId} />
			</Providers>
		</>
	);
}

// Queries ClickHouse at request time — never prerender.
export const dynamic = "force-dynamic";

export default async function TraceDetailPage({ params }: Props) {
	const { traceId } = await params;

	return (
		<div className="p-6">
			<div className="mb-6 space-y-3">
				<Link
					href="/traces"
					className="shrink-0 text-sm text-ink-2 transition-colors hover:text-ink"
				>
					← Traces
				</Link>
				{/* Trace ID is a hex identifier — mono font is correct here. */}
				<PageHeader title={traceId} />
				<Suspense fallback={<Skeleton className="h-6 w-40 rounded-control" />}>
					<ChainStatusChip traceId={traceId} />
				</Suspense>
				<TraceHeaderActions
					traceId={traceId}
					flag={
						<Suspense fallback={<Skeleton className="h-9 w-full" />}>
							<TraceFlagPanel traceId={traceId} embedded />
						</Suspense>
					}
				/>
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
		</div>
	);
}
