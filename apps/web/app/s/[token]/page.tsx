/**
 * `/s/[token]` — OBS-48 public share page. UNAUTHENTICATED end to end: no
 * `requireSession`, no `withAuth`, no user JWT anywhere in this file. Fetches
 * `GET /v1/share/{token}` directly with the platform `fetch()` — never
 * `gatewayGet`/`gatewayGetOrNull`, both of which mint a WorkOS access token via
 * `requireGatewayToken()` this route has no session to mint (it would redirect
 * an anonymous visitor to `/sign-in`, defeating the entire feature).
 *
 * ── MIDDLEWARE: CONFIRMED, NO CHANGE NEEDED ──────────────────────────────────
 * `apps/web/middleware.ts` calls `authkitMiddleware()` with NO options. Per
 * `apps/web/app/(legal)/legal/[doc]/page.tsx:9` (a page reaching the identical
 * question for `/legal/*`): "`authkitMiddleware()` runs with
 * `middlewareAuth.enabled = false`, so it refreshes a session if there is one
 * and lets anonymous requests through." The middleware itself never redirects
 * — a redirect to `/sign-in` only happens when a PAGE calls
 * `withAuth({ensureSignedIn:true})` / `requireSession()` /
 * `requireGatewayToken()`. This file calls none of them, so an anonymous
 * request reaches it unredirected, matching the spec's own note at §2's
 * `app/s/[token]/page.tsx` row. No middleware matcher change, no opt-out flag.
 *
 * ── WHY generateMetadata AND THE PAGE SHARE ONE FETCH ────────────────────────
 * The gateway increments `view_count` on every `GET /v1/share/{token}` (spec
 * §2). Next.js calls `generateMetadata` and the page component separately per
 * request; fetching twice would double-count a single visitor's view. `cache()`
 * from `react` (the same per-request memoization `requireGatewayToken` already
 * uses in `lib/auth.ts`) makes the two calls in this file resolve to ONE
 * network request.
 */

import { ShareLedgerBadge } from "@/components/trace-viewer/ShareLedgerBadge";
import { TraceDetailView } from "@/components/trace-viewer/TraceDetailView";
import type { Span } from "@/components/trace-viewer/types";
import { gatewayBaseUrl } from "@/lib/gateway";
import { computeTraceSummary } from "@/lib/trace-summary";
import { EmptyState, ErrorState, Logo, fmtDur } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { cache } from "react";

interface Props {
	params: Promise<{ token: string }>;
}

type ShareChainStatus = {
	chained: boolean;
	seq: number | null;
	anchored: boolean;
};

type SharePayload = {
	trace_id: string;
	root_name: string;
	shared_at: string;
	expires_at: string;
	span_count: number;
	spans: Span[];
	chain: ShareChainStatus;
	rekor_entry_id?: string;
	workspace_name: string;
};

type ShareFetchResult =
	| { kind: "ok"; data: SharePayload }
	| { kind: "not_found" }
	| { kind: "rate_limited" }
	| { kind: "error" };

/**
 * The ONE fetch. 404 covers "missing, expired AND revoked" — the gateway
 * deliberately returns one indistinguishable body for all three (spec §2/§4),
 * so this never tries to tell them apart either.
 */
const fetchShare = cache(async (token: string): Promise<ShareFetchResult> => {
	let res: Response;
	try {
		res = await fetch(
			`${gatewayBaseUrl()}/v1/share/${encodeURIComponent(token)}`,
			{
				cache: "no-store",
				signal: AbortSignal.timeout(10_000),
			},
		);
	} catch {
		return { kind: "error" };
	}
	if (res.status === 404) return { kind: "not_found" };
	if (res.status === 429) return { kind: "rate_limited" };
	if (!res.ok) return { kind: "error" };
	try {
		return { kind: "ok", data: (await res.json()) as SharePayload };
	} catch {
		return { kind: "error" };
	}
});

/** Days from now until `iso`, floored — spec §3 "expires in N days". */
function daysUntil(iso: string, nowMs = Date.now()): number {
	const ms = new Date(iso).getTime() - nowMs;
	return Math.max(0, Math.floor(ms / 86_400_000));
}

/** Same three-bucket cost format `TraceSummaryHeader` uses — kept local: that
 * component's copy is not exported and this file may not edit it (OBS-48 scope). */
function fmtCost(usd: number): string {
	if (usd === 0) return "$0";
	if (usd < 0.01) return `$${usd.toFixed(4)}`;
	if (usd < 1) return `$${usd.toFixed(3)}`;
	return `$${usd.toFixed(2)}`;
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
	const { token } = await params;
	const result = await fetchShare(token);
	if (result.kind !== "ok") {
		return { title: "Shared trace — Tracelane" };
	}
	const { data } = result;
	// `spans.length`, not `data.span_count` — spec §3's "spans (OG + header)"
	// row names `spans.length` explicitly (what the caps actually returned),
	// distinct from a possibly-larger pre-cap count.
	const spanCount = data.spans.length;
	const summary = computeTraceSummary(data.spans);
	const seqPart =
		data.chain.seq !== null ? ` · ledger seq #${data.chain.seq}` : "";
	const description = `${data.root_name} · ${spanCount} spans · ${fmtDur(summary.totalDurationUs)}${seqPart}`;
	return {
		title: `${data.root_name} — shared trace · Tracelane`,
		openGraph: {
			title: `${data.root_name} — shared trace`,
			description,
		},
	};
}

export const dynamic = "force-dynamic";

/** Minimal chrome shared by every non-happy-path state: logo, no nav, no data. */
function PublicMessageShell({
	title,
	description,
}: {
	title: string;
	description: string;
}) {
	return (
		<div className="flex min-h-screen flex-col">
			<header className="flex items-center border-b border-line px-6 py-4">
				<Logo withWordmark height={22} />
			</header>
			<div className="flex flex-1 items-center justify-center p-6">
				<ErrorState title={title} description={description} />
			</div>
		</div>
	);
}

export default async function SharedTracePage({ params }: Props) {
	const { token } = await params;
	const result = await fetchShare(token);

	if (result.kind === "not_found") {
		// Renders app/s/[token]/not-found.tsx — the three cases (missing, expired,
		// revoked) are byte-identical by design (spec §4/§7 proof 3).
		notFound();
	}

	if (result.kind === "rate_limited") {
		return (
			<PublicMessageShell
				title="Too many requests"
				description="Too many requests, try again in a minute."
			/>
		);
	}

	if (result.kind === "error") {
		// NOT the 404 copy (TRAPS §18: error ≠ empty).
		return (
			<PublicMessageShell
				title="Could not load this trace right now"
				description="The gateway couldn't be reached. Try reloading in a moment."
			/>
		);
	}

	const { data } = result;
	const summary = computeTraceSummary(data.spans);
	const spanCount = data.spans.length;
	const expiresIn = daysUntil(data.expires_at);

	return (
		<div className="flex min-h-screen flex-col">
			<header className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-6 py-4">
				<Logo withWordmark height={22} />
				<p className="text-sm text-ink-2">
					Shared trace · {data.workspace_name} · expires in {expiresIn} day
					{expiresIn === 1 ? "" : "s"}
				</p>
			</header>

			<div className="mx-auto w-full max-w-6xl flex-1 p-6">
				<div className="mb-4 space-y-2 border-b border-line pb-4">
					<div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
						<h1 className="t-h1 min-w-0 truncate">{data.root_name}</h1>
						<p className="shrink-0 text-sm text-ink-2">
							{spanCount} span{spanCount === 1 ? "" : "s"} ·{" "}
							{fmtDur(summary.totalDurationUs)}
							{summary.cost !== undefined ? ` · ${fmtCost(summary.cost)}` : ""}
						</p>
					</div>
					<ShareLedgerBadge
						chain={data.chain}
						rekorEntryId={data.rekor_entry_id}
					/>
				</div>

				{spanCount === 0 ? (
					// Same copy as the trace page's own empty state
					// (`app/traces/[traceId]/page.tsx`'s `SpanData`) — spec §4.
					<EmptyState
						title="No spans for this trace yet"
						description="This trace exists but hasn't recorded any spans. They'll appear here as the agent runs."
					/>
				) : (
					<TraceDetailView spans={data.spans} />
				)}
			</div>

			<footer className="border-t border-line px-6 py-6 text-center text-sm text-ink-2">
				Recorded with Tracelane, the flight recorder for AI agents.{" "}
				<Link
					href="https://tracelane.dev"
					className="font-medium text-ink underline underline-offset-2"
				>
					Record your own →
				</Link>
			</footer>
		</div>
	);
}
