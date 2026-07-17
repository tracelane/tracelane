/**
 * Per-trace tamper-evident-ledger chip (wedge item 4).
 *
 * Answers, at a glance on the trace-detail header: is THIS trace's call recorded
 * in the audit hash chain? The distinction is the wedge — a gateway-proxied call
 * is chained (a tamper-evident record); an SDK/OTLP span is full-fidelity capture
 * but NOT chained. We state that honestly and never fake a green.
 *
 * Honesty boundary (B-scope): the chip reports PRESENCE + ANCHOR, not a live
 * cryptographic verdict. The full-chain verify — recompute every row hash, walk
 * `prev_hash` to genesis, check the Rekor anchor — runs on the Audit page via the
 * same open-source verifier a customer runs. The chained chip links there for the
 * actual proof; it does not claim "verified" it did not compute.
 *
 * Fetched via `gatewayGetOrNull` (per-user WorkOS JWT, tenant-isolated in the
 * gateway). The endpoint always 200s — a not-chained trace is a legitimate state,
 * not an error — so `null` only means the gateway was unreachable; we then render
 * an explicit "unavailable" badge rather than silently omitting the chip.
 *
 * Loading state: the Suspense fallback in page.tsx renders a skeleton so the
 * header space does not jump when the async data resolves.
 */

import { gatewayGetOrNull } from "@/lib/gateway";
import { Badge } from "@tracelanedev/ui";
import Link from "next/link";

interface TraceChainStatus {
	chained: boolean;
	seq: number | null;
	anchored: boolean;
}

/** Small shield-check glyph so the seal tone never reads on colour alone. */
function ShieldCheck() {
	return (
		<svg
			viewBox="0 0 16 16"
			width="11"
			height="11"
			fill="none"
			stroke="currentColor"
			strokeWidth="1.6"
			strokeLinecap="round"
			strokeLinejoin="round"
			aria-hidden="true"
		>
			<path d="M8 1.5 3 3.2v4.3c0 3 2.1 5.4 5 6.5 2.9-1.1 5-3.5 5-6.5V3.2L8 1.5Z" />
			<path d="m6 7.8 1.6 1.6L10.4 6" />
		</svg>
	);
}

/** Slash-circle glyph used on the "unavailable" state — never on provenance. */
function SlashCircle() {
	return (
		<svg
			viewBox="0 0 16 16"
			width="11"
			height="11"
			fill="none"
			stroke="currentColor"
			strokeWidth="1.6"
			strokeLinecap="round"
			aria-hidden="true"
		>
			<circle cx="8" cy="8" r="6" />
			<line x1="4.2" y1="4.2" x2="11.8" y2="11.8" />
		</svg>
	);
}

export async function ChainStatusChip({ traceId }: { traceId: string }) {
	let status: TraceChainStatus | null = null;
	let gatewayUnreachable = false;

	try {
		status = await gatewayGetOrNull<TraceChainStatus>(
			`/v1/traces/${encodeURIComponent(traceId)}/chain`,
		);
	} catch {
		// Gateway unreachable — render an explicit "unavailable" badge so the chip
		// space doesn't silently disappear. The trace still renders fully; only the
		// ledger status is unknown. This is NOT an error in the trace itself.
		gatewayUnreachable = true;
	}

	// Gateway unreachable: show neutral "unavailable" badge so users know the
	// ledger status couldn't be determined (vs. the chip simply not rendering).
	if (gatewayUnreachable) {
		return (
			<Badge
				tone="neutral"
				title="Ledger status is unavailable — the gateway could not be reached. The trace data is still intact. Try reloading or check gateway connectivity."
			>
				<SlashCircle />
				Ledger status unavailable
			</Badge>
		);
	}

	// Gateway returned null: /chain endpoint returned 404 (no chain record for
	// this trace). This is a legitimate state (SDK/OTLP ingest, no gateway proxy).
	if (status === null) return null;

	if (!status.chained) {
		return (
			<Badge
				tone="neutral"
				title="Captured via SDK/OTLP — full-fidelity trace, not gateway hash-chained. Route the call through the gateway for a tamper-evident record."
			>
				Full-fidelity capture
			</Badge>
		);
	}

	// "Anchor recorded" (not "anchored"): the endpoint confirms a transparency-log
	// entry id was recorded for this row's batch, but does NOT fetch the inclusion
	// proof — that live verification is the Audit page's job. Honest B-scope.
	const label = status.anchored
		? "Anchor recorded"
		: "In tamper-evident ledger";
	const title = status.anchored
		? "This call is a hash-chained ledger record with a transparency-log anchor recorded. Verify the full chain and anchor on the Audit page."
		: "This call is a hash-chained record in the tamper-evident audit ledger. Verify the full chain on the Audit page.";

	return (
		<Link
			href="/audit"
			title={title}
			className="rounded-md no-underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
		>
			<Badge tone="seal">
				<ShieldCheck />
				{label}
				{status.seq !== null && (
					<span className="tabular-nums opacity-70">· #{status.seq}</span>
				)}
			</Badge>
		</Link>
	);
}
