/**
 * ShareLedgerBadge — OBS-48's ledger badge, rendered on the PUBLIC share page
 * (`app/s/[token]/page.tsx`) from the gateway's UNAUTHENTICATED
 * `GET /v1/share/{token}` response.
 *
 * THE THREE STRINGS BELOW ARE EXACT COPY from
 * `specs/OBS-48-shareable-verified-trace-link.md` §2 — do not paraphrase them.
 * Only the seq NUMBER is substituted. Never "third-party verifiable",
 * "tamper-proof" or "verified offline" (B-249 stands; `docs/reference/TRAPS.md`
 * §11): this badge states the ledger POSITION and ANCHOR status the gateway
 * records, nothing stronger — same honesty boundary `ChainStatusChip` already
 * enforces on the authenticated trace page.
 *
 * THE REKOR COORDINATE IS NEVER A LINK. `AuditLedgerView`'s `LogIndexChip`
 * carries this exact trust-surface guard, proven by
 * `e2e/audit-hero.spec.ts` ("a Rekor v2 index must NEVER link to..."): Rekor v2
 * has no per-entry web page, and a plausible-looking URL
 * (`search.sigstore.dev`) resolves the WRONG log (legacy v1). A public,
 * unauthenticated page is exactly where a wrong link would be clicked most.
 */

import { Badge } from "@tracelanedev/ui";

export interface ShareChainStatus {
	chained: boolean;
	seq: number | null;
	anchored: boolean;
}

export function ShareLedgerBadge({
	chain,
	rekorEntryId,
}: {
	chain: ShareChainStatus;
	rekorEntryId?: string;
}) {
	if (!chain.chained) {
		return (
			<Badge tone="neutral">
				Not in the audit ledger (SDK/OTLP traces are not ledgered)
			</Badge>
		);
	}

	// `#—` rather than `#0` — a chained record with no recorded seq is an
	// unexpected gateway shape, not a legitimate zero (CLAUDE.md §1: never
	// invent a number). Should not occur in practice since `chained` implies a
	// seq was assigned, but the type is `number | null` and this file does not
	// assume the stronger invariant.
	const seqText = chain.seq !== null ? `#${chain.seq.toLocaleString()}` : "#—";

	if (!chain.anchored) {
		return (
			<span className="inline-flex items-center gap-1.5">
				{/* DSH-16: the recorder's amber — "this workspace is being recorded",
				    a second, independent signal beside the green `seal` tone (which
				    means "verified"). Decorative only; copy is exactly the OBS-48 §2
				    text above, untouched. */}
				<span aria-hidden="true" className="recorder-dot" />
				<Badge tone="seal">
					Recorded in the audit ledger · seq {seqText} · operator-signed
				</Badge>
			</span>
		);
	}

	return (
		<span className="inline-flex flex-wrap items-center gap-1.5">
			<span aria-hidden="true" className="recorder-dot" />
			<Badge tone="seal">
				Recorded in the audit ledger · seq {seqText} · anchored to a public
				transparency log
			</Badge>
			{rekorEntryId && (
				<span
					title={`Rekor v2 log index ${rekorEntryId}. Not a link — Rekor v2 has no per-entry web page, and a plausible-looking URL would resolve the wrong (legacy v1) log.`}
					className="inline-flex items-center gap-1 rounded-md border border-seal-line bg-seal-soft px-1.5 py-0.5 font-mono text-2xs text-seal-ink"
				>
					logIndex {rekorEntryId}
				</span>
			)}
		</span>
	);
}
