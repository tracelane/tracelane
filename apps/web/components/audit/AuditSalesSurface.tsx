import { Card } from "@tracelanedev/ui";
import Link from "next/link";

/**
 * Shown to tenants WITHOUT the Audit SKU entitlement — the page exists + what it
 * does (a sales surface), never a fake/empty render implying they have it.
 */
export function AuditSalesSurface() {
	return (
		<Card provenance className="p-6">
			<div className="text-[11px] font-semibold uppercase tracking-wide text-seal-ink">
				Audit SKU · $999/mo add-on
			</div>
			<h2 className="mt-1 text-lg font-semibold text-ink">
				A provable record of every gateway call and guardrail verdict
			</h2>
			<p className="mt-2 max-w-2xl text-[13px] text-ink-2">
				Every gateway-proxied call and guardrail verdict is appended to a
				SHA-256 hash chain. The chain is <strong>tamper-evident</strong>: any
				change to a past event breaks the recomputed hash. You — or a regulator
				— can download the ledger and verify it independently with our
				open-source CLI{" "}
				<code className="font-mono text-ink">tlane verify --offline</code> (
				<code className="font-mono text-ink">npm i -g @tracelanedev/cli</code>),
				without trusting Tracelane. Built for EU AI Act Article 12
				record-keeping.
			</p>
			<ul className="mt-3 space-y-1.5 text-[13px] text-ink-2">
				<li>
					• Tamper-evident SHA-256 hash chain over every gateway call and
					guardrail verdict (OTLP/SDK-captured spans are full-fidelity; chaining
					them is on the roadmap)
				</li>
				<li>
					• Browser-side "Verify integrity" — recompute the chain yourself and
					see exactly where any break is
				</li>
				<li>
					• Article-12 evidence export (NDJSON), independently verifiable
					off-platform
				</li>
				<li>
					• Cryptographic signing &amp; public-transparency (Rekor) anchoring —
					on the roadmap
				</li>
			</ul>
			<div className="mt-5">
				<Link
					href="/settings/billing"
					className="cta-lava inline-flex h-9 items-center rounded-lg px-4 text-[13px] font-medium"
				>
					Add the Audit SKU
				</Link>
			</div>
		</Card>
	);
}
