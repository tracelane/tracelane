/**
 * /settings/byok — Customer-Managed Key (BYOK) management page.
 *
 * Wraps ByokKeyManager client component in a server page shell.
 */

import { ByokKeyManager } from "@/components/settings/ByokKeyManager";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Encryption Keys (CMK) — Settings" };

export default function ByokPage() {
	return (
		<div className="space-y-1">
			<h2 className="text-sm font-semibold text-ink">Encryption Keys (CMK)</h2>
			<p className="mb-3 max-w-2xl text-xs text-ink-2">
				<span className="font-medium text-ink">Optional.</span> Register your
				own public key so your provider keys and trace payloads are
				envelope-encrypted such that{" "}
				<span className="text-ink">Tracelane cannot read them</span> —
				customer-managed keys (CMK) for regulated environments. Stored as
				fingerprints only.
			</p>
			<div className="mb-4 max-w-2xl rounded-md border border-line bg-surface-2/30 p-3 text-xs text-ink-2">
				<div className="mb-1.5 font-medium text-ink">How to use</div>
				<ol className="list-decimal space-y-1 pl-4">
					<li>Generate a keypair (your CMK) and keep the private key.</li>
					<li>
						Register the <span className="text-ink">public</span> key below.
					</li>
					<li>
						New data is envelope-encrypted under it — Tracelane holds only the
						fingerprint, never your private key.
					</li>
				</ol>
			</div>
			<p className="mb-6 text-xs text-ink-3">
				Looking for the provider API keys the gateway routes with (Anthropic,
				OpenAI, …)?{" "}
				<a
					href="/settings/providers"
					className="font-medium text-accent-ink hover:underline"
				>
					LLM Provider Keys →
				</a>
			</p>
			<ByokKeyManager />
		</div>
	);
}
