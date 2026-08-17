/**
 * /settings/providers — LLM **provider** key management (BYOK).
 *
 * Wraps ProviderKeyManager in a server page shell. This is where customers
 * store their upstream provider credentials (sk-ant-/sk-…) that the gateway
 * proxies with — distinct from /settings/byok (Customer-Managed Encryption
 * Keys, which encrypt data at rest).
 */

import { ProviderKeyManager } from "@/components/settings/ProviderKeyManager";
import { canAdmin, requireSession } from "@/lib/auth";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "LLM Providers — Settings" };

// Touches the gateway via a session-bound proxy; never statically rendered.
export const dynamic = "force-dynamic";

export default async function ProvidersPage() {
	// Same source the Team page gates on. UI-only: the gateway's owner-only gate
	// (`provider_keys_api.rs::authenticate`) stays authoritative.
	const session = await requireSession();

	return (
		<div className="space-y-1">
			<h2 className="text-sm font-semibold text-ink">LLM Provider Keys</h2>
			<p className="mb-1 max-w-2xl text-xs text-ink-2">
				The API keys the gateway uses to call Anthropic, OpenAI, and the other
				providers <span className="text-ink">on your behalf</span> — bring your
				own keys (BYOK). Envelope-encrypted, bound to your tenant, and never
				shown again after upload.
			</p>
			<p className="mb-6 text-xs text-ink-3">
				Looking for your own encryption keys (CMK)?{" "}
				<a
					href="/settings/byok"
					className="font-medium text-action-ink hover:underline"
				>
					Encryption Keys →
				</a>
			</p>
			<ProviderKeyManager canManage={canAdmin(session.role)} />
		</div>
	);
}
