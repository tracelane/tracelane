/**
 * Playground — run a prompt through the gateway and land on its trace
 * (`specs/OBS-16-playground.md`). Server shell: proves a provider is
 * connected and computes the model dropdown, then hands off to the client
 * form (`PlaygroundForm`), which is the only thing that talks to
 * `POST /api/playground`.
 *
 * WHO WRITES THE DATA THIS READS: the gateway writes the span for the run
 * (the existing `/v1/chat/completions` path); this page reads nothing else.
 */

import { defaultModelFor } from "@/app/playground/default-models";
import { PlaygroundForm } from "@/components/playground/PlaygroundForm";
import { PROVIDER_LABEL } from "@/components/settings/provider-catalog.generated";
import { canAdmin, requireSession } from "@/lib/auth";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { EmptyState } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = { title: "Playground — Tracelane" };

// Reads the tenant's connected providers at request time — never prerender.
export const dynamic = "force-dynamic";

interface ProviderKeySummary {
	provider_id: string;
	last4: string;
}

/**
 * `GET /v1/byok/provider-keys` is owner-only at the gateway
 * (`crates/gateway/src/byok_api/provider_keys_api.rs::authenticate`,
 * `Access::Read` → `claims.can_admin()`) — a member's JWT gets a 403, not an
 * empty list. Mirroring `canAdmin(session.role)` here (the same allowlist the
 * gateway itself enforces, per its own doc comment) lets us skip the call for
 * a member/viewer entirely rather than always eating the round trip and
 * catching the 403.
 */
type ProviderState =
	| { kind: "keys"; keys: ProviderKeySummary[] }
	| { kind: "locked" } // member/viewer — cannot list, cannot say either way
	| { kind: "unreachable" };

async function loadProviderState(canList: boolean): Promise<ProviderState> {
	if (!canList) return { kind: "locked" };
	try {
		const keys = await gatewayGet<ProviderKeySummary[]>(
			"/v1/byok/provider-keys",
		);
		return { kind: "keys", keys };
	} catch (err) {
		if (err instanceof GatewayError) return { kind: "unreachable" };
		throw err;
	}
}

function NoProviderPanel() {
	return (
		<EmptyState
			title="Connect a provider to run prompts"
			description="The playground calls the gateway with your tenant's own provider keys — add one to get started."
			action={
				<Link
					href="/settings/providers"
					className="text-sm font-medium text-action-ink underline underline-offset-2 hover:opacity-80"
				>
					Settings → LLM Providers
				</Link>
			}
		/>
	);
}

function LockedPanel() {
	return (
		<EmptyState
			title="Provider visibility is owner-only"
			description="Whether your workspace has a connected provider isn't visible to your role — ask an owner to check Settings → LLM Providers, or to run this for you."
			action={
				<Link
					href="/settings/providers"
					className="text-sm font-medium text-action-ink underline underline-offset-2 hover:opacity-80"
				>
					Settings → LLM Providers
				</Link>
			}
		/>
	);
}

export default async function PlaygroundPage() {
	const session = await requireSession();
	const providerState = await loadProviderState(canAdmin(session.role));

	let body: React.ReactNode;
	if (providerState.kind === "locked") {
		body = <LockedPanel />;
	} else if (
		providerState.kind === "unreachable" ||
		providerState.keys.length === 0
	) {
		body = <NoProviderPanel />;
	} else {
		const models = providerState.keys
			.map((k) => ({
				value: defaultModelFor(k.provider_id),
				label: `${PROVIDER_LABEL.get(k.provider_id) ?? k.provider_id} (${defaultModelFor(k.provider_id)})`,
			}))
			// A tenant can hold more than one key per provider is not possible
			// (BYOK is one key per provider id), but two provider ids can share a
			// mapped default (rare) — de-dupe on the model value so the <select>
			// never repeats an option.
			.filter((m, i, arr) => arr.findIndex((o) => o.value === m.value) === i);
		body = <PlaygroundForm models={models} />;
	}

	return (
		<div className="mx-auto max-w-3xl space-y-4 px-6 py-10">
			<div>
				<h1 className="t-h1">Playground</h1>
				<p className="mt-1 text-sm text-ink-2">
					Prototype prompts against your connected providers through the gateway
					— every run is captured as a trace.
				</p>
			</div>
			{body}
		</div>
	);
}
