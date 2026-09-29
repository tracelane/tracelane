import { PageHeader } from "@tracelanedev/ui";
/**
 * Playground — run a prompt through the gateway and land on its trace
 * (`specs/EVL-03-playground-v2-and-open-in-playground.md`, extends the v1
 * `OBS-16-playground.md` surface). Server shell: proves a provider is
 * connected, computes the model dropdown and the reference-table limits, and
 * — when opened as `?trace=&span=` from a span's "Open in playground" button
 * (A3, Codex) — resolves the ONE prefill this button exists for (§2). The
 * client form (`PlaygroundForm`) is the only thing that talks to
 * `POST /api/playground`.
 *
 * WHO WRITES THE DATA THIS READS: the gateway writes the span for a run (the
 * existing `/v1/chat/completions` path) and the span this page prefills FROM.
 * This page reads nothing else.
 *
 * TENANT ISOLATION (§2 "Tenant scoping"): `GET /v1/traces/{id}/spans` binds
 * `tenant_id` from the caller's OWN JWT first
 * (`crates/gateway/src/trace_reads.rs:2393-2400`); a trace id from another
 * tenant 404s exactly like one that never existed — this page renders the
 * SAME "span not found" state either way (spec §2, never distinguished).
 */

import { defaultModelFor } from "@/app/playground/default-models";
import { ReadFailure } from "@/components/empty-states/ReadFailure";
import { PlaygroundForm } from "@/components/playground/PlaygroundForm";
import { PROVIDER_LABEL } from "@/components/settings/provider-catalog.generated";
import type { Span } from "@/components/trace-viewer/types";
import { canAdmin, requireSession } from "@/lib/auth";
import { GatewayError, gatewayGet, gatewayGetOrNull } from "@/lib/gateway";
import { type PrefillResult, prefillFromSpan } from "@/lib/playground-prefill";
import { getPlaygroundSettings } from "@/lib/playground-settings";
import { EmptyState } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = { title: "Playground — Tracelane" };

// Reads the tenant's connected providers at request time — never prerender.
export const dynamic = "force-dynamic";

type SearchParams = Record<string, string | string[] | undefined>;

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
	| { kind: "unreachable"; status: number };

async function loadProviderState(canList: boolean): Promise<ProviderState> {
	if (!canList) return { kind: "locked" };
	try {
		const keys = await gatewayGet<ProviderKeySummary[]>(
			"/v1/byok/provider-keys",
		);
		return { kind: "keys", keys };
	} catch (err) {
		if (err instanceof GatewayError)
			return { kind: "unreachable", status: err.status };
		throw err;
	}
}

/** The one place "Open in playground" resolves its span (§2). A single
 * `GET /v1/traces/{trace}/spans` read — never a per-span endpoint, since the
 * gateway does not have one and this list is small. */
type PrefillOutcome =
	| { kind: "none" }
	| { kind: "ok"; result: PrefillResult }
	| { kind: "not_found"; traceId: string }
	| { kind: "unreachable"; status: number };

async function loadPrefill(
	traceId: string,
	spanId: string,
): Promise<PrefillOutcome> {
	let spans: Span[] | null;
	try {
		spans = await gatewayGetOrNull<Span[]>(
			`/v1/traces/${encodeURIComponent(traceId)}/spans`,
		);
	} catch (err) {
		if (err instanceof GatewayError)
			return { kind: "unreachable", status: err.status };
		throw err;
	}
	// 404 (gatewayGetOrNull → null) and "trace exists but this span id isn't in
	// it" render the SAME state — a trace from another tenant already reads as
	// 404 at the gateway, so this page never distinguishes the two (spec §2).
	const span = spans?.find((s) => s.span_id === spanId);
	if (!span) return { kind: "not_found", traceId };
	return { kind: "ok", result: prefillFromSpan(span, traceId) };
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

/** §4 "Span not found / other tenant" — the form still renders, empty, per
 * the spec: a missing source span is not an error the user can fix. */
function SpanNotFoundBanner({ traceId }: { traceId: string }) {
	return (
		<div className="rounded-card border border-line bg-canvas-sunken p-3 text-xs text-ink-2">
			That span isn&apos;t in this workspace (or no longer exists). Opened an
			empty playground.{" "}
			<Link
				href={`/traces/${encodeURIComponent(traceId)}`}
				className="font-medium text-action-ink underline underline-offset-2 hover:opacity-80"
			>
				Back to the trace →
			</Link>
		</div>
	);
}

/** §4 "Span read failed (5xx / network)" — retryable, and the form beneath it
 * stays usable (never dressed up as "no data", TRAPS §18). */
function SpanReadFailedBanner({ retryHref }: { retryHref: string }) {
	return (
		<div className="rounded-card border border-danger bg-danger-soft p-3 text-xs text-danger-ink">
			Couldn&apos;t load the source span.{" "}
			<Link
				href={retryHref}
				className="font-medium underline underline-offset-2 hover:opacity-80"
			>
				Retry
			</Link>
		</div>
	);
}

export default async function PlaygroundPage({
	searchParams,
}: {
	searchParams: Promise<SearchParams>;
}) {
	const session = await requireSession();
	const sp = await searchParams;
	const traceParam = typeof sp.trace === "string" ? sp.trace.trim() : "";
	const spanParam = typeof sp.span === "string" ? sp.span.trim() : "";

	const [providerState, { limits }] = await Promise.all([
		loadProviderState(canAdmin(session.role)),
		getPlaygroundSettings(),
	]);

	let body: React.ReactNode;
	if (providerState.kind === "unreachable") {
		body = (
			<ReadFailure
				status={providerState.status}
				resource="connected providers"
				retryHref="/playground"
			/>
		);
	} else if (providerState.kind === "keys" && providerState.keys.length === 0) {
		body = <NoProviderPanel />;
	} else {
		const models = (providerState.kind === "keys" ? providerState.keys : [])
			.map((k) => ({
				value: defaultModelFor(k.provider_id),
				label: `${PROVIDER_LABEL.get(k.provider_id) ?? k.provider_id} (${defaultModelFor(k.provider_id)})`,
			}))
			// A tenant can hold more than one key per provider is not possible
			// (BYOK is one key per provider id), but two provider ids can share a
			// mapped default (rare) — de-dupe on the model value so the <select>
			// never repeats an option.
			.filter((m, i, arr) => arr.findIndex((o) => o.value === m.value) === i);

		let prefill: PrefillResult | undefined;
		let banner: React.ReactNode = null;
		if (traceParam && spanParam) {
			const outcome = await loadPrefill(traceParam, spanParam);
			if (outcome.kind === "ok") {
				prefill = outcome.result;
			} else if (outcome.kind === "not_found") {
				banner = <SpanNotFoundBanner traceId={outcome.traceId} />;
			} else if (outcome.kind === "unreachable") {
				banner = (
					<SpanReadFailedBanner
						retryHref={`/playground?trace=${encodeURIComponent(traceParam)}&span=${encodeURIComponent(spanParam)}`}
					/>
				);
			}
		}

		body = (
			<div className="space-y-3">
				{banner}
				{providerState.kind === "locked" && (
					<p className="text-sm text-ink-2">
						Your role can't list connected providers — type a model id
					</p>
				)}
				<PlaygroundForm
					models={models}
					limits={limits}
					prefill={prefill}
					canRun={["owner", "admin", "member"].includes(session.role ?? "")}
					canSave={canAdmin(session.role)}
				/>
			</div>
		);
	}

	return (
		<div className="mx-auto max-w-7xl space-y-4 px-6 py-10">
			<div>
				<PageHeader title={<>Playground</>} />
				<p className="mt-1 text-sm text-ink-2">
					Prototype prompts against your connected providers through the gateway
					— every run is captured as a trace.
				</p>
			</div>
			{body}
		</div>
	);
}
