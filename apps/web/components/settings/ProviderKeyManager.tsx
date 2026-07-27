"use client";

/**
 * ProviderKeyManager — self-service LLM **provider** key management (BYOK).
 *
 * Lets a customer store the upstream provider credentials (`sk-ant-…`, `sk-…`,
 * etc.) that the gateway uses to proxy their traffic. Unlike API keys, the
 * customer supplies the secret — so there is NO copy-on-create reveal; we show
 * only the last 4 characters after upload and never display the key again.
 *
 * Distinct from CMK / "Encryption Keys" (ByokKeyManager / /settings/byok),
 * which are the keys that envelope-encrypt data at rest.
 *
 * Pain-points: PP-G5 (BYOK key management), PP-G1 (developer onboarding).
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

interface ProviderKeySummary {
	provider_id: string;
	last4: string;
}

/**
 * Providers accepted by the gateway allowlist
 * (`crates/gateway/src/byok_api/provider_keys_api.rs::is_known_provider`).
 * Keep this in sync with that match arm — the gateway re-validates and
 * rejects unknown ids with 400. `hint` is a UX nicety for the common ones.
 */
const PROVIDERS: ReadonlyArray<{ id: string; label: string; hint?: string }> = [
	{ id: "anthropic", label: "Anthropic", hint: "starts with sk-ant-" },
	{ id: "openai", label: "OpenAI", hint: "starts with sk-" },
	{ id: "google", label: "Google (Gemini)" },
	{ id: "bedrock", label: "AWS Bedrock" },
	{ id: "azure", label: "Azure OpenAI" },
	{ id: "cohere", label: "Cohere" },
	{ id: "mistral", label: "Mistral" },
	{ id: "perplexity", label: "Perplexity" },
	{ id: "deepseek", label: "DeepSeek" },
	{ id: "xai", label: "xAI (Grok)" },
	{ id: "nvidia", label: "NVIDIA" },
	{ id: "cerebras", label: "Cerebras" },
	{ id: "sambanova", label: "SambaNova" },
	{ id: "lepton", label: "Lepton" },
	{ id: "lambda", label: "Lambda" },
	{ id: "novita", label: "Novita" },
	{ id: "ai21", label: "AI21" },
	{ id: "hyperbolic", label: "Hyperbolic" },
	{ id: "deepinfra", label: "DeepInfra" },
	{ id: "cloudflare", label: "Cloudflare Workers AI" },
	{ id: "ollama", label: "Ollama" },
	{ id: "baseten", label: "Baseten" },
	{ id: "huggingface", label: "Hugging Face" },
	{ id: "anyscale", label: "Anyscale" },
	{ id: "modal", label: "Modal" },
	{ id: "predibase", label: "Predibase" },
	{ id: "moonshot", label: "Moonshot" },
	{ id: "upstage", label: "Upstage (Solar)" },
	{ id: "yi", label: "01.AI (Yi)" },
	{ id: "aleph-alpha", label: "Aleph Alpha" },
];

const PROVIDER_LABEL = new Map(PROVIDERS.map((p) => [p.id, p.label]));

async function fetchProviderKeys(): Promise<ProviderKeySummary[]> {
	const res = await fetch("/api/settings/provider-keys");
	if (!res.ok) throw new Error(`HTTP ${res.status}`);
	return res.json() as Promise<ProviderKeySummary[]>;
}

async function uploadProviderKey(input: {
	provider_id: string;
	plaintext: string;
}): Promise<ProviderKeySummary> {
	const res = await fetch("/api/settings/provider-keys", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(input),
	});
	if (!res.ok) {
		const body = (await res.json().catch(() => ({}))) as { error?: string };
		throw new Error(body.error ?? `HTTP ${res.status}`);
	}
	return res.json() as Promise<ProviderKeySummary>;
}

async function revokeProviderKey(providerId: string): Promise<void> {
	const res = await fetch(
		`/api/settings/provider-keys/${encodeURIComponent(providerId)}`,
		{ method: "DELETE" },
	);
	if (!res.ok) throw new Error(`HTTP ${res.status}`);
}

function AddKeyDialog({
	onClose,
	onSubmit,
	pending,
	error,
}: {
	onClose: () => void;
	onSubmit: (input: { provider_id: string; plaintext: string }) => void;
	pending: boolean;
	error: string | null;
}) {
	const [providerId, setProviderId] = useState(PROVIDERS[0]?.id ?? "anthropic");
	const [plaintext, setPlaintext] = useState("");
	const hint = PROVIDERS.find((p) => p.id === providerId)?.hint;

	return (
		<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
			<div className="bg-surface border border-line rounded-lg p-6 w-full max-w-md shadow-2xl space-y-4">
				<h3 className="text-base font-semibold text-ink">Add provider key</h3>
				<form
					onSubmit={(e) => {
						e.preventDefault();
						if (providerId && plaintext.trim()) {
							// space (a common paste artifact) was sent verbatim and then
							// rejected upstream as a 401. The gateway also trims on save,
							// but trimming here keeps the UI honest about what is stored.
							onSubmit({
								provider_id: providerId,
								plaintext: plaintext.trim(),
							});
						}
					}}
					className="space-y-3"
				>
					<div>
						<label
							htmlFor="provider-select"
							className="text-xs font-medium text-ink-2 block mb-1"
						>
							Provider
						</label>
						<select
							id="provider-select"
							value={providerId}
							onChange={(e) => setProviderId(e.target.value)}
							className="w-full rounded border border-line bg-bg px-3 py-2 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-accent-ink"
						>
							{PROVIDERS.map((p) => (
								<option key={p.id} value={p.id}>
									{p.label}
								</option>
							))}
						</select>
					</div>
					<div>
						<label
							htmlFor="provider-key"
							className="text-xs font-medium text-ink-2 block mb-1"
						>
							API key
						</label>
						<input
							id="provider-key"
							type="password"
							autoComplete="off"
							value={plaintext}
							onChange={(e) => setPlaintext(e.target.value)}
							placeholder={hint ? `${hint}` : "paste your provider API key"}
							className="w-full rounded border border-line bg-bg px-3 py-2 text-sm font-mono text-ink placeholder:text-ink-3 focus:outline-none focus:ring-2 focus:ring-accent-ink"
							required
						/>
						<p className="text-[11px] text-ink-2 mt-1">
							Encrypted at rest (AES-256-GCM, bound to your tenant). Stored once
							— we show only the last 4 characters afterward.
						</p>
					</div>
					{error && <p className="text-xs text-danger">{error}</p>}
					<div className="flex justify-end gap-2 pt-1">
						<button
							type="button"
							onClick={onClose}
							className="px-4 py-2 rounded text-sm border border-line text-ink-2 hover:bg-surface-2 transition-colors"
						>
							Cancel
						</button>
						<button
							type="submit"
							disabled={!plaintext.trim() || pending}
							className="px-4 py-2 rounded text-sm bg-accent text-accent-on hover:bg-accent/90 disabled:opacity-40 transition-colors"
						>
							{pending ? "Saving…" : "Save key"}
						</button>
					</div>
				</form>
			</div>
		</div>
	);
}

export function ProviderKeyManager() {
	const qc = useQueryClient();
	const [showAdd, setShowAdd] = useState(false);

	const {
		data: keys = [],
		isLoading,
		isError,
	} = useQuery({
		queryKey: ["provider-keys"],
		queryFn: fetchProviderKeys,
		staleTime: 30_000,
	});

	const uploadMutation = useMutation({
		mutationFn: uploadProviderKey,
		onSuccess: () => {
			void qc.invalidateQueries({ queryKey: ["provider-keys"] });
			setShowAdd(false);
		},
	});

	const revokeMutation = useMutation({
		mutationFn: revokeProviderKey,
		onSuccess: () => void qc.invalidateQueries({ queryKey: ["provider-keys"] }),
	});

	return (
		<div className="space-y-4">
			<div className="flex items-center justify-between">
				<div>
					<h3 className="text-sm font-semibold text-ink">Your keys</h3>
				</div>
				<button
					type="button"
					onClick={() => {
						uploadMutation.reset();
						setShowAdd(true);
					}}
					className="px-3 py-1.5 rounded text-sm bg-accent text-accent-on hover:bg-accent/90 transition-colors"
				>
					+ Add provider key
				</button>
			</div>

			{isLoading && (
				<p className="text-sm text-ink-2 animate-pulse">Loading…</p>
			)}
			{isError && (
				<p className="text-sm text-danger">Failed to load provider keys.</p>
			)}

			{!isLoading && !isError && keys.length === 0 && (
				<div className="rounded-lg border border-dashed border-line p-8 text-center">
					<p className="text-sm text-ink-2">No provider keys yet.</p>
					<p className="text-xs text-ink-3 mt-1">
						Add your Anthropic, OpenAI, or other provider key to start routing
						traffic through Tracelane.
					</p>
				</div>
			)}

			{keys.length > 0 && (
				<div className="rounded-lg border border-line overflow-hidden">
					<table className="w-full text-left">
						<thead className="bg-surface text-xs text-ink-2">
							<tr>
								<th className="py-2.5 px-4 font-medium">Provider</th>
								<th className="py-2.5 pr-4 font-medium">Key</th>
								<th className="py-2.5 pr-4 font-medium" />
							</tr>
						</thead>
						<tbody>
							{keys.map((key) => (
								<tr
									key={key.provider_id}
									className="border-t border-line last:border-0"
								>
									<td className="py-3 px-4 text-sm text-ink">
										{PROVIDER_LABEL.get(key.provider_id) ?? key.provider_id}
									</td>
									<td className="py-3 pr-4 font-mono text-xs text-ink-2">
										••••••••{key.last4}
									</td>
									<td className="py-3 pr-4">
										<button
											type="button"
											onClick={() => revokeMutation.mutate(key.provider_id)}
											className="text-xs px-2 py-1 rounded border border-danger text-danger hover:bg-danger-soft transition-colors"
										>
											Revoke
										</button>
									</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			)}

			{showAdd && (
				<AddKeyDialog
					onClose={() => setShowAdd(false)}
					onSubmit={(input) => uploadMutation.mutate(input)}
					pending={uploadMutation.isPending}
					error={
						uploadMutation.isError
							? (uploadMutation.error as Error).message
							: null
					}
				/>
			)}
		</div>
	);
}
