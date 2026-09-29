"use client";
import { Button } from "@tracelanedev/ui";

import { TBody, TD, TH, THead, TR, Table } from "@tracelanedev/ui";

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

import { Modal } from "@/components/Modal";
import { apiFetch, apiFetchRaw } from "@/lib/api-fetch";
import { formatDateTimeUtc } from "@/lib/format-date";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import {
	type CatalogProvider,
	PROVIDERS,
	PROVIDER_LABEL,
} from "./provider-catalog.generated";

interface KeyValidation {
	status:
		| "valid"
		| "rejected"
		| "unavailable"
		| "cannot_validate"
		| "unsupported";
	reason: string;
	checked_at: string;
}

interface ProviderKeySummary {
	provider_id: string;
	last4: string;
	saved_at?: string;
	last_validation?: KeyValidation | null;
	last_rejected_at?: string | null;
	rejection_history_available?: boolean;
}

/**
 * The provider list is GENERATED from the gateway's own catalog
 * (`crates/gateway/providers.tsv` → `provider-catalog.generated.ts`), so this
 * file no longer carries one.
 *
 *  is why. This list, the gateway's BYOK allowlist and the routing
 * registry were three hand-maintained lists, and they drifted: Groq, Together,
 * Fireworks and OpenRouter routed correctly and the API would have stored their
 * keys, but they were missing HERE — so a customer had no way to add one.
 * Routed ≠ usable ≠ **offered**, and the third list is the one a customer
 * actually touches. `scripts/ci/check-byok-provider-coverage.py` proves all
 * three agree.
 *
 * The gateway re-validates every id on upload and rejects an unknown one with
 * 400, so this list is a convenience and never the security boundary.
 */

/** The handful worth putting above the fold. Everything else is alphabetical. */
const POPULAR = [
	"anthropic",
	"openai",
	"google",
	"vertex",
	"bedrock",
	"azure",
	"groq",
	"mistral",
	"openrouter",
	"together",
] as const;

const POPULAR_SET = new Set<string>(POPULAR);
const POPULAR_PROVIDERS = POPULAR.map((id) =>
	PROVIDERS.find((p) => p.id === id),
).filter((p): p is CatalogProvider => p !== undefined);
const OTHER_PROVIDERS = PROVIDERS.filter((p) => !POPULAR_SET.has(p.id));

/** Thrown by the fetchers so the UI can tell "locked" (403) from "broken". */
class HttpError extends Error {
	constructor(readonly status: number) {
		super(`HTTP ${status}`);
	}
}

async function fetchProviderKeys(): Promise<ProviderKeySummary[]> {
	return apiFetch<ProviderKeySummary[]>("/api/settings/provider-keys");
}

async function uploadProviderKey(input: {
	provider_id: string;
	plaintext: string;
}): Promise<ProviderKeySummary> {
	const res = await apiFetchRaw("/api/settings/provider-keys", {
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
	const res = await apiFetchRaw(
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
	const [providerId, setProviderId] = useState<string>(POPULAR[0]);
	const [plaintext, setPlaintext] = useState("");
	const hint = PROVIDERS.find((p) => p.id === providerId)?.hint;

	return (
		<Modal title="Add provider key" onClose={onClose}>
			<form
				onSubmit={(e) => {
					e.preventDefault();
					if (providerId !== "bedrock" && providerId && plaintext.trim()) {
						// Submit the TRIMMED key. A trailing/leading newline or
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
						className="w-full rounded border border-line bg-bg px-3 py-2 text-sm text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
					>
						{/* Two groups, not 169 flat options. A native <select> keeps
						    the browser's type-ahead, which is the fastest way to find
						    one of 169 names and costs no JavaScript. */}
						<optgroup label="Popular">
							{POPULAR_PROVIDERS.map((p) => (
								<option key={p.id} value={p.id}>
									{p.label}
								</option>
							))}
						</optgroup>
						<optgroup label={`All providers (${OTHER_PROVIDERS.length})`}>
							{OTHER_PROVIDERS.map((p) => (
								<option key={p.id} value={p.id}>
									{p.label}
								</option>
							))}
						</optgroup>
					</select>
				</div>
				{providerId === "bedrock" ? (
					<p className="text-xs text-ink-2">
						No tenant credential to validate. Bedrock uses the gateway’s AWS
						credentials.
					</p>
				) : (
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
							className="w-full rounded border border-line bg-bg px-3 py-2 text-sm font-mono text-ink placeholder:text-ink-3 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
							required
						/>
						<p className="text-2xs text-ink-2 mt-1">
							Encrypted at rest (AES-256-GCM, bound to your tenant). Stored once
							— we show only the last 4 characters afterward.
						</p>
					</div>
				)}
				{error && <p className="text-xs text-danger-ink">{error}</p>}
				<div className="flex justify-end gap-2 pt-1">
					<Button
						variant="bare"
						type="button"
						onClick={onClose}
						className="px-4 py-2 rounded text-sm border border-line text-ink-2 hover:bg-surface-2 transition-colors"
					>
						Cancel
					</Button>
					<Button
						variant="bare"
						type="submit"
						disabled={providerId === "bedrock" || !plaintext.trim() || pending}
						className="px-4 py-2 rounded text-sm bg-action text-action-on hover:bg-action/90 disabled:opacity-40 transition-colors"
					>
						{pending ? "Saving…" : "Save key"}
					</Button>
				</div>
			</form>
		</Modal>
	);
}

/**
 * Owner-only empty state. Provider keys are the tenant's upstream credentials,
 * so IDENTITY_TEAM_SPEC §1 scopes both viewing and mutating them to the owner
 * — a member hitting this page is blocked by design, not by a fault.
 */
function OwnerOnlyPanel() {
	return (
		<div className="surface-card border border-dashed border-line bg-surface p-8 text-center shadow-none">
			<p className="text-sm text-ink-2">
				Provider keys are visible to workspace owners only.
			</p>
			<p className="text-xs text-ink-3 mt-1">
				Your workspace&rsquo;s keys are already in use for the calls you make
				through the gateway — you just can&rsquo;t view or change them. Ask an
				owner if a key needs adding or rotating.
			</p>
		</div>
	);
}

export function ProviderKeyManager({ canManage }: { canManage: boolean }) {
	const qc = useQueryClient();
	const [showAdd, setShowAdd] = useState(false);

	const {
		data: keys = [],
		isLoading,
		error,
	} = useQuery({
		queryKey: ["provider-keys"],
		queryFn: fetchProviderKeys,
		staleTime: 30_000,
		// Non-owners are gated at the gateway; don't fire a request that can only
		// 403. The query still runs for owners, and a 403 slipping through (stale
		// session role) is handled below — the server stays authoritative.
		enabled: canManage,
		retry: false,
	});

	// 403 => locked, not broken. Covers a session minted before a role change.
	const locked =
		!canManage || (error instanceof HttpError && error.status === 403);
	const isError = error != null && !locked;

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

	const validationMutation = useMutation({
		mutationFn: async ({
			providerId,
		}: { providerId: string; savedAt?: string }): Promise<
			KeyValidation & { saved_at: string }
		> => {
			const response = await apiFetchRaw(
				`/api/settings/provider-keys/${encodeURIComponent(providerId)}/validate`,
				{ method: "POST" },
			);
			if (!response.ok) {
				const body = (await response.json().catch(() => ({}))) as {
					error?: string;
				};
				throw new Error(body.error ?? "Could not validate this key");
			}
			return response.json();
		},
		onSuccess: (result, { providerId, savedAt }) => {
			qc.setQueryData<ProviderKeySummary[]>(["provider-keys"], (previous) =>
				previous?.map((key) =>
					key.provider_id === providerId &&
					key.saved_at === savedAt &&
					key.saved_at === result.saved_at
						? { ...key, last_validation: result }
						: key,
				),
			);
		},
	});

	// All hooks above this line — the locked branch is a render-time choice only.
	if (locked) {
		return (
			<div className="space-y-4">
				<h3 className="text-sm font-semibold text-ink">Your keys</h3>
				<OwnerOnlyPanel />
			</div>
		);
	}

	return (
		<div className="space-y-4">
			<div className="flex items-center justify-between gap-3">
				<div>
					<h3 className="text-sm font-semibold text-ink">Your keys</h3>
				</div>
				<Button
					variant="bare"
					type="button"
					onClick={() => {
						uploadMutation.reset();
						setShowAdd(true);
					}}
					className="px-3 py-1.5 rounded text-sm bg-action text-action-on hover:bg-action/90 transition-colors"
				>
					+ Add provider key
				</Button>
			</div>

			<p className="text-xs text-ink-2">
				Saved is not validated. A successful check confirms access at that time;
				model permissions and quota may differ.
			</p>
			{isLoading && (
				<p className="text-sm text-ink-2 animate-pulse">Loading…</p>
			)}
			{isError && (
				<p className="text-sm text-danger-ink">Failed to load provider keys.</p>
			)}

			{!isLoading && !isError && keys.length === 0 && (
				<div className="surface-card border border-dashed border-line bg-surface p-8 text-center shadow-none">
					<p className="text-sm text-ink-2">No provider keys yet.</p>
					<p className="text-xs text-ink-3 mt-1">
						Add your Anthropic, OpenAI, or other provider key to start routing
						traffic through Tracelane.
					</p>
				</div>
			)}

			{keys.length > 0 && (
				<div className="surface-card overflow-x-auto border border-line">
					<Table className="w-full text-left">
						<THead className="bg-surface text-xs text-ink-2">
							<TR>
								<TH className="py-1.5 px-3 font-medium">Provider</TH>
								<TH className="py-1.5 pr-3 font-medium">Key</TH>
								<TH className="py-1.5 pr-3 font-medium">Status</TH>
								<TH className="py-1.5 pr-3 font-medium" />
							</TR>
						</THead>
						<TBody>
							{keys.map((key) => (
								<TR
									key={key.provider_id}
									className="border-t border-line last:border-0"
								>
									<TD className="py-2 px-3 text-sm text-ink">
										{PROVIDER_LABEL.get(key.provider_id) ?? key.provider_id}
										{key.saved_at && (
											<p className="text-xs text-ink-2">
												Saved {formatDateTimeUtc(key.saved_at)}
											</p>
										)}
									</TD>
									<TD className="py-2 pr-3 font-mono text-xs text-ink-2">
										••••••••{key.last4}
									</TD>
									<TD className="py-2 pr-3 text-xs text-ink-2">
										{key.provider_id === "bedrock" ? (
											<p>No tenant credential to validate</p>
										) : key.last_validation ? (
											<p>
												{
													{
														valid: "Valid",
														rejected: "Rejected",
														unavailable: "Could not validate",
														cannot_validate: "Cannot validate",
														unsupported: "Cannot validate",
													}[key.last_validation.status]
												}{" "}
												{formatDateTimeUtc(key.last_validation.checked_at)} ·{" "}
												{validationReason(key.last_validation.reason)}
											</p>
										) : (
											<p>Not validated</p>
										)}
										{key.provider_id !== "bedrock" && key.last_rejected_at && (
											<p>
												Last rejected {formatDateTimeUtc(key.last_rejected_at)}{" "}
												· provider rejected the credential
											</p>
										)}
										{key.provider_id !== "bedrock" &&
											key.rejection_history_available === false && (
												<p>Rejection history unavailable</p>
											)}
										{key.provider_id !== "bedrock" &&
											key.rejection_history_available &&
											!key.last_rejected_at && (
												<p>
													No rejection observed in retained traces since this
													save
												</p>
											)}
										{validationMutation.isError &&
											validationMutation.variables?.providerId ===
												key.provider_id && (
												<p role="alert" className="text-danger-ink">
													{validationMutation.error.message}
												</p>
											)}
									</TD>
									<TD className="py-2 pr-3">
										<Button
											variant="bare"
											type="button"
											disabled={
												validationMutation.isPending ||
												key.provider_id === "bedrock"
											}
											onClick={() =>
												validationMutation.mutate({
													providerId: key.provider_id,
													savedAt: key.saved_at,
												})
											}
											className="text-xs px-2 py-1 mr-2 rounded border border-line text-ink disabled:opacity-40"
										>
											{validationMutation.isPending &&
											validationMutation.variables?.providerId ===
												key.provider_id
												? "Validating…"
												: "Validate now"}
										</Button>
										<Button
											variant="bare"
											type="button"
											onClick={() => revokeMutation.mutate(key.provider_id)}
											className="text-xs px-2 py-1 rounded border border-danger text-danger-ink hover:bg-danger-soft transition-colors"
										>
											Revoke
										</Button>
									</TD>
								</TR>
							))}
						</TBody>
					</Table>
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

function validationReason(reason: string): string {
	switch (reason) {
		case "authenticated":
			return "provider accepted the credential";
		case "authentication_rejected":
			return "provider rejected the credential";
		case "rate_limited":
			return "provider rate limit";
		case "public_catalog":
			return "public model catalog accepts invalid credentials";
		case "no_tenant_credential":
			return "no tenant credential to validate";
		case "inconclusive_probe":
			return "model catalog responses could not establish credential validity";
		case "credential_malformed":
			return "credential format is invalid";
		case "token_exchange_failed":
			return "service-account token exchange did not succeed";
		case "probe_not_supported":
			return "run a new check to validate this saved credential";
		case "target_blocked":
			return "provider endpoint could not be verified";
		case "transport_failed":
			return "provider could not be reached";
		default:
			return "provider did not confirm credential validity";
	}
}
