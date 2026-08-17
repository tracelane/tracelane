"use client";

/**
 * ApiKeyManager — self-service tlane_* API key management UI.
 *
 * Lists active keys (prefix + name + dates), creates new keys, revokes keys.
 * The raw key is shown exactly once after creation in a copy-and-dismiss dialog.
 *
 * Pain-points: PP-G1 (developer onboarding), PP-G5 (BYOK key management).
 */

import { absoluteDate } from "@/lib/format-date";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

export interface ApiKeyRow {
	id: string;
	name: string;
	keyPrefix: string;
	createdAt: string;
	lastUsedAt: string | null;
	/** WorkOS user id of the minter (null for pre-0011 keys → rendered "—"). */
	mintedBy?: string | null;
	/**
	 * A13. `null` means the key was minted BEFORE scopes existed and carries the
	 * full API surface — rendered as "Full access (legacy)" rather than as an
	 * empty list, because "no scopes" and "all scopes" are opposite meanings and
	 * showing a blank cell for the permissive one would be dangerously wrong.
	 */
	scope?: string[] | null;
	/** A13. `null` = never expires. */
	expiresAt?: string | null;
}

/** The closed scope vocabulary, mirrored from `tracelane_shared::api_scope`. */
const SCOPES: { value: string; label: string; hint: string }[] = [
	{
		value: "chat",
		label: "Chat",
		hint: "Send completions through the gateway",
	},
	{
		value: "read",
		label: "Read",
		hint: "Read traces, sessions and the audit ledger",
	},
	{
		value: "ingest",
		label: "Ingest",
		hint: "Send traces from an SDK (OTLP)",
	},
	{
		value: "admin",
		label: "Admin",
		hint: "Manage keys, providers and settings",
	},
];

/** Human label for a key's capability. */
function scopeLabel(scope: string[] | null | undefined): string {
	if (scope == null) return "Full access (legacy)";
	if (scope.length === 0) return "No access";
	return scope
		.map((v) => SCOPES.find((s) => s.value === v)?.label ?? v)
		.join(" · ");
}

/** Is this key past its expiry? Display-only — the gateway is the real gate. */
function isExpired(expiresAt: string | null | undefined): boolean {
	if (!expiresAt) return false;
	const t = new Date(expiresAt).getTime();
	return Number.isFinite(t) && t <= Date.now();
}

/**
 * Idle hint for a key that has never been used. A key >7 days old with no
 * last-used is likely dead → a gentle "consider revoking"; a fresh key just
 * hasn't been used yet. Idle ≠ compromised — never imply the key is unsafe.
 */
function idleHint(createdAt: string, lastUsedAt: string | null): string | null {
	if (lastUsedAt) return null;
	const ageMs = Date.now() - new Date(createdAt).getTime();
	if (!Number.isFinite(ageMs)) return null;
	return ageMs > 7 * 86_400_000 ? "unused — consider revoking" : "unused (new)";
}

interface CreateResult extends ApiKeyRow {
	rawKey: string;
}

async function fetchKeys(): Promise<ApiKeyRow[]> {
	const res = await fetch("/api/settings/api-keys");
	if (!res.ok) throw new Error(`HTTP ${res.status}`);
	return res.json() as Promise<ApiKeyRow[]>;
}

export interface CreateKeyInput {
	name: string;
	scope: string[];
	expiresAt: string | null;
}

async function createKey(input: CreateKeyInput): Promise<CreateResult> {
	const res = await fetch("/api/settings/api-keys", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			name: input.name,
			scope: input.scope,
			...(input.expiresAt ? { expiresAt: input.expiresAt } : {}),
		}),
	});
	if (!res.ok) {
		// The gateway 400s with a message naming the bad scope or a past expiry,
		// and the proxy now preserves it. Surfacing `HTTP 400` instead would throw
		// away the only part the user can act on.
		const body = (await res.json().catch(() => ({}))) as { error?: string };
		throw new Error(body.error ?? `HTTP ${res.status}`);
	}
	return res.json() as Promise<CreateResult>;
}

async function revokeKey(id: string): Promise<void> {
	const res = await fetch(`/api/settings/api-keys/${encodeURIComponent(id)}`, {
		method: "DELETE",
	});
	if (!res.ok) throw new Error(`HTTP ${res.status}`);
}

function CopyButton({ text }: { text: string }) {
	const [copied, setCopied] = useState(false);

	const copy = async () => {
		await navigator.clipboard.writeText(text);
		setCopied(true);
		setTimeout(() => setCopied(false), 2000);
	};

	return (
		<button
			type="button"
			onClick={copy}
			className="text-xs px-2 py-1 rounded border border-line text-ink-2 hover:text-ink hover:border-ink-3 transition-colors"
		>
			{copied ? "Copied!" : "Copy"}
		</button>
	);
}

function NewKeyModal({
	rawKey,
	name,
	onDone,
}: {
	rawKey: string;
	name: string;
	onDone: () => void;
}) {
	return (
		<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
			<div className="bg-surface border border-line rounded-xl p-6 w-full max-w-lg shadow-2xl space-y-4">
				<div className="flex items-start justify-between">
					<div>
						<h3 className="text-base font-semibold text-ink">
							API key created
						</h3>
						<p className="text-xs text-ink-2 mt-0.5">{name}</p>
					</div>
					<span className="text-xs text-warn-ink bg-warn/10 border border-warn/20 rounded px-2 py-0.5">
						Copy now — shown once
					</span>
				</div>

				<div className="rounded-lg bg-bg border border-line p-3 flex items-center justify-between gap-3">
					<code className="text-xs font-mono text-action-ink break-all">
						{rawKey}
					</code>
					<CopyButton text={rawKey} />
				</div>

				<p className="text-[11px] text-ink-2">
					Store this key in your secrets manager — this is the only time it's
					shown. We keep only a one-way verifier digest (HMAC + Argon2id), never
					the key itself; if you lose it, revoke and create a new one.
				</p>

				<div className="flex justify-end pt-1">
					<button
						type="button"
						onClick={onDone}
						className="px-4 py-2 rounded text-sm bg-surface-2 text-ink hover:bg-surface-3 transition-colors"
					>
						I&apos;ve saved it
					</button>
				</div>
			</div>
		</div>
	);
}

function CreateKeyDialog({
	onClose,
	onCreate,
	pending,
	error,
}: {
	onClose: () => void;
	onCreate: (input: CreateKeyInput) => void;
	pending: boolean;
	error: Error | null;
}) {
	const [name, setName] = useState("");
	// A13. Default = chat + read + ingest, NOT all four. The mint default at the
	// API is full-surface for backwards compatibility with existing callers, but a
	// human choosing in this dialog should be offered least-privilege — `admin`
	// lets a key mint further keys, which is the one capability worth an explicit
	// tick.
	//
	// GWY-41 added `ingest` to the default deliberately: the key someone mints in
	// their first five minutes is the key they paste into their app, and an app
	// both calls models and reports its traces. Leaving it off would mean the SDK
	// quickstart 403s for every new user, with the fix three screens away.
	// Unticking it is still one click for anyone who wants a chat-only key.
	const [scope, setScope] = useState<string[]>(["chat", "read", "ingest"]);
	const [expiresAt, setExpiresAt] = useState("");
	const toggle = (v: string) =>
		setScope((cur) =>
			cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v],
		);

	return (
		<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
			<div className="bg-surface border border-line rounded-xl p-6 w-full max-w-md shadow-2xl space-y-4">
				<h3 className="text-base font-semibold text-ink">Create API key</h3>
				<form
					onSubmit={(e) => {
						e.preventDefault();
						if (name.trim() && !pending && scope.length > 0) {
							onCreate({
								name: name.trim(),
								scope,
								// <input type="datetime-local"> yields local wall-clock with
								// no zone. Send an explicit UTC instant rather than a naive
								// string — the gateway parses RFC3339 strictly, and a naive
								// value is the timestamp bug this repo has hit before.
								expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
							});
						}
					}}
					className="space-y-3"
				>
					<div>
						<label
							htmlFor="key-name"
							className="text-xs font-medium text-ink-2 block mb-1"
						>
							Key name
						</label>
						<input
							id="key-name"
							type="text"
							value={name}
							onChange={(e) => setName(e.target.value)}
							placeholder="e.g. prod-agent, ci-runner"
							disabled={pending}
							className="w-full rounded border border-line bg-bg px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus:ring-2 focus:ring-action-ink disabled:opacity-50"
							required
						/>
					</div>
					<fieldset className="space-y-1.5">
						<legend className="text-xs font-medium text-ink-2 mb-1">
							Scope — what this key may do
						</legend>
						{SCOPES.map((sc) => (
							<label
								key={sc.value}
								className="flex items-start gap-2 text-xs text-ink cursor-pointer"
							>
								<input
									type="checkbox"
									checked={scope.includes(sc.value)}
									onChange={() => toggle(sc.value)}
									disabled={pending}
									className="mt-0.5"
								/>
								<span>
									<span className="font-medium">{sc.label}</span>
									<span className="text-ink-2"> — {sc.hint}</span>
								</span>
							</label>
						))}
						{scope.length === 0 && (
							<p className="text-[11px] text-danger-ink">
								Pick at least one — a key with no scope can do nothing.
							</p>
						)}
					</fieldset>

					<div>
						<label
							htmlFor="key-expires"
							className="text-xs font-medium text-ink-2 block mb-1"
						>
							Expires <span className="text-ink-3">(optional)</span>
						</label>
						<input
							id="key-expires"
							type="datetime-local"
							value={expiresAt}
							onChange={(e) => setExpiresAt(e.target.value)}
							disabled={pending}
							className="w-full rounded border border-line bg-bg px-3 py-2 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-action-ink disabled:opacity-50"
						/>
						<p className="text-[11px] text-ink-3 mt-1">
							Leave blank for a key that never expires. Times are your local
							zone; the key expires at that instant in UTC.
						</p>
					</div>

					{/* Surface the create error inline — without this the request could
					    fail (e.g. gateway/DB 500) and the dialog would appear to do
					    nothing. */}
					{error && (
						<p
							role="alert"
							className="text-xs text-danger-ink bg-danger-soft border border-danger/30 rounded px-2 py-1.5"
						>
							{/* Claims ONLY what the code knows. The previous copy read
							    "…check that the workspace has API-key creation enabled",
							    which named a setting that DOES NOT EXIST anywhere in the
							    product — no entitlement flag, no column, no config key —
							    and told the user to retry a failure that was 100%
							    deterministic. It invented a plausible cause for an upstream
							    fault and sent the customer to look for it. `error.message`
							    is the gateway's own 4xx text when the request was the
							    problem, or a generic string when the fault was ours
							    (api-keys/route.ts:117-126); the UI cannot tell which, so it
							    must not assert either. */}
							Couldn&apos;t create the key: {error.message}
						</p>
					)}
					<div className="flex justify-end gap-2 pt-1">
						<button
							type="button"
							onClick={onClose}
							disabled={pending}
							className="px-4 py-2 rounded text-sm border border-line text-ink-2 hover:bg-surface-2 transition-colors disabled:opacity-50"
						>
							Cancel
						</button>
						<button
							type="submit"
							disabled={!name.trim() || pending}
							className="px-4 py-2 rounded text-sm bg-action text-action-on hover:bg-action/90 disabled:opacity-40 transition-colors"
						>
							{pending ? "Creating…" : "Create"}
						</button>
					</div>
				</form>
			</div>
		</div>
	);
}

export function ApiKeyManager() {
	const qc = useQueryClient();
	const [showCreate, setShowCreate] = useState(false);
	const [newKey, setNewKey] = useState<CreateResult | null>(null);

	const {
		data: keys = [],
		isLoading,
		isError,
	} = useQuery({
		queryKey: ["api-keys"],
		queryFn: fetchKeys,
		staleTime: 30_000,
	});

	const createMutation = useMutation({
		mutationFn: createKey,
		onSuccess: (result) => {
			void qc.invalidateQueries({ queryKey: ["api-keys"] });
			setShowCreate(false);
			setNewKey(result);
		},
	});

	const revokeMutation = useMutation({
		mutationFn: revokeKey,
		onSuccess: () => void qc.invalidateQueries({ queryKey: ["api-keys"] }),
	});

	return (
		<div className="space-y-4">
			<div className="flex items-center justify-between">
				<div>
					<h2 className="text-sm font-semibold text-ink">API keys</h2>
					<p className="text-xs text-ink-2 mt-0.5">
						Keys authenticate agent traffic through the gateway. Use one key per
						environment.
					</p>
				</div>
				<button
					type="button"
					onClick={() => {
						createMutation.reset(); // clear any stale error before reopening
						setShowCreate(true);
					}}
					className="px-3 py-1.5 rounded text-sm bg-action text-action-on hover:bg-action/90 transition-colors"
				>
					+ New key
				</button>
			</div>

			{isLoading && (
				<p className="text-sm text-ink-2 animate-pulse">Loading…</p>
			)}
			{isError && (
				<p className="text-sm text-danger-ink">Failed to load API keys.</p>
			)}
			{revokeMutation.isError && (
				<p role="alert" className="text-sm text-danger-ink">
					Couldn&apos;t revoke the key: {revokeMutation.error.message}
				</p>
			)}

			{!isLoading && !isError && keys.length === 0 && (
				<div className="rounded-lg border border-dashed border-line p-8 text-center">
					<p className="text-sm text-ink-2">No API keys yet.</p>
					<p className="text-xs text-ink-3 mt-1">
						Create one to start routing agent traffic through Tracelane.
					</p>
				</div>
			)}

			{keys.length > 0 && (
				<div className="rounded-lg border border-line overflow-hidden">
					<table className="w-full text-left">
						<thead className="bg-surface text-xs text-ink-2">
							<tr>
								<th className="py-1.5 px-3 font-medium">Name</th>
								<th className="py-1.5 pr-3 font-medium">Prefix</th>
								<th className="py-1.5 pr-3 font-medium">Scope</th>
								<th className="py-1.5 pr-3 font-medium">Expires</th>
								<th className="py-1.5 pr-3 font-medium">Created</th>
								<th className="py-1.5 pr-3 font-medium">Created by</th>
								<th
									className="py-1.5 pr-3 font-medium"
									title="Refreshed when a key misses the auth cache, so it can lag real usage by up to 15 minutes."
								>
									Last used{" "}
									<span className="font-normal text-ink-3" aria-hidden="true">
										†
									</span>
								</th>
								<th className="py-1.5 pr-3 font-medium" />
							</tr>
						</thead>
						<tbody>
							{keys.map((key) => (
								<tr key={key.id} className="border-t border-line last:border-0">
									<td className="py-2 px-3 text-sm text-ink">{key.name}</td>
									<td className="py-2 pr-3 font-mono text-xs text-ink-2">
										tlane_{key.keyPrefix}…
									</td>
									<td className="py-2 pr-3 text-xs">
										{/* `null` scope is a LEGACY key with the full surface —
										    never render it as an empty list, which would read as
										    "no access" and is the opposite of the truth. */}
										<span
											className={
												key.scope == null ? "text-warn-ink" : "text-ink-2"
											}
											title={
												key.scope == null
													? "Minted before scopes existed — carries the full API surface. Re-mint with explicit scopes to narrow it."
													: undefined
											}
										>
											{scopeLabel(key.scope)}
										</span>
									</td>
									<td className="py-2 pr-3 text-xs">
										{key.expiresAt ? (
											<span
												className={
													isExpired(key.expiresAt)
														? "text-danger-ink"
														: "text-ink-2"
												}
											>
												{absoluteDate(key.expiresAt)}
												{isExpired(key.expiresAt) ? " (expired)" : ""}
											</span>
										) : (
											<span className="text-ink-3">Never</span>
										)}
									</td>
									<td className="py-2 pr-3 text-xs text-ink-2">
										{absoluteDate(key.createdAt)}
									</td>
									<td className="py-2 pr-3 font-mono text-xs text-ink-3">
										{key.mintedBy ? `${key.mintedBy.slice(0, 14)}…` : "—"}
									</td>
									<td className="py-2 pr-3 text-xs text-ink-2">
										{key.lastUsedAt ? (
											absoluteDate(key.lastUsedAt)
										) : (
											<span
												title={idleHint(key.createdAt, key.lastUsedAt) ?? ""}
												className="text-ink-3"
											>
												{idleHint(key.createdAt, key.lastUsedAt) ?? "Never"}
											</span>
										)}
									</td>
									<td className="py-2 pr-3">
										<button
											type="button"
											onClick={() => {
												if (
													window.confirm(
														// The gateway caches a positive auth result, so a
														// revoked key keeps working until that entry expires —
														// bounded at 60 seconds, and it was 15 minutes until
														// 2026-08-12. Revocation is recorded instantly; it is
														// ENFORCED within a minute, and the copy now says which.
														`Revoke "${key.name}"? The key stops working within 60 seconds — any agent still using it will start failing authentication. This cannot be undone.`,
													)
												) {
													revokeMutation.mutate(key.id);
												}
											}}
											className="text-xs px-2 py-1 rounded border border-danger text-danger-ink hover:bg-danger-soft transition-colors"
										>
											Revoke
										</button>
									</td>
								</tr>
							))}
						</tbody>
					</table>
					<p className="px-4 pb-3 pt-2 text-[11px] text-ink-3">
						† <strong>Last used</strong> is refreshed when a key misses the auth
						cache, so it can lag real usage by up to 15 minutes. A key used
						seconds ago may still read as older. Treat it as a staleness signal,
						not an audit trail — the audit ledger is authoritative.
					</p>
				</div>
			)}

			{showCreate && (
				<CreateKeyDialog
					onClose={() => {
						setShowCreate(false);
						createMutation.reset();
					}}
					onCreate={(input) => createMutation.mutate(input)}
					pending={createMutation.isPending}
					error={createMutation.error}
				/>
			)}

			{newKey && (
				<NewKeyModal
					rawKey={newKey.rawKey}
					name={newKey.name}
					onDone={() => setNewKey(null)}
				/>
			)}
		</div>
	);
}
