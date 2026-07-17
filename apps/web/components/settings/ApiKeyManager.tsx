"use client";

/**
 * ApiKeyManager — self-service tlane_* API key management UI.
 *
 * Lists active keys (prefix + name + dates), creates new keys, revokes keys.
 * The raw key is shown exactly once after creation in a copy-and-dismiss dialog.
 *
 * Pain-points: PP-G1 (developer onboarding), PP-G5 (BYOK key management).
 */

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

async function createKey(name: string): Promise<CreateResult> {
	const res = await fetch("/api/settings/api-keys", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ name }),
	});
	if (!res.ok) throw new Error(`HTTP ${res.status}`);
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
		<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
			<div className="bg-surface border border-line rounded-lg p-6 w-full max-w-lg shadow-2xl space-y-4">
				<div className="flex items-start justify-between">
					<div>
						<h3 className="text-base font-semibold text-ink">
							API key created
						</h3>
						<p className="text-xs text-ink-2 mt-0.5">{name}</p>
					</div>
					<span className="text-xs text-warn bg-warn/10 border border-warn/20 rounded px-2 py-0.5">
						Copy now — shown once
					</span>
				</div>

				<div className="rounded-md bg-bg border border-line p-3 flex items-center justify-between gap-3">
					<code className="text-xs font-mono text-accent-ink break-all">
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
	onCreate: (name: string) => void;
	pending: boolean;
	error: Error | null;
}) {
	const [name, setName] = useState("");

	return (
		<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
			<div className="bg-surface border border-line rounded-lg p-6 w-full max-w-md shadow-2xl space-y-4">
				<h3 className="text-base font-semibold text-ink">Create API key</h3>
				<form
					onSubmit={(e) => {
						e.preventDefault();
						if (name.trim() && !pending) onCreate(name.trim());
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
							className="w-full rounded border border-line bg-bg px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus:ring-2 focus:ring-accent-ink disabled:opacity-50"
							required
						/>
					</div>
					{/* Surface the create error inline — without this the request could
					    fail (e.g. gateway/DB 500) and the dialog would appear to do
					    nothing. */}
					{error && (
						<p
							role="alert"
							className="text-xs text-danger bg-danger-soft border border-danger/30 rounded px-2 py-1.5"
						>
							Couldn&apos;t create the key: {error.message}. Please retry — if
							it persists, check that the workspace has API-key creation
							enabled.
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
							className="px-4 py-2 rounded text-sm bg-accent text-accent-on hover:bg-accent/90 disabled:opacity-40 transition-colors"
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
					className="px-3 py-1.5 rounded text-sm bg-accent text-accent-on hover:bg-accent/90 transition-colors"
				>
					+ New key
				</button>
			</div>

			{isLoading && (
				<p className="text-sm text-ink-2 animate-pulse">Loading…</p>
			)}
			{isError && (
				<p className="text-sm text-danger">Failed to load API keys.</p>
			)}
			{revokeMutation.isError && (
				<p role="alert" className="text-sm text-danger">
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
								<th className="py-2.5 px-4 font-medium">Name</th>
								<th className="py-2.5 pr-4 font-medium">Prefix</th>
								<th className="py-2.5 pr-4 font-medium">Created</th>
								<th className="py-2.5 pr-4 font-medium">Created by</th>
								<th className="py-2.5 pr-4 font-medium">Last used</th>
								<th className="py-2.5 pr-4 font-medium" />
							</tr>
						</thead>
						<tbody>
							{keys.map((key) => (
								<tr key={key.id} className="border-t border-line last:border-0">
									<td className="py-3 px-4 text-sm text-ink">{key.name}</td>
									<td className="py-3 pr-4 font-mono text-xs text-ink-2">
										tlane_{key.keyPrefix}…
									</td>
									<td className="py-3 pr-4 text-xs text-ink-2">
										{new Date(key.createdAt).toLocaleDateString()}
									</td>
									<td className="py-3 pr-4 font-mono text-xs text-ink-3">
										{key.mintedBy ? `${key.mintedBy.slice(0, 14)}…` : "—"}
									</td>
									<td className="py-3 pr-4 text-xs text-ink-2">
										{key.lastUsedAt ? (
											new Date(key.lastUsedAt).toLocaleDateString()
										) : (
											<span
												title={idleHint(key.createdAt, key.lastUsedAt) ?? ""}
												className="text-ink-3"
											>
												{idleHint(key.createdAt, key.lastUsedAt) ?? "Never"}
											</span>
										)}
									</td>
									<td className="py-3 pr-4">
										<button
											type="button"
											onClick={() => {
												if (
													window.confirm(
														`Revoke "${key.name}"? Any agent still using this key will immediately fail authentication. This cannot be undone.`,
													)
												) {
													revokeMutation.mutate(key.id);
												}
											}}
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

			{showCreate && (
				<CreateKeyDialog
					onClose={() => {
						setShowCreate(false);
						createMutation.reset();
					}}
					onCreate={(name) => createMutation.mutate(name)}
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
