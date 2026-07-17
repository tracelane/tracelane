"use client";

/**
 * ByokKeyManager — self-service CMK/BYOK key management UI.
 *
 * Allows tenants to register, rotate, and revoke their Customer-Managed
 * Keys (CMK) for envelope encryption of provider API keys and trace payloads.
 * Keys are stored server-side as envelope-encrypted entries; only the
 * public key fingerprint is shown in the UI (the raw key never transits here).
 *
 * Pain-points: PP-G5 (BYOK provider keys), PP-P15 (enterprise CMK self-service).
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

type KeyStatus = "active" | "rotating" | "revoked";

export interface CmkEntry {
	id: string;
	alias: string;
	fingerprint: string; // SHA-256 of public key, hex
	algorithm: "ed25519" | "rsa-4096";
	status: KeyStatus;
	createdAt: string; // ISO 8601
	rotatedAt?: string;
	purpose: "provider-keys" | "trace-payload" | "all";
}

interface AddKeyPayload {
	alias: string;
	publicKeyPem: string;
	purpose: CmkEntry["purpose"];
}

async function fetchKeys(): Promise<CmkEntry[]> {
	const res = await fetch("/api/settings/cmk-keys");
	if (!res.ok) throw new Error(`HTTP ${res.status}`);
	return res.json() as Promise<CmkEntry[]>;
}

async function addKey(payload: AddKeyPayload): Promise<CmkEntry> {
	const res = await fetch("/api/settings/cmk-keys", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(payload),
	});
	if (!res.ok) throw new Error(`HTTP ${res.status}`);
	return res.json() as Promise<CmkEntry>;
}

async function revokeKey(id: string): Promise<void> {
	const res = await fetch(`/api/settings/cmk-keys/${encodeURIComponent(id)}`, {
		method: "DELETE",
	});
	if (!res.ok) throw new Error(`HTTP ${res.status}`);
}

async function rotateKey(id: string, publicKeyPem: string): Promise<CmkEntry> {
	const res = await fetch(
		`/api/settings/cmk-keys/${encodeURIComponent(id)}/rotate`,
		{
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ publicKeyPem }),
		},
	);
	if (!res.ok) throw new Error(`HTTP ${res.status}`);
	return res.json() as Promise<CmkEntry>;
}

const STATUS_BADGE: Record<KeyStatus, string> = {
	active: "bg-ok-soft text-ok",
	rotating: "bg-warn-soft text-warn",
	revoked: "bg-danger-soft text-danger",
};

function KeyRow({
	entry,
	onRevoke,
	onRotate,
}: {
	entry: CmkEntry;
	onRevoke: (id: string) => void;
	onRotate: (id: string) => void;
}) {
	return (
		<tr className="border-b border-border last:border-0">
			<td className="py-3 pr-4 text-sm font-medium">{entry.alias}</td>
			<td className="py-3 pr-4 font-mono text-xs text-muted-foreground">
				{entry.fingerprint.slice(0, 16)}…
			</td>
			<td className="py-3 pr-4 text-xs text-muted-foreground">
				{entry.algorithm}
			</td>
			<td className="py-3 pr-4 text-xs text-muted-foreground">
				{entry.purpose}
			</td>
			<td className="py-3 pr-4">
				<span
					className={`inline-block px-2 py-0.5 rounded text-[11px] font-medium ${STATUS_BADGE[entry.status]}`}
				>
					{entry.status}
				</span>
			</td>
			<td className="py-3 pr-4 text-xs text-muted-foreground">
				{new Date(entry.createdAt).toLocaleDateString()}
			</td>
			<td className="py-3 flex gap-2">
				{entry.status === "active" && (
					<>
						<button
							type="button"
							onClick={() => onRotate(entry.id)}
							className="text-xs px-2 py-1 rounded border border-border hover:bg-muted transition-colors"
						>
							Rotate
						</button>
						<button
							type="button"
							onClick={() => onRevoke(entry.id)}
							className="text-xs px-2 py-1 rounded border border-destructive text-destructive hover:bg-destructive/10 transition-colors"
						>
							Revoke
						</button>
					</>
				)}
			</td>
		</tr>
	);
}

function AddKeyModal({
	onClose,
	onAdd,
}: {
	onClose: () => void;
	onAdd: (payload: AddKeyPayload) => void;
}) {
	const [alias, setAlias] = useState("");
	const [pem, setPem] = useState("");
	const [purpose, setPurpose] = useState<CmkEntry["purpose"]>("all");

	const handleSubmit = (e: React.FormEvent) => {
		e.preventDefault();
		if (!alias.trim() || !pem.trim()) return;
		onAdd({ alias: alias.trim(), publicKeyPem: pem.trim(), purpose });
	};

	return (
		<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
			<div className="bg-card border rounded-lg p-6 w-full max-w-lg shadow-xl space-y-4">
				<h3 className="text-base font-semibold">Register CMK Public Key</h3>
				<form onSubmit={handleSubmit} className="space-y-3">
					<div>
						<label
							htmlFor="cmk-alias"
							className="text-xs font-medium text-muted-foreground block mb-1"
						>
							Key alias
						</label>
						<input
							id="cmk-alias"
							type="text"
							value={alias}
							onChange={(e) => setAlias(e.target.value)}
							placeholder="e.g. prod-cmk-2026"
							className="w-full rounded border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
							required
						/>
					</div>
					<div>
						<label
							htmlFor="cmk-purpose"
							className="text-xs font-medium text-muted-foreground block mb-1"
						>
							Purpose
						</label>
						<select
							id="cmk-purpose"
							value={purpose}
							onChange={(e) =>
								setPurpose(e.target.value as CmkEntry["purpose"])
							}
							className="w-full rounded border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
						>
							<option value="all">All (provider keys + trace payload)</option>
							<option value="provider-keys">Provider API keys only</option>
							<option value="trace-payload">Trace payload only</option>
						</select>
					</div>
					<div>
						<label
							htmlFor="cmk-pem"
							className="text-xs font-medium text-muted-foreground block mb-1"
						>
							Public key (PEM — Ed25519 or RSA-4096)
						</label>
						<textarea
							id="cmk-pem"
							value={pem}
							onChange={(e) => setPem(e.target.value)}
							placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----"
							rows={6}
							className="w-full rounded border border-input bg-background px-3 py-2 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-ring resize-none"
							required
						/>
					</div>
					<p className="text-[11px] text-muted-foreground">
						Only the public key is transmitted. Keys are stored as a
						fingerprint; the raw PEM is not retained after processing.
					</p>
					<div className="flex justify-end gap-2 pt-2">
						<button
							type="button"
							onClick={onClose}
							className="px-4 py-2 rounded text-sm border border-border hover:bg-muted transition-colors"
						>
							Cancel
						</button>
						<button
							type="submit"
							className="px-4 py-2 rounded text-sm bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
						>
							Register Key
						</button>
					</div>
				</form>
			</div>
		</div>
	);
}

export function ByokKeyManager() {
	const qc = useQueryClient();
	const [showAdd, setShowAdd] = useState(false);
	const [rotateId, setRotateId] = useState<string | null>(null);
	const [rotatePem, setRotatePem] = useState("");

	const {
		data: keys = [],
		isLoading,
		isError,
	} = useQuery({
		queryKey: ["cmk-keys"],
		queryFn: fetchKeys,
		staleTime: 30_000,
	});

	const addMutation = useMutation({
		mutationFn: addKey,
		onSuccess: () => {
			void qc.invalidateQueries({ queryKey: ["cmk-keys"] });
			setShowAdd(false);
		},
	});

	const revokeMutation = useMutation({
		mutationFn: revokeKey,
		onSuccess: () => void qc.invalidateQueries({ queryKey: ["cmk-keys"] }),
	});

	const rotateMutation = useMutation({
		mutationFn: ({ id, pem }: { id: string; pem: string }) =>
			rotateKey(id, pem),
		onSuccess: () => {
			void qc.invalidateQueries({ queryKey: ["cmk-keys"] });
			setRotateId(null);
			setRotatePem("");
		},
	});

	return (
		<div className="space-y-4">
			<div className="flex items-center justify-between">
				<div>
					<h3 className="text-sm font-semibold text-ink">Registered keys</h3>
				</div>
				<button
					type="button"
					onClick={() => setShowAdd(true)}
					className="px-4 py-2 rounded text-sm bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
				>
					+ Add Key
				</button>
			</div>

			{isLoading && (
				<p className="text-sm text-muted-foreground animate-pulse">
					Loading keys…
				</p>
			)}
			{isError && (
				<p className="text-sm text-destructive">Failed to load CMK keys.</p>
			)}

			{!isLoading && !isError && keys.length === 0 && (
				<div className="rounded-lg border border-dashed border-border p-8 text-center text-sm text-muted-foreground">
					No CMK keys registered. Add a key to enable BYOK encryption.
				</div>
			)}

			{keys.length > 0 && (
				<div className="rounded-lg border overflow-hidden">
					<table className="w-full text-left">
						<thead className="bg-muted/50 text-xs text-muted-foreground">
							<tr>
								<th className="py-2.5 pr-4 pl-4 font-medium">Alias</th>
								<th className="py-2.5 pr-4 font-medium">Fingerprint</th>
								<th className="py-2.5 pr-4 font-medium">Algorithm</th>
								<th className="py-2.5 pr-4 font-medium">Purpose</th>
								<th className="py-2.5 pr-4 font-medium">Status</th>
								<th className="py-2.5 pr-4 font-medium">Created</th>
								<th className="py-2.5 pr-4 font-medium">Actions</th>
							</tr>
						</thead>
						<tbody className="pl-4">
							{keys.map((key) => (
								<KeyRow
									key={key.id}
									entry={key}
									onRevoke={(id) => revokeMutation.mutate(id)}
									onRotate={(id) => setRotateId(id)}
								/>
							))}
						</tbody>
					</table>
				</div>
			)}

			{/* Add key modal */}
			{showAdd && (
				<AddKeyModal
					onClose={() => setShowAdd(false)}
					onAdd={(payload) => addMutation.mutate(payload)}
				/>
			)}

			{/* Rotate key modal */}
			{rotateId !== null && (
				<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
					<div className="bg-card border rounded-lg p-6 w-full max-w-lg shadow-xl space-y-4">
						<h3 className="text-base font-semibold">Rotate CMK Key</h3>
						<p className="text-xs text-muted-foreground">
							Provide the new public key. The old key will remain active during
							re-encryption (status: rotating) and be revoked automatically once
							complete.
						</p>
						<textarea
							value={rotatePem}
							onChange={(e) => setRotatePem(e.target.value)}
							placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----"
							rows={6}
							className="w-full rounded border border-input bg-background px-3 py-2 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-ring resize-none"
						/>
						<div className="flex justify-end gap-2 pt-2">
							<button
								type="button"
								onClick={() => {
									setRotateId(null);
									setRotatePem("");
								}}
								className="px-4 py-2 rounded text-sm border border-border hover:bg-muted transition-colors"
							>
								Cancel
							</button>
							<button
								type="button"
								onClick={() =>
									rotateMutation.mutate({ id: rotateId, pem: rotatePem })
								}
								disabled={!rotatePem.trim()}
								className="px-4 py-2 rounded text-sm bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition-colors"
							>
								Rotate Key
							</button>
						</div>
					</div>
				</div>
			)}
		</div>
	);
}
