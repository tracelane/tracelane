"use client";
import { Button } from "@tracelanedev/ui";

import { ReadFailure } from "@/components/empty-states/ReadFailure";
import { apiFetchRaw } from "@/lib/api-fetch";
import type { Canary } from "@/lib/prompts";
import { useRouter } from "next/navigation";
import { useState } from "react";
export function CanaryPanel({
	promptName,
	candidateVersionId,
	initial,
	readStatus,
}: {
	promptName: string;
	candidateVersionId: string;
	initial: Canary | null;
	readStatus: number;
}) {
	const router = useRouter();
	const [candidate, setCandidate] = useState(
		initial?.candidate_version_id ?? candidateVersionId,
	);
	const [percent, setPercent] = useState(
		initial ? String(initial.candidate_percent) : "",
	);
	const [busy, setBusy] = useState(false);
	const [message, setMessage] = useState("");
	const [upgrade, setUpgrade] = useState("");
	async function save(method: "PUT" | "DELETE") {
		setBusy(true);
		setMessage("");
		setUpgrade("");
		try {
			const res = await apiFetchRaw(
				`/api/prompts/${encodeURIComponent(promptName)}/canary`,
				{
					method,
					headers: { "content-type": "application/json" },
					body:
						method === "PUT"
							? JSON.stringify({
									candidate_version_id: candidate.trim(),
									candidate_percent: Number(percent),
								})
							: undefined,
				},
			);
			const body = res.status === 204 ? {} : await res.json();
			if (!res.ok) {
				setMessage(
					res.status === 401
						? "Sign in again to manage canaries."
						: res.status === 403 && !body.upgrade_url
							? "Access denied. Ask a workspace administrator for permission."
							: (body.message ??
								body.error ??
								`Gateway returned ${res.status}.`),
				);
				if (body.upgrade_url) setUpgrade(body.upgrade_url);
			} else
				setMessage(method === "DELETE" ? "Canary stopped." : "Canary saved.");
			router.refresh();
		} catch {
			setMessage(
				"Couldn't reach the gateway. Reload to check the saved state before retrying.",
			);
		} finally {
			setBusy(false);
		}
	}
	return (
		<div className="surface-card space-y-3 border border-line bg-surface p-5">
			<h2 className="text-sm font-semibold">Canary · Team+</h2>
			<p className="text-sm text-ink-2">
				Choose a percentage of prompt resolutions for a candidate. Repeated
				caller identities stay in the same arm. Fetching once and reusing the
				prompt counts as one resolution.
			</p>
			<p className="text-sm text-ink-2">
				A stable user, conversation or agent identity header is required during
				a split. Observed proportions can differ from the configured percentage.
			</p>
			<p className="text-sm text-warn-ink">
				Workspace response caching is suspended while any canary is active. A
				production promotion or rollback stops this split; previous cached
				responses are not reused afterward.
			</p>
			{readStatus !== 200 ? (
				<ReadFailure
					status={readStatus}
					resource="canary configuration"
					retryHref={`/prompts/${encodeURIComponent(promptName)}`}
				/>
			) : (
				<>
					{initial ? (
						<p className="text-sm break-words">
							Configured: {initial.candidate_percent}% candidate (
							{initial.candidate_version_id}); {100 - initial.candidate_percent}
							% stable ({initial.stable_version_id}).
						</p>
					) : (
						<p className="text-sm">
							No active canary. Production must have a stable version before
							starting.
						</p>
					)}
					<form
						className="space-y-3"
						onSubmit={(e) => {
							e.preventDefault();
							void save("PUT");
						}}
					>
						<label className="block text-sm">
							Candidate version ID
							<input
								className="mt-1 w-full rounded border border-line bg-surface p-2"
								required
								value={candidate}
								onChange={(e) => setCandidate(e.target.value)}
							/>
						</label>
						<label className="block text-sm">
							Candidate percentage of prompt resolutions
							<input
								className="mt-1 w-full rounded border border-line bg-surface p-2"
								type="number"
								required
								min="0"
								max="100"
								step="any"
								value={percent}
								onChange={(e) => setPercent(e.target.value)}
							/>
						</label>
						<div className="flex flex-wrap gap-3">
							<Button
								variant="bare"
								className="rounded-control bg-action px-4 py-2 text-xs font-semibold text-action-on disabled:opacity-40 disabled:cursor-not-allowed"
								disabled={
									busy || !candidate.trim() || !percent || Number(percent) <= 0
								}
								type="submit"
							>
								{busy ? "Saving…" : initial ? "Update canary" : "Start canary"}
							</Button>
							{initial && (
								<Button
									variant="bare"
									className="rounded-control border border-line px-4 py-2 text-xs font-semibold disabled:opacity-40"
									disabled={busy}
									type="button"
									onClick={() => void save("DELETE")}
								>
									Stop canary
								</Button>
							)}
						</div>
					</form>
				</>
			)}
			{message && <output className="text-sm">{message}</output>}
			{upgrade && (
				<a className="underline" href={upgrade}>
					Upgrade plan
				</a>
			)}
		</div>
	);
}
