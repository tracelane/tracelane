"use client";

/**
 * PromotionPanel — B1 eval-gated prompt promotion UI.
 *
 * Calls POST /api/prompts/:name/promote (Next.js route → gateway proxy with
 * per-user JWT). The gateway enforces entitlements:
 *
 *   - Builder $59  → 403 with { error, feature, message, upgrade_url }
 *   - Team $249+   → 200/201 (decision: promoted / blocked_by_eval /
 *                    blocked_by_policy / manual_override)
 *   - Eval gate blocked → 409
 *
 * The 403 case renders an upgrade prompt with the gateway-supplied upgrade_url
 * rather than a broken/disabled button. The 409 case explains the block.
 *
 * Honesty: no eval_scores are rendered here. The promote DTO does NOT carry
 * per-version eval metrics (the EWMA baselines are in-memory only). Rendering
 * fabricated scores is a honesty violation — DO NOT add them.
 */

import { useRouter } from "next/navigation";
import { useState } from "react";

interface PromotionDecision {
	promotion_id: string;
	from_version_id: string | null;
	to_version_id: string;
	from_env: string;
	to_env: string;
	eval_run_id: string | null;
	decision:
		| "promoted"
		| "blocked_by_eval"
		| "blocked_by_policy"
		| "manual_override";
	notes: string;
}

/** Shape of the gateway's 403 entitlement-required body. */
interface EntitlementError {
	error: string;
	feature: string;
	message: string;
	upgrade_url: string;
}

export interface PromotionPanelProps {
	promptName: string;
	/** Pre-fill the version ID input (e.g. from the staging env card). */
	candidateVersionId?: string;
}

type Status =
	| "idle"
	| "loading"
	| "success"
	| "blocked"
	| "upgrade_required"
	| "error";

export function PromotionPanel({
	promptName,
	candidateVersionId = "",
}: PromotionPanelProps) {
	const router = useRouter();
	const [versionId, setVersionId] = useState(candidateVersionId);
	const [evalRunId, setEvalRunId] = useState("");
	const [overrideReason, setOverrideReason] = useState("");
	const [fromEnv, setFromEnv] = useState<"staging" | "canary">("staging");
	const [status, setStatus] = useState<Status>("idle");
	const [result, setResult] = useState<PromotionDecision | null>(null);
	const [errorMsg, setErrorMsg] = useState("");
	const [upgradeUrl, setUpgradeUrl] = useState("");

	async function handlePromote(e: React.FormEvent) {
		e.preventDefault();
		if (!versionId.trim()) return;

		setStatus("loading");
		setResult(null);
		setErrorMsg("");
		setUpgradeUrl("");

		try {
			const res = await fetch(
				`/api/prompts/${encodeURIComponent(promptName)}/promote`,
				{
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify({
						from_env: fromEnv,
						to_env: "production",
						to_version_id: versionId.trim(),
						eval_run_id: evalRunId.trim() || null,
						override_reason: overrideReason.trim() || undefined,
					}),
				},
			);

			// 403 = Team+ entitlement required. Surface the upgrade_url from the
			// gateway body so the user has a direct path to upgrade.
			if (res.status === 403) {
				const body = (await res.json()) as EntitlementError;
				setStatus("upgrade_required");
				setUpgradeUrl(body.upgrade_url ?? "/#pricing");
				setErrorMsg(
					body.message ?? "Team plan ($249/mo) required to promote prompts.",
				);
				return;
			}

			const json = (await res.json()) as PromotionDecision;
			setResult(json);

			if (res.ok) {
				setStatus("success");
				// Refresh the page so the env cards reflect the new active version.
				router.refresh();
			} else if (res.status === 409) {
				setStatus("blocked");
			} else {
				setStatus("error");
				setErrorMsg(`Gateway returned ${res.status}.`);
			}
		} catch (err) {
			setStatus("error");
			setErrorMsg(err instanceof Error ? err.message : "Network error");
		}
	}

	const isLoading = status === "loading";

	return (
		<div className="rounded-lg border border-line bg-surface p-5 space-y-4">
			<h2 className="text-sm font-semibold text-ink">Promote to production</h2>
			<p className="text-xs leading-relaxed text-ink-2">
				Point <span className="text-ink">production</span> at a specific
				version. Every promotion is written to the{" "}
				<span className="text-ink">tamper-evident audit ledger</span> as an
				attributed decision.
			</p>
			<details className="text-xs text-ink-2">
				<summary className="cursor-pointer font-medium text-ink-2 outline-none hover:text-ink focus-visible:ring-2 focus-visible:ring-seal">
					How promotion works
				</summary>
				<p className="mt-1.5 leading-relaxed">
					Today you promote with an{" "}
					<span className="text-ink">override reason</span>, recorded as a
					tamper-evident, attributed decision. Automated eval-gating — a passing
					eval run clears the gate automatically — is on the roadmap; until it
					ships, an override reason is required. Promoting requires the Team
					plan.
				</p>
			</details>

			<form onSubmit={handlePromote} className="space-y-3">
				{/* From env selector */}
				<div>
					<span className="block text-xs text-ink-2 mb-1.5">Promote from</span>
					<div className="flex gap-2">
						{(["staging", "canary"] as const).map((env) => (
							<button
								key={env}
								type="button"
								onClick={() => setFromEnv(env)}
								className={`rounded px-3 py-1 text-xs font-medium transition-colors ${
									fromEnv === env
										? "bg-surface-3 text-ink"
										: "text-ink-2 hover:text-ink"
								}`}
							>
								{env}
							</button>
						))}
					</div>
				</div>

				{/* Candidate version ID — copy from the env card above */}
				<div>
					<label
						htmlFor="promotion-version-id"
						className="block text-xs text-ink-2 mb-1"
					>
						Candidate version ID{" "}
						<span className="text-ink-3">
							(pre-filled from staging — edit to promote another version)
						</span>
					</label>
					<input
						id="promotion-version-id"
						type="text"
						value={versionId}
						onChange={(e) => setVersionId(e.target.value)}
						placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
						className="w-full rounded-md border border-line bg-bg px-3 py-1.5 text-xs font-mono text-ink placeholder:text-ink-3 outline-none focus:border-accent-line"
						required
						disabled={isLoading}
					/>
				</div>

				{/* Eval run ID (optional) */}
				<div>
					<label
						htmlFor="promotion-eval-run-id"
						className="block text-xs text-ink-2 mb-1"
					>
						Eval run ID{" "}
						<span className="text-ink-3">
							(for automated eval-gating once it ships — leave blank and use an
							override reason today)
						</span>
					</label>
					<input
						id="promotion-eval-run-id"
						type="text"
						value={evalRunId}
						onChange={(e) => setEvalRunId(e.target.value)}
						placeholder="Leave blank today — promote with an override reason below"
						className="w-full rounded-md border border-line bg-bg px-3 py-1.5 text-xs font-mono text-ink placeholder:text-ink-3 outline-none focus:border-accent-line"
						disabled={isLoading}
					/>
				</div>

				{/* Override reason — promote without a passing eval run, recorded as
				    a tamper-evident, attributed ManualOverride decision. */}
				<div>
					<label
						htmlFor="promotion-override-reason"
						className="block text-xs text-ink-2 mb-1"
					>
						Override reason{" "}
						<span className="text-ink-3">
							(promote without an eval run — recorded as a tamper-evident
							override)
						</span>
					</label>
					<input
						id="promotion-override-reason"
						type="text"
						value={overrideReason}
						onChange={(e) => setOverrideReason(e.target.value)}
						placeholder="e.g. urgent prod hotfix — approved by …"
						className="w-full rounded-md border border-line bg-bg px-3 py-1.5 text-xs text-ink placeholder:text-ink-3 outline-none focus:border-accent-line"
						disabled={isLoading}
					/>
				</div>

				<button
					type="submit"
					disabled={isLoading || !versionId.trim()}
					className="w-full rounded-md bg-accent px-4 py-2 text-xs font-semibold text-accent-on transition-colors hover:bg-accent/90 disabled:opacity-40 disabled:cursor-not-allowed"
				>
					{isLoading
						? "Promoting…"
						: overrideReason.trim()
							? "Override → production"
							: `Promote ${fromEnv} → production`}
				</button>
			</form>

			{status === "success" && result ? (
				<div className="rounded-md border border-ok bg-ok-soft/40 p-3 text-xs space-y-1">
					<p className="font-semibold text-ok">
						{result.decision === "manual_override"
							? "Manual override applied"
							: "Promoted successfully"}
					</p>
					<p className="text-ink-2">
						Promotion ID:{" "}
						<span className="font-mono text-ink">
							{result.promotion_id.slice(0, 8)}…
						</span>
					</p>
					{result.notes ? <p className="text-ink-2">{result.notes}</p> : null}
				</div>
			) : null}

			{status === "blocked" && result ? (
				<div className="rounded-md border border-warn bg-warn-soft/40 p-3 text-xs space-y-1">
					<p className="font-semibold text-warn">
						{result.decision === "blocked_by_eval"
							? "Blocked by eval gate"
							: "Blocked by policy"}
					</p>
					{result.notes ? <p className="text-ink-2">{result.notes}</p> : null}
					<p className="text-ink-2">
						Enter an override reason above and re-promote — it's recorded as a
						tamper-evident, attributed decision. (Automated eval-gating via a
						passing eval run is on the roadmap.)
					</p>
				</div>
			) : null}

			{status === "upgrade_required" ? (
				<div className="rounded-md border border-accent-line bg-accent-soft/40 p-3 text-xs space-y-1">
					<p className="font-semibold text-accent-ink">Team plan required</p>
					<p className="text-ink-2">{errorMsg}</p>
					<a
						href={upgradeUrl || "/#pricing"}
						className="inline-block mt-1 text-accent-ink underline underline-offset-2 hover:opacity-80 transition-opacity"
					>
						Upgrade to Team →
					</a>
				</div>
			) : null}

			{status === "error" ? (
				<div className="rounded-md border border-danger bg-danger-soft/40 p-3 text-xs text-danger">
					{errorMsg || "Unexpected failure — check gateway logs."}
				</div>
			) : null}

			<p className="text-[10px] text-ink-3">
				Promotions are written to the tamper-evident audit ledger and visible
				under Recent activity below.
			</p>
		</div>
	);
}
