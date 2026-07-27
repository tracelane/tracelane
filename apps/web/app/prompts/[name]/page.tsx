/**
 * /prompts/[name] — prompt detail: active versions per env, history,
 * authoring form, and promotion control.
 *
 * RSC. Fans out three env reads + history in parallel (gateway, per-user JWT).
 * Client islands for the two write actions:
 *   - AuthorVersionForm — POST /api/prompts/[name]/versions (Builder+)
 *   - PromotionPanel    — POST /api/prompts/[name]/promote  (Team+ gated;
 *                         403 → upgrade_url rendered, not a broken button)
 *
 * Honesty guard: NO per-version metric tiles (cost/latency/quality/eval score).
 * Those are not durably captured in the create/promote DTO — rendering them
 * would fabricate data. Show only: versions, active-per-env, history, controls.
 *
 */

import { AuthorVersionForm } from "@/app/prompts/[name]/AuthorVersionForm";
import { PromotionPanel } from "@/components/prompt-promotion/PromotionPanel";
import { ENVS, fetchHistory, fetchVersion } from "@/lib/prompts";
import type { Metadata } from "next";
import Link from "next/link";

interface Props {
	params: Promise<{ name: string }>;
}

export const dynamic = "force-dynamic";

export async function generateMetadata({ params }: Props): Promise<Metadata> {
	const { name } = await params;
	return { title: `Prompt — ${decodeURIComponent(name)} — Tracelane` };
}

function formatTimestamp(microsSinceEpoch: number): string {
	const ms = Math.floor(microsSinceEpoch / 1000);
	if (!Number.isFinite(ms) || ms <= 0) return "—";
	return new Date(ms).toISOString().replace("T", " ").replace(/\..+$/, " UTC");
}

function shortId(uuid: string | null | undefined): string {
	if (!uuid) return "—";
	return uuid.slice(0, 8);
}

const S = {
	page: "mx-auto max-w-4xl px-6 py-8",
	header: "mb-8",
	title: "text-2xl font-semibold tracking-tight font-mono",
	subtitle: "mt-2 text-sm text-ink-2",
	section: "mt-6",
	sectionHeading: "mb-3 text-sm font-medium text-ink",
	envGrid: "grid gap-4 md:grid-cols-3",
	envCard: "rounded-md border border-line bg-surface p-4",
	envCardError: "rounded-md border border-warn bg-warn-soft/20 p-4",
	envLabel: "text-xs uppercase tracking-wide text-ink-2",
	versionLabel: "mt-2 text-lg font-semibold tabular-nums text-ink",
	field: "mt-2 text-xs",
	fieldLabel: "text-ink-2",
	fieldValue: "ml-1 font-mono text-ink break-all",
	contentBlock: "mt-6 rounded-md border border-line bg-surface p-4",
	contentPre: "whitespace-pre-wrap font-mono text-xs text-ink leading-relaxed",
	historyList: "space-y-3",
	historyEmpty: "text-xs text-ink-2",
	historyEntry: "flex gap-3 text-xs",
	historyDot: "mt-1 h-2 w-2 flex-none rounded-full",
	dotPromotion: "bg-ok",
	dotRollback: "bg-warn",
	dotBlocked: "bg-ink-3",
	historyMain: "min-w-0 flex-1",
	historyTitle: "font-medium text-ink",
	historyMeta: "mt-0.5 text-ink-2",
	historyTime: "ml-auto whitespace-nowrap font-mono tabular-nums text-ink-2",
	footerLinks: "mt-8 flex gap-4 text-sm",
	link: "underline decoration-ink-3 underline-offset-4 hover:decoration-ink transition-[text-decoration-color]",
} as const;

/**
 * Lifecycle strip — the environments ARE the mental model: author → staging →
 * canary → production. Each stage lights when the prompt has an active version
 * there ("author" lights once any version exists). Pure render from the env reads.
 */
function LifecycleStrip({ active }: { active: Set<string> }) {
	const authored = active.size > 0;
	const stages: { key: string; label: string; on: boolean }[] = [
		{ key: "author", label: "Author", on: authored },
		{ key: "staging", label: "Staging", on: active.has("staging") },
		{ key: "canary", label: "Canary", on: active.has("canary") },
		{ key: "production", label: "Production", on: active.has("production") },
	];
	return (
		<ol className="mb-6 flex flex-wrap items-center gap-1.5 text-xs">
			{stages.map((s, i) => (
				<li key={s.key} className="flex items-center gap-1.5">
					<span
						className={
							s.on
								? "rounded-full bg-seal-soft px-2.5 py-1 font-semibold text-seal-ink"
								: "rounded-full border border-line px-2.5 py-1 font-medium text-ink-3"
						}
					>
						{s.on && <span aria-hidden>✓ </span>}
						{s.label}
					</span>
					{i < stages.length - 1 && (
						<span aria-hidden className="text-ink-3">
							→
						</span>
					)}
				</li>
			))}
		</ol>
	);
}

export default async function PromptDetailPage({ params }: Props) {
	const { name } = await params;
	const decodedName = decodeURIComponent(name);

	// Fan out env queries + history in parallel. Each is a fresh gateway
	// round-trip minted with the per-user JWT. History is best-effort — a
	// GatewayError yields [] and the empty state renders.
	const [results, history] = await Promise.all([
		Promise.all(
			ENVS.map(async (env) => ({
				env,
				data: await fetchVersion(decodedName, env),
			})),
		),
		fetchHistory(decodedName, 50),
	]);

	// Surface the production content for inline preview.
	const productionEntry = results.find((r) => r.env === "production");
	const productionContent =
		productionEntry && !("error" in productionEntry.data)
			? productionEntry.data.content
			: null;

	// Pre-fill the PromotionPanel with the staging version ID (the most common
	// promotion source). Falls back to "" if staging has no active version.
	const stagingEntry = results.find((r) => r.env === "staging");
	const stagingVersionId =
		stagingEntry && !("error" in stagingEntry.data)
			? stagingEntry.data.prompt_version_id
			: "";

	// Which envs have an active version → drives the lifecycle strip + the
	// contextual next-step nudge (the "walk" for a first-run prompt).
	const activeEnvs = new Set(
		results.filter((r) => !("error" in r.data)).map((r) => r.env),
	);
	const nextStep =
		activeEnvs.size === 0
			? "Author version 1 below — it lands in staging, ready to promote."
			: !activeEnvs.has("production")
				? "A version is live in a lower environment — promote it to production below."
				: null;

	return (
		<main className={S.page}>
			{/* ── Header ── */}
			<header className={S.header}>
				<h1 className={S.title}>{decodedName}</h1>
				<p className={S.subtitle}>
					Active version per environment. Updates on a successful promote or
					auto-rollback.
				</p>
			</header>

			{/* ── Lifecycle strip — the environments are the mental model ── */}
			<LifecycleStrip active={activeEnvs} />

			{nextStep && (
				<div className="mb-6 rounded-md border border-line bg-surface-2/40 px-4 py-2.5 text-sm text-ink-2">
					<span className="font-medium text-ink">Next:</span> {nextStep}
				</div>
			)}

			{/* ── Active versions per env ── */}
			<div className={S.envGrid}>
				{results.map(({ env, data }) => (
					<div
						key={env}
						className={"error" in data ? S.envCardError : S.envCard}
					>
						<div className={S.envLabel}>{env}</div>
						{"error" in data ? (
							<div className="mt-2 text-sm text-warn">
								{data.error.includes("404")
									? "No active version"
									: `Error — ${data.error}`}
							</div>
						) : (
							<>
								<div className={S.versionLabel}>v{data.version_number}</div>
								<div className={S.field}>
									<span className={S.fieldLabel}>id</span>
									<span className={S.fieldValue}>{data.prompt_version_id}</span>
								</div>
								<div className={S.field}>
									<span className={S.fieldLabel}>sha256</span>
									<span className={S.fieldValue}>
										{data.sha256_hex.slice(0, 16)}…
									</span>
								</div>
								{data.model_pin ? (
									<div className={S.field}>
										<span className={S.fieldLabel}>model</span>
										<span className={S.fieldValue}>{data.model_pin}</span>
									</div>
								) : null}
							</>
						)}
					</div>
				))}
			</div>

			{/* ── Production content preview ── */}
			{productionContent ? (
				<section className={S.contentBlock}>
					<div className={S.sectionHeading}>Production content</div>
					<pre className={S.contentPre}>{productionContent}</pre>
				</section>
			) : null}

			{/* ── Author new version (Builder+) ── */}
			<section className={S.section}>
				<AuthorVersionForm promptName={decodedName} />
			</section>

			{/* ── Promote to production (Team+ gated — 403 → upgrade prompt) ── */}
			<section className={S.section}>
				<PromotionPanel
					// Re-mount when the staging version changes so the candidate-ID
					// input re-initialises from the prop (e.g. right after authoring
					// v1 → refresh). Without the key, useState keeps its first value.
					key={stagingVersionId || "no-staging"}
					promptName={decodedName}
					candidateVersionId={stagingVersionId}
				/>
			</section>

			{/* ── Promotion / rollback history ── */}
			<section className={S.section}>
				<div className="rounded-md border border-line bg-surface p-4">
					<div className="mb-3 flex flex-wrap items-baseline justify-between gap-1">
						<span className={S.sectionHeading.replace("mb-3 ", "")}>
							Recent activity · all prompts
						</span>
						<Link
							href="/audit"
							className="text-xs font-medium text-seal-ink hover:underline"
						>
							Tamper-evident ledger →
						</Link>
					</div>
					<p className="mb-3 text-xs text-ink-2">
						Every promotion and auto-rollback across your prompts, written to
						the tamper-evident audit ledger. Promote a version and it appears
						here.
					</p>
					{history.length === 0 ? (
						<div className={S.historyEmpty}>
							No promotion or rollback events yet.
						</div>
					) : (
						<ul className={S.historyList}>
							{history.map((entry) => {
								const key =
									entry.kind === "promotion"
										? `p-${entry.promotion_id}`
										: `r-${entry.rollback_id}`;
								const dotClass =
									entry.kind === "rollback"
										? S.dotRollback
										: entry.kind === "promotion" &&
												entry.decision !== "promoted" &&
												entry.decision !== "manual_override"
											? S.dotBlocked
											: S.dotPromotion;
								return (
									<li key={key} className={S.historyEntry}>
										<span
											className={`${S.historyDot} ${dotClass}`}
											aria-hidden
										/>
										<div className={S.historyMain}>
											{entry.kind === "promotion" ? (
												<>
													<div className={S.historyTitle}>
														{entry.decision === "promoted"
															? `Promoted ${entry.from_env} → ${entry.to_env}`
															: entry.decision === "manual_override"
																? `Manual override → ${entry.to_env}`
																: entry.decision === "blocked_by_eval"
																	? `Blocked by eval (${entry.from_env} → ${entry.to_env})`
																	: `Blocked by policy (${entry.from_env} → ${entry.to_env})`}
													</div>
													<div className={S.historyMeta}>
														v→{shortId(entry.to_version_id)}
														{entry.from_version_id
															? ` from v${shortId(entry.from_version_id)}`
															: ""}
														{entry.notes ? ` — ${entry.notes}` : ""}
													</div>
												</>
											) : (
												<>
													<div className={S.historyTitle}>
														{entry.rollback_mode === "auto"
															? `Auto-rollback fired (${entry.trigger_metric})`
															: entry.rollback_mode === "suggested"
																? `Suggested rollback (${entry.trigger_metric})`
																: entry.rollback_mode === "human_confirmed"
																	? `Rollback confirmed (${entry.trigger_metric})`
																	: `Rollback dismissed (${entry.trigger_metric})`}
													</div>
													<div className={S.historyMeta}>
														{entry.sigma_drift.toFixed(1)}σ drift, value{" "}
														{entry.trigger_value.toFixed(2)} — v→
														{shortId(entry.to_version_id)} from v
														{shortId(entry.from_version_id)}
													</div>
												</>
											)}
										</div>
										<span className={S.historyTime}>
											{formatTimestamp(entry.at_micros)}
										</span>
									</li>
								);
							})}
						</ul>
					)}
				</div>
			</section>

			{/* ── Footer nav ── */}
			<nav className={S.footerLinks}>
				<Link className={S.link} href="/prompts">
					← All prompts
				</Link>
				<Link className={S.link} href="/audit">
					Audit ledger →
				</Link>
			</nav>
		</main>
	);
}
