"use client";

/**
 * OnlineEvalsManager — configure and read online evals (`EVL-28`, item 11).
 *
 * The parent RSC has already checked `f_online_evals`, so this component
 * assumes entitlement and renders the real thing.
 *
 * ── THE TWO NUMBERS, AND WHY BOTH ARE ALWAYS SHOWN ──────────────────────────
 *
 * **Configured** is the policy. **Achieved** is counted — sampled traces over
 * eligible chat spans in the same window. They are DIFFERENT FACTS and the
 * labels say so.
 *
 * Sampling is a keyed hash, not an exact 1-in-N counter, so the realised rate
 * WILL differ from the setting over any finite window. A customer who sets 1%
 * and sees 0.7% must be able to read that as expected rather than as drift —
 * which they can only do if both numbers are on screen with their names on
 * them. Showing *achieved* alone presents an observation as if it were the
 * setting; showing *configured* alone hides a real observation. Neither is
 * acceptable, so both, always.
 *
 * ── ZERO IS NOT UNKNOWN, AND THIS IS THE FILE WHERE IT MATTERS ──────────────
 *
 * `achieved_sample_rate` is `null` when nothing was eligible, and this renders
 * **"no traffic in this window"** — never "0%". A quiet day and a broken
 * sampler are different facts, and 0/0 rendered as 0.0% collapses them into
 * one. Same rule for `mean_score` (null when nothing scored) and `cost_usd`
 * (null for an unpriced model): every one of them has a distinct
 * "we measured, it was zero" rendering and a distinct "we could not measure"
 * rendering.
 */

import { apiFetch } from "@/lib/api-fetch";
import { formatDateTimeUtc } from "@/lib/format-date";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
	Badge,
	Button,
	Card,
	EmptyState,
	Skeleton,
	StatCard,
	StatGrid,
	TBody,
	TD,
	TH,
	THead,
	TR,
	Table,
} from "@tracelanedev/ui";
import { useState } from "react";

interface Policy {
	id: string;
	enabled: boolean;
	rubric_kind: string;
	rubric: string;
	judge_model: string;
	sample_rate: number;
	judge_budget_usd_monthly: number;
	created_at: string;
	updated_at: string;
}

interface PolicyEnvelope {
	policy: Policy | null;
	max_sample_rate: number;
	built_in_rubrics: string[];
}

export interface Summary {
	window_hours: number;
	configured_sample_rate: number | null;
	enabled: boolean;
	achieved_sample_rate: number | null;
	eligible_spans: number;
	sampled_traces: number;
	scored: number;
	errored: number;
	mean_score: number | null;
	judge_cost_usd: number | null;
	judge_budget_usd_monthly: number | null;
}

export interface Score {
	trace_id: string;
	span_id: string;
	rubric: string;
	judge_model: string;
	status: string;
	score: number | null;
	verdict: string;
	reason: string;
	error: string | null;
	cost_usd: number | null;
	latency_ms: number;
	scored_at: number;
}

const RUBRIC_LABELS: Record<string, string> = {
	answers_the_question: "Answers the question",
	groundedness: "Groundedness",
	instruction_following: "Instruction following",
};

/** A rate as a percentage with enough precision to be honest at 0.1%. */
function pct(rate: number): string {
	return `${(rate * 100).toFixed(rate < 0.01 ? 2 : 1)}%`;
}

/** "1 in 100" — the form people actually reason about coverage in. */
function oneIn(rate: number): string {
	return rate > 0 ? `1 in ${Math.round(1 / rate).toLocaleString()}` : "off";
}

function usd(v: number): string {
	return `$${v.toFixed(v < 1 ? 4 : 2)}`;
}

// ── the summary strip ────────────────────────────────────────────────────────

/**
 * Exported ONLY so `online-evals-render.test.tsx` can drive it. It is pure —
 * props in, markup out — which is what makes the zero-vs-unknown property
 * assertable without mounting react-query, a router or a session.
 */
export function SummaryStrip({ s }: { s: Summary }) {
	return (
		<StatGrid title={`Last ${s.window_hours} hours`}>
			{/*
			 * CONFIGURED. The policy, never an observation. "off" rather than
			 * "0%" when disabled — a disabled policy has no rate, it has no
			 * sampling at all, and "0%" would read as a rate that happens to
			 * round down.
			 */}
			<StatCard
				label="Sampling — configured"
				value={
					!s.enabled || s.configured_sample_rate === null
						? "off"
						: oneIn(s.configured_sample_rate)
				}
				sub={
					s.enabled && s.configured_sample_rate !== null
						? `${pct(s.configured_sample_rate)} of eligible requests`
						: "no policy is sampling"
				}
				hint="What you asked for. This is the setting, not a measurement."
			/>
			{/*
			 * ACHIEVED. Counted, and `null` renders as words rather than a
			 * number — the whole reason the gateway sends `null` instead of 0.
			 */}
			<StatCard
				label="Sampling — achieved"
				value={
					s.achieved_sample_rate === null ? "—" : pct(s.achieved_sample_rate)
				}
				sub={
					s.achieved_sample_rate === null
						? "no traffic in this window"
						: `${s.sampled_traces.toLocaleString()} of ${s.eligible_spans.toLocaleString()} eligible traces (cached responses excluded)`
				}
				hint="What the sampler actually selected, counted from your traces. The denominator counts only requests it could have taken — responses served from the cache are excluded, because they never reach the judge. Sampling is a keyed hash, so this still differs from the setting over any finite window; that is expected, not drift."
			/>
			<StatCard
				label="Scored"
				value={s.scored.toLocaleString()}
				sub={
					s.errored > 0
						? `${s.errored.toLocaleString()} not judged`
						: "none failed to judge"
				}
				tone={s.errored > s.scored ? "warn" : "default"}
				hint="Judge responses that passed schema and range validation. A response that did not is counted as 'not judged' and carries no score."
			/>
			<StatCard
				label="Mean score"
				value={s.mean_score === null ? "—" : s.mean_score.toFixed(2)}
				sub={s.mean_score === null ? "nothing scored yet" : "0.00 – 1.00"}
				hint="Average over scored samples only. Responses that failed validation have no score and are excluded — they are not counted as zero."
			/>
			<StatCard
				label="Judge spend"
				value={s.judge_cost_usd === null ? "—" : usd(s.judge_cost_usd)}
				sub={
					s.judge_budget_usd_monthly === null
						? "no policy"
						: `cap ${usd(s.judge_budget_usd_monthly)} / month`
				}
				hint="Judge calls run on your own provider key. This spend is also counted against your workspace budget and appears in /gateway costs — it is a sub-limit, not a second wallet."
			/>
		</StatGrid>
	);
}

// ── the policy form ──────────────────────────────────────────────────────────

function PolicyForm({
	policy,
	maxRate,
	rubrics,
	onSaved,
}: {
	policy: Policy | null;
	maxRate: number;
	rubrics: string[];
	onSaved: () => void;
}) {
	const [budget, setBudget] = useState(
		policy ? String(policy.judge_budget_usd_monthly) : "",
	);
	const [rate, setRate] = useState(String((policy?.sample_rate ?? 0.01) * 100));
	const [rubric, setRubric] = useState(
		policy?.rubric ?? rubrics[0] ?? "answers_the_question",
	);
	const [model, setModel] = useState(
		policy?.judge_model ?? "claude-haiku-4-5-20251001",
	);
	const [error, setError] = useState<string | null>(null);

	const save = useMutation({
		mutationFn: async (enabled: boolean) => {
			setError(null);
			// `budget` is sent as `null` when blank rather than omitted or
			// coerced to 0 — the gateway's `budget_required` refusal is the
			// message the user needs, and inventing a client-side default here
			// would be the single most expensive convenience in this file.
			const parsedBudget = budget.trim() === "" ? null : Number(budget);
			return apiFetch<Policy>("/api/online-evals/policy", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					judge_budget_usd_monthly: parsedBudget,
					sample_rate: Number(rate) / 100,
					rubric_kind: "builtin",
					rubric,
					judge_model: model,
					enabled,
				}),
			});
		},
		onSuccess: onSaved,
		onError: (e: unknown) => {
			// The gateway's NAMED reason, rendered as the sentence it wrote.
			// `apiFetch` throws an `ApiError` whose `message` is the response
			// body's `error` field, and the `/api` proxy puts the human sentence
			// there precisely so this line has something a user can act on.
			// Never "something went wrong" — this is a refusal they can fix, and
			// the fix is in the text.
			setError(
				(e as { message?: string }).message ?? "Could not save the policy.",
			);
		},
	});

	const disable = useMutation({
		mutationFn: () =>
			apiFetch<{ disabled: boolean }>("/api/online-evals/policy", {
				method: "DELETE",
			}),
		onSuccess: onSaved,
	});

	return (
		<Card className="p-5 space-y-4">
			<div className="grid gap-4 sm:grid-cols-2">
				<label className="space-y-1 block">
					<span className="text-xs font-medium text-ink">
						Monthly judge budget (USD){" "}
						<span className="text-danger-ink">*</span>
					</span>
					<input
						type="number"
						min="0"
						step="0.01"
						value={budget}
						onChange={(e) => setBudget(e.target.value)}
						placeholder="e.g. 25.00"
						className="w-full rounded-md border border-line bg-surface-1 px-3 py-2 text-sm text-ink"
					/>
					{/*
					 * The no-default rule, stated where the decision is made.
					 * It is not a form hint — it is the reason the field is
					 * required, and a customer who does not read it is the
					 * customer who meets eval spend on an invoice.
					 */}
					<span className="text-2xs text-ink-2 block">
						Required — there is no default. Judge spend scales with your
						traffic, so a policy cannot be created without a ceiling. Scoring
						pauses when it is reached.
					</span>
				</label>

				<label className="space-y-1 block">
					<span className="text-xs font-medium text-ink">
						Sample rate (% of requests)
					</span>
					<input
						type="number"
						min="0.01"
						max={maxRate * 100}
						step="0.01"
						value={rate}
						onChange={(e) => setRate(e.target.value)}
						className="w-full rounded-md border border-line bg-surface-1 px-3 py-2 text-sm text-ink"
					/>
					<span className="text-2xs text-ink-2 block">
						At most {pct(maxRate)} ({oneIn(maxRate)}). Sampling is a keyed hash
						of the trace id, so the same traces are selected on a re-run — you
						can always say which ones were scored.
					</span>
				</label>

				<label className="space-y-1 block">
					<span className="text-xs font-medium text-ink">Rubric</span>
					<select
						value={rubric}
						onChange={(e) => setRubric(e.target.value)}
						className="w-full rounded-md border border-line bg-surface-1 px-3 py-2 text-sm text-ink"
					>
						{rubrics.map((r) => (
							<option key={r} value={r}>
								{RUBRIC_LABELS[r] ?? r}
							</option>
						))}
					</select>
				</label>

				<label className="space-y-1 block">
					<span className="text-xs font-medium text-ink">Judge model</span>
					<input
						type="text"
						value={model}
						onChange={(e) => setModel(e.target.value)}
						className="w-full rounded-md border border-line bg-surface-1 px-3 py-2 text-sm text-ink"
					/>
					<span className="text-2xs text-ink-2 block">
						Runs on your own provider key, so it appears in your traces and
						costs. Must be a model this gateway can route.
					</span>
				</label>
			</div>

			{error ? (
				<p
					role="alert"
					className="rounded-md border border-danger-line bg-danger-surface px-3 py-2 text-xs text-danger-ink"
				>
					{error}
				</p>
			) : null}

			<div className="flex items-center gap-2">
				<Button onClick={() => save.mutate(true)} disabled={save.isPending}>
					{save.isPending
						? "Saving…"
						: policy?.enabled
							? "Save changes"
							: "Enable online evals"}
				</Button>
				{policy?.enabled ? (
					<Button
						variant="secondary"
						onClick={() => disable.mutate()}
						disabled={disable.isPending}
					>
						{disable.isPending ? "Disabling…" : "Disable"}
					</Button>
				) : null}
			</div>
		</Card>
	);
}

// ── recent scores ────────────────────────────────────────────────────────────

/** Exported for the render proof — see {@link SummaryStrip}. */
export function ScoresTable({ scores }: { scores: Score[] }) {
	if (scores.length === 0) {
		return (
			<EmptyState
				title="Nothing scored in this window"
				description="Scores appear here as sampled requests are judged. If sampling is on and this stays empty, your rate may be low relative to your traffic."
			/>
		);
	}
	return (
		<Table>
			<THead>
				<TR>
					<TH>Trace</TH>
					<TH>Rubric</TH>
					<TH align="right">Score</TH>
					<TH>Verdict</TH>
					<TH align="right">Cost</TH>
					<TH>Scored (UTC)</TH>
				</TR>
			</THead>
			<TBody>
				{scores.map((s) => (
					<TR key={`${s.trace_id}-${s.span_id}`}>
						<TD>
							<a
								href={`/traces/${s.trace_id}`}
								className="font-mono text-xs text-action-ink hover:underline"
							>
								{s.trace_id.slice(0, 8)}
							</a>
						</TD>
						<TD className="text-xs">{RUBRIC_LABELS[s.rubric] ?? s.rubric}</TD>
						{/*
						 * `score` is null for an errored judge, and it renders as
						 * the ERROR, not as a number. A 0.00 here would be a
						 * fabricated verdict on the customer's own traffic.
						 */}
						<TD align="right" className="font-mono text-xs">
							{s.score === null ? "—" : s.score.toFixed(2)}
						</TD>
						<TD>
							{s.status === "errored" ? (
								<Badge tone="warn">not judged</Badge>
							) : (
								<Badge tone={s.verdict === "pass" ? "ok" : "danger"}>
									{s.verdict || "—"}
								</Badge>
							)}
						</TD>
						<TD align="right" className="font-mono text-xs">
							{s.cost_usd === null ? "—" : usd(s.cost_usd)}
						</TD>
						<TD className="text-xs text-ink-2">
							{formatDateTimeUtc(new Date(s.scored_at).toISOString())}
						</TD>
					</TR>
				))}
			</TBody>
		</Table>
	);
}

// ── the manager ──────────────────────────────────────────────────────────────

export function OnlineEvalsManager() {
	const qc = useQueryClient();
	const invalidate = () => {
		void qc.invalidateQueries({ queryKey: ["online-evals"] });
	};

	const policyQ = useQuery({
		queryKey: ["online-evals", "policy"],
		queryFn: () => apiFetch<PolicyEnvelope>("/api/online-evals/policy"),
	});
	const summaryQ = useQuery({
		queryKey: ["online-evals", "summary"],
		queryFn: () => apiFetch<Summary>("/api/online-evals/summary?hours=24"),
	});
	const scoresQ = useQuery({
		queryKey: ["online-evals", "scores"],
		queryFn: () =>
			apiFetch<{ scores: Score[] }>("/api/online-evals/scores?hours=24"),
	});

	if (policyQ.isLoading) {
		return (
			<div className="space-y-3">
				<Skeleton className="h-24 w-full" />
				<Skeleton className="h-48 w-full" />
			</div>
		);
	}
	if (policyQ.isError) {
		return (
			<p
				role="alert"
				className="rounded-md border border-danger-line bg-danger-surface px-3 py-2 text-xs text-danger-ink"
			>
				Could not load your online-eval policy. Retry, or check that the gateway
				is reachable.
			</p>
		);
	}

	const env = policyQ.data;
	const policy = env?.policy ?? null;

	return (
		<div className="space-y-6">
			{/*
			 * The summary is rendered whenever it resolves — including for a
			 * workspace with no policy, where it truthfully reports the traffic
			 * that WOULD have been eligible. That answers "what would 1% get
			 * me" before anyone spends anything.
			 */}
			{summaryQ.data ? (
				<SummaryStrip s={summaryQ.data} />
			) : summaryQ.isLoading ? (
				<Skeleton className="h-24 w-full" />
			) : null}

			<div className="space-y-2">
				<div className="flex items-center gap-2">
					<h3 className="text-sm font-semibold text-ink">Policy</h3>
					{policy ? (
						<Badge tone={policy.enabled ? "ok" : "neutral"}>
							{policy.enabled ? "sampling" : "disabled"}
						</Badge>
					) : (
						<Badge tone="neutral">not configured</Badge>
					)}
					{policy ? (
						<span className="text-2xs text-ink-2">
							updated {formatDateTimeUtc(policy.updated_at)}
						</span>
					) : null}
				</div>
				<PolicyForm
					policy={policy}
					maxRate={env?.max_sample_rate ?? 0.1}
					rubrics={env?.built_in_rubrics ?? []}
					onSaved={invalidate}
				/>
			</div>

			<div className="space-y-2">
				<h3 className="text-sm font-semibold text-ink">
					Recent scores — last 24 hours
				</h3>
				{scoresQ.isLoading ? (
					<Skeleton className="h-32 w-full" />
				) : scoresQ.isError ? (
					<p role="alert" className="text-xs text-danger-ink">
						Could not read scores.
					</p>
				) : (
					<ScoresTable scores={scoresQ.data?.scores ?? []} />
				)}
			</div>
		</div>
	);
}
