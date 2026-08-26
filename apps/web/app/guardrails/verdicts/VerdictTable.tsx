"use client";

/**
 * Expandable verdict table — the honest detail behind each guardrail decision.
 *
 * A blocked request is 403'd pre-flight (before any span), so there is no trace
 * to open and the prompt body is deliberately NOT retained. What IS captured per
 * rail is rich: outcome, reason code, score vs threshold, per-rail latency,
 * policy version, and a rail-specific `details` payload (e.g. R3 records the
 * offending tool + violation kinds; R6 the leaked spans). This component surfaces
 * all of it on row click, so the list stops reading as opaque correlation IDs.
 *
 * Client-side only: expansion is local UI state. Every value rendered comes from
 * the stored verdict — nothing is derived or invented.
 */

import { formatDateTimeUtc } from "@/lib/format-date";
import type { GuardrailVerdict } from "@/lib/guardrails";
import {
	Badge,
	type BadgeProps,
	TBody,
	TD,
	TDetail,
	TH,
	THead,
	TR,
	Table,
} from "@tracelanedev/ui";
import { Fragment, useState } from "react";

/** One per-rail entry inside the `rails` JSON column (gateway `RailVerdict`). */
type RailEntry = {
	rail?: string;
	outcome?: string;
	reason_code?: string | null;
	score?: number;
	threshold?: number;
	latency_micros?: number;
	policy_version?: string;
	model_version?: string;
	details?: unknown;
};

/**
 * Reason code → plain language. The stored code stays visible (it is the stable
 * contract for policy/audit); this is the human gloss beside it.
 */
const REASON_LABEL: Record<string, string> = {
	BUDGET_CAP: "Spend/budget cap reached",
	BUDGET_STATE_UNKNOWN: "Budget state unavailable",
	COMPETITOR_MENTION: "Competitor mentioned",
	CONFIG_MISSING: "Rail configuration missing",
	DEPENDENCY_UNAVAILABLE: "Rail dependency unavailable",
	DETECTOR_ERROR: "Detector errored",
	FORMAT_INVALID_JSON: "Response was not valid JSON",
	FORMAT_REASK_EXHAUSTED: "Re-ask attempts exhausted",
	FORMAT_REGEX_FAIL: "Output failed the required pattern",
	FORMAT_SCHEMA_FAIL: "Output failed the required schema",
	INJECTION_DIRECT: "Direct prompt injection — instruction override",
	INJECTION_INDIRECT_RAG: "Indirect injection via retrieved content",
	INJECTION_INDIRECT_TOOL_RESULT: "Indirect injection via a tool result",
	INJECTION_PROMPT_EXTRACTION: "Attempt to extract the system prompt",
	INPUT_TOKEN_CAP: "Input token cap exceeded",
	LOOP_CAP: "Tool-call loop cap exceeded",
	OUTPUT_TOKEN_CAP: "Output token cap exceeded",
	PII_CARD: "Payment card number detected",
	PII_EMAIL: "Email address detected",
	PII_IBAN: "IBAN detected",
	PII_PHONE: "Phone number detected",
	PII_SSN: "National ID / SSN detected",
	RAIL_TIMEOUT: "Rail timed out",
	SECRET_DETECTED: "Secret / API key detected",
	SYS_PROMPT_LEAK: "System prompt leaked in the response",
	TOOL_ARG_POLICY: "Tool argument violated policy",
	TOOL_DEF_DRIFT: "Tool definition changed since it was pinned",
	TOOL_DESC_INJECTION: "Injection inside a tool description",
	TOOL_SCHEMA_INVALID: "Tool call did not match its schema",
	TOPIC_DENIED: "Denied topic",
};

/**
 * Decision → badge tone. `redact` moved from `info` to `neutral` (P1,
 * 2026-08-22) so this table, the rail roster and the decision-mix row on
 * /guardrails all speak ONE badge grammar: danger = it stopped the request,
 * warn = it flagged something to look at, ok = it passed, neutral = it recorded
 * something. `--info-soft` and `--surface-2` are both grey and four values
 * apart, so this changes the tone's PLACE IN THE GRAMMAR, not what a redaction
 * means — the word "redact" is still the label and still carries the meaning.
 */
const DECISION_TONE: Record<string, NonNullable<BadgeProps["tone"]>> = {
	block: "danger",
	redact: "neutral",
	warn: "warn",
	allow: "ok",
};

function parseRails(json: string): RailEntry[] {
	try {
		const arr = JSON.parse(json) as RailEntry[];
		return Array.isArray(arr) ? arr : [];
	} catch {
		return [];
	}
}

/** ClickHouse "YYYY-MM-DD HH:MM:SS.ffffff" or ISO → a UTC Date. */
function parseDate(s: string): Date {
	// A "…T08:45:53" with a T but NO zone parses as LOCAL — anchor to UTC unless
	// the string already carries a zone (the naive-timestamp class; see parseUtcMs).
	const hasZone = /([zZ]|[+-]\d{2}:?\d{2})$/.test(s);
	return new Date(hasZone ? s : `${s.replace(" ", "T")}Z`);
}

function fmtLatency(us: number | undefined): string {
	if (us === undefined || us <= 0) return "—";
	if (us < 1000) return `${us}µs`;
	return `${(us / 1000).toFixed(1)}ms`;
}

function reasonText(code: string | null | undefined): string | null {
	if (!code) return null;
	return REASON_LABEL[code] ?? code;
}

/** Render a rail's `details` payload as readable key → value pairs. */
function DetailPayload({ details }: { details: unknown }) {
	if (details === null || details === undefined) return null;
	if (typeof details !== "object") {
		return (
			<span className="font-mono text-2xs text-ink">{String(details)}</span>
		);
	}
	const entries = Object.entries(details as Record<string, unknown>);
	if (entries.length === 0) return null;
	return (
		<dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5">
			{entries.map(([k, val]) => (
				<Fragment key={k}>
					<dt className="font-mono text-2xs text-ink-3">{k}</dt>
					<dd className="font-mono text-2xs text-ink">
						{typeof val === "object" && val !== null
							? JSON.stringify(val)
							: String(val)}
					</dd>
				</Fragment>
			))}
		</dl>
	);
}

function CopyButton({ value }: { value: string }) {
	const [copied, setCopied] = useState(false);
	return (
		<button
			type="button"
			onClick={() => {
				navigator.clipboard?.writeText(value).then(
					() => {
						setCopied(true);
						setTimeout(() => setCopied(false), 1500);
					},
					() => undefined,
				);
			}}
			className="rounded border border-line px-1.5 py-0.5 text-2xs text-ink-2 transition-colors hover:bg-surface-2 hover:text-ink"
		>
			{copied ? "Copied" : "Copy"}
		</button>
	);
}

/** One rail's full record, shown in the expanded panel. */
function RailDetail({ r }: { r: RailEntry }) {
	const gloss = reasonText(r.reason_code);
	const isAllow = !r.outcome || r.outcome === "allow";
	return (
		<div className="rounded-lg border border-line bg-surface px-3 py-2.5">
			<div className="flex flex-wrap items-center gap-2">
				<span className="font-mono text-xs font-medium text-ink">
					{r.rail ?? "—"}
				</span>
				<Badge
					tone={isAllow ? "ok" : (DECISION_TONE[r.outcome ?? ""] ?? "warn")}
				>
					{r.outcome ?? "—"}
				</Badge>
				{r.reason_code && (
					<span className="font-mono text-2xs text-ink-3">{r.reason_code}</span>
				)}
			</div>
			{gloss && gloss !== r.reason_code && (
				<p className="mt-1 text-xs text-ink-2">{gloss}</p>
			)}
			<div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-0.5 text-2xs text-ink-3">
				{r.score !== undefined && (
					<span>
						score{" "}
						<span className="font-mono tabular-nums text-ink">
							{r.score.toFixed(3)}
						</span>
						{r.threshold !== undefined && (
							<>
								{" "}
								/ threshold{" "}
								<span className="font-mono tabular-nums text-ink">
									{r.threshold.toFixed(3)}
								</span>
							</>
						)}
					</span>
				)}
				{r.latency_micros !== undefined && (
					<span>
						took{" "}
						<span className="font-mono tabular-nums text-ink">
							{fmtLatency(r.latency_micros)}
						</span>
					</span>
				)}
				{r.policy_version && (
					<span>
						policy{" "}
						<span className="font-mono text-ink">{r.policy_version}</span>
					</span>
				)}
				{r.model_version && (
					<span>
						model <span className="font-mono text-ink">{r.model_version}</span>
					</span>
				)}
			</div>
			<DetailPayload details={r.details} />
		</div>
	);
}

/**
 * ── ON THE SHARED TABLE SYSTEM (P1, 2026-08-22) ─────────────────────────────
 * `Table/THead/TBody/TR/TH/TD/TDetail`, replacing the hand-rolled `<table>` and
 * its private `th` class string. Three things this buys that the local version
 * did not have: the header band is the SAME recessed rail the rail roster draws
 * (they are two tables one click apart and had different `<thead>` treatments),
 * the Overhead column gets right-align + tabular + mono as one indivisible
 * decision rather than three utilities that can drift apart, and the open row
 * keeps the hover tone via `expanded` so the row and its evidence panel read as
 * one object.
 *
 * Behaviour is untouched: the row is still a `tabIndex={0}` element with
 * `aria-expanded` and an Enter/Space handler, expansion is still local state,
 * and every rendered value still comes straight from the stored verdict.
 */
export function VerdictTable({ verdicts }: { verdicts: GuardrailVerdict[] }) {
	const [openKey, setOpenKey] = useState<string | null>(null);

	return (
		<Table>
			{/* `border-t-0`: the shared `THead` is bordered top AND bottom so it holds
			    its edge "whether or not the table starts at the top of its card"
			    (its own words). This one DOES start at the top of a card, so its
			    top border lands 1px inside the card's border in the same `--line`
			    colour — two hairlines reading as one 2px rule along the top edge
			    only, heavier than the three edges around it. Suppressed here, at
			    the call site, rather than in the primitive: a table that starts
			    mid-card still wants the border, and this is a question for one
			    shared change rather than three concurrent ones. */}
			<THead className="border-t-0">
				<TR>
					<TH className="w-10 px-2" aria-label="Expand" />
					<TH>Time (UTC)</TH>
					<TH>Side</TH>
					<TH>Decision</TH>
					<TH>Why it fired</TH>
					<TH numeric>Overhead</TH>
				</TR>
			</THead>
			<TBody>
				{verdicts.map((v, i) => {
					const key = `${v.correlation_id}-${v.side}-${i}`;
					const isOpen = openKey === key;
					const rails = parseRails(v.rails);
					const fired = rails.filter((r) => r.outcome && r.outcome !== "allow");
					const primary = fired[0];
					const gloss = reasonText(primary?.reason_code);
					const failedOpen = v.fail_open_rails.length > 0;

					return (
						<Fragment key={key}>
							<TR
								interactive
								expanded={isOpen}
								onClick={() => setOpenKey(isOpen ? null : key)}
								onKeyDown={(e) => {
									if (e.key === "Enter" || e.key === " ") {
										e.preventDefault();
										setOpenKey(isOpen ? null : key);
									}
								}}
								tabIndex={0}
								aria-expanded={isOpen}
								className="align-top focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-focus-ring"
							>
								<TD className="w-10 px-2 align-middle">
									<span
										aria-hidden
										className={`inline-block text-ink-3 transition-transform ${isOpen ? "rotate-90" : ""}`}
									>
										▸
									</span>
								</TD>
								{/* A timestamp is a technical value, so it is MONO — and in a
								    left column, so `mono` rather than `numeric`. Aligning the
								    digits is what lets a reader scan for the minute a burst
								    happened instead of reading every row. */}
								<TD mono muted className="whitespace-nowrap text-xs">
									{formatDateTimeUtc(parseDate(v.event_time).toISOString())}
								</TD>
								<TD className="text-2xs uppercase tracking-wide text-ink-3">
									{v.side}
								</TD>
								<TD>
									<Badge tone={DECISION_TONE[v.decision] ?? "neutral"}>
										{v.decision}
									</Badge>
								</TD>
								{/* The substance: which rail + WHY, in plain language. */}
								<TD>
									{primary ? (
										<>
											<div className="text-sm text-ink">
												{gloss ?? primary.rail ?? "—"}
											</div>
											<div className="mt-0.5 font-mono text-2xs text-ink-3">
												{primary.rail}
												{primary.reason_code ? ` · ${primary.reason_code}` : ""}
												{fired.length > 1
													? ` · +${fired.length - 1} more rail${fired.length > 2 ? "s" : ""}`
													: ""}
											</div>
										</>
									) : (
										<span className="text-xs text-ink-3">
											No rail flagged this request
										</span>
									)}
									{failedOpen && (
										<p className="mt-1 text-2xs text-warn-ink">
											failed open: {v.fail_open_rails.join(", ")}
										</p>
									)}
								</TD>
								<TD numeric muted className="text-xs">
									{fmtLatency(v.total_latency_micros)}
								</TD>
							</TR>

							{isOpen && (
								<TDetail colSpan={6}>
									<div className="space-y-3">
										<div>
											<p className="t-card-title text-ink-3">
												Rails evaluated ({rails.length})
											</p>
											<div className="mt-1.5 grid gap-2 sm:grid-cols-2">
												{rails.length > 0 ? (
													rails.map((r, ri) => (
														<RailDetail
															key={`${r.rail ?? "rail"}-${ri}`}
															r={r}
														/>
													))
												) : (
													<p className="text-xs text-ink-3">
														No per-rail record stored for this verdict.
													</p>
												)}
											</div>
										</div>

										<div className="flex flex-wrap items-center gap-2 border-t border-line pt-3">
											<span className="text-2xs text-ink-3">
												Correlation ID (support reference)
											</span>
											<code className="font-mono text-2xs text-ink">
												{v.correlation_id}
											</code>
											<CopyButton value={v.correlation_id} />
										</div>

										<p className="text-2xs text-ink-3">
											A blocked request is stopped pre-flight, before any span
											is written — so the prompt body is not retained and there
											is no trace to open. The rail records above are the
											complete stored evidence for this decision.
										</p>
									</div>
								</TDetail>
							)}
						</Fragment>
					);
				})}
			</TBody>
		</Table>
	);
}
