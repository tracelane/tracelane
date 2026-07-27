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
import { Badge } from "@tracelanedev/ui";
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

const DECISION_TONE: Record<string, "danger" | "info" | "warn" | "ok"> = {
	block: "danger",
	redact: "info",
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
			<span className="font-mono text-[11px] text-ink">{String(details)}</span>
		);
	}
	const entries = Object.entries(details as Record<string, unknown>);
	if (entries.length === 0) return null;
	return (
		<dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5">
			{entries.map(([k, val]) => (
				<Fragment key={k}>
					<dt className="font-mono text-[11px] text-ink-3">{k}</dt>
					<dd className="font-mono text-[11px] text-ink">
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
			className="rounded border border-line px-1.5 py-0.5 text-[10px] text-ink-2 transition-colors hover:bg-surface-2 hover:text-ink"
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
				<span className="font-mono text-[12px] font-medium text-ink">
					{r.rail ?? "—"}
				</span>
				<Badge
					tone={isAllow ? "ok" : (DECISION_TONE[r.outcome ?? ""] ?? "warn")}
				>
					{r.outcome ?? "—"}
				</Badge>
				{r.reason_code && (
					<span className="font-mono text-[10.5px] text-ink-3">
						{r.reason_code}
					</span>
				)}
			</div>
			{gloss && gloss !== r.reason_code && (
				<p className="mt-1 text-[12px] text-ink-2">{gloss}</p>
			)}
			<div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-0.5 text-[11px] text-ink-3">
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

export function VerdictTable({ verdicts }: { verdicts: GuardrailVerdict[] }) {
	const [openKey, setOpenKey] = useState<string | null>(null);
	const th =
		"px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3";

	return (
		<div className="overflow-x-auto">
			<table className="w-full text-sm">
				<thead className="border-b border-line">
					<tr>
						<th className="w-8 py-3 pl-4" aria-label="Expand" />
						<th className={th}>Time (UTC)</th>
						<th className={th}>Side</th>
						<th className={th}>Decision</th>
						<th className={th}>Why it fired</th>
						<th className={`${th} text-right`}>Overhead</th>
					</tr>
				</thead>
				<tbody>
					{verdicts.map((v, i) => {
						const key = `${v.correlation_id}-${v.side}-${i}`;
						const isOpen = openKey === key;
						const rails = parseRails(v.rails);
						const fired = rails.filter(
							(r) => r.outcome && r.outcome !== "allow",
						);
						const primary = fired[0];
						const gloss = reasonText(primary?.reason_code);
						const failedOpen = v.fail_open_rails.length > 0;

						return (
							<Fragment key={key}>
								<tr
									onClick={() => setOpenKey(isOpen ? null : key)}
									onKeyDown={(e) => {
										if (e.key === "Enter" || e.key === " ") {
											e.preventDefault();
											setOpenKey(isOpen ? null : key);
										}
									}}
									tabIndex={0}
									aria-expanded={isOpen}
									className="cursor-pointer border-b border-line align-top transition-colors last:border-0 hover:bg-surface-2/40 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-seal"
								>
									<td className="py-3 pl-4 align-middle">
										<span
											aria-hidden
											className={`inline-block text-ink-3 transition-transform ${isOpen ? "rotate-90" : ""}`}
										>
											▸
										</span>
									</td>
									<td className="px-4 py-3 text-xs text-ink-2">
										{formatDateTimeUtc(parseDate(v.event_time).toISOString())}
									</td>
									<td className="px-4 py-3 text-[11px] uppercase tracking-wide text-ink-3">
										{v.side}
									</td>
									<td className="px-4 py-3">
										<Badge tone={DECISION_TONE[v.decision] ?? "neutral"}>
											{v.decision}
										</Badge>
									</td>
									{/* The substance: which rail + WHY, in plain language. */}
									<td className="px-4 py-3">
										{primary ? (
											<>
												<div className="text-[13px] text-ink">
													{gloss ?? primary.rail ?? "—"}
												</div>
												<div className="mt-0.5 font-mono text-[10.5px] text-ink-3">
													{primary.rail}
													{primary.reason_code
														? ` · ${primary.reason_code}`
														: ""}
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
											<p className="mt-1 text-[11px] text-warn">
												failed open: {v.fail_open_rails.join(", ")}
											</p>
										)}
									</td>
									<td className="px-4 py-3 text-right font-mono text-xs tabular-nums text-ink-2">
										{fmtLatency(v.total_latency_micros)}
									</td>
								</tr>

								{isOpen && (
									<tr className="border-b border-line last:border-0">
										<td colSpan={6} className="bg-surface-2/30 px-4 py-4">
											<div className="space-y-3">
												<div>
													<p className="text-[11px] font-semibold uppercase tracking-wide text-ink-3">
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
															<p className="text-[12px] text-ink-3">
																No per-rail record stored for this verdict.
															</p>
														)}
													</div>
												</div>

												<div className="flex flex-wrap items-center gap-2 border-t border-line pt-3">
													<span className="text-[11px] text-ink-3">
														Correlation ID (support reference)
													</span>
													<code className="font-mono text-[11px] text-ink">
														{v.correlation_id}
													</code>
													<CopyButton value={v.correlation_id} />
												</div>

												<p className="text-[11px] text-ink-3">
													A blocked request is stopped pre-flight, before any
													span is written — so the prompt body is not retained
													and there is no trace to open. The rail records above
													are the complete stored evidence for this decision.
												</p>
											</div>
										</td>
									</tr>
								)}
							</Fragment>
						);
					})}
				</tbody>
			</table>
		</div>
	);
}
