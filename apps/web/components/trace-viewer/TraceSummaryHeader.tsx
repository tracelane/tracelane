/**
 * TraceSummaryHeader — the at-a-glance rollup strip above the span view. Every
 * stat is summed from the real span set (`computeTraceSummary`); a metric with
 * no source span renders "—", never a fabricated 0/$0. Cost is the sum of the
 * gateway's stored per-span `gen_ai_usage_cost` (real), blank when unpriced.
 *
 * Layout grammar:
 *  - Duration + error-state are the lead metrics (larger value, prominent).
 *  - Secondary stats (spans, tokens, cost, model, provider) are smaller.
 *  - The "loop detected" badge uses a warn-tone Badge + SVG glyph (no raw emoji).
 *
 * The grammar above used to cite ADR-053 ("Tinted Slate + Lava"). That palette is
 * retired and its successor superseded in turn; the LAYOUT rule survived the
 * palette changes, so it is stated here on its own rather than under the name of
 * a colour system this file no longer uses (CLAUDE.md §17).
 */

import type { Span } from "@/components/trace-viewer/types";

import { countToolCallSpans, detectToolLoop } from "@/lib/tool-loop";
import { computeTraceSummary } from "@/lib/trace-summary";
import { Badge, StatCard, fmtDur } from "@tracelanedev/ui";

function fmtInt(n: number): string {
	return n.toLocaleString();
}

function fmtTokens(n: number): string {
	if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
	if (n >= 1000) return `${(n / 1000).toFixed(1)}K`;
	return String(n);
}

function fmtCost(usd: number): string {
	if (usd === 0) return "$0";
	if (usd < 0.01) return `$${usd.toFixed(4)}`;
	if (usd < 1) return `$${usd.toFixed(3)}`;
	return `$${usd.toFixed(2)}`;
}

/** Warn triangle SVG — consistent with the app's glyph style; replaces raw ⚠ emoji. */
function WarnTriangle() {
	return (
		<svg
			viewBox="0 0 16 16"
			width="11"
			height="11"
			fill="none"
			stroke="currentColor"
			strokeWidth="1.6"
			strokeLinecap="round"
			strokeLinejoin="round"
			aria-hidden="true"
		>
			<path d="M8 2 1.5 13.5h13L8 2Z" />
			<line x1="8" y1="7" x2="8" y2="10" />
			<circle cx="8" cy="12.5" r="0.5" fill="currentColor" />
		</svg>
	);
}

export function TraceSummaryHeader({ spans }: { spans: Span[] }) {
	const s = computeTraceSummary(spans);
	const toolCount = countToolCallSpans(spans);
	const loop = detectToolLoop(spans);

	const tokens =
		s.inputTokens !== undefined && s.outputTokens !== undefined
			? `${fmtTokens(s.inputTokens)} → ${fmtTokens(s.outputTokens)}`
			: s.totalTokens !== undefined
				? fmtTokens(s.totalTokens)
				: "—";

	const firstModel = s.models[0] ?? "—";
	const modelLabel =
		s.models.length <= 1 ? firstModel : `${firstModel} +${s.models.length - 1}`;

	return (
		<div className="space-y-3">
			{/* Premium metric tiles — one stat-card per KPI so each reads as first-class
			    data, not a flat label strip. Grid: 2 cols on mobile, 3 on sm, then
			    auto-fit at lg+ so all tiles always fill the available row width evenly.
			    StatCard owns the surface via `.stat-tile` — radius, hairline and the ~2%
			    contact shadow, all from tokens.css, no extra chrome here.

			    CORRECTED 2026-08-22: this said "StatCard handles the GRADIENT + hairline
			    + shadow". `.stat-tile` carried `linear-gradient(160deg, #fcfdfe …)` and
			    that gradient was DELETED — #fcfdfe has B > R, so every tile in the app
			    was washing faint blue over its top-left corner. Separation is tone +
			    hairline + shadow now.

			    Numeric values take `.t-metric` (28px) from StatCard; the two long STRING
			    values below override down the ramp so a model id or an "X.XK → Y.YK"
			    pair does not crack a narrow tile. */}
			<div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-[repeat(auto-fit,minmax(100px,1fr))]">
				{/* Duration — lead metric; always present. */}
				<StatCard label="Duration" value={fmtDur(s.totalDurationUs)} />

				{/* Errors — tone="danger" on non-zero to surface problems immediately. */}
				<StatCard
					label="Errors"
					value={fmtInt(s.errorCount)}
					tone={s.errorCount > 0 ? "danger" : "default"}
				/>

				<StatCard label="Spans" value={fmtInt(s.spanCount)} />

				{toolCount > 0 && (
					<StatCard label="Tool calls" value={fmtInt(toolCount)} />
				)}

				{s.interventionCount > 0 && (
					<StatCard
						label="Interventions"
						value={fmtInt(s.interventionCount)}
						tone="warn"
						hint="Spans where the guardrail applied a pre-flight policy enforcement (warn or blocked)."
					/>
				)}

				{/* Tokens — arrow-separated input→output can be long; drop one size so it
				    wraps gracefully at "X.XK → Y.YK" without cracking a narrow tile. */}
				<StatCard
					label="Tokens"
					// `.t-metric-sm` — the ramp's dense metric step (20px, tabular). It
					// was `text-lg`, which is not a point on the app ramp at all
					// (11/12/13/14/16/20/24/28/32) and so drifted from every other
					// down-sized value in the strip.
					value={<span className="t-metric-sm">{tokens}</span>}
					hint="Input → output tokens summed across LLM spans in this trace."
				/>

				{/* Cost — stored gen_ai_usage_cost; blank ("—") when model is unpriced. */}
				<StatCard
					label="Cost"
					value={s.cost !== undefined ? fmtCost(s.cost) : "—"}
					hint="Stored gen_ai_usage_cost from the model price catalog; blank when unpriced."
				/>

				{/* Model/Provider — prose values; text-sm to keep long names legible. */}
				<StatCard
					label={s.models.length > 1 ? "Models" : "Model"}
					value={
						<span className="text-sm font-semibold leading-snug">
							{modelLabel}
						</span>
					}
				/>

				{s.providers.length > 0 && (
					<StatCard
						label="Provider"
						value={
							<span className="text-sm font-semibold leading-snug">
								{s.providers.join(", ")}
							</span>
						}
					/>
				)}
			</div>

			{/* Loop badge — ADR-023: no raw emoji; AFT-1 title tooltip carries the
			    taxonomy reference ("agent entered a tool call loop with no circuit
			    breaker — AFT-1 category G-3, pre-flight guardrail: loop-depth cap").
			    Badge tone=warn (not danger) — a loop is an at-risk state, not a
			    runtime error per se. Sits below the tile grid rather than inside it. */}
			{loop && (
				<div className="flex items-center gap-2 px-1">
					<Badge
						tone="warn"
						title={`Tool call loop detected (AFT-1 G-3): "${loop.toolName}" called ${loop.count} times with no circuit breaker. This pattern is a pre-flight guardrail target — apply a loop-depth cap or deduplicate the tool inputs.`}
					>
						<WarnTriangle />
						loop — {loop.toolName} ×{loop.count}
					</Badge>
				</div>
			)}
		</div>
	);
}
