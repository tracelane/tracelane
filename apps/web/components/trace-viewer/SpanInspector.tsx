"use client";

/**
 * SpanInspector — side panel showing the details for a selected span.
 *
 * Leads with a structured GenAI summary (model, token counts, and the real
 * stored `gen_ai_usage_cost` in USD), then the raw attribute groups and
 * guardrail interventions. Cost is read as-stored (the gateway derives it from
 * the model price catalog or a provider-reported cost), never fabricated here;
 * blank when the model isn't priced.
 *
 * Font discipline (ADR-053): mono (JetBrains Mono) ONLY for ids, hashes, and
 * numeric values. Prose values (model names, messages, status labels) use the
 * regular body font — `font-mono` on everything was the pre-refactor default
 * and made prose unreadable.
 */

import { aftLabel } from "@/lib/aft-labels";
import { fmtDur } from "@/lib/fmt-dur";
import { extractGenAi } from "@/lib/trace-tree";
import { CopyButton } from "./CopyButton";
import type { Span } from "./types";

const STATUS_LABELS: Record<number, string> = {
	0: "Unset",
	1: "OK",
	2: "Error",
};

/**
 * Classify whether a key→value pair should be rendered in monospace.
 * Mono ONLY for: IDs/hashes (span_id, parent_span_id, hex strings),
 * numeric values, and duration strings. Prose (status labels, model names,
 * messages) uses the body font.
 */
function isMonoValue(k: string, v: unknown): boolean {
	// Absent placeholder — never mono (it's a dash, not data).
	if (v === "—" || v === null || v === undefined) return false;
	// Named ID keys — their values are always hex/UUID.
	if (
		k === "span_id" ||
		k === "parent_span_id" ||
		k === "trace_id" ||
		k.endsWith("_id") ||
		k.endsWith(".id")
	)
		return true;
	// Numbers are numeric → mono + tabular.
	if (typeof v === "number") return true;
	const s = String(v);
	// Pure UUID (8-4-4-4-12 hex).
	if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s))
		return true;
	// Raw hex hash (16+ hex chars, no other characters).
	if (/^[0-9a-f]{16,}$/i.test(s)) return true;
	// Duration string produced by fmtDur (adaptive µs/ms/s).
	if (/^\d+(\.\d+)?(µs|ms|us|s)$/.test(s)) return true;
	return false;
}

function AttributeRow({ k, v }: { k: string; v: unknown }) {
	const display =
		typeof v === "object" ? JSON.stringify(v, null, 2) : String(v);
	const mono = isMonoValue(k, v);
	return (
		<tr className="align-top">
			{/* Attribute key — always mono (it's a code symbol). */}
			<td className="whitespace-nowrap py-1 pr-3 font-mono text-xs text-ink-3">
				{k}
			</td>
			{/* Attribute value — mono for id/hash/numeric; regular for prose. */}
			<td
				className={
					mono
						? "break-all py-1 font-mono text-xs tabular-nums text-ink"
						: "break-all py-1 text-xs text-ink"
				}
			>
				{display}
			</td>
		</tr>
	);
}

function SectionHeading({ children }: { children: string }) {
	return (
		<h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-ink-3">
			{children}
		</h3>
	);
}

/** One label/value line in the GenAI summary. Value falls back to an em dash.
 * Numeric values (tokens, cost) stay mono+tabular; prose (model name, system,
 * operation) use regular font. */
function SummaryRow({
	label,
	value,
	mono = false,
}: {
	label: string;
	value: string;
	mono?: boolean;
}) {
	return (
		<div className="flex items-baseline justify-between gap-3 py-0.5">
			<span className="text-xs text-ink-3">{label}</span>
			<span
				className={
					mono ? "font-mono text-xs tabular-nums text-ink" : "text-xs text-ink"
				}
			>
				{value}
			</span>
		</div>
	);
}

const fmt = (n: number | undefined): string =>
	n === undefined ? "—" : n.toLocaleString("en-US");

export function SpanInspector({ span }: { span: Span | null }) {
	if (!span) {
		return (
			<div className="flex h-full items-center justify-center text-sm text-ink-3">
				Select a span to inspect
			</div>
		);
	}

	let attrs: Record<string, unknown> = {};
	try {
		attrs = JSON.parse(span.attributes) as Record<string, unknown>;
	} catch {
		attrs = { raw: span.attributes };
	}

	// Group attributes by prefix for display. GenAI covers both the dotted OTel
	// form and the underscore-flattened stored form (ADR-043).
	const genAi = Object.entries(attrs).filter(
		([k]) => k.startsWith("gen_ai.") || k.startsWith("gen_ai_"),
	);
	const llm = Object.entries(attrs).filter(([k]) => k.startsWith("llm."));
	const tracelane = Object.entries(attrs).filter(([k]) =>
		k.startsWith("tracelane."),
	);
	const other = Object.entries(attrs).filter(
		([k]) =>
			!k.startsWith("gen_ai.") &&
			!k.startsWith("gen_ai_") &&
			!k.startsWith("llm.") &&
			!k.startsWith("tracelane."),
	);

	const summary = extractGenAi(span.attributes);
	const hasSummary =
		summary.model !== undefined ||
		summary.inputTokens !== undefined ||
		summary.outputTokens !== undefined ||
		summary.cost !== undefined;

	// Customer business reference (BFSI evidence). Stored underscore-flattened
	// (`tracelane_business_reference`); also accept the dotted OTLP form that can
	// land in the raw `extra` blob. First-class, not buried in raw attrs.
	const businessRefRaw =
		attrs.tracelane_business_reference ?? attrs["tracelane.business_reference"];
	const businessRef =
		typeof businessRefRaw === "string" && businessRefRaw.length > 0
			? businessRefRaw
			: undefined;

	return (
		<div className="h-full space-y-4 overflow-y-auto p-4">
			<div>
				<div className="mb-2 flex items-center justify-between gap-2">
					<SectionHeading>Span</SectionHeading>
					<div className="flex items-center gap-1.5">
						<CopyButton value={span.span_id} label="Copy ID" />
						<CopyButton value={span.attributes} label="Copy attributes" />
					</div>
				</div>
				<table className="w-full">
					<tbody>
						<AttributeRow k="name" v={span.name} />
						<AttributeRow k="span_id" v={span.span_id} />
						<AttributeRow k="parent_span_id" v={span.parent_span_id ?? "—"} />
						<AttributeRow
							k="status"
							v={STATUS_LABELS[span.status_code] ?? span.status_code}
						/>
						{span.status_message && (
							<AttributeRow k="status_message" v={span.status_message} />
						)}
						{/* Duration formatted with shared adaptive formatter (µs/ms/s). */}
						<AttributeRow k="duration" v={fmtDur(span.duration_us)} />
						<AttributeRow
							k="start_time"
							v={new Date(span.start_time).toISOString()}
						/>
					</tbody>
				</table>
			</div>

			{businessRef && (
				<div className="rounded-lg border border-line bg-surface-2/40 p-3">
					<div className="mb-1 flex items-center justify-between gap-2">
						<SectionHeading>Business reference</SectionHeading>
						<CopyButton value={businessRef} label="Copy" />
					</div>
					<p className="break-all font-mono text-sm text-ink">{businessRef}</p>
					<p className="mt-1.5 text-[11px] leading-snug text-ink-3">
						Customer-supplied reference tying this activity to a business event
						(loan, transaction, case). On a gateway-proxied call it is also part
						of the tamper-evident ledger record.
					</p>
				</div>
			)}

			{hasSummary && (
				<div className="rounded-lg border border-line bg-surface-2/40 p-3">
					<SectionHeading>GenAI</SectionHeading>
					<div>
						{/* Model/system/operation are names (prose) — regular font. */}
						<SummaryRow label="Model" value={summary.model ?? "—"} />
						{summary.system && (
							<SummaryRow label="Provider" value={summary.system} />
						)}
						{summary.operation && (
							<SummaryRow label="Operation" value={summary.operation} />
						)}
						{/* Token counts and cost are numeric — mono + tabular. */}
						<SummaryRow
							label="Input tokens"
							value={fmt(summary.inputTokens)}
							mono
						/>
						<SummaryRow
							label="Output tokens"
							value={fmt(summary.outputTokens)}
							mono
						/>
						<SummaryRow
							label="Total tokens"
							value={fmt(summary.totalTokens)}
							mono
						/>
						<SummaryRow
							label="Cost"
							value={
								summary.cost !== undefined ? `$${summary.cost.toFixed(4)}` : "—"
							}
							mono={summary.cost !== undefined}
						/>
					</div>
					<p className="mt-2 text-[11px] leading-snug text-ink-3">
						Cost is the stored{" "}
						<code className="font-mono">gen_ai_usage_cost</code> — the gateway
						derives it from the model price catalog (or a provider-reported
						cost); it's blank when the model isn't priced. Token counts are the
						as-emitted usage values.
					</p>
				</div>
			)}

			{span.aft_ids.length > 0 && (
				<div>
					<h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-danger">
						Guardrail Interventions
					</h3>
					<div className="space-y-1">
						{span.aft_ids.map((id) => (
							<div
								key={id}
								className="flex items-center gap-2 text-xs"
								title={`${id}: ${aftLabel(id)}`}
							>
								<span className="font-mono font-semibold text-danger">
									{id}
								</span>
								<span className="text-ink-3">{aftLabel(id)}</span>
							</div>
						))}
					</div>
					<p className="mt-1 text-xs text-ink-3">
						Intervention level:{" "}
						<span
							className={
								span.intervention === 2
									? "font-medium text-danger"
									: "font-medium text-warn"
							}
						>
							{span.intervention === 2 ? "blocked" : "warned"}
						</span>
					</p>
				</div>
			)}

			{genAi.length > 0 && (
				<div>
					<SectionHeading>GenAI Attributes</SectionHeading>
					<table className="w-full">
						<tbody>
							{genAi.map(([k, v]) => (
								<AttributeRow key={k} k={k} v={v} />
							))}
						</tbody>
					</table>
				</div>
			)}

			{llm.length > 0 && (
				<div>
					<SectionHeading>LLM Attributes</SectionHeading>
					<table className="w-full">
						<tbody>
							{llm.map(([k, v]) => (
								<AttributeRow key={k} k={k} v={v} />
							))}
						</tbody>
					</table>
				</div>
			)}

			{tracelane.length > 0 && (
				<div>
					<SectionHeading>Tracelane</SectionHeading>
					<table className="w-full">
						<tbody>
							{tracelane.map(([k, v]) => (
								<AttributeRow key={k} k={k} v={v} />
							))}
						</tbody>
					</table>
				</div>
			)}

			{other.length > 0 && (
				<div>
					<SectionHeading>Other</SectionHeading>
					<table className="w-full">
						<tbody>
							{other.map(([k, v]) => (
								<AttributeRow key={k} k={k} v={v} />
							))}
						</tbody>
					</table>
				</div>
			)}
		</div>
	);
}
