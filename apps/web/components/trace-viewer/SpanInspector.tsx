"use client";
import { ObjectPageCommands } from "@/components/command-palette/object-commands";
import { fmtUsd } from "@/lib/metrics/format";

import { fmtCount } from "@/lib/metrics/format";

import { TBody, TD, TR, Table } from "@tracelanedev/ui";

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

import { DatasetAction } from "@/app/datasets/DatasetAction";
import { aftLabel } from "@/lib/aft-labels";

import { formatDateTimeUtc } from "@/lib/format-date";
import { extractToolCalls, formatBytes } from "@/lib/tool-calls";
import { extractGenAi } from "@/lib/trace-tree";
import { fmtDur } from "@tracelanedev/ui";
import { CopyButton } from "./CopyButton";
import { GenerationEvidence } from "./GenerationEvidence";
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
		<TR className="align-top">
			{/* Attribute key — always mono (it's a code symbol). */}
			<TD className="whitespace-nowrap py-1 pr-3 font-mono text-xs text-ink-3">
				{k}
			</TD>
			{/* Attribute value — mono for id/hash/numeric; regular for prose. */}
			<TD
				className={
					mono
						? "break-all py-1 font-mono text-xs tabular-nums text-ink"
						: "break-all py-1 text-xs text-ink"
				}
			>
				{display}
			</TD>
		</TR>
	);
}

function SectionHeading({ children }: { children: string }) {
	return <h3 className="mb-2 t-metric-label">{children}</h3>;
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
	n === undefined ? "—" : fmtCount(n);

export function SpanInspector({
	span,
	traceId,
}: { span: Span | null; traceId?: string }) {
	if (!span) {
		return (
			<div className="flex h-full min-h-64 flex-col items-center justify-center gap-3 p-8 text-center">
				<span
					aria-hidden
					className="flex h-12 w-12 items-center justify-center rounded-card border border-line bg-action-soft text-xl text-action-ink"
				>
					⌖
				</span>
				<p className="text-sm font-medium text-ink">Select a span to inspect</p>
				<p className="max-w-60 text-xs leading-relaxed text-ink-2">
					Choose a step in the trace to explore its recorded attributes and
					timing.
				</p>
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
	// Both spellings: the dotted OTLP form AND the underscore-flattened stored form
	// the gateway writes (`tracelane_response_tool_names`, `tracelane_dispatch_attempts`)
	// — until OBS-50 (2026-09-20) only the dotted form matched, so every gateway
	// `tracelane_*` attribute rendered under "Other".
	const tracelane = Object.entries(attrs).filter(
		([k]) => k.startsWith("tracelane.") || k.startsWith("tracelane_"),
	);
	const other = Object.entries(attrs).filter(
		([k]) =>
			!k.startsWith("gen_ai.") &&
			!k.startsWith("gen_ai_") &&
			!k.startsWith("llm.") &&
			!k.startsWith("tracelane.") &&
			!k.startsWith("tracelane_"),
	);

	// OBS-50: per-tool-call detail. Empty rows → no section at all (never an empty one).
	const toolCalls = extractToolCalls(span.attributes);

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
			<ObjectPageCommands
				commands={[
					...(traceId && summary.model !== undefined
						? [
								{
									id: "span-playground",
									label: "Open selected span in playground",
									href: `/playground?trace=${encodeURIComponent(traceId)}&span=${encodeURIComponent(span.span_id)}`,
									group: "action" as const,
								},
							]
						: []),
					...(typeof attrs.gen_ai_conversation_id === "string" &&
					attrs.gen_ai_conversation_id
						? [
								{
									id: "span-session",
									label: "Open session",
									href: `/sessions/${encodeURIComponent(attrs.gen_ai_conversation_id)}`,
									group: "action" as const,
								},
							]
						: []),
				]}
			/>
			<div>
				<div className="mb-2 flex items-center justify-between gap-2">
					<SectionHeading>Span</SectionHeading>
					{traceId && summary.model !== undefined && (
						<a
							className="text-xs text-action-ink underline"
							href={`/playground?trace=${encodeURIComponent(traceId)}&span=${encodeURIComponent(span.span_id)}`}
						>
							Open in playground
						</a>
					)}
					{traceId && <DatasetAction traceId={traceId} spanId={span.span_id} />}
					<div className="flex items-center gap-1.5">
						<CopyButton value={span.span_id} label="Copy ID" />
						<CopyButton value={span.attributes} label="Copy attributes" />
					</div>
				</div>
				<div className="overflow-x-auto">
					<Table className="w-full">
						<TBody>
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
								v={formatDateTimeUtc(span.start_time)}
							/>
						</TBody>
					</Table>
				</div>
			</div>

			<GenerationEvidence evidence={span} attributes={attrs} />
			{businessRef && (
				<div className="rounded-card border border-line bg-surface-2 p-3">
					<div className="mb-1 flex items-center justify-between gap-2">
						<SectionHeading>Business reference</SectionHeading>
						<CopyButton value={businessRef} label="Copy" />
					</div>
					<p className="break-all font-mono text-sm text-ink">{businessRef}</p>
					<p className="mt-1.5 text-2xs leading-snug text-ink-3">
						Customer-supplied reference tying this activity to a business event
						(loan, transaction, case). On a gateway-proxied call it is also part
						of the tamper-evident ledger record.
					</p>
				</div>
			)}

			{toolCalls.rows.length > 0 && (
				<div
					className="rounded-card border border-line bg-surface-2 p-3"
					data-testid="tool-calls"
				>
					<SectionHeading>{`Tool calls (${toolCalls.rows.length})`}</SectionHeading>
					{/* Turn outcome from the provider's own finish reason; this span's
					    latency is the PROVIDER round trip — the tool itself runs on the
					    customer's side and its duration is not on this span. */}
					<div className="mb-2 flex items-baseline justify-between gap-3 text-xs text-ink-3">
						<span>
							{toolCalls.endedOnToolCall
								? "turn ended on the tool call"
								: toolCalls.finishReasons.length > 0
									? `turn ended: ${toolCalls.finishReasons.join(", ")}`
									: "turn outcome —"}
						</span>
						<span className="font-mono tabular-nums">
							{fmtDur(span.duration_us)} provider round trip
						</span>
					</div>
					<ul className="space-y-2">
						{toolCalls.rows.map((row, i) => (
							<li key={`${row.name}-${i}`} className="text-xs">
								<div className="flex items-baseline justify-between gap-3">
									{/* A function name is a code symbol — mono. */}
									<span className="font-mono text-ink">{row.name}</span>
									<span className="font-mono tabular-nums text-ink-3">
										{formatBytes(row.argumentBytes)}
									</span>
								</div>
								{row.captured ? (
									<pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-surface p-2 font-mono text-2xs text-ink">
										{typeof row.arguments === "string"
											? row.arguments
											: JSON.stringify(row.arguments, null, 2)}
									</pre>
								) : (
									<div className="mt-1 text-ink-3">
										— arguments not captured (content capture is off for this
										workspace)
									</div>
								)}
							</li>
						))}
					</ul>
				</div>
			)}

			{hasSummary && (
				<div className="rounded-card border border-line bg-surface-2 p-3">
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
							value={summary.cost !== undefined ? fmtUsd(summary.cost) : "—"}
							mono={summary.cost !== undefined}
						/>
					</div>
					<p className="mt-2 text-2xs leading-snug text-ink-3">
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
					<h3 className="mb-2 t-metric-label text-danger-ink">
						Guardrail Interventions
					</h3>
					<div className="space-y-1">
						{span.aft_ids.map((id) => (
							<div
								key={id}
								className="flex items-center gap-2 text-xs"
								title={`${id}: ${aftLabel(id)}`}
							>
								<span className="font-mono font-semibold text-danger-ink">
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
									? "font-medium text-danger-ink"
									: "font-medium text-warn-ink"
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
					<div className="overflow-x-auto">
						<Table className="w-full">
							<TBody>
								{genAi.map(([k, v]) => (
									<AttributeRow key={k} k={k} v={v} />
								))}
							</TBody>
						</Table>
					</div>
				</div>
			)}

			{llm.length > 0 && (
				<div>
					<SectionHeading>LLM Attributes</SectionHeading>
					<div className="overflow-x-auto">
						<Table className="w-full">
							<TBody>
								{llm.map(([k, v]) => (
									<AttributeRow key={k} k={k} v={v} />
								))}
							</TBody>
						</Table>
					</div>
				</div>
			)}

			{tracelane.length > 0 && (
				<div>
					<SectionHeading>Tracelane</SectionHeading>
					<div className="overflow-x-auto">
						<Table className="w-full">
							<TBody>
								{tracelane.map(([k, v]) => (
									<AttributeRow key={k} k={k} v={v} />
								))}
							</TBody>
						</Table>
					</div>
				</div>
			)}

			{other.length > 0 && (
				<div>
					<SectionHeading>Other</SectionHeading>
					<div className="overflow-x-auto">
						<Table className="w-full">
							<TBody>
								{other.map(([k, v]) => (
									<AttributeRow key={k} k={k} v={v} />
								))}
							</TBody>
						</Table>
					</div>
				</div>
			)}
		</div>
	);
}
