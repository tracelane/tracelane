/**
 * One row of the `/sessions` table, plus the small pure helpers it shares
 * with the page's derived-window computation (`sessionWindow` in `page.tsx`).
 *
 * SPLIT OUT OF `app/sessions/page.tsx` (PLT-46) so this row's rendered shape
 * can be proven directly by `sessions-agent-chip-render.test.tsx` — importing
 * the row from `page.tsx` itself pulls in that file's data-fetching imports
 * (`fetchSessionsFor` → `@/lib/auth` → `@workos-inc/authkit-nextjs`), which
 * fails to resolve under Vitest's module graph in this Next/pnpm combination
 * (`next/cache` subpath resolution) — unrelated to anything this row does,
 * but it makes the whole module untestable by import alone. A component with
 * no server-only imports is; this file has none.
 */

import { isRedactedEndUser } from "@/lib/end-user";
import { formatDateTimeUtc } from "@/lib/format-date";
import { fmtCompact, fmtDurationMs, fmtUsd } from "@/lib/metrics/format";
import type { SessionSummary } from "@/lib/sessions";
import { Badge } from "@tracelanedev/ui";
import Link from "next/link";

/** Format a ClickHouse toString datetime or ISO 8601 string for display. */
export function parseDate(s: string): Date {
	// A "…T08:45:53" with a T but NO zone parses as LOCAL — anchor to UTC unless
	// the string already carries a zone (the naive-timestamp class; see parseUtcMs).
	const hasZone = /([zZ]|[+-]\d{2}:?\d{2})$/.test(s);
	return new Date(hasZone ? s : `${s.replace(" ", "T")}Z`);
}

// ONE formatter per kind — the registry's (DSH-11 §3.1: this page carried a
// fifth cost formatter). A session with no priced usage renders `—`, not `$0`.
export const formatCost = (usd: number): string =>
	usd > 0 ? fmtUsd(usd) : "—";
export const formatTokens = (n: number): string =>
	n > 0 ? fmtCompact(n) : "—";
export const formatDuration = (us: number): string => fmtDurationMs(us / 1000);

/**
 * OBS-20: render the customer's end user, distinguishing THREE states that a
 * naive `{value || "—"}` would collapse into two.
 *
 * The one that matters is `[REDACTED:email]`. A customer who sends an email
 * address as the user id gets it scrubbed by ingest's PII redaction before
 * storage — the policy working exactly as designed — and if that rendered as
 * blank, or as the raw placeholder, the customer would file a bug against a
 * feature that is behaving correctly. So it renders as an explained chip that
 * tells them what to send instead.
 */
export function EndUserCell({ value }: { value?: string }) {
	if (!value) {
		return <span className="text-ink-3">—</span>;
	}
	if (isRedactedEndUser(value)) {
		return (
			<Badge
				tone="neutral"
				title="An email address was sent as the user id and was removed by PII redaction before storage. Send an opaque id (a UUID or hash) instead."
			>
				redacted
			</Badge>
		);
	}
	// A real id links to this person's traces — that link IS the feature. The
	// /traces filter has no text input for it on purpose: you arrive here, you
	// do not type an opaque id from memory.
	return (
		<Link
			href={`/traces?end_user=${encodeURIComponent(value)}&range=all`}
			className="font-mono text-xs text-action-ink hover:underline"
			title={`Show every trace from ${value}`}
		>
			{value}
		</Link>
	);
}

/** One session's bar — real start, real duration, inside the shared window. */
export function SessionBar({
	s,
	win,
}: { s: SessionSummary; win: { startMs: number; endMs: number } }) {
	const span = win.endMs - win.startMs;
	const end = parseDate(s.last_activity).getTime();
	if (!Number.isFinite(end) || span <= 0) return null;
	const start = end - Math.max(0, s.duration_us) / 1_000;
	const leftPct = ((start - win.startMs) / span) * 100;
	const widthPct = Math.min(
		Math.max(((end - start) / span) * 100, 0.6),
		Math.max(0, 100 - leftPct),
	);
	return (
		<span className="relative flex h-4 items-center" aria-hidden="true">
			<span className="absolute inset-x-0 top-1/2 h-px -translate-y-1/2 bg-line/60" />
			<span
				// `--chart-secondary` (the de-emphasised data-mark role) rather than
				// `bg-ink-2/70`: an alpha re-composites against the row behind it, so
				// the same bar changed value the moment the row was hovered.
				className="absolute top-1/2 h-2 -translate-y-1/2 rounded-sm bg-chart-secondary"
				style={{ left: `${leftPct}%`, width: `${widthPct}%` }}
			/>
		</span>
	);
}

export function SessionRow({
	s,
	win,
}: { s: SessionSummary; win: { startMs: number; endMs: number } | null }) {
	const isError = s.status === "error";
	return (
		<tr className="border-b border-line transition-colors last:border-0 hover:bg-surface-hover">
			<td className="px-3 py-2">
				<span className="inline-flex items-center gap-1.5">
					<Link
						href={`/sessions/${encodeURIComponent(s.session_id)}`}
						className="font-mono text-xs text-action-ink hover:underline"
					>
						{s.session_id.length > 24
							? `${s.session_id.slice(0, 12)}…${s.session_id.slice(-8)}`
							: s.session_id}
					</Link>
					{/* PLT-46: the session's `gen_ai.agent.name` (e.g. Claude Code),
					    when the gateway sent one. `SessionSummary.agent_name` is
					    optional and this checks truthiness, not presence, so it
					    renders nothing for both "field absent" (gateway not yet
					    deployed) and "field present but empty string" (no agent
					    name on any span) — the two ways today's data can say
					    "no agent". */}
					{s.agent_name && <Badge tone="neutral">{s.agent_name}</Badge>}
				</span>
			</td>
			<td className="px-3 py-2">
				<EndUserCell value={s.end_user} />
			</td>
			<td className="px-3 py-2 tabular-nums text-right text-sm text-ink-2">
				{s.turns}
			</td>
			<td className="px-3 py-2 font-mono text-xs text-ink-2">
				{s.model || "—"}
			</td>
			{win && (
				<td className="px-3 py-2">
					<SessionBar s={s} win={win} />
				</td>
			)}
			<td className="px-3 py-2 tabular-nums text-right text-sm text-ink-2">
				{formatTokens(s.total_tokens)}
			</td>
			<td className="px-3 py-2 tabular-nums text-right text-sm text-ink-2">
				{formatDuration(s.duration_us)}
			</td>
			<td className="px-3 py-2 tabular-nums text-right text-sm text-ink-2">
				{formatCost(s.cost_usd)}
			</td>
			<td className="px-3 py-2">
				{isError ? (
					<Badge tone="danger">error</Badge>
				) : (
					<Badge tone="ok">ok</Badge>
				)}
			</td>
			<td className="px-3 py-2 text-right text-xs text-ink-2">
				{formatDateTimeUtc(parseDate(s.last_activity).toISOString())}
			</td>
		</tr>
	);
}
