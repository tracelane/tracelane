"use client";

/**
 * LiveTraces — opt-in live trace feed (V-4).
 *
 * Wires the previously-unconsumed FT-07 SSE route (`/api/traces/stream`) to a
 * real "Live" toggle. When off, it renders the server-rendered (filtered,
 * paginated) list passed as `children`. When on, it opens an EventSource
 * against the stream — which carries the SAME active filters via
 * `streamParams` — and renders the live rows, refreshing each read cycle.
 *
 * The FT-07 route is one-shot: it emits a `partial` frame (cached/stale, for a
 * cold paint), then a `full` frame (fresh rows), then closes. EventSource then
 * auto-reconnects, which re-runs the gateway read — giving a polling live tail
 * without holding a persistent socket. Frame shape: see
 * `lib/query-deadline.ts` (`{ rows, stale, servedAt }`, or `{ message }` on a
 * server `error` frame).
 */

import { EmptyState } from "@tracelanedev/ui";
import { useEffect, useRef, useState } from "react";
import { TraceList, type TraceSummary } from "./TraceList";

type Frame = { rows: TraceSummary[]; stale: boolean; servedAt: number };

type LiveStatus = "connecting" | "live" | "reconnecting" | "error";

/** Relative label for the last-updated timestamp. */
function updateLabel(ts: number): string {
	const diff = Date.now() - ts;
	if (diff < 5_000) return "just now";
	if (diff < 60_000) return `${Math.floor(diff / 1_000)}s ago`;
	return `${Math.floor(diff / 60_000)}m ago`;
}

export function LiveTraces({
	children,
	streamParams,
}: {
	children: React.ReactNode;
	streamParams: string;
}) {
	const [live, setLive] = useState(false);
	const [rows, setRows] = useState<TraceSummary[] | null>(null);
	const [status, setStatus] = useState<LiveStatus>("connecting");
	const [updatedAt, setUpdatedAt] = useState<number | null>(null);
	const esRef = useRef<EventSource | null>(null);

	useEffect(() => {
		if (!live) {
			esRef.current?.close();
			esRef.current = null;
			return;
		}

		setStatus("connecting");
		const url = streamParams
			? `/api/traces/stream?${streamParams}`
			: "/api/traces/stream";
		const es = new EventSource(url);
		esRef.current = es;

		const onPartial = (e: MessageEvent) => {
			// Cold paint only — never clobber fresher rows with the stale cache.
			try {
				const f = JSON.parse(e.data) as Frame;
				setRows((cur) => (cur === null ? f.rows : cur));
			} catch {
				/* malformed frame — ignore, the next full frame recovers */
			}
		};
		const onFull = (e: MessageEvent) => {
			try {
				const f = JSON.parse(e.data) as Frame;
				setRows(f.rows);
				setUpdatedAt(Date.now());
				setStatus("live");
			} catch {
				/* malformed frame — keep last-good rows */
			}
		};
		const onError = (e: Event) => {
			// A server `error` frame carries data; a bare connection drop does not
			// (EventSource auto-reconnects → the next read cycle resumes the feed).
			const data = (e as MessageEvent).data;
			setStatus(
				typeof data === "string" && data.length > 0 ? "error" : "reconnecting",
			);
		};

		es.addEventListener("partial", onPartial);
		es.addEventListener("full", onFull);
		es.addEventListener("error", onError);

		return () => {
			es.removeEventListener("partial", onPartial);
			es.removeEventListener("full", onFull);
			es.removeEventListener("error", onError);
			es.close();
		};
	}, [live, streamParams]);

	// Status indicator dot color — ok-soft for live (operational status),
	// danger for error, warn for transitional states.
	const dotClass =
		status === "live"
			? "bg-ok animate-pulse"
			: status === "error"
				? "bg-danger"
				: "bg-warn";
	const statusLabel =
		status === "live"
			? "Live"
			: status === "error"
				? "Feed error — retrying"
				: status === "reconnecting"
					? "Reconnecting…"
					: "Connecting…";

	return (
		<div>
			<div className="mb-3 flex items-center justify-end gap-3 text-sm">
				{live && (
					<span className="flex items-center gap-1.5 text-xs text-ink-2">
						<span className={`h-2 w-2 rounded-full ${dotClass}`} />
						{statusLabel}
						{status === "live" && updatedAt && (
							<span className="text-ink-3" suppressHydrationWarning>
								· updated {updateLabel(updatedAt)}
							</span>
						)}
					</span>
				)}
				{/* Live toggle: active = surface-3 bg (operational state, not CTA) */}
				<button
					type="button"
					onClick={() => setLive((v) => !v)}
					aria-pressed={live}
					className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal ${
						live
							? "border-line-2 bg-surface-3 text-ink"
							: "border-line text-ink-2 hover:text-ink"
					}`}
				>
					{live ? "Stop live" : "● Live"}
				</button>
			</div>

			{live && rows !== null ? (
				rows.length === 0 ? (
					<EmptyState
						title="No live traces yet"
						description="New traces matching the current filters appear here automatically."
					/>
				) : (
					<TraceList traces={rows} />
				)
			) : (
				children
			)}
		</div>
	);
}
