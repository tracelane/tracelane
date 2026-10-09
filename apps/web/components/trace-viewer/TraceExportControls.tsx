"use client";

import { apiFetchRaw } from "@/lib/api-fetch";
import { Toast } from "@tracelanedev/ui";
import { useState } from "react";

type Format = "csv" | "json";
type NextFile = { cursor: string; rows: number; format: Format };

export function TraceExportControls({
	baseQuery,
	windowQuery,
}: { baseQuery: string; windowQuery: string }) {
	const [busy, setBusy] = useState(false);
	const [next, setNext] = useState<NextFile | null>(null);
	const [notice, setNotice] = useState<string | null>(null);
	const [error, setError] = useState(false);

	async function download(format: Format, cursor?: string) {
		setBusy(true);
		setError(false);
		setNotice(null);
		try {
			const params = new URLSearchParams(baseQuery);
			params.delete("range");
			for (const [key, value] of new URLSearchParams(windowQuery))
				params.set(key, value);
			params.set("format", format);
			if (cursor) params.set("cursor", cursor);
			else params.delete("cursor");
			const response = await apiFetchRaw(`/api/traces/export?${params}`);
			if (!response.ok) throw new Error(`export HTTP ${response.status}`);
			const blob = await response.blob();
			const url = URL.createObjectURL(blob);
			const link = document.createElement("a");
			link.href = url;
			link.download = `traces.${format}`;
			link.click();
			setTimeout(() => URL.revokeObjectURL(url), 0);
			const rowHeader = response.headers.get("x-tracelane-row-count");
			const rows = Number(rowHeader);
			const knownRows =
				rowHeader !== null && Number.isSafeInteger(rows) && rows >= 0;
			const truncated =
				response.headers.get("x-tracelane-truncated") === "true";
			const nextCursor = response.headers.get("x-tracelane-next-cursor");
			if (truncated && nextCursor && knownRows) {
				setNext({ cursor: nextCursor, rows, format });
				setNotice(`Exported ${rows.toLocaleString()} rows — more remain`);
			} else {
				setNext(null);
				setNotice(
					truncated
						? "Export stopped at its row cap; continuation is unavailable"
						: knownRows
							? `Exported ${rows.toLocaleString()} ${rows === 1 ? "row" : "rows"}`
							: "Exported trace file",
				);
			}
		} catch {
			setError(true);
			setNotice("Export failed — try a narrower range");
		} finally {
			setBusy(false);
		}
	}
	return (
		<div className="flex flex-wrap items-center gap-2 text-xs">
			<button
				type="button"
				disabled={busy}
				onClick={() => download("csv")}
				className="rounded-control border border-line px-2.5 py-1.5 font-medium text-ink-2 hover:border-line-2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
			>
				Export CSV
			</button>
			<button
				type="button"
				disabled={busy}
				onClick={() => download("json")}
				className="rounded-control border border-line px-2.5 py-1.5 font-medium text-ink-3 hover:border-line-2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
			>
				JSON
			</button>
			{next && (
				<>
					<button
						type="button"
						disabled={busy}
						onClick={() => download(next.format, next.cursor)}
						className="rounded-control border border-line px-2.5 py-1.5 font-medium text-action-ink hover:bg-surface-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
					>
						Export next {next.rows.toLocaleString()}
					</button>
					<span className="text-ink-3">Rows can change between files.</span>
				</>
			)}
			<Toast
				message={notice}
				tone={error ? "danger" : "neutral"}
				onDismiss={() => setNotice(null)}
			/>
		</div>
	);
}
