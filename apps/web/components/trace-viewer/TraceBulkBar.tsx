"use client";
import { Button, ObjectActions, Toast } from "@tracelanedev/ui";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { BulkTraceWrites } from "./BulkTraceWrites";
import type { TraceSummary } from "./TraceList";
export const traceExportFields = [
	"trace_id",
	"root_name",
	"start_time",
	"duration_us",
	"span_count",
	"error_count",
	"intervention",
	"model",
	"cost_usd",
	"total_tokens",
] as const;
export function selectedTraceCsv(rows: TraceSummary[]) {
	const field = (v: unknown) => {
		const s = String(v ?? "");
		if (/^[=+@-]/.test(s)) return `"'${s.replaceAll('"', '""')}"`;
		return /[",\r\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
	};
	return `${[traceExportFields.join(","), ...rows.map((row) => traceExportFields.map((key) => field(row[key])).join(","))].join("\n")}\n`;
}
export function downloadText(text: string, name: string, type: string) {
	const url = URL.createObjectURL(new Blob([text], { type }));
	const link = document.createElement("a");
	link.href = url;
	link.download = name;
	link.click();
	setTimeout(() => URL.revokeObjectURL(url), 0);
}
export function TraceBulkBar({
	rows,
	hidden,
	onClear,
	viewerRole,
	onSelection,
	onBusy,
	busy,
}: {
	rows: TraceSummary[];
	hidden: number;
	onClear: () => void;
	viewerRole?: string | null;
	onSelection: (ids: string[]) => void;
	onBusy: (busy: boolean) => void;
	busy: boolean;
}) {
	const router = useRouter();
	const [notice, setNotice] = useState<string | null>(null);
	function exportRows(format: "csv" | "json") {
		downloadText(
			format === "csv" ? selectedTraceCsv(rows) : JSON.stringify(rows, null, 2),
			`selected-traces.${format}`,
			format === "csv" ? "text/csv" : "application/json",
		);
		setNotice(`Exported ${rows.length} traces`);
	}
	return (
		<>
			<BulkTraceWrites
				ids={rows.map((r) => r.trace_id)}
				viewerRole={viewerRole}
				onSelection={onSelection}
				onBusy={onBusy}
			>
				<strong>{rows.length} selected</strong>
				{hidden > 0 && (
					<span className="text-xs text-ink-2">
						({hidden} hidden by the filter)
					</span>
				)}
				<Button variant="ghost" disabled={busy} onClick={onClear}>
					Clear selection
				</Button>
				<ObjectActions
					label="Export selected"
					actions={[
						{
							disabled: busy,
							label: "Export CSV",
							onSelect: () => exportRows("csv"),
						},
						{
							disabled: busy,
							label: "Export JSON",
							onSelect: () => exportRows("json"),
						},
					]}
				/>
				<Button
					disabled={busy}
					onClick={async () => {
						try {
							await navigator.clipboard.writeText(
								rows
									.map(
										(r) =>
											`${window.location.origin}/traces/${encodeURIComponent(r.trace_id)}`,
									)
									.join("\n"),
							);
							setNotice(`Copied ${rows.length} trace links`);
						} catch {
							setNotice(
								"Could not copy links. Check clipboard permissions and try again.",
							);
						}
					}}
				>
					Copy links
				</Button>
				<Button
					disabled={busy || rows.length !== 2}
					title={rows.length !== 2 ? "Select exactly two traces" : undefined}
					onClick={() =>
						router.push(
							`/traces/compare?a=${encodeURIComponent(rows[0]?.trace_id ?? "")}&b=${encodeURIComponent(rows[1]?.trace_id ?? "")}`,
						)
					}
				>
					Compare
				</Button>
			</BulkTraceWrites>
			<Toast message={notice} onDismiss={() => setNotice(null)} />
		</>
	);
}
