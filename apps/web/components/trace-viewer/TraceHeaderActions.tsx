"use client";
import { DatasetAction } from "@/app/datasets/DatasetAction";
import { useObjectCommands } from "@/components/command-palette/object-commands";
import { Dialog, ObjectActions, Toast } from "@tracelanedev/ui";
import { useRouter } from "next/navigation";
import { type ReactNode, useState } from "react";
import { ShareDialog } from "./ShareDialog";
export function TraceHeaderActions({
	traceId,
	flag,
}: { traceId: string; flag: ReactNode }) {
	const router = useRouter();
	const [mode, setMode] = useState<"flag" | "share" | null>(null);
	const [notice, setNotice] = useState<string | null>(null);
	async function copy(value: string) {
		try {
			await navigator.clipboard.writeText(value);
			setNotice("Copied");
		} catch {
			setNotice("Could not copy. Check clipboard permissions.");
		}
	}
	useObjectCommands([
		{
			id: "trace-copy-link",
			label: "Copy link",
			href: "",
			group: "action",
			onSelect: () => void copy(window.location.href),
		},
		{
			id: "trace-copy-id",
			label: "Copy trace ID",
			href: "",
			group: "action",
			onSelect: () => void copy(traceId),
		},
		{
			id: "trace-flag",
			label: "Flag trace",
			href: "",
			group: "action",
			onSelect: () => setMode("flag"),
		},
		{
			id: "trace-share",
			label: "Share trace",
			href: "",
			group: "action",
			onSelect: () => setMode("share"),
		},
		{
			id: "trace-compare",
			label: "Compare this trace",
			href: `/traces/compare?a=${encodeURIComponent(traceId)}`,
			group: "action",
		},
		{
			id: "trace-ledger",
			label: "View ledger",
			href: "/audit",
			group: "action",
		},
	]);
	return (
		<div className="flex items-center gap-2">
			<DatasetAction traceId={traceId} primary />
			<ObjectActions
				label="Trace actions"
				actions={[
					{ label: "Copy ID", onSelect: () => void copy(traceId) },
					{
						label: "Copy link",
						onSelect: () => void copy(window.location.href),
					},
					{
						label: "Compare",
						onSelect: () =>
							router.push(`/traces/compare?a=${encodeURIComponent(traceId)}`),
					},
					{ label: "Flag trace", onSelect: () => setMode("flag") },
					{ label: "Share trace", onSelect: () => setMode("share") },
					{ label: "View ledger", onSelect: () => router.push("/audit") },
				]}
			/>
			<Dialog
				open={mode !== null}
				title={mode === "flag" ? "Flag trace" : "Share trace"}
				onClose={() => setMode(null)}
			>
				{mode === "flag" ? (
					flag
				) : mode === "share" ? (
					<ShareDialog traceId={traceId} embedded />
				) : null}
			</Dialog>
			<Toast message={notice} onDismiss={() => setNotice(null)} />
		</div>
	);
}
