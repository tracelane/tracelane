"use client";

/**
 *
 * Shows the tool definitions the gateway has ACTUALLY SEEN on this tenant's
 * traffic, so approving is one click instead of hand-authoring tool JSON.
 *
 * Deliberately shows no schema or description text: the gateway stores the
 * definition HASH, never the tool text. What you approve is the hash the gateway
 * computed at request time.
 *
 * The drift signal is the point of the screen: when a tool name appears with a
 * hash different from its approved one, its definition changed after you
 * approved it — the rug-pull R3 exists to catch.
 */

import { absoluteDate } from "@/lib/format-date";
import { Badge, EmptyState } from "@tracelanedev/ui";
import { useCallback, useEffect, useState } from "react";

type Observed = {
	tool_name: string;
	def_hash: string;
	first_seen: string;
	last_seen: string;
	seen_count: number;
	approved: boolean;
};

type LoadState =
	| { kind: "loading" }
	| { kind: "ok"; rows: Observed[] }
	| { kind: "forbidden" }
	| { kind: "error"; detail: string };

export function ToolPins() {
	const [state, setState] = useState<LoadState>({ kind: "loading" });
	const [busy, setBusy] = useState<string | null>(null);

	const load = useCallback(async () => {
		try {
			const res = await fetch("/api/guardrails/observed-tools", {
				cache: "no-store",
			});
			if (res.status === 403) {
				setState({ kind: "forbidden" });
				return;
			}
			if (!res.ok) {
				setState({ kind: "error", detail: `HTTP ${res.status}` });
				return;
			}
			setState({ kind: "ok", rows: (await res.json()) as Observed[] });
		} catch {
			setState({ kind: "error", detail: "network" });
		}
	}, []);

	useEffect(() => {
		void load();
	}, [load]);

	async function approve(row: Observed) {
		setBusy(`${row.tool_name}:${row.def_hash}`);
		try {
			const res = await fetch("/api/guardrails/approve-tool", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					tool_name: row.tool_name,
					def_hash: row.def_hash,
				}),
			});
			if (res.ok) await load();
			else if (res.status === 403) setState({ kind: "forbidden" });
		} finally {
			setBusy(null);
		}
	}

	if (state.kind === "loading") {
		return <p className="text-sm text-ink-2">Loading observed tools…</p>;
	}

	if (state.kind === "forbidden") {
		return (
			<EmptyState
				title="Owner access required"
				description="Tool pinning changes what the guardrail engine treats as an approved tool definition, so it is limited to workspace owners."
			/>
		);
	}

	if (state.kind === "error") {
		return (
			<p className="text-sm text-ink-2">
				Could not load observed tools ({state.detail}).
			</p>
		);
	}

	if (state.rows.length === 0) {
		return (
			<EmptyState
				title="No tool definitions observed yet"
				description="Tracelane records a tool definition the first time it appears on a request. Send a request that carries tools and it will show up here for approval — there is nothing to configure."
			/>
		);
	}

	// A tool with an approved hash, appearing under a DIFFERENT hash, is drift.
	const approvedByName = new Map<string, string>();
	for (const r of state.rows)
		if (r.approved) approvedByName.set(r.tool_name, r.def_hash);

	return (
		<div className="overflow-x-auto">
			<table className="w-full text-sm">
				<thead>
					<tr className="text-left text-ink-2">
						<th className="py-2 pr-4 font-medium">Tool</th>
						<th className="py-2 pr-4 font-medium">Definition</th>
						<th className="py-2 pr-4 font-medium">First seen (UTC)</th>
						<th className="py-2 pr-4 font-medium">Last seen (UTC)</th>
						<th className="py-2 pr-4 font-medium">Status</th>
						<th className="py-2 font-medium" />
					</tr>
				</thead>
				<tbody>
					{state.rows.map((r) => {
						const approvedHash = approvedByName.get(r.tool_name);
						const isDrift = !r.approved && approvedHash !== undefined;
						const key = `${r.tool_name}:${r.def_hash}`;
						return (
							<tr key={key} className="border-t border-line">
								<td className="py-2 pr-4 font-mono">{r.tool_name}</td>
								<td className="py-2 pr-4 font-mono text-ink-2">
									{r.def_hash.slice(0, 12)}…
								</td>
								<td className="py-2 pr-4 text-ink-2">
									{absoluteDate(r.first_seen)}
								</td>
								<td className="py-2 pr-4 text-ink-2">
									{absoluteDate(r.last_seen)}
								</td>
								<td className="py-2 pr-4">
									{r.approved ? (
										<Badge tone="ok">Approved</Badge>
									) : isDrift ? (
										<Badge tone="danger">Definition changed</Badge>
									) : (
										<Badge tone="neutral">Not approved</Badge>
									)}
								</td>
								<td className="py-2">
									{r.approved ? null : (
										<button
											type="button"
											onClick={() => void approve(r)}
											disabled={busy === key}
											className="rounded-md border border-line px-2.5 py-1 text-[13px] font-medium hover:bg-surface-2 disabled:opacity-50"
										>
											{busy === key
												? "Approving…"
												: isDrift
													? "Approve new definition"
													: "Approve"}
										</button>
									)}
								</td>
							</tr>
						);
					})}
				</tbody>
			</table>
			<p className="mt-3 text-[13px] text-ink-2">
				Approving pins this exact definition. If the tool's name, schema or
				description changes afterwards, the guardrail engine flags it as
				definition drift on the next request. Approving never grants a tool any
				capability — that is a separate, owner-only setting.
			</p>
		</div>
	);
}
