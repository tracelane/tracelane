"use client";

/**
 * Tool pinning — the approve surface for R3 rug-pull detection (/B).
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
 *
 * ── PRESENTATION PASS (P1, 2026-08-22) ──────────────────────────────────────
 * On the shared `Table` system and the shared `Button`; the fetch, the approve
 * and unpin calls, the 403/404 handling and every string are untouched. Two
 * things worth naming because they are judgement calls, not conversions:
 *
 *  · DRIFT STAYS A BADGE, NOT A ROW COLOUR. "Definition changed" is the loudest
 *    fact this table can report, and the tempting move is to tint the whole row
 *    danger. A tinted row colours five cells that are not the finding — the
 *    hash, the timestamps, the button — and once one row is tinted the eye reads
 *    the UNTINTED rows as a second category rather than as normal. The chip is
 *    where the meaning is, and it already carries the words.
 *  · LOADING IS SKELETON ROWS, NOT A SENTENCE. "Loading observed tools…" told
 *    the reader nothing about the shape that was arriving; three row-height
 *    placeholders hold the layout so the section does not jump when the fetch
 *    lands. They are `aria-hidden` (the Skeleton primitive sets it) and carry no
 *    numbers — an empty grey bar cannot be misread as a value.
 */

import { absoluteDate } from "@/lib/format-date";
import {
	Badge,
	Button,
	Card,
	EmptyState,
	Skeleton,
	TBody,
	TD,
	TH,
	THead,
	TR,
	Table,
} from "@tracelanedev/ui";
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

	// GWY-15b. The gateway has always exposed this; nothing called it, so approving
	// was a one-way door. Unpin is per TOOL NAME, not per hash — the gateway stores
	// one pin per tool — so this removes approval for the tool outright.
	async function unpin(row: Observed) {
		setBusy(`${row.tool_name}:${row.def_hash}`);
		try {
			const res = await fetch(
				`/api/guardrails/tool-pins/${encodeURIComponent(row.tool_name)}`,
				{ method: "DELETE" },
			);
			// 404 = already gone (a second click, or another owner got there first).
			// Reloading shows the true state, so treat it as success rather than
			// showing an error for an outcome the user already wanted.
			if (res.ok || res.status === 404) await load();
			else if (res.status === 403) setState({ kind: "forbidden" });
		} finally {
			setBusy(null);
		}
	}

	if (state.kind === "loading") {
		return (
			<Card quiet className="space-y-2 p-4">
				{[0, 1, 2].map((i) => (
					<Skeleton key={i} className="h-9 w-full" />
				))}
			</Card>
		);
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
		// The `inline` variant: one muted line, no frame. An error inside a titled
		// section does not need a second box drawn around it, and a danger-tinted
		// panel for a transient fetch failure would outweigh the drift chips that
		// are the actual signal on this surface. Copy unchanged.
		return (
			<EmptyState
				inline
				title={`Could not load observed tools (${state.detail}).`}
			/>
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
		<div className="space-y-3">
			<Card quiet className="overflow-hidden p-0">
				<Table>
					{/* `border-t-0`: the shared `THead` is bordered top AND bottom so it holds
					    its edge "whether or not the table starts at the top of its card"
					    (its own words). This one DOES start at the top of a card, so its
					    top border lands 1px inside the card's border in the same `--line`
					    colour — two hairlines reading as one 2px rule along the top edge
					    only, heavier than the three edges around it. Suppressed here, at
					    the call site, rather than in the primitive: a table that starts
					    mid-card still wants the border, and this is a question for one
					    shared change rather than three concurrent ones. */}
					<THead className="border-t-0">
						<TR>
							<TH>Tool</TH>
							<TH>Definition</TH>
							<TH>First seen (UTC)</TH>
							<TH>Last seen (UTC)</TH>
							<TH>Status</TH>
							<TH aria-label="Actions" />
						</TR>
					</THead>
					<TBody>
						{state.rows.map((r) => {
							const approvedHash = approvedByName.get(r.tool_name);
							const isDrift = !r.approved && approvedHash !== undefined;
							const key = `${r.tool_name}:${r.def_hash}`;
							return (
								<TR key={key}>
									{/* Both are technical identifiers in LEFT columns, so both
									    take `mono` rather than `numeric` — they are not numbers
									    and right-aligning a hash next to a tool name would put
									    two ragged left edges in the middle of the table. */}
									<TD mono>{r.tool_name}</TD>
									<TD mono muted>
										{r.def_hash.slice(0, 12)}…
									</TD>
									<TD muted>{absoluteDate(r.first_seen)}</TD>
									<TD muted>{absoluteDate(r.last_seen)}</TD>
									<TD>
										{r.approved ? (
											<Badge tone="ok">Approved</Badge>
										) : isDrift ? (
											<Badge tone="danger">Definition changed</Badge>
										) : (
											<Badge tone="neutral">Not approved</Badge>
										)}
									</TD>
									<TD className="text-right">
										{r.approved ? (
											<Button
												variant="secondary"
												size="sm"
												onClick={() => void unpin(r)}
												disabled={busy === key}
											>
												{busy === key ? "Removing…" : "Remove approval"}
											</Button>
										) : (
											<Button
												variant="secondary"
												size="sm"
												onClick={() => void approve(r)}
												disabled={busy === key}
											>
												{busy === key
													? "Approving…"
													: isDrift
														? "Approve new definition"
														: "Approve"}
											</Button>
										)}
									</TD>
								</TR>
							);
						})}
					</TBody>
				</Table>
			</Card>
			{/* The authorisation semantics, verbatim. `text-xs`/`ink-2`: it is a
			    footnote to the table, not a second body paragraph competing with the
			    section intro above it. */}
			<p className="max-w-3xl text-xs text-ink-2">
				Approving pins this exact definition. If the tool's name, schema or
				description changes afterwards, the guardrail engine flags it as
				definition drift on the next request. Approving never grants a tool any
				capability — that is a separate, owner-only setting. Removing an
				approval deletes the pin, so the tool goes back to unapproved and there
				is no longer a definition to compare against — drift is no longer
				reported for it until you approve one again.
			</p>
		</div>
	);
}
