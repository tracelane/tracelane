"use client";
/**
 * OG-60 Change log — `OG-35`: every change to a gateway control, who made it, from where,
 * and the before / after state (`GET /v1/audit/control-changes`). Filterable, paged with the
 * gateway's cursor, downloadable as NDJSON. Secrets are scrubbed by the gateway before a
 * row is written; the page shows the stored row as is.
 */

import { formatDateTimeUtc } from "@/lib/format-date";
import type { ControlChangeRow } from "@/lib/gateway-controls";
import { Button, TBody, TD, TH, THead, TR, Table } from "@tracelanedev/ui";
import { useState } from "react";
import {
	Boundary,
	CONTROL_BASE,
	controlRequest,
	useControlQuery,
} from "./control";
import { EmptyNote, Field, Panel, inputClass } from "./fields";

/** The gateway's `page_max` (`control_policy.v1.json`); the page asks for a smaller page. */
const PAGE = 50;
const DOWNLOAD_LIMIT = 500;

interface Page {
	items: ControlChangeRow[];
	next_cursor: number | null;
}
interface Filters {
	action: string;
	target_type: string;
	since: string;
	until: string;
}
const NO_FILTERS: Filters = {
	action: "",
	target_type: "",
	since: "",
	until: "",
};

function toIso(local: string): string | null {
	if (!local) return null;
	const t = Date.parse(`${local}:00Z`);
	return Number.isNaN(t) ? null : new Date(t).toISOString();
}

export function changeLogQuery(
	f: Filters,
	extra: Record<string, string> = {},
): string {
	const q = new URLSearchParams();
	if (f.action.trim()) q.set("action", f.action.trim());
	if (f.target_type.trim()) q.set("target_type", f.target_type.trim());
	const since = toIso(f.since);
	if (since) q.set("since", since);
	const until = toIso(f.until);
	if (until) q.set("until", until);
	for (const [k, v] of Object.entries(extra)) q.set(k, v);
	return q.toString();
}

function Row({ r }: { r: ControlChangeRow }) {
	return (
		<TR>
			<TD className="whitespace-nowrap">{formatDateTimeUtc(r.occurred_at)}</TD>
			<TD>
				<span className="break-words">{r.actor}</span>
				{r.actor_role ? (
					<span className="ml-1 text-xs text-ink-3">{r.actor_role}</span>
				) : null}
				{r.ip ? (
					<span className="block font-mono text-xs text-ink-3">{r.ip}</span>
				) : null}
			</TD>
			<TD mono>{r.action}</TD>
			<TD>
				<span className="text-xs text-ink-3">{r.target_type}</span>{" "}
				<span className="break-all font-mono text-xs">{r.target_id}</span>
			</TD>
			<TD>
				<details>
					<summary className="cursor-pointer text-xs text-ink-2">
						Before / after
					</summary>
					<pre className="mt-1 max-w-md overflow-x-auto whitespace-pre-wrap break-all rounded-control bg-surface-2 p-2 font-mono text-xs">
						{JSON.stringify({ before: r.before, after: r.after }, null, 2)}
					</pre>
				</details>
			</TD>
		</TR>
	);
}

export function ChangeLog() {
	const [draft, setDraft] = useState<Filters>(NO_FILTERS);
	const [applied, setApplied] = useState<Filters>(NO_FILTERS);
	const [older, setOlder] = useState<ControlChangeRow[]>([]);
	const [cursor, setCursor] = useState<number | null | undefined>(undefined);
	const [more, setMore] = useState<{ busy: boolean; error: string | null }>({
		busy: false,
		error: null,
	});
	const first = useControlQuery<Page>(
		`audit/control-changes?${changeLogQuery(applied, { limit: String(PAGE) })}`,
	);
	const set = (k: keyof Filters, v: string) =>
		setDraft((d) => ({ ...d, [k]: v }));
	const nextCursor = cursor === undefined ? first.data?.next_cursor : cursor;
	return (
		<div className="space-y-6">
			<Panel
				id="change-log"
				title="Control changes"
				description="Newest first, in UTC. Each row is a change to a gateway control — limits, budgets, projects, keys, emergency actions, security and team changes."
			>
				<form
					className="grid gap-3 sm:grid-cols-5"
					onSubmit={(e) => {
						e.preventDefault();
						setOlder([]);
						setCursor(undefined);
						setApplied(draft);
					}}
				>
					<Field label="Action" hint="Exact, e.g. workspace.pause">
						<input
							className={inputClass}
							value={draft.action}
							onChange={(e) => set("action", e.target.value)}
						/>
					</Field>
					<Field label="Target type" hint="Exact, e.g. api_key">
						<input
							className={inputClass}
							value={draft.target_type}
							onChange={(e) => set("target_type", e.target.value)}
						/>
					</Field>
					<Field label="Since (UTC)">
						<input
							type="datetime-local"
							className={inputClass}
							value={draft.since}
							onChange={(e) => set("since", e.target.value)}
						/>
					</Field>
					<Field label="Until (UTC)">
						<input
							type="datetime-local"
							className={inputClass}
							value={draft.until}
							onChange={(e) => set("until", e.target.value)}
						/>
					</Field>
					<div className="flex items-end gap-2">
						<Button type="submit" variant="primary" size="sm">
							Apply filters
						</Button>
						<Button
							type="button"
							size="sm"
							onClick={() => {
								setDraft(NO_FILTERS);
								setApplied(NO_FILTERS);
								setOlder([]);
								setCursor(undefined);
							}}
						>
							Clear
						</Button>
					</div>
				</form>
				<Boundary query={first} resource="the control-change log" rows={4}>
					{(page) => {
						const rows = [...page.items, ...older];
						const filtered =
							JSON.stringify(applied) !== JSON.stringify(NO_FILTERS);
						return rows.length === 0 ? (
							<EmptyNote>
								{filtered
									? "No changes match these filters. Clear them to see everything."
									: "No control changes recorded yet. Changing a limit, budget, project, key or security setting writes a row here."}
							</EmptyNote>
						) : (
							<div className="space-y-3">
								<div className="overflow-x-auto">
									<Table className="w-full text-left text-sm">
										<THead>
											<TR>
												<TH>When</TH>
												<TH>Who</TH>
												<TH>Action</TH>
												<TH>Target</TH>
												<TH>Detail</TH>
											</TR>
										</THead>
										<TBody>
											{rows.map((r) => (
												<Row key={r.id} r={r} />
											))}
										</TBody>
									</Table>
								</div>
								<div className="flex flex-wrap items-center gap-3">
									{nextCursor ? (
										<Button
											size="sm"
											disabled={more.busy}
											onClick={async () => {
												setMore({ busy: true, error: null });
												try {
													const p = await controlRequest<Page>(
														"GET",
														`audit/control-changes?${changeLogQuery(applied, { limit: String(PAGE), cursor: String(nextCursor) })}`,
													);
													setOlder((o) => [...o, ...p.items]);
													setCursor(p.next_cursor);
													setMore({ busy: false, error: null });
												} catch (err) {
													setMore({
														busy: false,
														error:
															err instanceof Error
																? err.message
																: "Couldn't load older changes.",
													});
												}
											}}
										>
											{more.busy ? "Loading…" : "Load older changes"}
										</Button>
									) : (
										<span className="text-xs text-ink-3">
											That is every matching change.
										</span>
									)}
									<a
										className="text-sm underline"
										download="control-changes.ndjson"
										href={`${CONTROL_BASE}/audit/control-changes?${changeLogQuery(applied, { format: "ndjson", limit: String(DOWNLOAD_LIMIT) })}`}
									>
										Download newest {DOWNLOAD_LIMIT} (NDJSON)
									</a>
									{more.error ? (
										<span role="alert" className="text-sm text-danger-ink">
											{more.error}
										</span>
									) : null}
								</div>
							</div>
						);
					}}
				</Boundary>
			</Panel>
		</div>
	);
}
