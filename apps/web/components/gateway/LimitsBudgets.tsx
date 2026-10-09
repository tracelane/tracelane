"use client";
/**
 * OG-60 Gateway › Limits & budgets — the WORKSPACE layer of the OG-20/21/22 policy
 * (`PUT /v1/controls/policy`) and this gateway's live budget counters
 * (`GET /v1/controls/budgets`). Projects and keys carry their own layer on their own tabs;
 * every layer must pass, so a project or key can narrow this and never widen it.
 */

import { formatDateTimeUtc } from "@/lib/format-date";
import type { BudgetCounter, ControlsState } from "@/lib/gateway-controls";
import { Badge, TBody, TD, TH, THead, TR, Table } from "@tracelanedev/ui";
import { PolicyCard } from "./PolicyEditor";
import { Boundary, useCan, useControlQuery, useControlWrite } from "./control";
import { EmptyNote, Panel } from "./fields";

const usd = (n: number) =>
	new Intl.NumberFormat("en-US", {
		style: "currency",
		currency: "USD",
		maximumFractionDigits: n < 1 ? 4 : 2,
	}).format(n);

/** A UUID wrapped one hyphen-group per line made the table unreadable (2026-10-05 render);
 *  show its first 8 characters and keep the full value in the cell's title. */
export const shortId = (s: string): string =>
	/^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(s) ? `${s.slice(0, 8)}…` : s;

export function BudgetCounters({ rows }: { rows: BudgetCounter[] }) {
	if (rows.length === 0) {
		return (
			<EmptyNote>
				No budget counters on this gateway. A counter appears once a budget is
				set at any layer and a request under it has been admitted.
			</EmptyNote>
		);
	}
	return (
		<div className="overflow-x-auto">
			<Table className="w-full text-left text-sm">
				<THead>
					<TR>
						<TH>Layer</TH>
						<TH>Subject</TH>
						<TH>Window</TH>
						<TH>When spent</TH>
						<TH numeric>Spent</TH>
						<TH numeric>Budget</TH>
						<TH>Resets</TH>
					</TR>
				</THead>
				<TBody>
					{rows.map((r, i) => (
						<TR
							key={`${r.scope}-${r.subjectId ?? "ws"}-${r.endUser ?? ""}-${r.window}-${r.policy}-${i}`}
						>
							<TD>{r.scope}</TD>
							<TD
								mono
								className="whitespace-nowrap"
								title={r.endUser ?? r.subjectId ?? undefined}
							>
								{r.endUser
									? `end user ${shortId(r.endUser)}`
									: r.subjectId
										? shortId(r.subjectId)
										: "workspace"}
							</TD>
							<TD>{r.window}</TD>
							<TD>
								<Badge tone={r.mode === "hard" ? "danger" : "neutral"}>
									{r.mode === "hard" ? "hard · refuse" : "soft · alert"}
								</Badge>
							</TD>
							<TD numeric>
								{r.known && r.spentUsd !== null ? (
									usd(r.spentUsd)
								) : (
									<span title="The spend baseline could not be read, so no figure is shown rather than a zero.">
										unknown
									</span>
								)}
							</TD>
							<TD numeric>{usd(r.budgetUsd)}</TD>
							<TD className="whitespace-nowrap">
								{r.resetsAt ? formatDateTimeUtc(r.resetsAt) : "rolling"}
							</TD>
						</TR>
					))}
				</TBody>
			</Table>
		</div>
	);
}

export function LimitsBudgets() {
	const controls = useControlQuery<ControlsState>("controls");
	const budgets = useControlQuery<{ budgets: BudgetCounter[] }>(
		"controls/budgets",
	);
	const { allowed, reason } = useCan("manage_controls");
	const save = useControlWrite<
		ControlsState,
		{ policy: Record<string, unknown> | null }
	>("PUT", "controls/policy", ["controls", "controls/budgets"]);
	return (
		<div className="space-y-6">
			<Panel
				id="workspace-policy"
				title="Workspace policy"
				description="Limits, budgets, model and provider rules and source IPs that bind every key and session in this workspace. A project or key can narrow these, never widen them."
			>
				<Boundary query={controls} resource="the workspace policy" rows={5}>
					{(c) => (
						<div className="space-y-4">
							{c.policy === null ? (
								<EmptyNote>
									No workspace policy: traffic is not restricted at this layer.
									Projects and keys may still carry their own.
								</EmptyNote>
							) : null}
							<PolicyCard
								scope="workspace"
								doc={c.policy}
								canEdit={allowed}
								reason={reason}
								saving={save.isPending}
								error={save.error}
								resetKey={c.updatedAt ?? "none"}
								onSave={(doc) => save.mutate({ policy: doc })}
								saveLabel="Save workspace policy"
							/>
							{save.isSuccess ? (
								<output className="text-sm text-ok-ink">
									Saved. The gateway applies it to the next request.
								</output>
							) : null}
						</div>
					)}
				</Boundary>
			</Panel>
			<Panel
				id="budget-counters"
				title="Live budget counters"
				description="Spend against every budget this gateway is enforcing, read from the gateway's own counters — not a sum of what you set. Hard budgets refuse once spent; soft budgets alert."
			>
				<Boundary query={budgets} resource="budget counters" rows={3}>
					{(b) => <BudgetCounters rows={b.budgets} />}
				</Boundary>
			</Panel>
		</div>
	);
}
