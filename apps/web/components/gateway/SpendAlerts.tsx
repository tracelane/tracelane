"use client";
/**
 * OG-60 Gateway › Spend alerts — `OG-24`: the channels a budget alert is delivered to
 * (`/v1/controls/alert-channels*`) and the recent deliveries (`GET …/alert-events`).
 * Thresholds themselves are set on each budget (Limits & budgets, Projects, Keys). A
 * webhook channel's signing secret is shown ONCE, at creation.
 */

import { formatDateTimeUtc } from "@/lib/format-date";
import type { AlertChannel } from "@/lib/gateway-controls";
import {
	Badge,
	Button,
	ConfirmDialog,
	TBody,
	TD,
	TH,
	THead,
	TR,
	Table,
} from "@tracelanedev/ui";
import { useState } from "react";
import {
	Boundary,
	RefusalNote,
	controlRequest,
	useCan,
	useControlQuery,
	useControlWrite,
} from "./control";
import { EmptyNote, Field, Panel, WhyDisabled, inputClass } from "./fields";

interface AlertEvent {
	id: string;
	channelId: string;
	status: string;
	attempts: number;
	lastError: string | null;
	createdAt: string;
	deliveredAt: string | null;
	payload: {
		scope?: string;
		policy?: string;
		threshold?: string | number;
		window?: string;
		budget_usd?: number;
		spent_usd?: number;
		type?: string;
	};
}

const KIND_HINT: Record<AlertChannel["kind"], string> = {
	email: "One email address.",
	slack:
		"A Slack incoming-webhook URL (https). It is stored encrypted and shown only as its host.",
	webhook:
		"An https URL. Deliveries are signed; the signing secret is shown once after you add it.",
};

function CreateChannel({ allowed }: { allowed: boolean }) {
	const [kind, setKind] = useState<AlertChannel["kind"]>("email");
	const [name, setName] = useState("");
	const [target, setTarget] = useState("");
	const create = useControlWrite<
		AlertChannel & { signingSecret?: string },
		{ kind: string; name: string; target: string }
	>("POST", "controls/alert-channels", ["controls/alert-channels"]);
	const fieldError = (f: string) =>
		create.error?.refusal.field === f ? create.error.refusal.message : null;
	return (
		<div className="space-y-3">
			<div className="grid gap-3 sm:grid-cols-[1fr_1fr_2fr]">
				<Field label="Kind">
					<select
						className={inputClass}
						disabled={!allowed || create.isPending}
						value={kind}
						onChange={(e) => setKind(e.target.value as AlertChannel["kind"])}
					>
						<option value="email">Email</option>
						<option value="slack">Slack</option>
						<option value="webhook">Webhook</option>
					</select>
				</Field>
				<Field label="Name" error={fieldError("name")}>
					<input
						className={inputClass}
						disabled={!allowed || create.isPending}
						value={name}
						maxLength={128}
						onChange={(e) => setName(e.target.value)}
					/>
				</Field>
				<Field
					label="Target"
					hint={KIND_HINT[kind]}
					error={fieldError("target")}
				>
					<input
						className={inputClass}
						disabled={!allowed || create.isPending}
						value={target}
						onChange={(e) => setTarget(e.target.value)}
					/>
				</Field>
			</div>
			<RefusalNote error={create.error} />
			<div className="flex items-center gap-3">
				<Button
					variant="primary"
					size="sm"
					disabled={
						!allowed || create.isPending || !name.trim() || !target.trim()
					}
					onClick={() =>
						create.mutate(
							{ kind, name: name.trim(), target: target.trim() },
							{
								onSuccess: () => {
									setName("");
									setTarget("");
								},
							},
						)
					}
				>
					{create.isPending ? "Adding…" : "Add channel"}
				</Button>
			</div>
			{create.data?.signingSecret ? (
				<output className="space-y-1 rounded-control border border-line bg-surface-2 p-3 text-sm">
					<p className="font-medium">
						Signing secret for “{create.data.name}” — copy it now, it is not
						shown again.
					</p>
					<code className="block break-all font-mono text-xs">
						{create.data.signingSecret}
					</code>
				</output>
			) : null}
		</div>
	);
}

function ChannelRow({ c, allowed }: { c: AlertChannel; allowed: boolean }) {
	const [confirm, setConfirm] = useState(false);
	const [test, setTest] = useState<
		| { state: "idle" }
		| { state: "busy" }
		| { state: "ok" }
		| { state: "fail"; message: string }
	>({ state: "idle" });
	const del = useControlWrite<void, void>(
		"DELETE",
		`controls/alert-channels/${c.id}`,
		["controls/alert-channels"],
	);
	return (
		<TR>
			<TD>{c.name}</TD>
			<TD>
				<Badge tone="neutral">{c.kind}</Badge>
			</TD>
			<TD mono className="break-all">
				{c.target}
			</TD>
			<TD>{formatDateTimeUtc(c.createdAt)}</TD>
			<TD>
				<div className="flex flex-wrap items-center gap-2">
					<Button
						size="sm"
						disabled={!allowed || test.state === "busy"}
						aria-label={`Send a test to ${c.name}`}
						onClick={async () => {
							setTest({ state: "busy" });
							try {
								await controlRequest(
									"POST",
									`controls/alert-channels/${c.id}/test`,
									{},
								);
								setTest({ state: "ok" });
							} catch (err) {
								setTest({
									state: "fail",
									message:
										err instanceof Error ? err.message : "The test failed.",
								});
							}
						}}
					>
						{test.state === "busy" ? "Sending…" : "Send test"}
					</Button>
					<Button
						size="sm"
						disabled={!allowed}
						aria-label={`Delete ${c.name}`}
						onClick={() => setConfirm(true)}
					>
						Delete
					</Button>
					{test.state === "ok" ? (
						<output className="text-xs text-ok-ink">Delivered</output>
					) : null}
					{test.state === "fail" ? (
						<span role="alert" className="text-xs text-danger-ink">
							{test.message}
						</span>
					) : null}
				</div>
				<ConfirmDialog
					open={confirm}
					onClose={() => setConfirm(false)}
					title={`Delete ${c.name}?`}
					confirmLabel="Delete channel"
					busy={del.isPending}
					error={del.error?.refusal.message ?? null}
					onConfirm={() =>
						del.mutate(undefined, { onSuccess: () => setConfirm(false) })
					}
				>
					<p className="text-sm text-ink-2">
						Budget alerts stop going to this channel. Budgets keep enforcing.
					</p>
				</ConfirmDialog>
			</TD>
		</TR>
	);
}

export function SpendAlerts() {
	const channels = useControlQuery<{ channels: AlertChannel[] }>(
		"controls/alert-channels",
	);
	const events = useControlQuery<{ events: AlertEvent[] }>(
		"controls/alert-events?limit=50",
	);
	const { allowed, reason } = useCan("manage_controls");
	return (
		<div className="space-y-6">
			<Panel
				id="channels"
				title="Alert channels"
				description="Where a spend alert is delivered. Set the thresholds on each budget; this is only where the alert goes."
			>
				<Boundary query={channels} resource="alert channels" rows={2}>
					{({ channels: rows }) =>
						rows.length === 0 ? (
							<EmptyNote>
								No channels: budget alerts are recorded but delivered nowhere.
								Hard budgets still refuse at their limit.
							</EmptyNote>
						) : (
							<div className="overflow-x-auto">
								<Table className="w-full text-left text-sm">
									<THead>
										<TR>
											<TH>Name</TH>
											<TH>Kind</TH>
											<TH>Target</TH>
											<TH>Added</TH>
											<TH>Actions</TH>
										</TR>
									</THead>
									<TBody>
										{rows.map((c) => (
											<ChannelRow key={c.id} c={c} allowed={allowed} />
										))}
									</TBody>
								</Table>
							</div>
						)
					}
				</Boundary>
				<CreateChannel allowed={allowed} />
				<WhyDisabled reason={reason} />
			</Panel>
			<Panel
				id="events"
				title="Recent alert deliveries"
				description="The latest 50 alerts the gateway tried to deliver, newest first."
			>
				<Boundary query={events} resource="alert deliveries" rows={2}>
					{({ events: rows }) =>
						rows.length === 0 ? (
							<EmptyNote>
								No alerts have fired yet. They fire when spend crosses a
								threshold you set on a budget.
							</EmptyNote>
						) : (
							<div className="overflow-x-auto">
								<Table className="w-full text-left text-sm">
									<THead>
										<TR>
											<TH>When</TH>
											<TH>Budget</TH>
											<TH>Threshold</TH>
											<TH>Status</TH>
											<TH numeric>Attempts</TH>
										</TR>
									</THead>
									<TBody>
										{rows.map((e) => (
											<TR key={e.id}>
												<TD>{formatDateTimeUtc(e.createdAt)}</TD>
												<TD>
													{e.payload.scope ?? "—"} · {e.payload.window ?? "—"}
													{typeof e.payload.spent_usd === "number" &&
													typeof e.payload.budget_usd === "number"
														? ` · $${e.payload.spent_usd} of $${e.payload.budget_usd}`
														: ""}
												</TD>
												<TD>{String(e.payload.threshold ?? "—")}</TD>
												<TD>
													<Badge
														tone={
															e.status === "delivered"
																? "ok"
																: e.lastError
																	? "danger"
																	: "neutral"
														}
													>
														{e.status}
													</Badge>
													{e.lastError ? (
														<span className="ml-2 text-xs text-danger-ink">
															{e.lastError}
														</span>
													) : null}
												</TD>
												<TD numeric>{e.attempts}</TD>
											</TR>
										))}
									</TBody>
								</Table>
							</div>
						)
					}
				</Boundary>
			</Panel>
		</div>
	);
}
