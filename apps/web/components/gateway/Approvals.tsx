"use client";
import { Button } from "@tracelanedev/ui";
import { type ReactNode, useEffect, useRef, useState } from "react";
import {
	Boundary,
	RefusalNote,
	useCan,
	useControlQuery,
	useControlWrite,
} from "./control";
import { Field, Panel, inputClass } from "./fields";
type Approval = {
	id: string;
	subject: string;
	subject_kind: string;
	server_name?: string;
	key_name?: string;
	requester_sub: string;
	status: string;
	created_at: string;
	expires_at: string;
	args_preview?: string;
	decided_by?: string;
	decision_note?: string;
};
type Settings = {
	settings: { require_second_approver: boolean; default_ttl_secs: number };
	limits: { max_ttl_secs: number; note_max_chars: number };
};
function ArgumentPreview({ text }: { text: string }) {
	let value: unknown;
	try {
		value = JSON.parse(text);
	} catch {
		return (
			<p>
				Argument preview was truncated or redacted and cannot be displayed as
				fields.
			</p>
		);
	}
	function fields(value: unknown, path: string): ReactNode {
		if (value === null) return <span>None</span>;
		if (typeof value !== "object")
			return (
				<span className="whitespace-pre-wrap break-words">{String(value)}</span>
			);
		const entries = Object.entries(value);
		if (entries.length === 0) return <span>No values</span>;
		return (
			<dl className="space-y-2 border-l border-line pl-3">
				{entries.map(([name, item]) => (
					<div key={`${path}.${name}`}>
						<dt className="font-medium">
							{Array.isArray(value) ? `Item ${Number(name) + 1}` : name}
						</dt>
						<dd>{fields(item, `${path}.${name}`)}</dd>
					</div>
				))}
			</dl>
		);
	}
	return (
		<section aria-label="Argument preview">
			{fields(value, "arguments")}
		</section>
	);
}
function Decision({
	row,
	query,
	noteMax,
}: { row: Approval; query: string; noteMax: number }) {
	const [note, setNote] = useState("");
	const yes = useControlWrite("POST", `approvals/${row.id}/approve`, [query]);
	const no = useControlWrite("POST", `approvals/${row.id}/deny`, [query]);
	const conflict = yes.error?.status === 409 || no.error?.status === 409;
	const refresh = useControlQuery<{ approvals: Approval[] }>(query, {
		enabled: conflict,
	});
	return (
		<div className="space-y-2">
			<Field label={`Decision note for ${row.subject}`}>
				<input
					className={inputClass}
					maxLength={noteMax}
					value={note}
					onChange={(e) => setNote(e.target.value)}
				/>
			</Field>
			<div className="flex gap-2">
				<Button
					disabled={yes.isPending || no.isPending}
					onClick={() => yes.mutate({ note })}
				>
					Approve {row.subject}
				</Button>
				<Button
					variant="ghost"
					disabled={yes.isPending || no.isPending}
					onClick={() => no.mutate({ note })}
				>
					Deny {row.subject}
				</Button>
			</div>
			<RefusalNote error={yes.error ?? no.error} />
			{conflict && (
				<p>
					This request is no longer pending.{" "}
					<button
						type="button"
						className="underline"
						onClick={() => void refresh.refetch()}
					>
						Refresh status
					</button>
				</p>
			)}
		</div>
	);
}
function SettingsForm({ view }: { view: Settings }) {
	const [second, setSecond] = useState(view.settings.require_second_approver);
	const [ttl, setTtl] = useState(String(view.settings.default_ttl_secs));
	const save = useControlWrite("PUT", "approvals/settings", [
		"approvals/settings",
	]);
	return (
		<Panel title="Approval settings">
			<form
				className="space-y-3"
				onSubmit={(e) => {
					e.preventDefault();
					save.mutate({
						require_second_approver: second,
						default_ttl_secs: Number(ttl),
					});
				}}
			>
				<fieldset disabled={save.isPending} className="space-y-3">
					<label className="flex gap-2">
						<input
							type="checkbox"
							checked={second}
							onChange={(e) => setSecond(e.target.checked)}
						/>
						Require a different approver from the key creator
					</label>
					<Field label="Request lifetime (seconds)">
						<input
							className={inputClass}
							type="number"
							min={1}
							max={view.limits.max_ttl_secs}
							required
							value={ttl}
							onChange={(e) => setTtl(e.target.value)}
						/>
					</Field>
					<Button type="submit">Save approval settings</Button>
				</fieldset>
			</form>
			<RefusalNote error={save.error} />
			{save.isSuccess && <output>Settings saved</output>}
		</Panel>
	);
}
type Rule = {
	id: string;
	model_glob: string;
	key_id: string | null;
	ttl_secs: number | null;
};
function ModelRules() {
	const query = useControlQuery<{
		rules: Rule[];
		keys: { id: string; name: string }[];
		limits: { tool_glob_max_chars: number; max_ttl_secs: number };
	}>("approval-rules");
	const [model, setModel] = useState("");
	const [key, setKey] = useState("");
	const [ttl, setTtl] = useState("");
	const add = useControlWrite("POST", "approval-rules", ["approval-rules"]);
	const remove = useControlWrite(
		"DELETE",
		(r: Rule) => `approval-rules/${r.id}`,
		["approval-rules"],
	);
	return (
		<Panel
			title="Model approvals"
			description="Matching model calls return an approval request immediately. Retry the same call after it is approved."
		>
			<Boundary query={query} resource="model approval rules">
				{(v) => (
					<>
						{v.rules.length === 0 ? (
							<p>No model approval rules.</p>
						) : (
							<ul>
								{v.rules.map((r) => (
									<li key={r.id}>
										{r.model_glob} ·{" "}
										{v.keys?.find((k) => k.id === r.key_id)?.name ?? "All keys"}{" "}
										·{" "}
										{r.ttl_secs ? `${r.ttl_secs} seconds` : "Default lifetime"}{" "}
										<Button
											variant="ghost"
											disabled={remove.isPending}
											onClick={() => remove.mutate(r)}
										>
											Remove {r.model_glob}
										</Button>
									</li>
								))}
							</ul>
						)}
						<form
							className="space-y-3"
							onSubmit={(e) => {
								e.preventDefault();
								add.mutate(
									{
										model_glob: model,
										key_id: key || null,
										ttl_secs: ttl ? Number(ttl) : null,
									},
									{ onSuccess: () => setModel("") },
								);
							}}
						>
							<Field label="Model pattern">
								<input
									className={inputClass}
									required
									maxLength={v.limits?.tool_glob_max_chars}
									value={model}
									onChange={(e) => setModel(e.target.value)}
								/>
							</Field>
							<Field label="Model rule key">
								<select
									className={inputClass}
									value={key}
									onChange={(e) => setKey(e.target.value)}
								>
									<option value="">All keys</option>
									{v.keys?.map((k) => (
										<option key={k.id} value={k.id}>
											{k.name}
										</option>
									))}
								</select>
							</Field>
							<Field label="Rule lifetime (seconds, optional)">
								<input
									className={inputClass}
									type="number"
									min={1}
									max={v.limits?.max_ttl_secs}
									value={ttl}
									onChange={(e) => setTtl(e.target.value)}
								/>
							</Field>
							<Button type="submit" disabled={add.isPending}>
								Add model approval rule
							</Button>
						</form>
					</>
				)}
			</Boundary>
			<RefusalNote error={add.error ?? remove.error} />
		</Panel>
	);
}
/** The approval a notification link points at (`?id=`), read once on the client. */
function useFocusedApprovalId(): string | null {
	const [id, setId] = useState<string | null>(null);
	useEffect(() => {
		setId(new URLSearchParams(window.location.search).get("id"));
	}, []);
	return id;
}
export function Approvals() {
	const focusId = useFocusedApprovalId();
	const scrolled = useRef(false);
	const { allowed } = useCan("approve_tool_calls");
	const { allowed: manage } = useCan("manage_mcp");
	const [status, setStatus] = useState("pending");
	const [cursor, setCursor] = useState<string | null>(null);
	const path = `approvals?status=${status}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`;
	const queue = useControlQuery<{
		approvals: Approval[];
		pending: number;
		next_cursor: string | null;
	}>(path);
	const settings = useControlQuery<Settings>("approvals/settings", {
		enabled: manage,
	});
	return (
		<div className="space-y-5">
			<Panel
				title="Approval queue"
				description="A pending request cannot execute. Approved grants can be used once before they expire."
			>
				<Field label="Approval status">
					<select
						className={inputClass}
						value={status}
						onChange={(e) => {
							setStatus(e.target.value);
							setCursor(null);
						}}
					>
						{["pending", "approved", "denied", "expired", "consumed"].map(
							(s) => (
								<option key={s} value={s}>
									{s.charAt(0).toUpperCase() + s.slice(1)}
								</option>
							),
						)}
					</select>
				</Field>
				<Boundary query={queue} resource="approval queue">
					{(v) => (
						<p className="flex items-center gap-2">
							{v.pending > 0 && (
								<span
									aria-hidden="true"
									className="inline-block h-2 w-2 bg-accent-warm"
								/>
							)}
							{v.pending} pending requests
						</p>
					)}
				</Boundary>
				<Boundary query={queue} resource="approval queue">
					{(v) => (
						<>
							{focusId && !v.approvals.some((r) => r.id === focusId) && (
								<output className="block">
									The request in your link is not in this list. It may be
									decided, expired or older: change the status filter above.
								</output>
							)}
							{v.approvals.length === 0 ? (
								<p>No {status} requests.</p>
							) : (
								<ul className="space-y-3">
									{v.approvals.map((row) => (
										<li
											key={row.id}
											ref={(el) => {
												if (el && row.id === focusId && !scrolled.current) {
													scrolled.current = true;
													el.scrollIntoView?.({ block: "center" });
												}
											}}
											aria-current={row.id === focusId ? "true" : undefined}
											className={`space-y-2 rounded border p-4 ${row.id === focusId ? "border-line-2 outline outline-2 outline-focus-ring" : "border-line"}`}
										>
											<h4 className="font-medium">
												{row.subject} · {row.server_name ?? "Model call"}
											</h4>
											<p>
												Requested by {row.key_name ?? "Workspace member"} ·{" "}
												{row.status}
											</p>
											<p className="text-sm">
												Requested {new Date(row.created_at).toISOString()} ·
												Expires {new Date(row.expires_at).toISOString()}
											</p>
											{row.args_preview && (
												<ArgumentPreview text={row.args_preview} />
											)}
											{row.decision_note && <p>{row.decision_note}</p>}
											{allowed && row.status === "pending" && settings.data && (
												<Decision
													row={row}
													query={path}
													noteMax={settings.data.limits.note_max_chars}
												/>
											)}
										</li>
									))}
								</ul>
							)}
							{v.next_cursor && (
								<Button onClick={() => setCursor(v.next_cursor)}>
									Older requests
								</Button>
							)}
							{cursor && (
								<Button variant="ghost" onClick={() => setCursor(null)}>
									Newest requests
								</Button>
							)}
						</>
					)}
				</Boundary>
			</Panel>
			{manage && (
				<Boundary query={settings} resource="approval settings">
					{(v) => <SettingsForm view={v} />}
				</Boundary>
			)}
			{manage && <ModelRules />}
		</div>
	);
}
