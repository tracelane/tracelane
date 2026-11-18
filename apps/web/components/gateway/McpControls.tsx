"use client";
import { Button } from "@tracelanedev/ui";
import { useState } from "react";
import {
	Boundary,
	RefusalNote,
	useCan,
	useControlQuery,
	useControlWrite,
} from "./control";
import { Field, Panel, inputClass } from "./fields";

type Server = {
	id: string;
	slug: string;
	name: string;
	url: string;
	transport: string;
	auth_mode: string;
	credential_kind: string;
	credential_header: string | null;
	credential_last4: string | null;
	enabled: boolean;
};
type Limits = {
	max_servers_per_workspace: number;
	max_name_chars: number;
	max_slug_chars: number;
	max_url_bytes: number;
};
type Policy = {
	rules_mode: string;
	pins_mode: string;
	injection_mode: string;
	default_action: string;
};
type Rule = {
	id: string;
	server_id: string | null;
	key_id: string | null;
	tool_glob: string;
	action: string;
	reason: string;
};
type View = {
	policy: Policy;
	rules: Rule[];
	keys?: { id: string; name: string }[];
	limits: {
		tool_glob_max_chars: number;
		reason_max_chars: number;
		preview_window_hours: number;
		preview_max_window_hours: number;
	};
};
type Tool = {
	server_id: string;
	server_name: string;
	tool_name: string;
	def_hash: string;
	status: string;
	last_seen: string;
};
const refresh = ["mcp-servers", "mcp-policy", "mcp-tools"];
function PolicyForm({ view, allowed }: { view: View; allowed: boolean }) {
	const [policy, setPolicy] = useState(view.policy);
	const save = useControlWrite("PUT", "mcp-policy", refresh);
	return (
		<Panel
			title="Tool policy"
			description="Observe records findings. Enforce blocks matching calls. Injection checks use heuristics."
		>
			<fieldset disabled={!allowed || save.isPending} className="space-y-3">
				{(
					[
						["rules_mode", "Tool rules"],
						["pins_mode", "Definition pins"],
						["injection_mode", "Injection heuristic"],
					] as const
				).map(([key, label]) => (
					<Field key={key} label={label}>
						<select
							className={inputClass}
							value={policy[key]}
							onChange={(e) => setPolicy({ ...policy, [key]: e.target.value })}
						>
							<option value="observe">Observe</option>
							<option value="enforce">Enforce</option>
						</select>
					</Field>
				))}
				<Field label="Unmatched tools">
					<select
						className={inputClass}
						value={policy.default_action}
						onChange={(e) =>
							setPolicy({ ...policy, default_action: e.target.value })
						}
					>
						<option value="allow">Allow</option>
						<option value="deny">Deny</option>
					</select>
				</Field>
				{allowed && (
					<Button onClick={() => save.mutate(policy)}>Save tool policy</Button>
				)}
			</fieldset>
			<RefusalNote error={save.error} />
			{save.isSuccess && <output>Policy saved</output>}
		</Panel>
	);
}
function ServerForm({
	server,
	limits,
	close,
}: { server?: Server; limits: Limits; close: () => void }) {
	const [name, setName] = useState(server?.name ?? "");
	const [slug, setSlug] = useState(server?.slug ?? "");
	const [url, setUrl] = useState(server?.url ?? "");
	const [transport, setTransport] = useState(
		server?.transport ?? "streamable_http",
	);
	const [auth, setAuth] = useState(server?.auth_mode ?? "none");
	const [kind, setKind] = useState(server?.credential_kind ?? "bearer");
	const [header, setHeader] = useState(server?.credential_header ?? "");
	const [secret, setSecret] = useState("");
	const save = useControlWrite(
		server ? "PATCH" : "POST",
		server ? `mcp-servers/${server.id}` : "mcp-servers",
		refresh,
	);
	return (
		<form
			className="space-y-3 rounded border border-line p-4"
			onSubmit={(e) => {
				e.preventDefault();
				save.mutate(
					{
						name,
						slug,
						url,
						transport,
						auth_mode: auth,
						credential_kind: kind,
						credential_header: kind === "header" ? header : null,
						...(secret ? { credential: secret } : {}),
					},
					{
						onSuccess: () => {
							setSecret("");
							close();
						},
					},
				);
			}}
		>
			<fieldset disabled={save.isPending} className="space-y-3">
				<Field label="Server name">
					<input
						className={inputClass}
						required
						maxLength={limits.max_name_chars}
						value={name}
						onChange={(e) => setName(e.target.value)}
					/>
				</Field>
				<Field
					label="Endpoint slug"
					hint="Lowercase letters, digits and hyphens."
				>
					<input
						className={inputClass}
						required
						pattern="[a-z0-9-]+"
						maxLength={limits.max_slug_chars}
						value={slug}
						onChange={(e) => setSlug(e.target.value)}
					/>
				</Field>
				<Field label="Upstream URL">
					<input
						className={inputClass}
						type="url"
						required
						maxLength={limits.max_url_bytes}
						value={url}
						onChange={(e) => setUrl(e.target.value)}
					/>
				</Field>
				<Field label="Transport">
					<select
						className={inputClass}
						value={transport}
						onChange={(e) => setTransport(e.target.value)}
					>
						<option value="streamable_http">Streamable HTTP</option>
						<option value="legacy_sse">Legacy SSE</option>
					</select>
				</Field>
				<Field label="Upstream authentication">
					<select
						className={inputClass}
						value={auth}
						onChange={(e) => setAuth(e.target.value)}
					>
						<option value="none">No credential</option>
						<option value="gateway_held">Stored credential</option>
						<option value="passthrough">Client supplies credential</option>
					</select>
				</Field>
				{auth === "gateway_held" && (
					<>
						<Field label="Credential type">
							<select
								className={inputClass}
								value={kind}
								onChange={(e) => setKind(e.target.value)}
							>
								<option value="bearer">Bearer token</option>
								<option value="header">Custom header</option>
							</select>
						</Field>
						{kind === "header" && (
							<Field label="Credential header">
								<input
									className={inputClass}
									required
									value={header}
									onChange={(e) => setHeader(e.target.value)}
								/>
							</Field>
						)}
						<Field
							label={server ? "Replacement credential" : "Credential"}
							hint={
								server?.credential_last4
									? `Stored credential ends in ${server.credential_last4}. Leave blank to keep it.`
									: undefined
							}
						>
							<input
								className={inputClass}
								type="password"
								autoComplete="new-password"
								required={!server?.credential_last4}
								value={secret}
								onChange={(e) => setSecret(e.target.value)}
							/>
						</Field>
					</>
				)}
				<div className="flex gap-2">
					<Button type="submit">Save server</Button>
					<Button type="button" variant="ghost" onClick={close}>
						Cancel
					</Button>
				</div>
			</fieldset>
			<RefusalNote error={save.error} />
		</form>
	);
}
function ServerRow({
	server,
	limits,
	allowed,
}: { server: Server; limits: Limits; allowed: boolean }) {
	const [editing, setEditing] = useState(false);
	const toggle = useControlWrite("PATCH", `mcp-servers/${server.id}`, refresh);
	const archive = useControlWrite(
		"DELETE",
		`mcp-servers/${server.id}`,
		refresh,
	);
	const test = useControlWrite<{ tools: number; tool_names: string[] }>(
		"POST",
		`mcp-servers/${server.id}/test`,
	);
	const [confirm, setConfirm] = useState(false);
	return (
		<article className="space-y-2 rounded border border-line p-3">
			<h4 className="font-medium">
				{server.name} · {server.enabled ? "Enabled" : "Disabled"}
			</h4>
			<p className="break-all text-sm">{server.url}</p>
			<p className="text-sm">
				Gateway endpoint: <code>/v1/mcp/{server.slug}</code>
			</p>
			{allowed && (
				<div className="flex flex-wrap gap-2">
					<Button
						disabled={toggle.isPending}
						onClick={() => toggle.mutate({ enabled: !server.enabled })}
					>
						{server.enabled ? "Disable" : "Enable"} {server.name}
					</Button>
					<Button onClick={() => setEditing(!editing)}>
						Edit {server.name}
					</Button>
					<Button disabled={test.isPending} onClick={() => test.mutate({})}>
						Test {server.name}
					</Button>
					<Button variant="ghost" onClick={() => setConfirm(!confirm)}>
						Archive {server.name}
					</Button>
				</div>
			)}
			{confirm && (
				<div>
					<p>Archive this server and remove its stored credential?</p>
					<Button
						disabled={archive.isPending}
						onClick={() => archive.mutate({})}
					>
						Confirm archive
					</Button>
					<Button variant="ghost" onClick={() => setConfirm(false)}>
						Cancel
					</Button>
				</div>
			)}
			{test.data && (
				<output>
					Connected · {test.data.tools} tools discovered
					{test.data.tool_names?.length > 0 && (
						<ul>
							{test.data.tool_names.map((name) => (
								<li key={name}>{name}</li>
							))}
						</ul>
					)}
				</output>
			)}
			<RefusalNote error={toggle.error ?? archive.error ?? test.error} />
			{editing && (
				<ServerForm
					server={server}
					limits={limits}
					close={() => setEditing(false)}
				/>
			)}
		</article>
	);
}
function Rules({
	view,
	servers,
	allowed,
}: { view: View; servers: Server[]; allowed: boolean }) {
	const [key, setKey] = useState("");
	const [glob, setGlob] = useState("");
	const [server, setServer] = useState("");
	const [action, setAction] = useState("deny");
	const [reason, setReason] = useState("");
	const add = useControlWrite("POST", "mcp-tool-rules", refresh);
	const remove = useControlWrite(
		"DELETE",
		(r: Rule) => `mcp-tool-rules/${r.id}`,
		refresh,
	);
	return (
		<Panel
			title="Tool rules"
			description="Deny takes precedence over approval, then allow. Matching is case-insensitive; * matches any text."
		>
			{view.rules.length === 0 ? (
				<p>No rules. The unmatched-tools policy applies.</p>
			) : (
				<ul className="space-y-2">
					{view.rules.map((r) => (
						<li key={r.id}>
							<strong>{r.tool_glob}</strong> ·{" "}
							{servers.find((s) => s.id === r.server_id)?.name ?? "All servers"}{" "}
							· {view.keys?.find((k) => k.id === r.key_id)?.name ?? "All keys"}{" "}
							· {r.action.replaceAll("_", " ")}
							{r.reason && ` · ${r.reason}`}{" "}
							{allowed && (
								<Button
									variant="ghost"
									disabled={remove.isPending}
									onClick={() => remove.mutate(r)}
								>
									Remove {r.tool_glob}
								</Button>
							)}
						</li>
					))}
				</ul>
			)}
			{allowed && (
				<form
					className="space-y-3"
					onSubmit={(e) => {
						e.preventDefault();
						add.mutate(
							{
								tool_glob: glob,
								server_id: server || null,
								key_id: key || null,
								action,
								reason,
							},
							{
								onSuccess: () => {
									setGlob("");
									setReason("");
								},
							},
						);
					}}
				>
					<fieldset disabled={add.isPending} className="space-y-3">
						<Field label="API key">
							<select
								className={inputClass}
								value={key}
								onChange={(e) => setKey(e.target.value)}
							>
								<option value="">All keys</option>
								{(view.keys ?? []).map((k) => (
									<option key={k.id} value={k.id}>
										{k.name}
									</option>
								))}
							</select>
						</Field>
						<Field label="Tool pattern">
							<input
								className={inputClass}
								required
								maxLength={view.limits.tool_glob_max_chars}
								value={glob}
								onChange={(e) => setGlob(e.target.value)}
							/>
						</Field>
						<Field label="Server">
							<select
								className={inputClass}
								value={server}
								onChange={(e) => setServer(e.target.value)}
							>
								<option value="">All servers</option>
								{servers.map((s) => (
									<option key={s.id} value={s.id}>
										{s.name}
									</option>
								))}
							</select>
						</Field>
						<Field label="Action">
							<select
								className={inputClass}
								value={action}
								onChange={(e) => setAction(e.target.value)}
							>
								<option value="deny">Deny</option>
								<option value="require_approval">Require approval</option>
								<option value="allow">Allow</option>
							</select>
						</Field>
						<Field label="Reason">
							<input
								className={inputClass}
								maxLength={view.limits.reason_max_chars}
								value={reason}
								onChange={(e) => setReason(e.target.value)}
							/>
						</Field>
						<Button type="submit">Add tool rule</Button>
					</fieldset>
				</form>
			)}
			<RefusalNote error={add.error ?? remove.error} />
		</Panel>
	);
}
function Definitions({ allowed }: { allowed: boolean }) {
	const query = useControlQuery<{ tools: Tool[] }>("mcp-tools");
	const approve = useControlWrite("POST", "mcp-tools/approve", refresh);
	const remove = useControlWrite(
		"DELETE",
		(t: Tool) => `mcp-tools/${t.server_id}/${encodeURIComponent(t.tool_name)}`,
		refresh,
	);
	return (
		<Panel
			title="Observed definitions"
			description="Pin a reviewed definition to detect later changes. Only enforce mode blocks a changed definition."
		>
			<Boundary query={query} resource="tool definitions">
				{(v) =>
					v.tools.length === 0 ? (
						<p>No definitions observed. Connect a client and list its tools.</p>
					) : (
						<ul className="space-y-3">
							{v.tools.map((t) => (
								<li key={`${t.server_id}:${t.tool_name}:${t.def_hash}`}>
									<p>
										<strong>{t.tool_name}</strong> · {t.server_name} ·{" "}
										{t.status}
									</p>
									<p className="text-sm">
										Fingerprint {t.def_hash.slice(0, 12)} · Last seen{" "}
										{new Date(t.last_seen).toISOString()}
									</p>
									{allowed &&
										(t.status === "approved" ? (
											<Button
												disabled={remove.isPending}
												onClick={() => remove.mutate(t)}
											>
												Unpin {t.tool_name}
											</Button>
										) : (
											<Button
												disabled={approve.isPending}
												onClick={() =>
													approve.mutate({
														server_id: t.server_id,
														tool_name: t.tool_name,
														def_hash: t.def_hash,
													})
												}
											>
												Approve definition of {t.tool_name}
											</Button>
										))}
								</li>
							))}
						</ul>
					)
				}
			</Boundary>
			<RefusalNote error={approve.error ?? remove.error} />
		</Panel>
	);
}
function Preview({ limits }: { limits: View["limits"] }) {
	const [hours, setHours] = useState(String(limits.preview_window_hours));
	const [since, setSince] = useState<string | null>(null);
	const query = useControlQuery<{
		since: string;
		would_block: number | null;
		stats_unavailable: boolean;
	}>(`mcp-policy/preview${since ? `?since=${encodeURIComponent(since)}` : ""}`);
	return (
		<Panel
			title="Observed policy impact"
			description="Counts come from recorded MCP calls in the selected window."
		>
			<form
				onSubmit={(e) => {
					e.preventDefault();
					setSince(
						new Date(Date.now() - Number(hours) * 60 * 60 * 1000).toISOString(),
					);
				}}
				className="flex items-end gap-2"
			>
				<Field label="Preview window (hours)">
					<input
						className={inputClass}
						type="number"
						required
						min={1}
						max={limits.preview_max_window_hours}
						value={hours}
						onChange={(e) => setHours(e.target.value)}
					/>
				</Field>
				<Button type="submit">Update preview</Button>
			</form>
			<Boundary query={query} resource="policy preview">
				{(v) =>
					v.would_block === null ? (
						<p>
							Policy preview is unavailable.{" "}
							<button
								type="button"
								className="underline"
								onClick={() => void query.refetch()}
							>
								Retry
							</button>
						</p>
					) : (
						<p>
							{v.would_block} calls would have been blocked since{" "}
							{new Date(v.since).toISOString()}.
						</p>
					)
				}
			</Boundary>
		</Panel>
	);
}
export function McpControls() {
	const read = useCan("view_policies");
	const { allowed } = useCan("manage_mcp");
	const policy = useControlQuery<View>("mcp-policy");
	const servers = useControlQuery<{ servers: Server[]; limits: Limits }>(
		"mcp-servers",
	);
	const [adding, setAdding] = useState(false);
	if (!read.allowed)
		return (
			<Panel title="MCP servers" description="Remote tool connections">
				<p role="alert">
					Only workspace owners and admins can view MCP server settings.
				</p>
			</Panel>
		);
	return (
		<div className="space-y-5">
			<Boundary query={servers} resource="MCP servers">
				{(v) => (
					<>
						<Panel
							title="MCP servers"
							description="Connect remote tools through the gateway. Clients need an API key explicitly scoped for MCP."
						>
							{v.servers.length === 0 && (
								<p>No servers connected. Add an upstream server to begin.</p>
							)}
							{v.servers.map((s) => (
								<ServerRow
									key={s.id}
									server={s}
									limits={v.limits}
									allowed={allowed}
								/>
							))}
							{allowed && !adding && (
								<Button
									disabled={
										v.servers.length >= v.limits.max_servers_per_workspace
									}
									onClick={() => setAdding(true)}
								>
									Add server
								</Button>
							)}
							{adding && (
								<ServerForm limits={v.limits} close={() => setAdding(false)} />
							)}
						</Panel>
						<Boundary query={policy} resource="MCP policy">
							{(p) => (
								<>
									<Preview limits={p.limits} />
									<PolicyForm view={p} allowed={allowed} />
									<Rules view={p} servers={v.servers} allowed={allowed} />
								</>
							)}
						</Boundary>
					</>
				)}
			</Boundary>
			<Definitions allowed={allowed} />
		</div>
	);
}
