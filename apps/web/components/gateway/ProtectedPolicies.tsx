"use client";

/**
 * Protected tools: the active protected-tool policies (`GET /v1/action-policies`) and the
 * publish step for a policy file (`POST /v1/action-policies`, admin, signed-in session).
 * Policies are files in v0 (BRD §1), so this uploads a document; it does not author one.
 * Every rule is enforced by the gateway; the browser only checks the file is JSON.
 */
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
	type ControlError,
	RawJson,
	useCan,
	useControlQuery,
	useControlWrite,
} from "./control";
import { EmptyNote, Panel, WhyDisabled, monoInput } from "./fields";

export interface ActivePolicy {
	tool_ref: string;
	server_id: string;
	tool_name: string;
	contract_version: number;
	policy_id: string;
	policy_version: number;
	policy_hash: string;
	contract_hash: string;
	publisher_sub: string;
}

interface PublishResult {
	tool_ref: string;
	policy_id: string;
	policy_version: number;
	policy_hash: string;
	contract_hash: string;
	warnings?: string[];
}

const WARNING_TEXT: Record<string, string> = {
	principal_issuer_missing:
		"This policy asks for a verified user, but no identity issuer is registered for the workspace yet, so matching calls will be refused until one is.",
};

/** Plain words for the publish refusals the gateway names (spec ACT-12 §2). */
export function publishRefusalText(err: ControlError): string {
	switch (err.refusal.code) {
		case "action_control_disabled":
			return "Action control is not turned on for this workspace.";
		case "contract_invalid":
			return "The file's tool contract is not valid.";
		case "policy_invalid":
			return "The file's approval policy is not valid for that contract.";
		case "policy_version_must_increase":
			return "A policy with this version or a later one is already active. Raise the version and publish again.";
		case "policy_conflict":
			return "That policy id is already used. Give this policy a new id.";
		case "mcp_server_not_found":
			return "The MCP server named in the contract is not registered in this workspace.";
		case "invalid_policy_request":
			return "The file must be a JSON object with a contract and a policy.";
		default:
			return err.refusal.message;
	}
}

/** A document is publishable when it parses to an object holding `contract` and `policy`. */
export function parseDocument(text: string): Record<string, unknown> | string {
	let doc: unknown;
	try {
		doc = JSON.parse(text);
	} catch {
		return "The file is not valid JSON.";
	}
	if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
		return "The file must be a JSON object with a contract and a policy.";
	}
	const o = doc as Record<string, unknown>;
	if (typeof o.contract !== "object" || o.contract === null) {
		return "The file has no contract.";
	}
	if (typeof o.policy !== "object" || o.policy === null) {
		return "The file has no policy.";
	}
	return o;
}

/** What the confirm dialog names: tool, policy id and version, when the file states them. */
export function describeDocument(doc: Record<string, unknown>): string {
	const c = doc.contract as Record<string, unknown>;
	const p = doc.policy as Record<string, unknown>;
	const v = (x: unknown) =>
		typeof x === "string" || typeof x === "number" ? String(x) : "not stated";
	return `tool ${v(c.tool_name)} · policy ${v(p.policy_id)} · version ${v(p.version)}`;
}

export interface DiscoveredTool {
	server_id: string;
	server_name: string;
	tool_name: string;
}

/**
 * A starting file for a discovered tool: every call needs a human approval. The ids are
 * new random UUIDs (a contract's `tool_ref` and a policy's `policy_id` are chosen by the
 * publisher); the TTL is the workspace's approval default (`GET /v1/approvals/settings`),
 * passed in rather than repeated here; the picker waits for it. The owner edits it before
 * publishing; the gateway validates every field.
 */
export function templateFor(
	tool: DiscoveredTool,
	ttlSecs: number,
	active?: ActivePolicy,
): string {
	// A tool that already has an active policy keeps its contract identity and policy id;
	// only the policy version moves (a new tool_ref would be refused as a different contract).
	return JSON.stringify(
		{
			contract: {
				tool_ref: active?.tool_ref ?? crypto.randomUUID(),
				server_id: tool.server_id,
				tool_name: tool.tool_name,
				version: active?.contract_version ?? 1,
				protected: true,
				fields: {},
			},
			policy: {
				policy_id: active?.policy_id ?? crypto.randomUUID(),
				version: (active?.policy_version ?? 0) + 1,
				approval_ttl_secs: ttlSecs,
				agents: null,
				rules: [
					{ id: "approve_every_call", when: [], decision: "require_approval" },
				],
			},
		},
		null,
		2,
	);
}

const short = (h: string) => (h.length > 12 ? `${h.slice(0, 12)}…` : h);

export function ProtectedPolicies() {
	const query = useControlQuery<{ policies: ActivePolicy[] }>(
		"action-policies",
	);
	const tools = useControlQuery<{ tools: DiscoveredTool[] }>("mcp-tools");
	const ttl = useControlQuery<{ settings: { default_ttl_secs: number } }>(
		"approvals/settings",
	);
	const ttlSecs = ttl.data?.settings.default_ttl_secs;
	const can = useCan("edit_policies");
	const publish = useControlWrite<PublishResult, RawJson>(
		"POST",
		"action-policies",
		["action-policies"],
	);
	const [text, setText] = useState("");
	const [localError, setLocalError] = useState<string | null>(null);
	/** The exact text the user chose and what the dialog names; the text is sent verbatim. */
	const [confirming, setConfirming] = useState<{
		text: string;
		summary: string;
	} | null>(null);

	const onFile = async (file: File | undefined) => {
		if (!file) return;
		setText(await file.text());
		setLocalError(null);
		publish.reset();
	};

	const review = () => {
		const parsed = parseDocument(text);
		if (typeof parsed === "string") {
			setLocalError(parsed);
			return;
		}
		setLocalError(null);
		setConfirming({ text, summary: describeDocument(parsed) });
	};

	return (
		<div className="space-y-6">
			<Panel
				id="protected-tools"
				title="Active protected-tool policies"
				description="A protected tool runs only under its published policy: the gateway checks the exact call against the contract, asks for approval where the policy says so, and records signed evidence before the call runs. Published policies cannot be edited; publish a higher version to change one."
			>
				<Boundary query={query} resource="protected-tool policies" rows={2}>
					{({ policies }) =>
						policies.length === 0 ? (
							<EmptyNote>
								No protected-tool policies are active. Publish a policy file
								below to protect a tool.
							</EmptyNote>
						) : (
							<Table>
								<THead>
									<TR>
										<TH>Tool</TH>
										<TH>Policy</TH>
										<TH>Contract</TH>
										<TH>Published by</TH>
									</TR>
								</THead>
								<TBody>
									{policies.map((p) => (
										<TR key={p.tool_ref}>
											<TD className="font-mono text-sm">{p.tool_name}</TD>
											<TD>
												<Badge>v{p.policy_version}</Badge>{" "}
												<span
													className="font-mono text-xs text-ink-3"
													title={p.policy_hash}
												>
													{short(p.policy_hash)}
												</span>
											</TD>
											<TD>
												<span className="text-sm">v{p.contract_version}</span>{" "}
												<span
													className="font-mono text-xs text-ink-3"
													title={p.contract_hash}
												>
													{short(p.contract_hash)}
												</span>
											</TD>
											<TD className="text-sm text-ink-2">{p.publisher_sub}</TD>
										</TR>
									))}
								</TBody>
							</Table>
						)
					}
				</Boundary>
			</Panel>

			<Panel
				id="protected-tools-publish"
				title="Publish a policy file"
				description="Upload or paste a JSON file holding a tool contract and its approval policy. Publishing needs an owner or admin signed in to the dashboard; API keys cannot publish."
			>
				<div className="space-y-3">
					{ttlSecs !== undefined && (tools.data?.tools.length ?? 0) > 0 ? (
						<select
							aria-label="Start from a discovered tool"
							disabled={!can.allowed}
							defaultValue=""
							onChange={(e) => {
								const t = tools.data?.tools.find(
									(x) => `${x.server_id}/${x.tool_name}` === e.target.value,
								);
								if (!t) return;
								setText(
									templateFor(
										t,
										ttlSecs,
										query.data?.policies.find(
											(p) =>
												p.server_id === t.server_id &&
												p.tool_name === t.tool_name,
										),
									),
								);
								setLocalError(null);
								publish.reset();
							}}
							className={`${monoInput} w-full`}
						>
							<option value="" disabled>
								Start from a discovered tool…
							</option>
							{tools.data?.tools.map((t) => (
								<option
									key={`${t.server_id}/${t.tool_name}`}
									value={`${t.server_id}/${t.tool_name}`}
								>
									{t.server_name} · {t.tool_name}
								</option>
							))}
						</select>
					) : null}
					<input
						type="file"
						accept="application/json,.json"
						aria-label="Policy file"
						disabled={!can.allowed}
						onChange={(e) => void onFile(e.target.files?.[0])}
						className="block text-sm"
					/>
					<textarea
						aria-label="Policy document"
						value={text}
						disabled={!can.allowed}
						onChange={(e) => {
							setText(e.target.value);
							setLocalError(null);
						}}
						rows={8}
						placeholder='{ "contract": { … }, "policy": { … } }'
						className={`${monoInput} w-full`}
					/>
					<WhyDisabled reason={can.reason} />
					{localError ? (
						<p role="alert" className="text-sm text-danger-ink">
							{localError}
						</p>
					) : null}
					{publish.isError ? (
						<p role="alert" className="text-sm text-danger-ink">
							{publishRefusalText(publish.error)}
						</p>
					) : null}
					{publish.isSuccess ? (
						<output className="block space-y-1 rounded-control bg-surface-2 px-3 py-2 text-sm">
							<p>Published policy version {publish.data.policy_version}.</p>
							<p className="font-mono text-xs text-ink-3">
								policy {publish.data.policy_hash} · contract{" "}
								{publish.data.contract_hash}
							</p>
							{(publish.data.warnings ?? []).map((w) => (
								<p key={w} className="text-warn-ink">
									{WARNING_TEXT[w] ?? w}
								</p>
							))}
						</output>
					) : null}
					<Button
						disabled={!can.allowed || text.trim() === "" || publish.isPending}
						onClick={review}
					>
						Publish policy
					</Button>
				</div>
				<ConfirmDialog
					open={confirming !== null}
					title="Publish this policy?"
					confirmLabel="Publish"
					busy={publish.isPending}
					onConfirm={() => {
						if (confirming) publish.mutate(new RawJson(confirming.text));
						setConfirming(null);
					}}
					onClose={() => setConfirming(null)}
				>
					<p className="font-mono text-sm">{confirming?.summary}</p>
					<p className="mt-2">
						Publishing is recorded in the audit log and cannot be undone. A
						later version replaces it.
					</p>
				</ConfirmDialog>
			</Panel>
		</div>
	);
}
