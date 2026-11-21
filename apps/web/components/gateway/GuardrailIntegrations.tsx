"use client";
/**
 * Gateway › Guardrail integrations — workspace guardrail hooks and their fixed vendor
 * adapters (`GET /v1/guardrails/hooks`, `PUT|DELETE /v1/guardrails/hooks/{id}`).
 *
 * A key or signing secret is write-only: it is sent once in the PUT body and never read
 * back, rendered or logged. The list shows only that a key is stored. Bounds come from the
 * reference table (`plans.v3.json` `policy.guardrail_hooks`), never literals.
 */

import { formatDateTimeUtc } from "@/lib/format-date";
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
import { useRef, useState } from "react";
import plans from "../../db/plans.v3.json";
import {
	Boundary,
	type ControlError,
	useCan,
	useControlQuery,
	useControlWrite,
} from "./control";
import { EmptyNote, Field, Panel, WhyDisabled, inputClass } from "./fields";

const LIMITS = plans.policy.guardrail_hooks;

export type Kind =
	| "lakera"
	| "openai_moderation"
	| "azure_content_safety"
	| "azure_prompt_shields"
	| "bedrock_guardrails"
	| "google_model_armor"
	| "presidio"
	| "custom";

type Category = "Hate" | "SelfHarm" | "Sexual" | "Violence";
const CATEGORIES: { key: Category; label: string }[] = [
	{ key: "Hate", label: "Hate" },
	{ key: "SelfHarm", label: "Self-harm" },
	{ key: "Sexual", label: "Sexual" },
	{ key: "Violence", label: "Violence" },
];

/** What the customer picks, what each needs, and where it sends text. */
const KINDS: Record<
	Kind,
	{
		label: string;
		note: string;
		fixed?: string;
		azure?: boolean;
		preOnly?: boolean;
		/** The gateway refuses fail-open for this kind: the control is fixed to block. */
		closedOnly?: boolean;
		/** The key is multi-line (a JSON key file), so it gets a text area. */
		multiline?: boolean;
		keyLabel: string;
	}
> = {
	lakera: {
		label: "Lakera Guard",
		note: "Prompt attack and content screening with your Lakera key.",
		fixed: "https://api.lakera.ai/v2/guard",
		keyLabel: "API key",
	},
	openai_moderation: {
		label: "OpenAI Moderation",
		note: "Harmful-content screening with your OpenAI key (omni-moderation-latest).",
		fixed: "https://api.openai.com/v1/moderations",
		keyLabel: "API key",
	},
	azure_content_safety: {
		label: "Azure Content Safety",
		note: "Hate, self-harm, sexual and violence severity with your Azure AI Content Safety resource.",
		azure: true,
		keyLabel: "API key",
	},
	azure_prompt_shields: {
		label: "Azure Prompt Shields",
		note: "Prompt attack and jailbreak detection with your Azure AI Content Safety resource. Runs before the model only.",
		azure: true,
		preOnly: true,
		keyLabel: "API key",
	},
	bedrock_guardrails: {
		label: "AWS Bedrock Guardrails",
		note: "A guardrail you configured in Amazon Bedrock, called with your own long-term AWS access key. Temporary credentials are not supported.",
		keyLabel: "Access key (ID:secret)",
	},
	google_model_armor: {
		label: "Google Cloud Model Armor",
		note: "A Model Armor template in your Google Cloud project, called with a service-account key. Use a service account that has only the Model Armor user role.",
		multiline: true,
		keyLabel: "Service-account key (JSON)",
	},
	presidio: {
		label: "Microsoft Presidio (self-hosted)",
		note: "Screened by your own Presidio analyzer over HTTPS; no other vendor sees the text. Matches are replaced with a redaction marker before the model or your users see them, or the request is refused.",
		closedOnly: true,
		keyLabel: "Bearer token for your proxy",
	},
	custom: {
		label: "Your own endpoint",
		note: "Tracelane sends each request to your HTTPS endpoint, signed with your secret, and follows its allow, deny or redact answer.",
		keyLabel: "Signing secret",
	},
};

export interface HookForm {
	kind: Kind;
	resource: string;
	endpoint: string;
	key: string;
	thresholds: Record<Category, number>;
	pre: boolean;
	post: boolean;
	timeout: string;
	failMode: "closed" | "open";
	region: string;
	guardrailId: string;
	guardrailVersion: string;
	project: string;
	location: string;
	template: string;
	language: string;
	entities: string;
	threshold: string;
	action: "redact" | "block";
}

export const emptyForm: HookForm = {
	kind: "lakera",
	resource: "",
	endpoint: "",
	key: "",
	thresholds: { Hate: 4, SelfHarm: 4, Sexual: 4, Violence: 4 },
	pre: true,
	post: false,
	timeout: "2000",
	failMode: "closed",
	region: "",
	guardrailId: "",
	guardrailVersion: "1",
	project: "",
	location: "",
	template: "",
	language: "en",
	entities: "PERSON, LOCATION, PHONE_NUMBER",
	threshold: "0.6",
	action: "redact",
};

/** One DNS label, as the gateway's Azure destination check requires. */
const AZURE_RESOURCE = /^[a-z0-9][a-z0-9-]{1,62}$/;
/** Each mirrors the gateway's own check in `crates/gateway/src/guardrail/adapters.rs`. */
const AWS_REGION = /^[a-z]{2}(-gov)?-[a-z]+-\d$/;
const BEDROCK_ID = /^[a-z0-9]{1,64}$/;
const BEDROCK_VERSION = /^(DRAFT|\d{1,8})$/;
const AWS_KEY = /^[A-Z0-9]{16,128}:[!-9;-~]{1,128}$/;
const GCP_PROJECT = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const GCP_LOCATION = /^[a-z]+-[a-z]+\d+$/;
const GCP_TEMPLATE = /^[A-Za-z0-9_-]{1,63}$/;
const GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token";
const ENTITY = /^[A-Z_]{2,48}$/;

/** The plain https URL rule shared by customer-hosted destinations. */
function plainHttps(raw: string, allowPort: boolean): URL | null {
	let url: URL;
	try {
		url = new URL(raw.trim());
	} catch {
		return null;
	}
	return url.protocol !== "https:" ||
		url.username ||
		url.password ||
		url.search ||
		url.hash ||
		(!allowPort && url.port)
		? null
		: url;
}

/** A Google service-account key the gateway will accept (token_uri pinned to Google). */
function serviceAccountOk(key: string): boolean {
	try {
		const sa = JSON.parse(key) as Record<string, unknown>;
		const filled = (v: unknown) => typeof v === "string" && v.length > 0;
		return (
			filled(sa.client_email) &&
			filled(sa.private_key) &&
			filled(sa.project_id) &&
			(sa.token_uri === undefined || sa.token_uri === GOOGLE_TOKEN_URI)
		);
	} catch {
		return false;
	}
}
const utf8 = new TextEncoder();

/** The PUT the gateway takes, or why the form cannot be sent. */
export function buildHookUpload(form: HookForm):
	| {
			id: string;
			body: { config: Record<string, unknown>; [k: string]: unknown };
	  }
	| { error: string } {
	const spec = KINDS[form.kind];
	// A signing secret is used byte for byte in the HMAC: never trim it silently.
	const key = form.kind === "custom" ? form.key : form.key.trim();
	if (!key.trim())
		return { error: `Enter the ${spec.keyLabel.toLowerCase()}.` };
	if (form.kind === "custom" && key !== key.trim())
		return {
			error:
				"The signing secret starts or ends with a space. Remove it, or it will not match your endpoint.",
		};
	if (utf8.encode(key).length > LIMITS.secret_bytes)
		return { error: `The ${spec.keyLabel.toLowerCase()} is too long.` };
	const pre = form.pre;
	const post = spec.preOnly ? false : form.post;
	if (!pre && !post)
		return {
			error: spec.preOnly
				? "This integration runs before the model only; keep that selected."
				: "Choose when it runs: before the model, after the response, or both.",
		};
	const timeout = Number(form.timeout);
	if (
		!/^\d+$/.test(form.timeout.trim()) ||
		timeout < 1 ||
		timeout > LIMITS.timeout_ms
	)
		return {
			error: `Timeout must be a whole number from 1 to ${LIMITS.timeout_ms} ms.`,
		};
	let endpoint: string;
	let adapter: Record<string, unknown> | undefined = { kind: form.kind };
	if (spec.fixed) endpoint = spec.fixed;
	else if (spec.azure) {
		const resource = form.resource.trim();
		if (!AZURE_RESOURCE.test(resource))
			return {
				error:
					"Enter the Azure resource name: lowercase letters, digits and hyphens, as in <name>.cognitiveservices.azure.com.",
			};
		endpoint = `https://${resource}.cognitiveservices.azure.com`;
		if (form.kind === "azure_content_safety")
			adapter = { kind: form.kind, thresholds: { ...form.thresholds } };
	} else if (form.kind === "bedrock_guardrails") {
		const region = form.region.trim();
		const id = form.guardrailId.trim();
		const version = form.guardrailVersion.trim();
		if (!AWS_REGION.test(region))
			return { error: "Enter the AWS region, such as eu-central-1." };
		if (!BEDROCK_ID.test(id))
			return {
				error: "Enter the guardrail ID: lowercase letters and digits.",
			};
		if (!BEDROCK_VERSION.test(version))
			return { error: "Enter the guardrail version: a number or DRAFT." };
		if (!AWS_KEY.test(key) || key.startsWith("ASIA"))
			return {
				error:
					"Enter a long-term access key as <access key ID>:<secret access key>. Temporary (ASIA…) keys and session tokens are not supported.",
			};
		endpoint = `https://bedrock-runtime.${region}.amazonaws.com`;
		adapter = {
			kind: form.kind,
			region,
			guardrail_id: id,
			guardrail_version: version,
		};
	} else if (form.kind === "google_model_armor") {
		const project = form.project.trim();
		const location = form.location.trim();
		const template = form.template.trim();
		if (!GCP_PROJECT.test(project))
			return { error: "Enter the Google Cloud project ID." };
		if (!GCP_LOCATION.test(location))
			return {
				error: "Enter the Model Armor location, such as europe-west4.",
			};
		if (!GCP_TEMPLATE.test(template))
			return {
				error:
					"Enter the template ID: letters, digits, hyphens and underscores.",
			};
		if (!serviceAccountOk(key))
			return {
				error:
					"Paste the service-account key file as downloaded from Google Cloud (JSON).",
			};
		endpoint = `https://modelarmor.${location}.rep.googleapis.com`;
		adapter = { kind: form.kind, project, location, template };
	} else if (form.kind === "presidio") {
		const url = plainHttps(form.endpoint, false);
		if (!url)
			return {
				error:
					"The analyzer URL must be https on the standard port, with no user, query or fragment.",
			};
		const language = form.language.trim();
		if (!/^[a-z]{2}$/.test(language))
			return { error: "Enter a two-letter language code, such as en." };
		const entities = form.entities
			.split(",")
			.map((e) => e.trim().toUpperCase())
			.filter(Boolean);
		if (
			entities.length < 1 ||
			entities.length > 32 ||
			new Set(entities).size !== entities.length ||
			!entities.every((e) => ENTITY.test(e))
		)
			return {
				error:
					"List 1 to 32 distinct entity types, such as PERSON, LOCATION, PHONE_NUMBER.",
			};
		const threshold = Number(form.threshold.trim());
		if (
			form.threshold.trim() === "" ||
			!Number.isFinite(threshold) ||
			threshold < 0 ||
			threshold > 1
		)
			return { error: "The score threshold must be between 0 and 1." };
		if (utf8.encode(key).length < LIMITS.min_secret_bytes)
			return {
				error: `The bearer token must be at least ${LIMITS.min_secret_bytes} bytes.`,
			};
		endpoint = url.toString();
		adapter = {
			kind: form.kind,
			language,
			entities,
			score_threshold: threshold,
			action: form.action,
		};
	} else {
		const url = plainHttps(form.endpoint, true);
		if (!url)
			return {
				error: "The endpoint must be https, with no user, query or fragment.",
			};
		if (utf8.encode(key).length < LIMITS.min_secret_bytes)
			return {
				error: `The signing secret must be at least ${LIMITS.min_secret_bytes} bytes.`,
			};
		endpoint = url.toString();
		adapter = undefined;
	}
	const config: Record<string, unknown> = {
		endpoint,
		...(adapter ? { adapter } : {}),
		pre,
		post,
		timeout_ms: timeout,
		fail_mode: spec.closedOnly ? "closed" : form.failMode,
	};
	return {
		id: crypto.randomUUID(),
		body:
			form.kind === "custom"
				? { config, signing_secret: key }
				: { config, api_key: key },
	};
}

interface HookRow {
	id: string;
	config: {
		endpoint: string;
		adapter?: { kind: Kind };
		pre: boolean;
		post: boolean;
		timeout_ms: number;
		fail_mode?: "closed" | "open";
	};
	updated_at: string;
	credential_configured: boolean;
}

/** Host, plus path for a customer endpoint: never a query, never a credential. */
function destination(row: HookRow): string {
	try {
		const url = new URL(row.config.endpoint);
		const ownHost =
			!row.config.adapter || row.config.adapter.kind === "presidio";
		const path = !ownHost || url.pathname === "/" ? "" : url.pathname;
		return `${url.host}${path}`;
	} catch {
		return "unreadable destination";
	}
}

function runs(row: HookRow): string {
	const { pre, post } = row.config;
	if (pre && post) return "Before the model, after the response";
	return pre ? "Before the model" : "After the response";
}

/** The gateway's refusal codes, in words. Never echoes the submitted key. */
function refusalText(error: ControlError | null): string | null {
	if (!error) return null;
	switch (error.refusal.code) {
		case "invalid_hook":
			return "The gateway refused these settings. Check the destination, timeout and when it runs.";
		case "invalid_hook_destination":
			return "The destination could not be reached safely (it must be public HTTPS). Check the address.";
		case "invalid_hook_credential":
			return "The key or secret was refused. Check its length and characters.";
		case "hook_limit_reached":
			return `This workspace already has the limit of ${LIMITS.max_hooks} integrations. Remove one first.`;
		case "hooks_unavailable":
		case "hook_write_failed":
			return "Integrations are unavailable right now. Reload the list before trying again: the change may or may not have been saved.";
		default:
			return error.refusal.message;
	}
}

function AddIntegration({
	allowed,
	full,
	savedIds,
}: {
	allowed: boolean;
	full: boolean;
	savedIds: string[];
}) {
	const [form, setForm] = useState<HookForm>(emptyForm);
	const [error, setError] = useState<string | null>(null);
	// The id rides in the path only (the gateway refuses unknown body fields). It is
	// minted once per form and kept until a save succeeds, so a retry after an unclear
	// failure upserts the same integration instead of creating a second one.
	const target = useRef(crypto.randomUUID());
	// An unclear failure that in fact saved: the id is now a listed integration, so a
	// further add must not silently replace it.
	if (savedIds.includes(target.current)) target.current = crypto.randomUUID();
	const save = useControlWrite<unknown, Record<string, unknown>>(
		"PUT",
		() => `guardrails/hooks/${target.current}`,
		["guardrails/hooks"],
	);
	const spec = KINDS[form.kind];
	const set = (change: Partial<HookForm>) =>
		setForm((f) => ({ ...f, ...change }));
	const disabled = !allowed || full || save.isPending;
	return (
		<div className="space-y-3">
			<div className="grid gap-3 sm:grid-cols-2">
				<Field label="Integration" hint={spec.note}>
					<select
						className={inputClass}
						disabled={disabled}
						value={form.kind}
						onChange={(e) =>
							set({ kind: e.target.value as Kind, post: false, key: "" })
						}
					>
						{(Object.keys(KINDS) as Kind[]).map((k) => (
							<option key={k} value={k}>
								{KINDS[k].label}
							</option>
						))}
					</select>
				</Field>
				{spec.azure ? (
					<Field
						label="Azure resource name"
						hint="The <name> in https://<name>.cognitiveservices.azure.com."
					>
						<input
							className={inputClass}
							disabled={disabled}
							value={form.resource}
							onChange={(e) => set({ resource: e.target.value })}
						/>
					</Field>
				) : null}
				{form.kind === "custom" ? (
					<Field label="Endpoint URL" hint="https only.">
						<input
							className={inputClass}
							disabled={disabled}
							value={form.endpoint}
							onChange={(e) => set({ endpoint: e.target.value })}
						/>
					</Field>
				) : null}
				{form.kind === "bedrock_guardrails" ? (
					<>
						<Field label="Region" hint="Such as eu-central-1.">
							<input
								className={inputClass}
								disabled={disabled}
								value={form.region}
								onChange={(e) => set({ region: e.target.value })}
							/>
						</Field>
						<Field label="Guardrail ID">
							<input
								className={inputClass}
								disabled={disabled}
								value={form.guardrailId}
								onChange={(e) => set({ guardrailId: e.target.value })}
							/>
						</Field>
						<Field label="Guardrail version" hint="A number, or DRAFT.">
							<input
								className={inputClass}
								disabled={disabled}
								value={form.guardrailVersion}
								onChange={(e) => set({ guardrailVersion: e.target.value })}
							/>
						</Field>
					</>
				) : null}
				{form.kind === "google_model_armor" ? (
					<>
						<Field
							label="Project"
							hint="The Google Cloud project ID that holds the template."
						>
							<input
								className={inputClass}
								disabled={disabled}
								value={form.project}
								onChange={(e) => set({ project: e.target.value })}
							/>
						</Field>
						<Field label="Location" hint="Such as europe-west4.">
							<input
								className={inputClass}
								disabled={disabled}
								value={form.location}
								onChange={(e) => set({ location: e.target.value })}
							/>
						</Field>
						<Field label="Template">
							<input
								className={inputClass}
								disabled={disabled}
								value={form.template}
								onChange={(e) => set({ template: e.target.value })}
							/>
						</Field>
					</>
				) : null}
				{form.kind === "presidio" ? (
					<>
						<Field
							label="Analyzer URL"
							hint="Your Presidio /analyze endpoint, https on the standard port."
						>
							<input
								className={inputClass}
								disabled={disabled}
								value={form.endpoint}
								onChange={(e) => set({ endpoint: e.target.value })}
							/>
						</Field>
						<Field label="Language" hint="Two letters, such as en.">
							<input
								className={inputClass}
								disabled={disabled}
								value={form.language}
								onChange={(e) => set({ language: e.target.value })}
							/>
						</Field>
						<Field
							label="Entity types"
							hint="Comma-separated, such as PERSON, LOCATION, PHONE_NUMBER."
						>
							<input
								className={inputClass}
								disabled={disabled}
								value={form.entities}
								onChange={(e) => set({ entities: e.target.value })}
							/>
						</Field>
						<Field
							label="Score threshold"
							hint="0 to 1. Lower finds more, with more false matches."
						>
							<input
								className={inputClass}
								disabled={disabled}
								value={form.threshold}
								onChange={(e) => set({ threshold: e.target.value })}
							/>
						</Field>
						<Field label="On a match">
							<select
								className={inputClass}
								disabled={disabled}
								value={form.action}
								onChange={(e) =>
									set({ action: e.target.value as "redact" | "block" })
								}
							>
								<option value="redact">
									Replace it with a redaction marker (not reversed)
								</option>
								<option value="block">Refuse the request</option>
							</select>
						</Field>
					</>
				) : null}
				<Field
					label={spec.keyLabel}
					hint="Stored encrypted and never shown again."
				>
					{spec.multiline ? (
						<textarea
							className={`${inputClass} font-mono`}
							rows={4}
							autoComplete="off"
							spellCheck={false}
							disabled={disabled}
							value={form.key}
							onChange={(e) => set({ key: e.target.value })}
						/>
					) : (
						<input
							className={inputClass}
							type="password"
							autoComplete="off"
							disabled={disabled}
							value={form.key}
							onChange={(e) => set({ key: e.target.value })}
						/>
					)}
				</Field>
				<Field label="Timeout (ms)" hint={`1 to ${LIMITS.timeout_ms}.`}>
					<input
						className={inputClass}
						inputMode="numeric"
						disabled={disabled}
						value={form.timeout}
						onChange={(e) => set({ timeout: e.target.value })}
					/>
				</Field>
				<Field
					label="If the integration fails or times out"
					hint={
						spec.closedOnly
							? "Fixed: personal-data screening always blocks when it cannot finish, so oversized or slow input cannot skip it."
							: "Timeouts, overload and error responses follow this setting: for your own endpoint any non-2xx answer, for a vendor 5xx, 408 and 429. A vendor's refusal (other 4xx) and an unreadable verdict always block."
					}
				>
					<select
						className={inputClass}
						disabled={disabled || spec.closedOnly}
						value={spec.closedOnly ? "closed" : form.failMode}
						onChange={(e) =>
							set({ failMode: e.target.value as "closed" | "open" })
						}
					>
						<option value="closed">Block the request</option>
						<option value="open">
							Allow the request and record that it was not screened
						</option>
					</select>
				</Field>
				<div className="space-y-2 text-sm">
					<span className="flex items-center gap-2">
						<input
							type="checkbox"
							disabled={disabled}
							checked={form.pre}
							onChange={(e) => set({ pre: e.target.checked })}
						/>
						Before the model
					</span>
					<span className="flex items-center gap-2">
						<input
							type="checkbox"
							disabled={disabled || spec.preOnly}
							checked={spec.preOnly ? false : form.post}
							onChange={(e) => set({ post: e.target.checked })}
						/>
						After the response
						{spec.preOnly ? (
							<span className="text-xs text-ink-3">
								(not available for this integration)
							</span>
						) : null}
					</span>
				</div>
			</div>
			{form.kind === "azure_content_safety" ? (
				<div className="grid gap-3 sm:grid-cols-4">
					{CATEGORIES.map((c) => (
						<Field
							key={c.key}
							label={`${c.label}: block at this severity or higher (0 blocks everything)`}
						>
							<select
								className={inputClass}
								disabled={disabled}
								value={form.thresholds[c.key]}
								onChange={(e) =>
									set({
										thresholds: {
											...form.thresholds,
											[c.key]: Number(e.target.value),
										},
									})
								}
							>
								{[0, 1, 2, 3, 4, 5, 6, 7].map((n) => (
									<option key={n} value={n}>
										{n}
									</option>
								))}
							</select>
						</Field>
					))}
				</div>
			) : null}
			{error || save.error ? (
				<p role="alert" className="text-sm text-danger-ink">
					{error ?? refusalText(save.error)}
				</p>
			) : null}
			<Button
				variant="primary"
				size="sm"
				disabled={disabled}
				onClick={() => {
					const built = buildHookUpload(form);
					if ("error" in built) {
						setError(built.error);
						return;
					}
					setError(null);
					save.mutate(built.body, {
						onSuccess: () => {
							setForm({ ...emptyForm, kind: form.kind });
							target.current = crypto.randomUUID();
							// Drop the submitted key from the mutation cache.
							save.reset();
						},
					});
				}}
			>
				{save.isPending ? "Adding…" : "Add integration"}
			</Button>
		</div>
	);
}

function HookRowView({ row, allowed }: { row: HookRow; allowed: boolean }) {
	const [confirm, setConfirm] = useState(false);
	const label =
		KINDS[row.config.adapter?.kind ?? "custom"]?.label ?? "Integration";
	const del = useControlWrite<void, void>(
		"DELETE",
		`guardrails/hooks/${row.id}`,
		["guardrails/hooks"],
	);
	return (
		<TR>
			<TD>{label}</TD>
			<TD mono className="break-all">
				{destination(row)}
			</TD>
			<TD>{runs(row)}</TD>
			<TD>
				<Badge tone={row.config.fail_mode === "open" ? "neutral" : "ok"}>
					{row.config.fail_mode === "open" ? "Allow" : "Block"}
				</Badge>
			</TD>
			<TD numeric>{row.config.timeout_ms} ms</TD>
			<TD>{formatDateTimeUtc(row.updated_at)}</TD>
			<TD>
				<Button
					size="sm"
					disabled={!allowed}
					aria-label={`Remove ${label}`}
					onClick={() => setConfirm(true)}
				>
					Remove
				</Button>
				<ConfirmDialog
					open={confirm}
					onClose={() => setConfirm(false)}
					title={`Remove ${label}?`}
					confirmLabel="Remove integration"
					busy={del.isPending}
					error={del.error ? refusalText(del.error) : null}
					onConfirm={() =>
						del.mutate(undefined, { onSuccess: () => setConfirm(false) })
					}
				>
					<p className="text-sm text-ink-2">
						Requests stop going to this integration. Its stored key is deleted.
						Built-in rails keep running.
					</p>
				</ConfirmDialog>
			</TD>
		</TR>
	);
}

export function GuardrailIntegrations() {
	const q = useControlQuery<{ hooks: HookRow[] }>("guardrails/hooks");
	const { allowed, reason } = useCan("edit_policies");
	return (
		<Boundary query={q} resource="Guardrail integrations" rows={2}>
			{({ hooks }) => {
				const full = hooks.length >= LIMITS.max_hooks;
				return (
					<div className="space-y-6">
						<Panel
							id="guardrail-integrations"
							title="Guardrail integrations"
							note="Add a guardrail you already use, with your own account and key, or your own HTTPS endpoint. Tracelane sends request text to it, and response text when After the response is on, and follows its answer."
						>
							<p className="text-sm text-ink-3">
								{hooks.length} of {LIMITS.max_hooks} connected
							</p>
							{hooks.length === 0 ? (
								<EmptyNote>
									No guardrail integrations. Built-in rails still run.
								</EmptyNote>
							) : (
								<div className="overflow-x-auto">
									<Table className="w-full text-left text-sm">
										<THead>
											<TR>
												<TH>Integration</TH>
												<TH>Destination</TH>
												<TH>Runs</TH>
												<TH>If it fails</TH>
												<TH numeric>Timeout</TH>
												<TH>Updated (UTC)</TH>
												<TH>Actions</TH>
											</TR>
										</THead>
										<TBody>
											{hooks.map((row) => (
												<HookRowView key={row.id} row={row} allowed={allowed} />
											))}
										</TBody>
									</Table>
								</div>
							)}
							<WhyDisabled reason={reason} />
						</Panel>
						<Panel
							id="guardrail-integrations-add"
							title="Add an integration"
							note={
								full
									? `This workspace has reached its limit of ${LIMITS.max_hooks} integrations.`
									: undefined
							}
						>
							<AddIntegration
								allowed={allowed}
								full={full}
								savedIds={hooks.map((h) => h.id)}
							/>
						</Panel>
					</div>
				);
			}}
		</Boundary>
	);
}
