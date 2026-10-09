/**
 * OG-60 — the dashboard's view of the gateway control plane (`specs/OG-60-…md` §2 Part B).
 *
 * Pure TypeScript, no React, no I/O: the allowlist the proxy enforces, the way a gateway
 * refusal is worded, and the policy document <-> form conversion. The gateway stays
 * authoritative on every value (`crates/shared/src/key_policy.rs` is the one vocabulary);
 * this file only helps a human type a document and read a refusal.
 *
 * Source of every shape: `crates/gateway/src/control_routes.rs`, `project_routes.rs`,
 * `control_plane.rs`, `key_routes.rs` (`KeyView`, `PatchKeyBody`).
 */

import {
	type CapabilitySlug,
	ROLE_CAPABILITIES,
} from "./role-capabilities.generated";

// ── The proxy allowlist ──────────────────────────────────────────────────────

type Verb = "GET" | "PUT" | "POST" | "PATCH" | "DELETE";

/**
 * Every gateway route the dashboard's generic control proxy may reach, as
 * `[verb, path pattern]`. `*` is exactly one path segment. A route that is not here is
 * refused 404 BEFORE a token is minted — the proxy is a typed relay, not a tunnel.
 * The OG-11/12/30 slot routes (routing, guardrail policy) are listed read-only so a slot
 * page can show what the route answers; the OG-51 cache and OG-50 OTel export routes carry
 * their writes too, because those pages are real editors.
 */
export const CONTROL_PROXY_ROUTES: readonly (readonly [Verb, string])[] = [
	["GET", "controls"],
	["PUT", "controls/policy"],
	["POST", "controls/pause"],
	["POST", "controls/resume"],
	["PUT", "controls/blocks"],
	["POST", "controls/revoke-all-keys"],
	["GET", "controls/budgets"],
	["GET", "controls/alert-channels"],
	["POST", "controls/alert-channels"],
	["DELETE", "controls/alert-channels/*"],
	["POST", "controls/alert-channels/*/test"],
	["GET", "controls/alert-events"],
	["GET", "projects"],
	["POST", "projects"],
	["GET", "projects/*"],
	["PATCH", "projects/*"],
	["DELETE", "projects/*"],
	["GET", "security/admin-access"],
	["PUT", "security/admin-access"],
	["GET", "audit/control-changes"],
	// Slot reads (OG-11/12 routing, OG-51 cache, OG-50 OTel export).
	["GET", "routing"],
	["GET", "cache"],
	["PUT", "cache/settings"],
	["POST", "cache/invalidate"],
	["GET", "exports/otel"],
	["POST", "exports/otel"],
	["PATCH", "exports/otel/*"],
	["DELETE", "exports/otel/*"],
	["POST", "exports/otel/*/test"],
	["GET", "guardrails/policy"],
];

/**
 * One path segment the relay forwards: RFC 3986 unreserved characters only. L1 (security
 * review, 2026-10-05): Next.js decodes the catch-all, so `%3F` / `%23` reach us as `?` /
 * `#` — a wildcard must never carry a query, a fragment or any other syntax upstream.
 */
const SEGMENT = /^[A-Za-z0-9._~-]+$/;

/** Is `verb path` (no leading `/v1/`, no query) a route the proxy may reach? */
export function isProxiedControlRoute(verb: string, path: string): boolean {
	const segs = path.split("/");
	if (segs.some((s) => s === "." || s === ".." || !SEGMENT.test(s)))
		return false;
	return CONTROL_PROXY_ROUTES.some(([v, pattern]) => {
		if (v !== verb) return false;
		const p = pattern.split("/");
		return (
			p.length === segs.length && p.every((s, i) => s === "*" || s === segs[i])
		);
	});
}

/** Feature-detected slots: shown in the Gateway tab strip only when the route answers. */
export const GATEWAY_SLOTS = [
	{ id: "routing", label: "Routing", probe: "routing", spec: "OG-11 / OG-12" },
	{ id: "cache", label: "Cache", probe: "cache", spec: "OG-51" },
	{ id: "otel", label: "OTel export", probe: "exports/otel", spec: "OG-50" },
	{
		id: "guardrails",
		label: "Guardrail policy",
		probe: "guardrails/policy",
		spec: "OG-30",
	},
] as const;
export type GatewaySlot = (typeof GATEWAY_SLOTS)[number];

// ── Roles ────────────────────────────────────────────────────────────────────

const ROLE_ORDER = ["viewer", "billing", "developer", "admin"] as const;
const ROLE_WORDS: Record<(typeof ROLE_ORDER)[number], string> = {
	viewer: "a viewer",
	billing: "a billing role",
	developer: "a developer",
	admin: "an owner or admin",
};

/** The least-privileged role that holds `cap` (the gateway's `Capability::least_role`). */
export function leastRole(cap: CapabilitySlug): (typeof ROLE_ORDER)[number] {
	const flags = ROLE_CAPABILITIES[cap];
	return ROLE_ORDER.find((r) => flags[r]) ?? "admin";
}

/** Why a role-gated control is disabled — shown beside the control, never silent. */
export function disabledReason(cap: CapabilitySlug): string {
	return `Needs ${ROLE_WORDS[leastRole(cap)]} (${cap}). Your role cannot change this.`;
}

// ── Refusals ─────────────────────────────────────────────────────────────────

export type RefusalKind =
	| "forbidden"
	| "ip_blocked"
	| "sso_required"
	| "paused"
	| "rate_limited"
	| "conflict"
	| "invalid"
	| "no_control_plane"
	| "unavailable"
	| "other";

export interface Refusal {
	kind: RefusalKind;
	message: string;
	/** The dotted field the gateway named, for beside-the-field display. */
	field?: string;
	code?: string;
}

const str = (v: unknown): string | undefined =>
	typeof v === "string" && v !== "" ? v : undefined;

/**
 * Word a gateway refusal. The gateway's own `message` wins for 400/409/503 (it names the
 * field and the bound); the control-plane gate codes get plain-language copy.
 */
export function describeRefusal(
	status: number,
	body: Record<string, unknown> | null | undefined,
): Refusal {
	const code = str(body?.error) ?? str(body?.code);
	const message = str(body?.message);
	const field = str(body?.field);
	if (status === 403 && code === "admin_ip_not_allowed") {
		return {
			kind: "ip_blocked",
			code,
			message:
				"This workspace restricts admin actions to an IP allowlist, and your address is not on it.",
		};
	}
	if (status === 403 && code === "sso_required") {
		return {
			kind: "sso_required",
			code,
			message:
				"This workspace requires an SSO sign-in for admin actions. Sign in through your identity provider and retry.",
		};
	}
	if (status === 403) {
		const need = str(body?.required_role);
		return {
			kind: "forbidden",
			code,
			message: need
				? `Your role cannot do this — it needs ${need === "admin" || need === "owner" ? "a workspace owner or admin" : `the ${need} role`}.`
				: "Your role cannot do this.",
		};
	}
	if (status === 423) {
		return {
			kind: "paused",
			code,
			message:
				"The workspace is paused, so inference is refused. Resume it from Emergency controls.",
		};
	}
	if (status === 429) {
		const secs =
			typeof body?.retry_after_secs === "number" ? body.retry_after_secs : null;
		return {
			kind: "rate_limited",
			code,
			message:
				message ??
				(secs === null
					? "Too many admin changes in a short time. Wait a moment and retry."
					: `Too many admin changes in a short time. Retry in ${secs}s.`),
		};
	}
	if (status === 409) {
		return {
			kind: "conflict",
			code,
			field,
			message: message ?? "That conflicts with current state.",
		};
	}
	if (status === 400 || status === 422) {
		return {
			kind: "invalid",
			code,
			field,
			message: message ?? "The gateway refused that value.",
		};
	}
	if (status === 404 && !code) {
		return {
			kind: "no_control_plane",
			message:
				"This needs a Postgres control plane, and this gateway has none (the route answered 404).",
		};
	}
	if (status === 404) {
		return { kind: "other", code, message: message ?? "Not found." };
	}
	if (status === 503 || status === 502 || status >= 500) {
		return {
			kind: "unavailable",
			code,
			message:
				message ??
				"The gateway could not complete that — retry shortly. If you were saving, nothing was changed.",
		};
	}
	return {
		kind: "other",
		code,
		field,
		message: message ?? `The gateway answered HTTP ${status}.`,
	};
}

// ── Gateway shapes ───────────────────────────────────────────────────────────

/** `GET /v1/controls` */
export interface ControlsState {
	paused: boolean;
	pausedAt: string | null;
	pausedBy: string | null;
	pauseReason: string | null;
	blocks: { models: string[]; providers: string[]; endUsers: string[] };
	policy: Record<string, unknown> | null;
	updatedAt: string | null;
}

/** One entry of `GET /v1/controls/budgets` (`budgets.rs` `snapshot`). */
export interface BudgetCounter {
	policy: string;
	scope: "workspace" | "project" | "key";
	subjectId: string | null;
	endUser: string | null;
	window: string;
	mode: "hard" | "soft";
	budgetUsd: number;
	spentUsd: number | null;
	known: boolean;
	resetsAt: string | null;
}

/** `GET /v1/projects` item. */
export interface ProjectView {
	id: string;
	name: string;
	environments: string[];
	policy: Record<string, unknown> | null;
	createdAt: string;
	updatedAt: string;
}

export interface AlertChannel {
	id: string;
	kind: "email" | "slack" | "webhook";
	name: string;
	target: string;
	createdAt: string;
}

export interface AdminAccessView {
	admin_ip_allowlist: string[];
	sso_required: boolean;
	updated_at: string | null;
	updated_by: string | null;
	your_ip: string | null;
	your_ip_attested: boolean;
	max_ip_allowlist_entries: number;
}

export interface ControlChangeRow {
	id: number;
	occurred_at: string;
	actor: string;
	actor_role: string | null;
	actor_auth_method: string | null;
	action: string;
	target_type: string;
	target_id: string;
	before: unknown;
	after: unknown;
	ip: string | null;
	user_agent: string | null;
	request_id: string | null;
}

// ── The policy document <-> form ─────────────────────────────────────────────

export const BUDGET_WINDOWS = [
	"daily",
	"weekly",
	"monthly",
	"rolling_1h",
	"rolling_24h",
	"rolling_7d",
	"rolling_30d",
] as const;
export const END_USER_WINDOWS = ["daily", "weekly", "monthly"] as const;

export interface BudgetForm {
	usd: string;
	window: string;
	mode: "hard" | "soft";
	alertPercent: string;
	alertUsd: string;
}
export interface PerModelForm {
	model: string;
	rpm: string;
	tpm: string;
}
/** Every field is text so a half-typed value round-trips; empty = unset. */
export interface PolicyForm {
	modelsAllow: string;
	modelsDeny: string;
	providersAllow: string;
	providersDeny: string;
	sourceIps: string;
	maxInputTokens: string;
	maxOutputTokens: string;
	maxBodyBytes: string;
	requiredTags: string;
	requiredMetadataKeys: string;
	rpm: string;
	tpm: string;
	perEndUserRpm: string;
	perEndUserTpm: string;
	perModel: PerModelForm[];
	budget: BudgetForm | null;
	endUserBudget: BudgetForm | null;
}

export type PolicyScope = "workspace" | "project" | "key";

const emptyBudget = (): BudgetForm => ({
	usd: "",
	window: "monthly",
	mode: "hard",
	alertPercent: "",
	alertUsd: "",
});

export const emptyPolicyForm = (): PolicyForm => ({
	modelsAllow: "",
	modelsDeny: "",
	providersAllow: "",
	providersDeny: "",
	sourceIps: "",
	maxInputTokens: "",
	maxOutputTokens: "",
	maxBodyBytes: "",
	requiredTags: "",
	requiredMetadataKeys: "",
	rpm: "",
	tpm: "",
	perEndUserRpm: "",
	perEndUserTpm: "",
	perModel: [],
	budget: null,
	endUserBudget: null,
});

export const newBudgetForm = emptyBudget;

const asObj = (v: unknown): Record<string, unknown> | null =>
	v !== null && typeof v === "object" && !Array.isArray(v)
		? (v as Record<string, unknown>)
		: null;
const lines = (v: unknown): string =>
	Array.isArray(v) ? v.filter((x) => typeof x === "string").join("\n") : "";
const num = (v: unknown): string =>
	typeof v === "number" && Number.isFinite(v) ? String(v) : "";
const nums = (v: unknown): string =>
	Array.isArray(v) ? v.filter((x) => typeof x === "number").join(", ") : "";

function budgetFromDoc(v: unknown): BudgetForm | null {
	const o = asObj(v);
	if (!o) return null;
	return {
		usd: num(o.usd),
		window: typeof o.window === "string" ? o.window : "monthly",
		mode: o.mode === "soft" ? "soft" : "hard",
		alertPercent: nums(o.alert_at_percent),
		alertUsd: nums(o.alert_at_usd),
	};
}

/** A stored policy document -> the form. `null` / unreadable -> an empty form. */
export function policyToForm(doc: unknown): PolicyForm {
	const o = asObj(doc);
	const f = emptyPolicyForm();
	if (!o) return f;
	const models = asObj(o.models);
	const providers = asObj(o.providers);
	const limits = asObj(o.limits);
	const perEnd = asObj(limits?.per_end_user);
	f.modelsAllow = lines(models?.allow);
	f.modelsDeny = lines(models?.deny);
	f.providersAllow = lines(providers?.allow);
	f.providersDeny = lines(providers?.deny);
	f.sourceIps = lines(o.source_ips);
	f.maxInputTokens = num(o.max_input_tokens);
	f.maxOutputTokens = num(o.max_output_tokens);
	f.maxBodyBytes = num(o.max_body_bytes);
	f.requiredTags = lines(o.required_tags);
	f.requiredMetadataKeys = lines(o.required_metadata_keys);
	f.rpm = num(limits?.rpm);
	f.tpm = num(limits?.tpm);
	f.perEndUserRpm = num(perEnd?.rpm);
	f.perEndUserTpm = num(perEnd?.tpm);
	f.perModel = Array.isArray(limits?.per_model)
		? (limits.per_model as unknown[]).flatMap((m) => {
				const e = asObj(m);
				return e && typeof e.model === "string"
					? [{ model: e.model, rpm: num(e.rpm), tpm: num(e.tpm) }]
					: [];
			})
		: [];
	f.budget = budgetFromDoc(o.budget);
	f.endUserBudget = budgetFromDoc(o.end_user_budget);
	return f;
}

export interface FormError {
	field: string;
	message: string;
}

const splitLines = (s: string): string[] =>
	s
		.split(/[\n,]/)
		.map((x) => x.trim())
		.filter(Boolean);

function posInt(
	field: string,
	raw: string,
	errors: FormError[],
): number | undefined {
	const t = raw.trim();
	if (t === "") return undefined;
	const n = Number(t);
	if (!Number.isSafeInteger(n) || n <= 0) {
		errors.push({
			field,
			message: "Enter a positive whole number, or leave it empty.",
		});
		return undefined;
	}
	return n;
}

function budgetToDoc(
	field: string,
	b: BudgetForm,
	errors: FormError[],
): Record<string, unknown> | undefined {
	const usd = Number(b.usd.trim());
	if (b.usd.trim() === "" || !Number.isFinite(usd) || usd <= 0) {
		errors.push({
			field: `${field}.usd`,
			message: "Enter a budget above 0 USD, or remove the budget.",
		});
		return undefined;
	}
	const doc: Record<string, unknown> = { usd, window: b.window, mode: b.mode };
	const pct = splitLines(b.alertPercent).map(Number);
	if (pct.some((p) => !Number.isInteger(p) || p < 1)) {
		errors.push({
			field: `${field}.alert_at_percent`,
			message: "Percent alerts are whole numbers, e.g. 50, 80, 100.",
		});
	} else if (pct.length) doc.alert_at_percent = pct;
	const usdAlerts = splitLines(b.alertUsd).map(Number);
	if (usdAlerts.some((u) => !Number.isFinite(u) || u <= 0)) {
		errors.push({
			field: `${field}.alert_at_usd`,
			message: "USD alerts are amounts above 0.",
		});
	} else if (usdAlerts.length) doc.alert_at_usd = usdAlerts;
	return doc;
}

/**
 * The form -> the policy document the gateway validates. `doc: null` means "no policy"
 * (clears it). A workspace policy never carries token / body / label rules
 * (`KeyPolicy::workspace_only`), so those form fields are ignored for it.
 */
export function formToPolicy(
	f: PolicyForm,
	scope: PolicyScope,
): { doc: Record<string, unknown> | null; errors: FormError[] } {
	const errors: FormError[] = [];
	const doc: Record<string, unknown> = {};
	const list = (allow: string, deny: string) => {
		const a = splitLines(allow);
		const d = splitLines(deny);
		return a.length || d.length ? { allow: a, deny: d } : undefined;
	};
	const models = list(f.modelsAllow, f.modelsDeny);
	if (models) doc.models = models;
	const providers = list(f.providersAllow, f.providersDeny);
	if (providers) doc.providers = providers;
	const ips = splitLines(f.sourceIps);
	if (ips.length) doc.source_ips = ips;
	if (scope !== "workspace") {
		const mi = posInt("max_input_tokens", f.maxInputTokens, errors);
		if (mi !== undefined) doc.max_input_tokens = mi;
		const mo = posInt("max_output_tokens", f.maxOutputTokens, errors);
		if (mo !== undefined) doc.max_output_tokens = mo;
		const mb = posInt("max_body_bytes", f.maxBodyBytes, errors);
		if (mb !== undefined) doc.max_body_bytes = mb;
		const tags = splitLines(f.requiredTags);
		if (tags.length) doc.required_tags = tags;
		const keys = splitLines(f.requiredMetadataKeys);
		if (keys.length) doc.required_metadata_keys = keys;
	}
	const limits: Record<string, unknown> = {};
	const rpm = posInt("limits.rpm", f.rpm, errors);
	if (rpm !== undefined) limits.rpm = rpm;
	const tpm = posInt("limits.tpm", f.tpm, errors);
	if (tpm !== undefined) limits.tpm = tpm;
	const eRpm = posInt("limits.per_end_user.rpm", f.perEndUserRpm, errors);
	const eTpm = posInt("limits.per_end_user.tpm", f.perEndUserTpm, errors);
	if (eRpm !== undefined || eTpm !== undefined) {
		limits.per_end_user = {
			...(eRpm !== undefined ? { rpm: eRpm } : {}),
			...(eTpm !== undefined ? { tpm: eTpm } : {}),
		};
	}
	const perModel = f.perModel.flatMap((m, i) => {
		const model = m.model.trim();
		const r = posInt(`limits.per_model.${i}.rpm`, m.rpm, errors);
		const t = posInt(`limits.per_model.${i}.tpm`, m.tpm, errors);
		if (!model) {
			errors.push({
				field: `limits.per_model.${i}.model`,
				message: "Name a model or pattern, or remove the row.",
			});
			return [];
		}
		if (r === undefined && t === undefined) {
			errors.push({
				field: `limits.per_model.${i}.rpm`,
				message:
					"Set a requests or tokens per minute limit, or remove the row.",
			});
			return [];
		}
		return [
			{
				model,
				...(r !== undefined ? { rpm: r } : {}),
				...(t !== undefined ? { tpm: t } : {}),
			},
		];
	});
	if (perModel.length) limits.per_model = perModel;
	if (Object.keys(limits).length) doc.limits = limits;
	if (f.budget) {
		const b = budgetToDoc("budget", f.budget, errors);
		if (b) doc.budget = b;
	}
	if (f.endUserBudget) {
		const b = budgetToDoc("end_user_budget", f.endUserBudget, errors);
		if (b) doc.end_user_budget = b;
	}
	return { doc: Object.keys(doc).length ? doc : null, errors };
}

/** One-line summary of what a stored policy does, for list rows. */
export function summarizePolicy(doc: unknown): string {
	const o = asObj(doc);
	if (!o) return "No policy — traffic is not restricted by this layer.";
	const parts: string[] = [];
	const limits = asObj(o.limits);
	if (limits?.rpm) parts.push(`${limits.rpm} req/min`);
	if (limits?.tpm) parts.push(`${limits.tpm} tokens/min`);
	const b = asObj(o.budget);
	if (b)
		parts.push(
			`$${b.usd} ${String(b.window ?? "monthly")} (${b.mode === "soft" ? "soft" : "hard"})`,
		);
	if (asObj(o.models)) parts.push("model rules");
	if (asObj(o.providers)) parts.push("provider rules");
	if (Array.isArray(o.source_ips) && o.source_ips.length)
		parts.push("source IPs");
	if (o.max_input_tokens || o.max_output_tokens || o.max_body_bytes)
		parts.push("size caps");
	if (o.required_tags || o.required_metadata_keys)
		parts.push("required labels");
	return parts.length ? parts.join(" · ") : "Policy set, no active rules.";
}
