/**
 * Protected-tool policy templates: parameters in, a `{contract, policy}` document for the
 * gateway's publish API out. Pure: ids and existing versions are passed in, so every state is
 * testable. The gateway re-parses and is the authority; this only refuses early. That the
 * documents parse and decide as described is proven by the Rust test
 * `template_documents_parse_and_decide` (`policy_tests.rs`) over a JSON fixture that
 * `policy-templates.test.ts` keeps equal to this output.
 *
 * Rules are first-match and the gateway's default is Deny (`policy.rs` `evaluate`), so each
 * template says what is allowed, what is held for approval, and what is denied outright.
 */

export type TemplateId = "payments" | "customer_data";

/** Gateway limits (`crates/gateway/mcp_policy.v1.json`): max_name_chars, max_ttl_secs. */
export const MAX_NAME_CHARS = 256;
export const MAX_TTL_SECS = 86_400;
export const MAX_LIST = 50;
export const MAX_ITEM_CHARS = 128;
/** `policy.rs` SAFE_INTEGER: the largest number the gateway accepts as a value. */
export const SAFE_INTEGER = 9_007_199_254_740_991;

export type AmountUnit = "cents" | "whole_dollars";

export interface TemplateParams {
	/** Payments only, no default: what one unit of the tool's `amount` argument is. */
	amountUnit?: AmountUnit;
	toolName: string;
	/** Dollars for payments; records for customer data. A positive whole number. */
	limit: number;
	/** Beneficiaries (payments) or destinations (customer data). */
	approved: string[];
	approvalMinutes: number;
	/** The tool's argument names; paths are derived from them. */
	args: Record<string, string>;
}

export interface TemplateInfo {
	id: TemplateId;
	title: string;
	summary: string;
	defaultTool: string;
	limitLabel: string;
	approvedLabel: string;
	defaultArgs: Record<string, string>;
}

export const TEMPLATES: readonly TemplateInfo[] = [
	{
		id: "payments",
		title: "Payments",
		summary:
			"Allow small payments to approved beneficiaries, hold larger ones for approval of the exact payment, and deny everyone else.",
		defaultTool: "release_payment",
		limitLabel: "Hold payments above (USD)",
		approvedLabel: "Approved beneficiaries",
		defaultArgs: {
			amount: "amount",
			currency: "currency",
			beneficiary: "beneficiary",
		},
	},
	{
		id: "customer_data",
		title: "Customer data",
		summary:
			"Allow small exports to approved destinations, hold bulk exports for approval of the exact call, and deny any other destination.",
		defaultTool: "export_customers",
		limitLabel: "Hold exports above (records)",
		approvedLabel: "Approved destinations",
		defaultArgs: { count: "record_count", destination: "destination" },
	},
];

export interface Existing {
	toolRef: string;
	contractVersion: number;
	policyVersion: number;
}
export interface BuildContext {
	serverId: string;
	toolRef: string;
	policyId: string;
	existing: Existing | null;
}
export type Doc = {
	contract: Record<string, unknown>;
	policy: Record<string, unknown>;
};
export type BuildResult =
	| { ok: true; doc: Doc }
	| { ok: false; errors: Record<string, string> };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NAME = /^[A-Za-z0-9_.-]+$/;

const pointer = (name: string) =>
	`/${name.replaceAll("~", "~0").replaceAll("/", "~1")}`;

/** Control (Cc) and format (Cf: zero-width, bidi) characters never belong in an approved name. */
const hasControlChar = (v: string) => /[\p{Cc}\p{Cf}]/u.test(v);

function cleanApproved(list: unknown): string[] | null {
	if (!Array.isArray(list)) return null;
	const out = [
		...new Set(
			list.map((v) => (typeof v === "string" ? v.trim().normalize("NFC") : "")),
		),
	];
	return out.every((v) => v.length > 0) ? out : null;
}

/** Field-level errors in plain words, keyed by form field. Empty means valid. */
export function validateTemplateParams(
	template: TemplateId,
	p: TemplateParams,
): Record<string, string> {
	const e: Record<string, string> = {};
	if (!TEMPLATES.some((t) => t.id === template))
		e.template = "Choose a template.";
	if (
		typeof p.toolName !== "string" ||
		!NAME.test(p.toolName) ||
		p.toolName.length > MAX_NAME_CHARS
	)
		e.toolName = "Use the tool's name: letters, digits, _ . - only.";
	if (
		template === "payments" &&
		p.amountUnit !== "cents" &&
		p.amountUnit !== "whole_dollars"
	)
		e.amountUnit =
			"Say whether the tool's amount is in cents or in whole dollars.";
	if (
		!Number.isSafeInteger(p.limit) ||
		p.limit < 1 ||
		(template === "payments" &&
			p.limit >
				Math.floor(SAFE_INTEGER / (p.amountUnit === "cents" ? 100 : 1))) ||
		p.limit > SAFE_INTEGER
	)
		e.limit = "Enter a whole number of 1 or more.";
	const approved = cleanApproved(p.approved);
	if (!approved || approved.length === 0)
		e.approved =
			"Add at least one approved entry; blank entries are not allowed.";
	else if (
		approved.length > MAX_LIST ||
		approved.some((v) => v.length > MAX_ITEM_CHARS || hasControlChar(v))
	)
		e.approved = `Up to ${MAX_LIST} entries, each up to ${MAX_ITEM_CHARS} characters.`;
	if (
		!Number.isSafeInteger(p.approvalMinutes) ||
		p.approvalMinutes < 1 ||
		p.approvalMinutes * 60 > MAX_TTL_SECS
	)
		e.approvalMinutes = `Enter 1 to ${MAX_TTL_SECS / 60} minutes.`;
	const names =
		template === "payments"
			? (["amount", "currency", "beneficiary"] as const)
			: (["count", "destination"] as const);
	for (const n of names)
		if (typeof p.args?.[n] !== "string" || !NAME.test(p.args[n]))
			e[`args.${n}`] = "Use letters, digits, _ . - only.";
	if (
		Object.keys(e).length === 0 &&
		new Set(names.map((n) => p.args[n])).size !== names.length
	)
		e.args = "Each argument needs a different name.";
	return e;
}

export function buildPolicyDocument(
	template: TemplateId,
	p: TemplateParams,
	ctx: BuildContext,
): BuildResult {
	const errors = validateTemplateParams(template, p);
	if (!UUID.test(ctx.serverId)) errors.server = "Choose a tool server.";
	if (!UUID.test(ctx.toolRef) || !UUID.test(ctx.policyId))
		errors.ids = "Could not prepare the policy. Try again.";
	if (Object.keys(errors).length > 0) return { ok: false, errors };

	const approved = cleanApproved(p.approved) as string[];
	const payments = template === "payments";
	const numeric = payments ? "amount" : "record_count";
	const text = payments ? "beneficiary" : "destination";
	const numArg = (payments ? p.args.amount : p.args.count) ?? "";
	const textArg = (payments ? p.args.beneficiary : p.args.destination) ?? "";
	const limit = limitInField(template, p);

	const fields: Record<string, unknown> = {
		[numeric]: {
			path: pointer(numArg),
			kind: "minor_units",
			required: true,
			evidence: "clear",
		},
		[text]: {
			path: pointer(textArg),
			kind: "string",
			required: true,
			evidence: "tokenize",
		},
	};
	if (payments)
		fields.currency = {
			path: pointer(p.args.currency ?? ""),
			kind: "currency",
			required: true,
			evidence: "clear",
		};
	const inApproved = { field: text, op: "in_list", value: approved };
	const rules = [
		{
			id: "allow-small-approved",
			when: [{ field: numeric, op: "lte", value: limit }, inApproved],
			decision: "allow",
		},
		{
			id: "hold-large-approved",
			when: [{ field: numeric, op: "gt", value: limit }, inApproved],
			decision: "require_approval",
		},
		{
			id: payments ? "deny-unknown-beneficiary" : "deny-unapproved-destination",
			when: [{ field: text, op: "not_in_list", value: approved }],
			decision: "deny",
		},
	];
	return {
		ok: true,
		doc: {
			contract: {
				tool_ref: ctx.toolRef,
				server_id: ctx.serverId,
				tool_name: p.toolName,
				version: (ctx.existing?.contractVersion ?? 0) + 1,
				protected: true,
				fields,
			},
			policy: {
				approval_ttl_secs: p.approvalMinutes * 60,
				policy_id: ctx.policyId,
				version: (ctx.existing?.policyVersion ?? 0) + 1,
				rules,
			},
		},
	};
}

/** The limit as the tool's own argument carries it (cents or whole dollars; records as is). */
export function limitInField(template: TemplateId, p: TemplateParams): number {
	return template === "payments" && p.amountUnit === "cents"
		? p.limit * 100
		: p.limit;
}

const usd = (n: number) =>
	n.toLocaleString("en-US", { style: "currency", currency: "USD" });

/** The confirmation sentence: the limit in plain words and in the tool's own units. */
export function describeLimit(template: TemplateId, p: TemplateParams): string {
	if (template === "payments")
		return `Payments above ${usd(p.limit)} (${limitInField(template, p)} in the amount field) need approval.`;
	return `Exports above ${p.limit.toLocaleString("en-US")} records need approval.`;
}

/** What the policy does, in plain words, for the preview. */
export function summarizeTemplate(
	template: TemplateId,
	p: TemplateParams,
): string {
	const n = new Set(
		p.approved.map((v) => v.trim().normalize("NFC")).filter(Boolean),
	).size;
	const payments = template === "payments";
	const who = payments ? "beneficiary" : "destination";
	const approved = `${n} approved ${payments ? (n === 1 ? "beneficiary" : "beneficiaries") : n === 1 ? "destination" : "destinations"}`;
	const upTo = payments
		? `Payments up to ${usd(p.limit)} to ${approved} are allowed`
		: `Exports up to ${p.limit.toLocaleString("en-US")} records to ${approved} are allowed`;
	return `${upTo}; larger ones wait up to ${p.approvalMinutes} ${p.approvalMinutes === 1 ? "minute" : "minutes"} for approval; any other ${who} is denied.`;
}

/** Plain words for the gateway's closed refusal vocabulary (`policy_api.rs`). */
export function explainRefusal(code: string | null | undefined): string {
	switch (code) {
		case "action_control_disabled":
			return "Action control is off for this workspace. Turn it on first.";
		case "contract_invalid":
			return "The gateway did not accept this policy. A tool with this name may already exist with different details; check the tool name and the argument names.";
		case "policy_invalid":
			return "The gateway did not accept this policy. Check the limit, the approved list and the approval window.";
		case "invalid_policy_request":
			return "The gateway did not accept this request.";
		case "policy_version_must_increase":
		case "policy_conflict":
			return "The policy changed while you were editing. Reload and try again.";
		case "mcp_server_not_found":
			return "That tool server was not found in this workspace.";
		case "forbidden":
		case "role_forbidden":
			return "Only workspace owners and admins can publish policies.";
		case "rate_limited":
			return "Too many changes. Try again in a few minutes.";
		default:
			return "Not published. The service did not confirm the change. Try again.";
	}
}

export interface ActivePolicy {
	tool_ref: string;
	server_id: string;
	tool_name: string;
	contract_version: number;
	policy_version: number;
}

/** The active policy for this exact tool, so a republish reuses its identity and bumps both versions. */
export function findExisting(
	policies: readonly ActivePolicy[],
	serverId: string,
	toolName: string,
): Existing | null {
	const p = policies.find(
		(x) => x.server_id === serverId && x.tool_name === toolName,
	);
	return p
		? {
				toolRef: p.tool_ref,
				contractVersion: p.contract_version,
				policyVersion: p.policy_version,
			}
		: null;
}
