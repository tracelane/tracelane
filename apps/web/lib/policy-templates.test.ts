/**
 * ACT-21 — template documents. `gatewayAccepts` is a PARTIAL mirror of `policy.rs` (shape,
 * field kinds, operators); it does not replace the real parser. The authority is the Rust test
 * `template_documents_parse_and_decide` in `policy_tests.rs`, which reads the JSON fixture this
 * file proves equal to what `buildPolicyDocument` produces. Negative cases first.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	type BuildContext,
	type Doc,
	MAX_TTL_SECS,
	SAFE_INTEGER,
	TEMPLATES,
	type TemplateId,
	type TemplateParams,
	buildPolicyDocument,
	describeLimit,
	explainRefusal,
	findExisting,
	summarizeTemplate,
	validateTemplateParams,
} from "./policy-templates";

const SERVER = "11111111-1111-4111-8111-111111111111";
const REF = "22222222-2222-4222-8222-222222222222";
const PID = "33333333-3333-4333-8333-333333333333";
const ctx: BuildContext = {
	serverId: SERVER,
	toolRef: REF,
	policyId: PID,
	existing: null,
};
const pay = (o: Partial<TemplateParams> = {}): TemplateParams => ({
	amountUnit: "cents",
	toolName: "release_payment",
	limit: 5000,
	approved: ["acme-ltd", "globex"],
	approvalMinutes: 60,
	args: { amount: "amount", currency: "currency", beneficiary: "beneficiary" },
	...o,
});
const data = (o: Partial<TemplateParams> = {}): TemplateParams => ({
	toolName: "export_customers",
	limit: 1000,
	approved: ["s3://approved-bucket"],
	approvalMinutes: 30,
	args: { count: "record_count", destination: "destination" },
	...o,
});

type Field = {
	path: string;
	kind: string;
	required: boolean;
	evidence: string;
};
/** Mirror of the Rust parser's acceptance rules. Returns the refusal code or null. */
function gatewayAccepts(doc: Doc): string | null {
	const c = doc.contract as {
		tool_ref: string;
		server_id: string;
		tool_name: string;
		version: number;
		protected: boolean;
		fields: Record<string, Field>;
	};
	const p = doc.policy as {
		approval_ttl_secs?: number;
		policy_id: string;
		version: number;
		rules: {
			id: string;
			when: { field: string; op: string; value?: unknown }[];
			decision: string;
		}[];
	};
	if (
		Object.keys(doc.contract).some(
			(k) =>
				![
					"tool_ref",
					"server_id",
					"tool_name",
					"version",
					"protected",
					"fields",
				].includes(k),
		)
	)
		return "contract_unknown_key";
	if (
		Object.keys(doc.policy).some(
			(k) =>
				![
					"require_principal",
					"approval_ttl_secs",
					"policy_id",
					"version",
					"rules",
					"agents",
				].includes(k),
		)
	)
		return "policy_unknown_key";
	if (!(c.version > 0) || !c.tool_name) return "contract_invalid";
	for (const [name, f] of Object.entries(c.fields)) {
		if (!/^[A-Za-z0-9_.-]+$/.test(name) || !f.path.startsWith("/"))
			return "contract_invalid";
		if (f.kind === "string" && f.evidence === "clear")
			return "contract_invalid";
		if (f.evidence === "tokenize" && f.kind !== "string")
			return "contract_invalid";
		if (Object.keys(f).sort().join() !== "evidence,kind,path,required")
			return "contract_invalid";
	}
	if (!(p.version > 0)) return "contract_invalid";
	if (
		p.rules.some((r) => r.decision === "require_approval") &&
		!(
			Number.isInteger(p.approval_ttl_secs) &&
			(p.approval_ttl_secs as number) > 0 &&
			(p.approval_ttl_secs as number) <= MAX_TTL_SECS
		)
	)
		return "approval_policy_invalid";
	const ids = new Set<string>();
	for (const r of p.rules) {
		if (!/^[A-Za-z0-9_.-]+$/.test(r.id) || ids.has(r.id))
			return "contract_invalid";
		ids.add(r.id);
		if (!["allow", "require_approval", "deny"].includes(r.decision))
			return "contract_invalid";
		for (const cond of r.when) {
			const f = c.fields[cond.field];
			if (!f) return "contract_invalid";
			const v = cond.value;
			const ok = (x: unknown) =>
				f.kind === "minor_units"
					? Number.isInteger(x) &&
						(x as number) >= 0 &&
						(x as number) <= SAFE_INTEGER
					: f.kind === "currency"
						? x === "USD"
						: f.kind === "string"
							? typeof x === "string"
							: typeof x === "boolean";
			const valid =
				cond.op === "present" || cond.op === "absent"
					? v === undefined || v === null
					: cond.op === "in_list" || cond.op === "not_in_list"
						? Array.isArray(v) && v.every(ok)
						: ["gt", "gte", "lt", "lte"].includes(cond.op)
							? f.kind === "minor_units" && ok(v)
							: ["eq", "ne"].includes(cond.op) && ok(v);
			if (!valid) return "contract_invalid";
		}
	}
	return null;
}
/** Mirror of `evaluate`: first matching rule, default deny. */
function decide(doc: Doc, args: Record<string, unknown>): string {
	const f = (doc.contract as { fields: Record<string, Field> }).fields;
	const vals: Record<string, unknown> = {};
	for (const [n, fd] of Object.entries(f)) vals[n] = args[fd.path.slice(1)];
	const rules = (
		doc.policy as {
			rules: {
				id: string;
				when: { field: string; op: string; value: unknown }[];
				decision: string;
			}[];
		}
	).rules;
	for (const r of rules) {
		const hit = r.when.every((c) => {
			const a = vals[c.field];
			if (a === undefined) return false;
			if (c.op === "in_list") return (c.value as unknown[]).includes(a);
			if (c.op === "not_in_list") return !(c.value as unknown[]).includes(a);
			if (c.op === "lte") return (a as number) <= (c.value as number);
			if (c.op === "gt") return (a as number) > (c.value as number);
			return false;
		});
		if (hit) return r.decision;
	}
	return "deny";
}
const build = (t: TemplateId, p: TemplateParams, c: BuildContext = ctx) => {
	const r = buildPolicyDocument(t, p, c);
	if (!r.ok) throw new Error(JSON.stringify(r.errors));
	return r.doc;
};

describe("validation — refusals (negative)", () => {
	const bad: [string, TemplateId, Partial<TemplateParams>, string][] = [
		["empty tool name", "payments", { toolName: "" }, "toolName"],
		[
			"tool name with a space",
			"payments",
			{ toolName: "release payment" },
			"toolName",
		],
		["tool name with a slash", "payments", { toolName: "a/b" }, "toolName"],
		[
			"tool name over 256",
			"payments",
			{ toolName: "a".repeat(257) },
			"toolName",
		],
		["limit zero", "payments", { limit: 0 }, "limit"],
		["limit negative", "payments", { limit: -5 }, "limit"],
		["limit fractional", "payments", { limit: 1.5 }, "limit"],
		["limit NaN", "payments", { limit: Number.NaN }, "limit"],
		[
			"limit Infinity",
			"customer_data",
			{ limit: Number.POSITIVE_INFINITY },
			"limit",
		],
		[
			"payment limit overflowing minor units",
			"payments",
			{ limit: SAFE_INTEGER },
			"limit",
		],
		[
			"records limit over safe integer",
			"customer_data",
			{ limit: SAFE_INTEGER + 2 },
			"limit",
		],
		["no approved entries", "payments", { approved: [] }, "approved"],
		["only blank entries", "payments", { approved: ["  "] }, "approved"],
		["a blank among entries", "payments", { approved: ["a", ""] }, "approved"],
		[
			"a non-string entry",
			"payments",
			{ approved: [1 as unknown as string] },
			"approved",
		],
		[
			"51 entries",
			"payments",
			{ approved: Array.from({ length: 51 }, (_, i) => `b${i}`) },
			"approved",
		],
		[
			"entry over 128 chars",
			"customer_data",
			{ approved: ["x".repeat(129)] },
			"approved",
		],
		[
			"control character in an entry",
			"customer_data",
			{ approved: ["a\nb"] },
			"approved",
		],
		["ttl zero", "payments", { approvalMinutes: 0 }, "approvalMinutes"],
		[
			"ttl over a day",
			"payments",
			{ approvalMinutes: 1441 },
			"approvalMinutes",
		],
		["ttl fractional", "payments", { approvalMinutes: 1.5 }, "approvalMinutes"],
		[
			"argument name with a slash",
			"payments",
			{
				args: {
					amount: "a/b",
					currency: "currency",
					beneficiary: "beneficiary",
				},
			},
			"args.amount",
		],
		[
			"duplicate argument names",
			"payments",
			{ args: { amount: "x", currency: "x", beneficiary: "beneficiary" } },
			"args",
		],
		[
			"missing customer-data argument",
			"customer_data",
			{ args: { count: "n" } },
			"args.destination",
		],
	];
	it.each(bad)("refuses %s", (_n, t, o, key) => {
		const p = t === "payments" ? pay(o) : data(o);
		expect(validateTemplateParams(t, p)[key]).toBeTruthy();
		expect(buildPolicyDocument(t, p, ctx).ok).toBe(false);
	});
	it("refuses an unknown template", () => {
		expect(
			validateTemplateParams("nope" as TemplateId, pay()).template,
		).toBeTruthy();
	});
	it("refuses a server or id that is not a UUID", () => {
		const a = buildPolicyDocument("payments", pay(), { ...ctx, serverId: "x" });
		const b = buildPolicyDocument("payments", pay(), { ...ctx, policyId: "x" });
		const c = buildPolicyDocument("payments", pay(), { ...ctx, toolRef: "x" });
		for (const r of [a, b, c]) expect(r.ok).toBe(false);
	});
	it("explains every refusal code and masks unknown ones", () => {
		for (const code of [
			"action_control_disabled",
			"contract_invalid",
			"policy_invalid",
			"invalid_policy_request",
			"policy_version_must_increase",
			"policy_conflict",
			"mcp_server_not_found",
			"forbidden",
			"role_forbidden",
			"rate_limited",
		])
			expect(explainRefusal(code)).not.toMatch(/_|undefined/);
		expect(explainRefusal("boom_internal_42")).toMatch(/Not published/);
		expect(explainRefusal(undefined)).toMatch(/Not published/);
	});
});

describe("documents — the gateway accepts them (positive)", () => {
	it("payments document passes the parser mirror", () => {
		expect(gatewayAccepts(build("payments", pay()))).toBeNull();
	});
	it("customer data document passes the parser mirror", () => {
		expect(gatewayAccepts(build("customer_data", data()))).toBeNull();
	});
	it("payments in cents converts dollars to minor units", () => {
		const d = build("payments", pay({ limit: 5000 }));
		const r = (d.policy as { rules: { when: { value: number }[] }[] }).rules[0];
		expect(r?.when[0]?.value).toBe(500_000);
	});
	it("customer data keeps the record count as is", () => {
		const d = build("customer_data", data({ limit: 1000 }));
		const r = (d.policy as { rules: { when: { value: number }[] }[] }).rules[1];
		expect(r?.when[0]?.value).toBe(1000);
	});
	it("derives JSON pointers from argument names and escapes ~ and /", () => {
		const d = build(
			"payments",
			pay({ args: { amount: "amt", currency: "cur", beneficiary: "to" } }),
		);
		const f = (d.contract as { fields: Record<string, Field> }).fields;
		expect(f.amount?.path).toBe("/amt");
		expect(f.beneficiary?.path).toBe("/to");
	});
	it("a name with dots and dashes is accepted", () => {
		expect(
			gatewayAccepts(build("payments", pay({ toolName: "pay.release-v2" }))),
		).toBeNull();
	});
	it("tokenizes the free-text field, never clear", () => {
		for (const [t, p] of [
			["payments", pay()],
			["customer_data", data()],
		] as const) {
			const f = (build(t, p).contract as { fields: Record<string, Field> })
				.fields;
			const text = f.beneficiary ?? f.destination;
			expect(text?.evidence).toBe("tokenize");
		}
	});
	it("marks the contract protected", () => {
		expect(build("payments", pay()).contract.protected).toBe(true);
	});
	it("approval ttl is minutes times 60", () => {
		expect(
			build("payments", pay({ approvalMinutes: 90 })).policy.approval_ttl_secs,
		).toBe(5400);
	});
	it("trims and de-duplicates the approved list", () => {
		const d = build("payments", pay({ approved: [" a ", "a", "b"] }));
		const r = (d.policy as { rules: { when: { value: unknown }[] }[] })
			.rules[0];
		expect(r?.when[1]?.value).toEqual(["a", "b"]);
	});
	it("first publish is version 1 for both", () => {
		const d = build("payments", pay());
		expect([d.contract.version, d.policy.version]).toEqual([1, 1]);
	});
	it("a republish reuses the tool identity and bumps both versions", () => {
		const d = build("payments", pay(), {
			...ctx,
			toolRef: REF,
			existing: { toolRef: REF, contractVersion: 3, policyVersion: 7 },
		});
		expect([d.contract.version, d.policy.version]).toEqual([4, 8]);
		expect(gatewayAccepts(d)).toBeNull();
	});
	it("every template listed builds", () => {
		for (const t of TEMPLATES) {
			const p = t.id === "payments" ? pay() : data();
			expect(buildPolicyDocument(t.id, p, ctx).ok).toBe(true);
		}
	});
	it("serializes without undefined or unknown keys", () => {
		const s = JSON.stringify(build("payments", pay()));
		expect(JSON.parse(s)).toEqual(build("payments", pay()));
		expect(Object.keys(build("payments", pay()))).toEqual([
			"contract",
			"policy",
		]);
	});
});

describe("behaviour — what the policy decides", () => {
	const d = build("payments", pay({ limit: 5000 }));
	it.each([
		[
			"small to approved",
			{ amount: 100_000, currency: "USD", beneficiary: "acme-ltd" },
			"allow",
		],
		[
			"exactly at the limit to approved",
			{ amount: 500_000, currency: "USD", beneficiary: "acme-ltd" },
			"allow",
		],
		[
			"one cent above the limit to approved",
			{ amount: 500_001, currency: "USD", beneficiary: "globex" },
			"require_approval",
		],
		[
			"small to an unknown beneficiary",
			{ amount: 100, currency: "USD", beneficiary: "mallory" },
			"deny",
		],
		[
			"large to an unknown beneficiary",
			{ amount: 9_999_999, currency: "USD", beneficiary: "mallory" },
			"deny",
		],
		["beneficiary missing", { amount: 100, currency: "USD" }, "deny"],
		[
			"case differs from the approved name",
			{ amount: 100, currency: "USD", beneficiary: "ACME-LTD" },
			"deny",
		],
	])("payments: %s -> %s", (_n, args, want) => {
		expect(decide(d, args)).toBe(want);
	});
	const e = build("customer_data", data({ limit: 1000 }));
	it.each([
		[
			"small export to approved",
			{ record_count: 10, destination: "s3://approved-bucket" },
			"allow",
		],
		[
			"bulk export to approved",
			{ record_count: 1001, destination: "s3://approved-bucket" },
			"require_approval",
		],
		[
			"bulk export to unapproved",
			{ record_count: 1001, destination: "s3://evil" },
			"deny",
		],
		[
			"small export to unapproved",
			{ record_count: 1, destination: "s3://evil" },
			"deny",
		],
	])("customer data: %s -> %s", (_n, args, want) => {
		expect(decide(e, args)).toBe(want);
	});
});

describe("findExisting", () => {
	const list = [
		{
			tool_ref: REF,
			server_id: SERVER,
			tool_name: "release_payment",
			contract_version: 2,
			policy_version: 5,
		},
	];
	it("finds the active policy for the same server and tool", () => {
		expect(findExisting(list, SERVER, "release_payment")).toEqual({
			toolRef: REF,
			contractVersion: 2,
			policyVersion: 5,
		});
	});
	it("does not match another server or tool", () => {
		expect(findExisting(list, "other", "release_payment")).toBeNull();
		expect(findExisting(list, SERVER, "other")).toBeNull();
		expect(findExisting([], SERVER, "release_payment")).toBeNull();
	});
});

describe("invariant sweep — every template x limit x list x ttl builds an accepted document", () => {
	const limits = [1, 99, 5000, 1_000_000];
	const lists = [["a"], ["a", "b"], ["with space", "ünï", "x".repeat(128)]];
	const ttls = [1, 60, 1440];
	const cases: [TemplateId, number, string[], number][] = [];
	for (const t of ["payments", "customer_data"] as const)
		for (const l of limits)
			for (const a of lists) for (const m of ttls) cases.push([t, l, a, m]);
	it.each(cases)(
		"%s limit %d list %j ttl %d",
		(t, limit, approved, approvalMinutes) => {
			const p =
				t === "payments"
					? pay({ limit, approved, approvalMinutes })
					: data({ limit, approved, approvalMinutes });
			const doc = build(t, p);
			expect(gatewayAccepts(doc)).toBeNull();
			const rules = (doc.policy as { rules: { decision: string }[] }).rules;
			// every protected tool ends in a deny for anything outside the approved list
			expect(rules.at(-1)?.decision).toBe("deny");
			expect(JSON.stringify(doc)).not.toMatch(/undefined|NaN/);
		},
	);
});

describe("amount unit — what the limit means in the tool's amount field", () => {
	const limitOf = (p: TemplateParams) =>
		(build("payments", p).policy as { rules: { when: { value: number }[] }[] })
			.rules[0]?.when[0]?.value;
	it("cents multiplies the dollar limit by 100", () => {
		expect(limitOf(pay({ limit: 5000, amountUnit: "cents" }))).toBe(500_000);
	});
	it("whole dollars keeps the dollar limit as is", () => {
		expect(limitOf(pay({ limit: 5000, amountUnit: "whole_dollars" }))).toBe(
			5000,
		);
	});
	it("a missing unit is refused with a reason", () => {
		const p = pay();
		(p as { amountUnit?: unknown }).amountUnit = undefined;
		const e = validateTemplateParams("payments", p);
		expect(e.amountUnit).toMatch(/cents|whole dollars/);
		expect(buildPolicyDocument("payments", p, ctx).ok).toBe(false);
	});
	it("an unknown unit is refused", () => {
		const p = pay({ amountUnit: "pounds" as never });
		expect(validateTemplateParams("payments", p).amountUnit).toBeTruthy();
	});
	it("customer data needs no unit", () => {
		expect(
			validateTemplateParams("customer_data", data()).amountUnit,
		).toBeUndefined();
	});
	it("a whole-dollar limit cannot exceed the safe integer", () => {
		expect(
			validateTemplateParams(
				"payments",
				pay({ amountUnit: "whole_dollars", limit: SAFE_INTEGER + 2 }),
			).limit,
		).toBeTruthy();
	});
});

describe("list entries — control and format characters, normalisation", () => {
	it.each([
		["a newline", "a\nb"],
		["a zero-width space", "a\u200bb"],
		["a bidi override", "a\u202eb"],
		["a DEL", "a\u007fb"],
	])("refuses %s", (_n, v) => {
		expect(
			validateTemplateParams("payments", pay({ approved: [v] })).approved,
		).toBeTruthy();
	});
	it("NFC-normalises entries", () => {
		const d = build("payments", pay({ approved: ["e\u0301"] }));
		const r = (d.policy as { rules: { when: { value: unknown }[] }[] })
			.rules[0];
		expect(r?.when[1]?.value).toEqual(["\u00e9"]);
	});
});

describe("fixture — what the Rust test parses is what is generated now", () => {
	const FIX = "../../../crates/gateway/tests/fixtures/template_documents.json";
	const cases: [string, TemplateId, TemplateParams][] = [
		["payments_cents", "payments", pay({ amountUnit: "cents" })],
		[
			"payments_whole_dollars",
			"payments",
			pay({ amountUnit: "whole_dollars" }),
		],
		["customer_data", "customer_data", data()],
	];
	const generated = Object.fromEntries(
		cases.map(([name, t, p]) => [name, build(t, p)]),
	);
	it("the checked-in fixture equals buildPolicyDocument", () => {
		const path = fileURLToPath(new URL(FIX, import.meta.url));
		if (process.env.UPDATE_FIXTURE === "1")
			writeFileSync(path, `${JSON.stringify(generated, null, 2)}\n`);
		expect(JSON.parse(readFileSync(path, "utf8"))).toEqual(generated);
	});
});

describe("plain-words copy", () => {
	it("describes a cents limit in dollars and in the amount field", () => {
		expect(
			describeLimit("payments", pay({ limit: 5000, amountUnit: "cents" })),
		).toBe(
			"Payments above $5,000.00 (500000 in the amount field) need approval.",
		);
	});
	it("describes a whole-dollar limit", () => {
		expect(
			describeLimit(
				"payments",
				pay({ limit: 5000, amountUnit: "whole_dollars" }),
			),
		).toBe(
			"Payments above $5,000.00 (5000 in the amount field) need approval.",
		);
	});
	it("describes a record limit", () => {
		expect(describeLimit("customer_data", data({ limit: 1000 }))).toBe(
			"Exports above 1,000 records need approval.",
		);
	});
	it("summarizes the payments policy without ids or minor units", () => {
		const t = summarizeTemplate("payments", pay({ limit: 5000 }));
		expect(t).toBe(
			"Payments up to $5,000.00 to 2 approved beneficiaries are allowed; larger ones wait up to 60 minutes for approval; any other beneficiary is denied.",
		);
		expect(t).not.toMatch(/[0-9a-f]{8}-|500000|_/);
	});
	it("summarizes the customer data policy with singular wording", () => {
		expect(
			summarizeTemplate("customer_data", data({ approvalMinutes: 1 })),
		).toBe(
			"Exports up to 1,000 records to 1 approved destination are allowed; larger ones wait up to 1 minute for approval; any other destination is denied.",
		);
	});
	it("counts the approved list after trimming and de-duplicating", () => {
		expect(
			summarizeTemplate("payments", pay({ approved: [" a ", "a", "b"] })),
		).toMatch(/to 2 approved/);
	});
});
