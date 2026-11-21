/**
 * OG-60 — the proxy allowlist, the refusal wording and the policy form round trip.
 * Negative cases first: a route that is not listed, a path that climbs, a wrong verb.
 */
import { describe, expect, it } from "vitest";
import {
	CONTROL_PROXY_ROUTES,
	describeRefusal,
	disabledReason,
	emptyPolicyForm,
	formToPolicy,
	isProxiedControlRoute,
	leastRole,
	newBudgetForm,
	policyToForm,
	summarizePolicy,
} from "./gateway-controls";

describe("isProxiedControlRoute", () => {
	it("refuses what is not a Gateway-settings route", () => {
		for (const [verb, path] of [
			["GET", "keys"], // key reads go through the keys proxy
			["POST", "chat/completions"],
			["GET", "billing/portal"],
			["DELETE", "controls"], // a read-only path with a write verb
			["PUT", "controls/pause"], // wrong verb for a real path
			["GET", "projects/a/b"], // too many segments
			["GET", "controls/../keys"],
			["GET", "controls//policy"],
			["GET", ""],
		] as const) {
			expect(isProxiedControlRoute(verb, path), `${verb} ${path}`).toBe(false);
		}
	});

	// L1 (security review, 2026-10-05): Next.js hands the catch-all its segments
	// DECODED, so `%3F` / `%23` arrive as `?` / `#` and used to pass the wildcard —
	// smuggling a query or fragment (or any other character) into the gateway path.
	it("refuses a wildcard segment that is not a plain id", () => {
		for (const [verb, path] of [
			["GET", "projects/p1?limit=1"],
			["DELETE", "projects/p1#frag"],
			["PATCH", "exports/otel/x?y=1"],
			["POST", "controls/alert-channels/a%3Fb/test"],
			["GET", "projects/p 1"],
			["GET", "projects/p\\1"],
			["GET", "projects/p;1"],
			["DELETE", "exports/otel/a&b"],
			["GET", "projects/p\u00e91"],
		] as const) {
			expect(isProxiedControlRoute(verb, path), `${verb} ${path}`).toBe(false);
		}
	});

	it("accepts every listed route, with a concrete id for a wildcard", () => {
		for (const [verb, pattern] of CONTROL_PROXY_ROUTES) {
			expect(
				isProxiedControlRoute(verb, pattern.replaceAll("*", "abc-123")),
				`${verb} ${pattern}`,
			).toBe(true);
		}
	});

	it("exposes the emergency writes and nothing wider", () => {
		const writes = CONTROL_PROXY_ROUTES.filter(([v]) => v !== "GET").map(
			([v, p]) => `${v} ${p}`,
		);
		expect(writes).toContain("POST controls/pause");
		expect(writes).toContain("POST controls/revoke-all-keys");
		// Whole-document editors use only their exact PUT paths.
		expect(writes.filter((w) => /routing|guardrails/.test(w)).sort()).toEqual([
			// Guardrail integrations: one hook per id, created or removed whole.
			"DELETE guardrails/hooks/*",
			"PUT guardrails/hooks/*",
			"PUT guardrails/policy",
			"PUT routing",
		]);
		expect(writes.filter((w) => /cache|exports/.test(w)).sort()).toEqual([
			"DELETE exports/otel/*",
			"PATCH exports/otel/*",
			"POST cache/invalidate",
			"POST exports/otel",
			"POST exports/otel/*/test",
			"PUT cache/settings",
		]);
	});
});

describe("describeRefusal", () => {
	it("explains an approval digest the server could not honour", () => {
		const r = describeRefusal(400, { error: "descriptor_unsupported" });
		expect(r.kind).toBe("invalid");
		expect(r.message).toMatch(/can't be decided from this view/);
	});
	it("explains a request whose details are past retention", () => {
		const r = describeRefusal(409, { error: "descriptor_expired" });
		expect(r.kind).toBe("conflict");
		expect(r.message).toMatch(/past retention/);
	});
	it("asks for a re-review when the bound request changed", () => {
		const r = describeRefusal(409, { error: "descriptor_mismatch" });
		expect(r.kind).toBe("conflict");
		expect(r.message).toMatch(/changed/);
	});
	it("names the role a 403 needs", () => {
		const r = describeRefusal(403, {
			error: "role_forbidden",
			required_role: "admin",
		});
		expect(r.kind).toBe("forbidden");
		expect(r.message).toMatch(/owner or admin/);
	});
	it("tells the IP-allowlist 403 from the role 403 and the SSO 403", () => {
		expect(describeRefusal(403, { error: "admin_ip_not_allowed" }).kind).toBe(
			"ip_blocked",
		);
		expect(describeRefusal(403, { error: "sso_required" }).kind).toBe(
			"sso_required",
		);
	});
	it("423 says paused and points at Emergency", () => {
		const r = describeRefusal(423, { error: "workspace_paused" });
		expect(r.kind).toBe("paused");
		expect(r.message).toMatch(/Resume it/);
	});
	it("429 carries the wait", () => {
		expect(
			describeRefusal(429, {
				error: "control_rate_limited",
				retry_after_secs: 7,
			}).message,
		).toMatch(/7s/);
	});
	it("keeps the gateway's own field and message on 400 and 409", () => {
		const r = describeRefusal(400, {
			error: "invalid_field",
			field: "policy.limits.rpm",
			message: "rpm must be 1-10000000",
		});
		expect(r).toMatchObject({
			kind: "invalid",
			field: "policy.limits.rpm",
			message: "rpm must be 1-10000000",
		});
		expect(
			describeRefusal(409, {
				error: "project_has_keys",
				message: "2 live keys",
			}).message,
		).toBe("2 live keys");
	});
	it("a bare 404 is a missing control plane; a coded 404 is not", () => {
		expect(describeRefusal(404, null).kind).toBe("no_control_plane");
		expect(describeRefusal(404, { error: "project_not_found" }).kind).toBe(
			"other",
		);
	});
	it("a 5xx never invents detail", () => {
		expect(describeRefusal(502, { error: "gateway_unavailable" }).kind).toBe(
			"unavailable",
		);
	});
});

describe("roles", () => {
	it("derives the least role from the generated matrix", () => {
		expect(leastRole("manage_controls")).toBe("admin");
		expect(leastRole("mint_keys")).toBe("developer");
		expect(leastRole("view_spend")).toBe("viewer");
		expect(disabledReason("manage_controls")).toMatch(/owner or admin/);
	});
});

describe("policy form <-> document", () => {
	const doc = {
		models: { allow: ["gpt-4o*"], deny: ["gpt-3.5*"] },
		providers: { allow: [], deny: ["badco"] },
		source_ips: ["203.0.113.0/24"],
		max_output_tokens: 4096,
		required_tags: ["team"],
		limits: {
			rpm: 600,
			tpm: 90000,
			per_end_user: { rpm: 20 },
			per_model: [{ model: "gpt-4o*", tpm: 30000 }],
		},
		budget: {
			usd: 500,
			window: "rolling_7d",
			mode: "soft",
			alert_at_percent: [50, 80],
			alert_at_usd: [250],
		},
		end_user_budget: { usd: 5, window: "daily", mode: "hard" },
	};

	it("round-trips a full key policy exactly", () => {
		const out = formToPolicy(policyToForm(doc), "key");
		expect(out.errors).toEqual([]);
		expect(out.doc).toEqual(doc);
	});

	it("an empty form is `null` (clears the policy), not `{}`", () => {
		expect(formToPolicy(emptyPolicyForm(), "project").doc).toBeNull();
		expect(policyToForm(null)).toEqual(emptyPolicyForm());
	});

	it("a workspace policy never carries token, body or label caps", () => {
		const { doc: d } = formToPolicy(policyToForm(doc), "workspace");
		expect(d).not.toHaveProperty("max_output_tokens");
		expect(d).not.toHaveProperty("required_tags");
		expect(d).toHaveProperty("limits");
	});

	it("names the field of every bad value instead of sending it", () => {
		const f = emptyPolicyForm();
		f.rpm = "-3";
		f.tpm = "1.5";
		f.perModel = [{ model: "", rpm: "", tpm: "" }];
		f.budget = { ...newBudgetForm(), usd: "0" };
		const { doc: d, errors } = formToPolicy(f, "key");
		expect(errors.map((e) => e.field).sort()).toEqual(
			[
				"budget.usd",
				"limits.per_model.0.model",
				"limits.rpm",
				"limits.tpm",
			].sort(),
		);
		expect(d).toBeNull();
	});

	it("summarises a policy, and says so when there is none", () => {
		expect(summarizePolicy(null)).toMatch(/not restricted/);
		expect(summarizePolicy(doc)).toMatch(/600 req\/min/);
		expect(summarizePolicy(doc)).toMatch(/\$500 rolling_7d \(soft\)/);
	});
});

describe("guardrail hook routes", () => {
	it("proxies the guardrail hook routes", () => {
		const id = "11111111-1111-4111-8111-111111111111";
		expect(isProxiedControlRoute("GET", "guardrails/hooks")).toBe(true);
		expect(isProxiedControlRoute("PUT", `guardrails/hooks/${id}`)).toBe(true);
		expect(isProxiedControlRoute("DELETE", `guardrails/hooks/${id}`)).toBe(
			true,
		);
	});
	it("does not proxy broader guardrail hook paths", () => {
		for (const [verb, path] of [
			["POST", "guardrails/hooks"],
			["DELETE", "guardrails/hooks"],
			["PUT", "guardrails/hooks"],
			["GET", "guardrails/hooks/a/b"],
			["PUT", "guardrails/hooks/a/test"],
			["GET", "guardrails/hooks/..%2fkeys"],
			["PATCH", "guardrails/hooks/abc"],
		] as const) {
			expect(isProxiedControlRoute(verb, path), `${verb} ${path}`).toBe(false);
		}
	});
});

describe("describeRefusal — approver step-up (ACT-41)", () => {
	it("words the window the gateway sent", () => {
		const m = (secs: unknown) =>
			describeRefusal(403, { error: "reauth_required", max_age_secs: secs })
				.message;
		expect(m(300)).toBe(
			"Approving needs a sign-in from the last 5 minutes. Sign in again, then approve.",
		);
		expect(m(60)).toContain("from the last minute.");
		expect(m(90)).toContain("from the last 90 seconds.");
		for (const bad of [null, 0, -60, 1.5, "900", undefined]) {
			expect(m(bad)).toBe(
				"Approving needs a recent sign-in. Sign in again, then approve.",
			);
		}
	});
	it("words reauth_required as a sign-in request, not a role problem", () => {
		const r = describeRefusal(403, {
			error: "reauth_required",
			max_age_secs: 900,
		});
		expect(r.kind).toBe("reauth_required");
		expect(r.code).toBe("reauth_required");
		expect(r.message).toBe(
			"Approving needs a sign-in from the last 15 minutes. Sign in again, then approve.",
		);
		expect(r.message).not.toMatch(/role/i);
	});
	it("only a 403 carries it; other statuses keep their meaning", () => {
		expect(describeRefusal(409, { error: "reauth_required" }).kind).toBe(
			"conflict",
		);
		expect(describeRefusal(503, { error: "reauth_required" }).kind).toBe(
			"unavailable",
		);
		expect(describeRefusal(403, { error: "forbidden" }).kind).toBe("forbidden");
	});
});
