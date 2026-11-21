/**
 * POST /api/settings/action-policies — publish a protected-tool policy from a template.
 * `specs/ACT-21-policy-templates-and-coverage.md`.
 *
 * The body is template parameters, never a policy document: the document is built here by
 * `lib/policy-templates.ts` and sent to the gateway's `POST /v1/action-policies`, which
 * re-parses it, checks server ownership and the human session, and records the activation
 * in the same transaction. The tenant is the token's; nothing tenant-shaped is read from
 * the body. CSRF is the middleware's; the role is checked here as well as by the gateway.
 */

import { requireOrgAdmin } from "@/lib/admin-gate";
import { requireSession } from "@/lib/auth";
import { GatewayError, gatewayGet, gatewayPost } from "@/lib/gateway";
import {
	type ActivePolicy,
	TEMPLATES,
	type TemplateId,
	type TemplateParams,
	buildPolicyDocument,
	explainRefusal,
	findExisting,
} from "@/lib/policy-templates";
import { rateLimit } from "@/lib/rate-limit";
import { type NextRequest, NextResponse } from "next/server";

const PASS = new Set([400, 403, 404, 409, 422]);

function codeOf(
	body: Record<string, unknown> | null | undefined,
): string | null {
	const e = body?.error;
	if (typeof e === "string") return e;
	if (
		e &&
		typeof e === "object" &&
		typeof (e as { code?: unknown }).code === "string"
	)
		return (e as { code: string }).code;
	return typeof body?.code === "string" ? body.code : null;
}

function refuse(status: number, code: string): NextResponse {
	return NextResponse.json(
		{ error: code, reason: explainRefusal(code) },
		{ status },
	);
}

export async function POST(request: NextRequest): Promise<NextResponse> {
	const session = await requireSession();
	const denied = await requireOrgAdmin(session);
	if (denied)
		return refuse(
			denied.status,
			denied.status === 403 ? "forbidden" : "evidence_unavailable",
		);

	let body: {
		template?: unknown;
		server_id?: unknown;
		params?: unknown;
	} | null;
	try {
		body = (await request.json()) as typeof body;
	} catch {
		return refuse(400, "invalid_body");
	}
	const params = body?.params as TemplateParams | undefined;
	if (
		!body ||
		typeof body.template !== "string" ||
		!TEMPLATES.some((t) => t.id === body.template) ||
		typeof body.server_id !== "string" ||
		!params ||
		typeof params !== "object" ||
		typeof params.toolName !== "string"
	)
		return refuse(400, "invalid_body");

	try {
		if (!(await rateLimit(`action-policy:t:${session.tenantId}`, 10, 300_000)))
			return refuse(429, "rate_limited");
	} catch {
		return refuse(503, "rate_limit_unavailable");
	}

	let existing = null;
	try {
		const list = await gatewayGet<{ policies: ActivePolicy[] }>(
			"/v1/action-policies",
		);
		existing = findExisting(list.policies, body.server_id, params.toolName);
	} catch (err) {
		// Fail closed: without the current versions a republish could collide or regress.
		const status =
			err instanceof GatewayError && PASS.has(err.status) ? err.status : 503;
		return refuse(
			status,
			codeOf(err instanceof GatewayError ? err.body : null) ??
				"evidence_unavailable",
		);
	}

	const built = buildPolicyDocument(
		body.template as TemplateId,
		{
			amountUnit: params.amountUnit,
			toolName: params.toolName,
			limit: params.limit,
			approved: params.approved,
			approvalMinutes: params.approvalMinutes,
			args: params.args,
		},
		{
			serverId: body.server_id,
			toolRef: existing?.toolRef ?? crypto.randomUUID(),
			policyId: crypto.randomUUID(),
			existing,
		},
	);
	if (!built.ok)
		return NextResponse.json(
			{
				error: "invalid_params",
				errors: built.errors,
				reason: Object.values(built.errors)[0] ?? "Check the form.",
			},
			{ status: 422 },
		);

	try {
		const out = await gatewayPost<Record<string, unknown>>(
			"/v1/action-policies",
			built.doc,
		);
		return NextResponse.json({
			published: true,
			tool_name: params.toolName,
			policy_version: out.policy_version ?? null,
			warnings: Array.isArray(out.warnings) ? out.warnings : [],
		});
	} catch (err) {
		if (err instanceof GatewayError && PASS.has(err.status))
			return refuse(err.status, codeOf(err.body) ?? "refused");
		console.error("[action-policies] publish failed");
		return refuse(503, "evidence_unavailable");
	}
}
