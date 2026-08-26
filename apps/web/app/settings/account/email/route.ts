/**
 * POST /settings/account/email — self-serve email change (SET-26).
 *
 * Before this, `apps/web/app/api/settings/account/route.ts` accepted a body of
 * `{ name }` only and the account page rendered the address in a `readOnly`
 * input: changing an email was a support ticket. This handler makes it
 * self-serve, and is co-located with the page that calls it
 * (`app/settings/account/page.tsx` → `components/settings/EmailChangeForm.tsx`)
 * so the surface and its only caller live together.
 *
 * ## What actually changes
 *
 * WorkOS is the identity system of record (IDENTITY_TEAM_SPEC principle #1), so
 * the change is a `PUT /user_management/users/:id` carrying `email` **and**
 * `email_verified: false`. Both fields matter:
 *
 *   - `email` is the change itself. The WorkOS SDK's `SerializedUpdateUserOptions`
 *     confirms the field is accepted (`@workos-inc/node@9.2.0`,
 *     `lib/workos-*.d.mts:2044-2055`), so this is not a hopeful extra key.
 *   - `email_verified: false` is what makes the flow safe. The *old* address is
 *     proved by the live session plus retyping it (`validate.ts`); the *new*
 *     address is proved by WorkOS, which will not treat it as verified until the
 *     user completes verification. Without this the handler would trust an
 *     address nobody has demonstrated they can receive mail at.
 *
 * A verification mail is then requested for the new address so the user is not
 * left waiting for their next sign-in to discover the step exists.
 *
 * ## Why the response is re-read
 *
 * A silently-ignored request field is the classic green-while-broken shape: the
 * API 200s, we report success, and the address never moved. So the handler
 * asserts the DISCRIMINATING field — the `email` on the returned user — equals
 * what was asked for. If it does not, the request FAILS (502
 * `workos_email_unchanged`) and nothing is mirrored. A 200 is not proof.
 *
 * ## Failure directions
 *
 * - Auth, validation, confirmation, and the read-back check: **fail CLOSED** —
 *   no change is reported unless WorkOS positively shows the new address.
 * - The Postgres mirror write, the verification mail and the audit row:
 *   **fail OPEN** — WorkOS already holds the truth, and a cache/notification
 *   blip must not tell the user their completed change failed.
 */

import { db } from "@/db";
import { tenants, users } from "@/db/schema";
import { ipFromRequest, recordAdminAction } from "@/lib/admin-audit";
import { requireSession } from "@/lib/auth";
import { rateLimit } from "@/lib/rate-limit";
import { eq } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";
import { validateEmailChange } from "./validate";

const WORKOS = "https://api.workos.com";

/** Per-user attempt cap. An email change is a rare, deliberate act; a burst of
 * them is either a typo storm or someone probing which addresses are taken. */
const ATTEMPT_LIMIT = 5;
const ATTEMPT_WINDOW_MS = 15 * 60_000;

/** Map validation failures onto status codes. 422 = the request was understood
 * and refused; nothing here is a 400 except unparseable JSON. */
const STATUS_FOR: Record<string, number> = {
	invalid_json: 400,
	email_required: 422,
	email_invalid: 422,
	email_too_long: 422,
	confirmation_mismatch: 422,
	current_email_mismatch: 422,
	email_unchanged: 422,
};

/**
 * True when a failed WorkOS update means "that address belongs to another
 * account". WorkOS signals this as `email_not_available`; the envelope has
 * varied between a top-level `code` and an `errors[]` entry, so the whole
 * serialized body is searched rather than one guessed field.
 */
function isAddressTaken(status: number, body: string): boolean {
	return (
		(status === 409 || status === 422 || status === 400) &&
		body.includes("email_not_available")
	);
}

/**
 * Change the caller's own email address.
 *
 * The target user is ALWAYS `session.userId` — the body carries addresses, never
 * an identity. There is deliberately no admin path to change someone else's
 * address here.
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
	const key = process.env.WORKOS_API_KEY;
	if (!key) {
		return NextResponse.json(
			{ error: "WorkOS API not configured" },
			{ status: 501 },
		);
	}
	const session = await requireSession();

	if (
		!rateLimit(
			`email-change:${session.userId}`,
			ATTEMPT_LIMIT,
			ATTEMPT_WINDOW_MS,
		)
	) {
		return NextResponse.json(
			{
				error: "rate_limited",
				detail: "too many attempts — try again in a few minutes",
			},
			{ status: 429 },
		);
	}

	let raw: unknown;
	try {
		raw = await request.json();
	} catch {
		return NextResponse.json(
			{ error: "invalid_json", detail: "request body must be JSON" },
			{ status: 400 },
		);
	}

	// The current address comes from the validated session — never the body.
	const parsed = validateEmailChange(raw, session.email);
	if (!parsed.ok) {
		return NextResponse.json(
			{ error: parsed.error, detail: parsed.detail },
			{ status: STATUS_FOR[parsed.error] ?? 422 },
		);
	}
	const { newEmail } = parsed.value;

	const res = await fetch(
		`${WORKOS}/user_management/users/${encodeURIComponent(session.userId)}`,
		{
			method: "PUT",
			headers: {
				Authorization: `Bearer ${key}`,
				"Content-Type": "application/json",
			},
			// email_verified:false — the new address is untrusted until proved.
			body: JSON.stringify({ email: newEmail, email_verified: false }),
		},
	).catch(() => null);

	if (!res) {
		return NextResponse.json(
			{
				error: "workos_unreachable",
				detail: "could not reach the identity provider",
			},
			{ status: 502 },
		);
	}
	if (!res.ok) {
		const body = await res.text().catch(() => "");
		if (isAddressTaken(res.status, body)) {
			return NextResponse.json(
				{
					error: "email_not_available",
					detail: "that address is already in use",
				},
				{ status: 409 },
			);
		}
		// The status is our own numeric field, not customer-controlled text, so it
		// needs no log sanitising — and the response BODY is deliberately not
		// logged: a provider error body is exactly where a credential echo lands.
		console.error("[account/email] workos update failed, status", res.status);
		return NextResponse.json(
			{ error: "workos_update_failed", detail: "the change was not applied" },
			{ status: 502 },
		);
	}

	// Read back the DISCRIMINATING field. A 200 whose user still carries the old
	// address means the field was ignored — that is a failure, not a success.
	const updated = (await res.json().catch(() => null)) as {
		email?: unknown;
	} | null;
	const applied =
		typeof updated?.email === "string" ? updated.email.toLowerCase() : null;
	if (applied !== newEmail) {
		console.error(
			"[account/email] workos accepted the call but did not move the address",
		);
		return NextResponse.json(
			{
				error: "workos_email_unchanged",
				detail:
					"the identity provider accepted the request but the address did not change",
			},
			{ status: 502 },
		);
	}

	// ---- past this point the change HAS happened; everything below fails open --

	// Ask WorkOS to mail the verification code to the NEW address now, rather
	// than leaving the user to discover the step at their next sign-in.
	let verificationSent = false;
	try {
		const v = await fetch(
			`${WORKOS}/user_management/users/${encodeURIComponent(session.userId)}/email_verification/send`,
			{ method: "POST", headers: { Authorization: `Bearer ${key}` } },
		);
		verificationSent = v.ok;
	} catch {
		// Non-fatal: signing in again re-triggers verification.
	}

	// Mirror into the `users` cache. WorkOS stays authoritative.
	try {
		await db
			.update(users)
			.set({ email: newEmail })
			.where(eq(users.workosUserId, session.userId));
	} catch {
		console.error(
			"[account/email] mirror update failed — WorkOS is authoritative",
		);
	}

	// Security-relevant: an email change is the account-recovery path moving.
	// Record which address it moved to; that is the field an investigation needs.
	try {
		const [t] = await db
			.select({ id: tenants.id })
			.from(tenants)
			.where(eq(tenants.workosOrgId, session.tenantId))
			.limit(1);
		await recordAdminAction({
			actorUserId: session.userId,
			actorWorkspaceId: t?.id ?? null,
			action: "account.email.change",
			targetType: "user",
			targetId: session.userId,
			beforeJson: { email: session.email },
			afterJson: { email: newEmail, email_verified: false },
			ipAddr: ipFromRequest(request),
			userAgent: request.headers.get("user-agent"),
		});
	} catch {
		console.error("[account/email] audit record failed");
	}

	return NextResponse.json(
		{ email: newEmail, verificationSent, reauthRequired: true },
		{ status: 200 },
	);
}
