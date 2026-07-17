/**
 * POST /api/support — persist an in-product support message from the dashboard
 * "Reach out" widget (Question / Feedback / Bug).
 *
 * `requireSession()` supplies the actor (WorkOS user + org) — never a body
 * field, so a request can't spoof who it's from. The row is written directly
 * via Drizzle (control-plane data, not ClickHouse). `kind` is checked against a
 * fixed allowlist and `message` is bounded to 5000 chars.
 */

import { db } from "@/db";
import { supportRequests } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { NextResponse } from "next/server";

const KINDS = new Set(["query", "feedback", "bug"]);
const MAX_MESSAGE = 5000;

export async function POST(req: Request) {
	const session = await requireSession();

	let body: unknown;
	try {
		body = await req.json();
	} catch {
		return NextResponse.json({ error: "invalid_json" }, { status: 400 });
	}
	const { kind, message } = (body ?? {}) as {
		kind?: unknown;
		message?: unknown;
	};

	if (typeof kind !== "string" || !KINDS.has(kind)) {
		return NextResponse.json(
			{ error: "invalid_kind", expected: "query|feedback|bug" },
			{ status: 400 },
		);
	}
	const text = typeof message === "string" ? message.trim() : "";
	if (text.length === 0 || text.length > MAX_MESSAGE) {
		return NextResponse.json(
			{ error: "invalid_message", max: MAX_MESSAGE },
			{ status: 400 },
		);
	}

	await db.insert(supportRequests).values({
		workosOrgId: session.tenantId,
		workosUserId: session.userId,
		email: session.email,
		kind,
		message: text,
	});

	return NextResponse.json({ ok: true }, { status: 201 });
}

// Writes Postgres at request time — never prerender.
export const dynamic = "force-dynamic";
