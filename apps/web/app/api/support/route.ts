/**
 * POST /api/support — persist an in-product support message from the dashboard
 * "Reach out" widget (Question / Feedback / Bug / Feature request).
 *
 * `requireSession()` supplies the actor (WorkOS user + org) — never a body
 * field, so a request can't spoof who it's from. The row is written directly
 * via Drizzle (control-plane data, not ClickHouse). `kind` is checked against a
 * fixed allowlist and `message` is bounded to 5000 chars.
 */

import { db } from "@/db";
import { supportRequests } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { SUPPORT_AREAS, SUPPORT_KINDS } from "@/lib/support-taxonomy";
import { NextResponse } from "next/server";

const KINDS = new Set<string>(SUPPORT_KINDS.map((k) => k.key));
const MAX_MESSAGE = 5000;

/**
 * Broad product area, so a request lands with routing context instead of just
 * "Bug". Stored as a labeled first line of `message` — `support_requests` has no
 * `category` column and this needs no migration; promote it to its own column if
 * we ever want to aggregate on it.
 *
 * Keyed by the stable `key` (what the client sends); the value is the human
 * LABEL, because a support inbox reading "[area: gateway]" made the operator
 * decode the key by hand. An unrecognised category is not an error — the
 * ticket still matters without one — so it is silently dropped rather than
 * rejecting the whole request (widened founder, 2026-09-07: 7 → 14 areas,
 * same soft-drop behaviour, same allowlist source as the client dropdown).
 */
const CATEGORY_LABELS = new Map<string, string>(
	SUPPORT_AREAS.map((a) => [a.key, a.label]),
);

/**
 * Human ticket reference derived from the row's UUID primary key — no extra
 * column, stable, and short enough to quote in an email. e.g. "TL-8F3A21C4".
 */
function ticketRef(id: string): string {
	return `TL-${id.replace(/-/g, "").slice(0, 8).toUpperCase()}`;
}

export async function POST(req: Request) {
	const session = await requireSession();

	let body: unknown;
	try {
		body = await req.json();
	} catch {
		return NextResponse.json({ error: "invalid_json" }, { status: 400 });
	}
	const { kind, message, category } = (body ?? {}) as {
		kind?: unknown;
		message?: unknown;
		category?: unknown;
	};

	if (typeof kind !== "string" || !KINDS.has(kind)) {
		return NextResponse.json(
			{
				error: "invalid_kind",
				expected: SUPPORT_KINDS.map((k) => k.key).join("|"),
			},
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

	// The human label, not the raw key — see CATEGORY_LABELS above.
	const areaLabel =
		typeof category === "string" ? CATEGORY_LABELS.get(category) : undefined;
	const stored = areaLabel ? `[area: ${areaLabel}]\n${text}` : text;

	const [row] = await db
		.insert(supportRequests)
		.values({
			workosOrgId: session.tenantId,
			workosUserId: session.userId,
			email: session.email,
			kind,
			message: stored,
		})
		.returning({ id: supportRequests.id });

	// Give the user something quotable. Falls back to ok-only if the driver
	// returned no row (never expected) rather than failing a saved request.
	return NextResponse.json(
		row ? { ok: true, ref: ticketRef(row.id) } : { ok: true },
		{ status: 201 },
	);
}

// Writes Postgres at request time — never prerender.
export const dynamic = "force-dynamic";
