/**
 * POST /api/client-errors — the browser's crash beacon (`lib/report-error.ts`).
 *
 * Writes ONE structured line per report to the Worker log, tagged `"tl":"client-error"`,
 * which `scripts/ops/web-errors.sh` queries. Unauthenticated on purpose (a crash on the
 * sign-in page must be reported too), so it trusts nothing: an 8 KB body cap, every field
 * truncated, unknown fields dropped, and it always answers 204 — an attacker learns
 * nothing and a reporter never retries.
 */
import { type NextRequest, NextResponse } from "next/server";

const MAX_BODY = 8 * 1024;
/*
 * Per-client cap (security review 2026-09-27): an unauthenticated endpoint that writes a
 * log line is a free log-write amplifier, and Worker log volume costs money. 30 reports a
 * minute per client IP, per isolate — bounded memory, a best-effort brake, not a quota.
 * A platform-protection constant, not a customer-facing limit, so it is not a §23
 * reference-table value; the reporter itself already caps a page at 10.
 */
const PER_CLIENT_PER_MINUTE = 30;
const MAX_TRACKED_CLIENTS = 5_000;
const seen = new Map<string, { windowStart: number; count: number }>();

function allow(client: string, now = Date.now()): boolean {
	const cur = seen.get(client);
	if (!cur || now - cur.windowStart >= 60_000) {
		if (seen.size >= MAX_TRACKED_CLIENTS) seen.clear();
		seen.set(client, { windowStart: now, count: 1 });
		return true;
	}
	cur.count += 1;
	return cur.count <= PER_CLIENT_PER_MINUTE;
}

/** A path, never its query string — a query can carry ids or tokens. */
function pathOnly(v: unknown): string | undefined {
	const p = field(v, 300);
	return p?.split(/[?#]/)[0];
}
const KINDS = new Set(["boundary", "global", "window", "rejection"]);

function field(v: unknown, max: number): string | undefined {
	return typeof v === "string" && v.length > 0 ? v.slice(0, max) : undefined;
}

export async function POST(req: NextRequest): Promise<NextResponse> {
	// Refuse an oversized body BEFORE buffering it (live review 2026-09-27: the 8 KB cap
	// was only checked after reading the whole body).
	const declared = Number(req.headers.get("content-length") ?? "0");
	if (declared > MAX_BODY) return new NextResponse(null, { status: 204 });
	const raw = await req.text().catch(() => "");
	const client =
		req.headers.get("cf-connecting-ip") ??
		req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
		"unknown";
	if (raw.length > 0 && raw.length <= MAX_BODY && allow(client)) {
		try {
			const b = JSON.parse(raw) as Record<string, unknown>;
			const kind =
				typeof b.kind === "string" && KINDS.has(b.kind) ? b.kind : "unknown";
			console.error(
				JSON.stringify({
					tl: "client-error",
					kind,
					message: field(b.message, 500),
					stack: field(b.stack, 2000),
					digest: field(b.digest, 64),
					path: pathOnly(b.path),
					ua: field(req.headers.get("user-agent"), 200),
				}),
			);
		} catch {
			// Not JSON — dropped silently; a malformed beacon is not an error worth a line.
		}
	}
	return new NextResponse(null, { status: 204 });
}
