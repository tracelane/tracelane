/**
 * OG-60 — ONE typed relay from the dashboard's Gateway settings to the gateway's control
 * routes (`specs/OG-60-openapi-and-gateway-settings.md` §2 Part B). ADR-042: the dashboard
 * reads and writes only through gateway `/v1/*`, with the signed-in user's token.
 *
 * It is a relay, not a tunnel:
 *  - only `(verb, path)` pairs in `CONTROL_PROXY_ROUTES` are reachable — anything else is
 *    404 before a token is minted;
 *  - the tenant is the token's, never a path or body field;
 *  - a gateway refusal keeps its status and the typed fields the page needs to word it
 *    (`error`, `message`, `field`, `required_role`, `retry_after_secs`, the lock-out
 *    `your_ip`), and nothing else; a 5xx other than 503 is masked as 502.
 * The gateway stays authoritative on role, allowlist, SSO and every value.
 */
import { requireGatewayToken } from "@/lib/auth";
import { gatewayResponse } from "@/lib/gateway";
import { isProxiedControlRoute } from "@/lib/gateway-controls";
import { type NextRequest, NextResponse } from "next/server";

const MAX_BODY_BYTES = 64 * 1024;
const RELAYED_ERROR_FIELDS = [
	"error",
	"message",
	"field",
	"required_role",
	"capability",
	"retry_after_secs",
	"reason",
	"your_ip",
	"your_ip_attested",
	"delivered",
] as const;

const noStore = { "cache-control": "no-store" };

async function relay(upstream: Response): Promise<NextResponse> {
	const retryAfter = upstream.headers.get("retry-after");
	if (upstream.ok) {
		if (upstream.status === 204) {
			return new NextResponse(null, { status: 204, headers: noStore });
		}
		const headers = new Headers(noStore);
		for (const h of ["content-type", "content-disposition"]) {
			const v = upstream.headers.get(h);
			if (v) headers.set(h, v);
		}
		return new NextResponse(upstream.body, {
			status: upstream.status,
			headers,
		});
	}
	const parsed = (await upstream.json().catch(() => null)) as Record<
		string,
		unknown
	> | null;
	if (upstream.status >= 500 && upstream.status !== 503) {
		return NextResponse.json(
			{ error: "gateway_unavailable" },
			{ status: 502, headers: noStore },
		);
	}
	const body: Record<string, unknown> = {};
	for (const k of RELAYED_ERROR_FIELDS) {
		const v = parsed?.[k];
		if (
			typeof v === "string" ||
			typeof v === "number" ||
			typeof v === "boolean"
		) {
			body[k] = v;
		}
	}
	const headers = new Headers(noStore);
	if (retryAfter) headers.set("retry-after", retryAfter);
	return NextResponse.json(body, { status: upstream.status, headers });
}

function sameOrigin(req: NextRequest): boolean {
	if (req.headers.get("sec-fetch-site") === "same-origin") return true;
	const origin = req.headers.get("origin");
	return origin !== null && origin === req.nextUrl.origin;
}

function isJson(contentType: string | null): boolean {
	return (
		contentType?.split(";")[0]?.trim().toLowerCase() === "application/json"
	);
}

async function handle(
	req: NextRequest,
	ctx: { params: Promise<{ path: string[] }> },
): Promise<NextResponse> {
	const { path } = await ctx.params;
	const verb = req.method;
	const joined = path.join("/");
	if (!isProxiedControlRoute(verb, joined)) {
		return NextResponse.json({ error: "not_proxied" }, { status: 404 });
	}
	// A state-changing call must come from our own pages (L2, security review
	// 2026-10-05). Positive proof only: `Sec-Fetch-Site: same-origin` (set by the browser,
	// unforgeable by page script) OR an `Origin` equal to this app's. A request carrying
	// NEITHER used to pass as "a non-browser client" — but an older browser or an
	// intermediary that strips the header also sends cookies. Absent is refused.
	if (verb !== "GET" && !sameOrigin(req)) {
		return NextResponse.json({ error: "cross_site" }, { status: 403 });
	}
	// Auth first: an unauthenticated caller is redirected before any body handling.
	await requireGatewayToken();

	const target = `/v1/${joined}${req.nextUrl.search}`;
	if (verb === "GET" || verb === "DELETE") {
		return relay(await gatewayResponse(target, { method: verb }));
	}
	const text = await req.text();
	// A body must be declared JSON: a cross-site `<form>` can only send simple content
	// types (L2), and the gateway is sent `application/json` regardless.
	if (text.trim() !== "" && !isJson(req.headers.get("content-type"))) {
		return NextResponse.json(
			{ error: "unsupported_media_type" },
			{ status: 415 },
		);
	}
	if (text.length > MAX_BODY_BYTES) {
		return NextResponse.json({ error: "body_too_large" }, { status: 400 });
	}
	if (text.trim() !== "") {
		try {
			const v: unknown = JSON.parse(text);
			if (v === null || typeof v !== "object" || Array.isArray(v)) {
				return NextResponse.json({ error: "invalid_body" }, { status: 400 });
			}
		} catch {
			return NextResponse.json({ error: "invalid_body" }, { status: 400 });
		}
	}
	return relay(
		await gatewayResponse(target, {
			method: verb,
			headers: { "content-type": "application/json" },
			body: text.trim() === "" ? "{}" : text,
		}),
	);
}

export const GET = handle;
export const PUT = handle;
export const POST = handle;
export const PATCH = handle;
export const DELETE = handle;
