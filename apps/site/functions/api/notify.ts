/**
 * Worker entrypoint for tracelane-site.
 *
 * Host routing:
 *   docs.tracelane.dev      → docs stub HTML (compile-time embedded)
 *   tracelane.dev (+ www)   → static assets from /dist (via env.ASSETS)
 *
 * Path routing on apex:
 *   POST /api/notify        → capture email into D1
 *   *                       → static assets
 */

interface Env {
	DB: D1Database;
	ASSETS: Fetcher;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

interface NotifyBody {
	email?: unknown;
}

const json = (data: unknown, status = 200): Response =>
	new Response(JSON.stringify(data), {
		status,
		headers: { "Content-Type": "application/json" },
	});

async function handleNotify(request: Request, env: Env): Promise<Response> {
	if (request.method !== "POST") {
		return json({ error: "method not allowed" }, 405);
	}

	try {
		const body = (await request.json().catch(() => ({}))) as NotifyBody;
		const rawEmail = typeof body.email === "string" ? body.email : "";
		const email = rawEmail.trim().toLowerCase();

		if (!EMAIL_RE.test(email) || email.length > 254) {
			return json({ error: "invalid email" }, 400);
		}

		const country = request.headers.get("cf-ipcountry") ?? null;
		const userAgentHeader = request.headers.get("user-agent");
		const userAgent = userAgentHeader ? userAgentHeader.slice(0, 255) : null;

		await env.DB.prepare(
			"INSERT INTO notifications (email, source, ip_country, user_agent) VALUES (?, ?, ?, ?) ON CONFLICT(email) DO NOTHING",
		)
			.bind(email, "landing", country, userAgent)
			.run();

		return json({ ok: true });
	} catch {
		return json({ error: "server error" }, 500);
	}
}

/**
 * Retired paths and host normalisation, as real 301s.
 *
 * ADR-074 §10 scoped the consolidated site to Home · Pricing · Security & Trust ·
 * Privacy · Terms. Two of the three previously-indexed URLs outside that scope still
 * redirect; `/changelog` was reinstated as a real page on 2026-09-07 (founder request,
 * see the supersession note in ADR-074 §10) — its redirect entry is deleted here.
 *
 * `/docs/` goes to the real docs host, which is served by Mintlify — not by this Worker.
 */
const GONE_TO: Record<string, string> = {
	"/docs": "https://docs.tracelane.dev/",
	"/vs/langsmith-engine": "/",
	// SITE-04 (2026-09-29): the four /product/<section> pages (2026-09-27) were folded into
	// one /product page; each old URL lands on its own section.
	"/product/gateway": "/product#gateway",
	"/product/observability": "/product#observability",
	"/product/audit": "/product#audit",
	"/product/evals": "/product#evals",
};

const APEX = "tracelane.dev";

export function resolveRedirect(host: string, url: URL): string | null {
	// www → apex. Verified live 2026-08-15: www returned 200 with NO redirect, so it has
	// been a duplicate-content surface. Only rel=canonical was holding the line.
	if (host === `www.${APEX}`) {
		const to = new URL(url.toString());
		to.hostname = APEX;
		return to.toString();
	}
	const path = url.pathname.replace(/\/+$/, "") || "/";
	const target = GONE_TO[path];
	if (!target) return null;
	return target.startsWith("http")
		? target
		: new URL(target, url.origin).toString();
}

/**
 * B-588: answer a byte-range request for a static asset. The static-asset handler
 * returns 200 + the whole file to a `Range` request, and Safari / iOS refuse to play
 * an mp4 served that way. RFC 9110 §14: one range per request (a video element never
 * asks for more), `bytes=a-b` / `bytes=a-` / `bytes=-n`, an end past the file is
 * clamped, a start past it is 416. Anything unparsable is served whole, as the spec
 * allows. A non-200 asset passes through untouched.
 */
export async function serveRange(
	request: Request,
	asset: Response,
): Promise<Response> {
	if (asset.status !== 200) return asset;
	const bytes = new Uint8Array(await asset.arrayBuffer());
	const size = bytes.length;
	const headers = new Headers(asset.headers);
	headers.set("accept-ranges", "bytes");
	const noBody = request.method === "HEAD";
	const m = /^bytes=(\d*)-(\d*)$/.exec(request.headers.get("range")?.trim() ?? "");
	if (!m || (m[1] === "" && m[2] === "")) {
		headers.set("content-length", String(size));
		return new Response(noBody ? null : bytes, { status: 200, headers });
	}
	let start: number;
	let end: number;
	if (m[1] === "") {
		start = Math.max(0, size - Number(m[2]));
		end = size - 1;
	} else {
		start = Number(m[1]);
		end = m[2] === "" ? size - 1 : Math.min(Number(m[2]), size - 1);
	}
	if (start >= size || start > end) {
		return new Response(null, {
			status: 416,
			headers: { "content-range": `bytes */${size}`, "accept-ranges": "bytes" },
		});
	}
	headers.set("content-range", `bytes ${start}-${end}/${size}`);
	headers.set("content-length", String(end - start + 1));
	return new Response(noBody ? null : bytes.slice(start, end + 1), {
		status: 206,
		headers,
	});
}

export default {
	async fetch(
		request: Request,
		env: Env,
		_ctx: ExecutionContext,
	): Promise<Response> {
		const url = new URL(request.url);
		const host = url.hostname.toLowerCase();

		// REDIRECTS — real 301s, issued by the Worker before the asset fetch.
		//
		// WHY HERE AND NOT `_redirects`: this is a Worker with a static-assets binding,
		// not Cloudflare Pages. `public/_redirects` is a PAGES feature and is inert here —
		// which is exactly the bug this replaces. `README-DEPLOY.md` claimed
		// "www.tracelane.dev — will follow the _redirects 301 to apex"; the live check
		// returned 200 with zero redirects, so www has been serving duplicate content.
		const redirect = resolveRedirect(host, url);
		if (redirect) {
			return Response.redirect(redirect, 301);
		}

		// Apex/www routes
		if (url.pathname === "/api/notify") {
			return handleNotify(request, env);
		}

		// Static assets. Guarded: if the ASSETS binding is ever missing, an
		// unguarded call turns every asset-miss path into a Worker exception
		// (CF 1101) rather than a 404.
		if (!env.ASSETS) {
			return new Response("Not found", { status: 404 });
		}
		// B-588: video needs byte ranges; `run_worker_first` routes *.mp4 here.
		if (url.pathname.endsWith(".mp4")) {
			const asset = await env.ASSETS.fetch(
				new Request(url.toString(), { method: "GET" }),
			);
			return serveRange(request, asset);
		}
		return env.ASSETS.fetch(request);
	},
};
