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
      "INSERT INTO notifications (email, source, ip_country, user_agent) VALUES (?, ?, ?, ?) ON CONFLICT(email) DO NOTHING"
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
 * ADR-074 §10 scopes the consolidated site to Home · Pricing · Security & Trust ·
 * Privacy · Terms. Three URLs that are LIVE AND INDEXED today fall outside it —
 * `/changelog/`, `/docs/` and `/vs/langsmith-engine/` were in the sitemap — so dropping
 * the pages without redirects would turn three indexed URLs into 404s and throw away
 * whatever ranking they carry. A 301 keeps the link equity and tells crawlers where it
 * went; a 404 tells them the site got smaller.
 *
 * `/docs/` goes to the real docs host, which is served by Mintlify — not by this Worker.
 */
const GONE_TO: Record<string, string> = {
  "/changelog": "/",
  "/docs": "https://docs.tracelane.dev/",
  "/vs/langsmith-engine": "/",
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
  return target.startsWith("http") ? target : new URL(target, url.origin).toString();
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
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
    return env.ASSETS.fetch(request);
  },
};
