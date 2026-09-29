/**
 * Next.js instrumentation — runs ONCE at server boot (Node runtime), before any
 * request is served. Used ONLY to stand up the in-process E2E database when the
 * dev/test auth bypass is active, so the L16 launch-gate webServer boots without
 * Neon. Everything is dynamic-imported behind `e2eAuthEnabled()` so a production
 * build never loads PGlite or the E2E DB module.
 */
export async function register(): Promise<void> {
	// Next runs instrumentation in BOTH the Node and the Edge runtimes (Edge for
	// middleware). `lib/e2e-db.ts` imports `node:fs` + PGlite, which the Edge
	// runtime cannot compile — so the import MUST be unreachable in the Edge build
	// or the whole webServer fails to boot. `NEXT_RUNTIME` and `NODE_ENV` are both
	// inlined per-build, so these two guards dead-code-eliminate the
	// `import("@/lib/e2e-db")` chunk out of (a) the Edge instrumentation bundle and
	// (b) any production build — keeping node:fs + PGlite strictly in the dev/test
	// Node bundle (security review HIGH + the Edge-runtime boot fix).
	if (process.env.NEXT_RUNTIME !== "nodejs") return;
	if (process.env.NODE_ENV === "production") return;
	const { e2eAuthEnabled } = await import("@/lib/e2e-auth");
	if (!e2eAuthEnabled()) return;
	const { setupE2EDb } = await import("@/lib/e2e-db");
	await setupE2EDb();
}

/**
 * Every error a request hits on the SERVER leaves one structured line in the Worker log,
 * tagged `"tl":"server-error"` (2026-09-27, launch readiness) — counted by
 * `scripts/ops/web-errors.sh`. Next 15 calls this for route handlers, server components,
 * actions and middleware. Never throws.
 */
export async function onRequestError(
	err: unknown,
	request: { path: string; method: string },
	context: { routePath?: string; routeType?: string },
): Promise<void> {
	try {
		const e = err as { message?: unknown; digest?: unknown };
		console.error(
			JSON.stringify({
				tl: "server-error",
				message: String(e?.message ?? err).slice(0, 500),
				digest:
					typeof e?.digest === "string" ? e.digest.slice(0, 64) : undefined,
				method: request.method,
				// Path without the query string — a query can carry ids a person typed.
				path: request.path.split("?")[0]?.slice(0, 300),
				route: context.routePath,
				type: context.routeType,
			}),
		);
	} catch {
		// Never throw from the error hook.
	}
}
