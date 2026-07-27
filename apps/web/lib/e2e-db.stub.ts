/**
 * Prod-build stub for `lib/e2e-db.ts` (the PGlite dev/test launch-gate harness).
 *
 * The real module statically imports `node:fs`/`node:path` + PGlite + drizzle's
 * pglite migrator (which pulls `node:crypto`). Those `node:` schemes cannot compile
 * in the Cloudflare Worker / Edge webpack build (`UnhandledSchemeError`), and
 * webpack builds the dynamic-import() chunk at parse time regardless of the runtime
 * `NODE_ENV`/`NEXT_RUNTIME` guards in `instrumentation.ts`.
 *
 * So `next.config.ts` swaps this stub in for `e2e-db` in the PROD webpack build only
 * (dev uses Turbopack, which loads the real module for the L16 gate). Prod never
 * calls `setupE2EDb` — instrumentation returns early in production — so a no-op is
 * correct; the stub exists purely to keep `node:*` out of the Worker bundle.
 */
export async function setupE2EDb(): Promise<void> {}
