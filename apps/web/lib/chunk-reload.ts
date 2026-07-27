/**
 * Self-heal for client↔server VERSION SKEW.
 *
 * When a new build ships while a browser still holds the PREVIOUS build's
 * chunks, a client-side navigation can throw a chunk-load / dynamic-import
 * failure — the RSC payload (or a lazily-imported component) references chunk
 * hashes the stale client cannot resolve. A hard reload fetches the fresh build
 * and the error is gone. So the error boundary reloads ONCE on a chunk error
 * instead of stranding the user on "Something went wrong".
 *
 * Stale clients exist at EVERY deploy (a user with a tab open when we ship), so
 * this is the standard, cheap, durable mitigation — paired with the
 * authenticated deploy smoke that DETECTS a real render break. Loop-guarded: if
 * a reload was already attempted within {@link LOOP_WINDOW_MS} (the reload did
 * NOT fix it → a genuine error, not skew), fall through to the normal boundary
 * so we never hard-loop the tab.
 *
 * Called from `app/error.tsx` and `app/global-error.tsx`.
 */

const RELOAD_TS_KEY = "tl_chunk_reload_ts";
const LOOP_WINDOW_MS = 10_000;

/** True if `error` looks like a build-skew chunk-load / dynamic-import failure. */
export function isChunkLoadError(error: unknown): boolean {
	if (!(error instanceof Error)) return false;
	if (error.name === "ChunkLoadError") return true;
	const m = error.message;
	return (
		/loading chunk [\w-]+ failed/i.test(m) ||
		/failed to fetch dynamically imported module/i.test(m) ||
		/error loading dynamically imported module/i.test(m) ||
		/importing a module script failed/i.test(m) ||
		/chunkloaderror/i.test(m)
	);
}

/**
 * If `error` is a chunk-load/skew error, trigger a ONE-TIME hard reload and
 * return `true` (the caller renders a minimal "updating…" state, not the alarm).
 * Returns `false` for non-chunk errors, during SSR (no `window`), or when a
 * reload was already attempted in the last {@link LOOP_WINDOW_MS} (loop guard) —
 * the caller then renders the normal error boundary.
 */
export function reloadOnChunkError(error: unknown): boolean {
	if (typeof window === "undefined") return false;
	if (!isChunkLoadError(error)) return false;
	try {
		const now = Date.now();
		const last = Number(window.sessionStorage.getItem(RELOAD_TS_KEY) ?? "0");
		if (now - last < LOOP_WINDOW_MS) return false; // recent reload didn't help → not skew
		window.sessionStorage.setItem(RELOAD_TS_KEY, String(now));
	} catch {
		// sessionStorage blocked (private mode) — still reload once, unguarded.
	}
	window.location.reload();
	return true;
}
