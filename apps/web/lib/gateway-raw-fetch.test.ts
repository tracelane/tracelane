/**
 * Structural guard (OG-36 M4): every gateway call from the dashboard goes
 * through the `lib/gateway.ts` helpers, which attach the signed client-IP
 * attestation (`x-tracelane-client-ip-attestation`).
 *
 * Why it matters: the dashboard runs on a Cloudflare Worker, so a raw
 * `fetch(`${gatewayBaseUrl()}/v1/...`)` reaches the gateway from the WORKER's
 * address. Under a workspace admin IP allowlist that request is refused 403 —
 * and the "fix" an admin would reach for is allowlisting a shared Cloudflare
 * Workers address, which admits anyone who can run a Worker. The helpers sign
 * the browser's address instead (`lib/client-ip-attestation.ts`).
 *
 * The rule, checked over every source file under app/, lib/ and components/:
 *   1. a file that builds a gateway URL (`gatewayBaseUrl`) AND calls `fetch(`
 *      must be listed in RAW_FETCH_EXEMPT with a reason; and
 *   2. no exempt file may name ANY path in the gateway's control-route registry
 *      (`crates/gateway/src/auth/capability.rs` `CONTROL_ROUTES`, parsed here,
 *      not copied) — the admin plane is exactly what the attestation exists for.
 * Plus: an exemption that no longer raw-fetches is stale and fails (so the list
 * cannot silently outlive its reason).
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const WEB_ROOT = fileURLToPath(new URL("..", import.meta.url));
const REPO_ROOT = join(WEB_ROOT, "..", "..");
const SCAN_DIRS = ["app", "lib", "components"];

/**
 * Raw gateway fetches that are deliberately NOT routed through the helpers.
 * Every entry must call no control route (rule 2 proves it).
 */
const RAW_FETCH_EXEMPT: Record<string, string> = {
	"app/api/health/deep/route.ts":
		"unauthenticated /health probe — no bearer token to bind an attestation to",
	"app/api/healthz/route.ts":
		"unauthenticated /health probe — no bearer token to bind an attestation to",
	"app/s/[token]/page.tsx":
		"public share-link read (/v1/share/{token}) — no session, no admin plane",
	"app/audit/trust-root.ts":
		"public platform pubkey read — no session, no admin plane",
	"app/api/tara/route.ts":
		"inference (/v1/chat/completions) streamed — not an admin-plane call",
	"app/api/playground/route.ts":
		"inference (/v1/chat/completions) streamed — not an admin-plane call",
	"app/api/prompts/[name]/route.ts":
		"prompt registry read/write — not in CONTROL_ROUTES",
	"app/api/prompts/[name]/versions/route.ts":
		"prompt registry write — not in CONTROL_ROUTES",
	"app/api/prompts/[name]/promote/route.ts":
		"prompt promote — not in CONTROL_ROUTES",
	"app/api/prompts/[name]/canary/route.ts":
		"prompt canary — not in CONTROL_ROUTES",
	"app/api/billing/usage/route.ts": "read-only usage — not in CONTROL_ROUTES",
	"app/api/billing/window-breakdown/route.ts":
		"read-only usage breakdown — not in CONTROL_ROUTES",
	"app/api/traces/export/route.ts":
		"streamed trace export (read) — not in CONTROL_ROUTES",
	"app/api/audit/export/route.ts":
		"streamed audit export (read) — not in CONTROL_ROUTES",
};

function walk(dir: string, out: string[]): void {
	for (const name of readdirSync(dir)) {
		if (name === "node_modules" || name === ".next") continue;
		const p = join(dir, name);
		if (statSync(p).isDirectory()) walk(p, out);
		else if (
			/\.(ts|tsx)$/.test(name) &&
			!/\.test\.tsx?$/.test(name) &&
			!name.endsWith(".d.ts")
		)
			out.push(p);
	}
}

/** Source files (relative to apps/web) that raw-fetch the gateway base URL. */
function rawGatewayFetchers(files: Map<string, string>): string[] {
	const hits: string[] = [];
	for (const [rel, src] of files) {
		if (rel === "lib/gateway.ts") continue; // the helpers themselves
		if (/\bgatewayBaseUrl\b/.test(src) && /\bfetch\s*\(/.test(src)) {
			hits.push(rel);
		}
	}
	return hits.sort();
}

/** `/v1/...` paths named in a TS source, `${…}` and `{name}` normalised to `{}`. */
function v1Paths(src: string): Set<string> {
	const flat = src.replace(/\$\{[^}]*\}/g, "{}");
	const out = new Set<string>();
	for (const m of flat.matchAll(/\/v1\/[A-Za-z0-9_\-/{}.]+/g)) {
		out.add(m[0].replace(/\/+$/, ""));
	}
	return out;
}

/** Paths in the gateway's CONTROL_ROUTES registry, `{name}` normalised to `{}`. */
function controlRoutePaths(rust: string): Set<string> {
	const start = rust.indexOf("pub const CONTROL_ROUTES");
	const end = rust.indexOf("];", start);
	if (start < 0 || end < 0) throw new Error("CONTROL_ROUTES not found");
	const out = new Set<string>();
	for (const m of rust
		.slice(start, end)
		.matchAll(/cr\(\s*\w+\s*,\s*"([^"]+)"/g)) {
		out.add((m[1] ?? "").replace(/\{[^}]*\}/g, "{}"));
	}
	return out;
}

function loadSources(): Map<string, string> {
	const files: string[] = [];
	for (const d of SCAN_DIRS) walk(join(WEB_ROOT, d), files);
	return new Map(
		files.map((f) => [
			relative(WEB_ROOT, f).split("\\").join("/"),
			readFileSync(f, "utf8"),
		]),
	);
}

describe("gateway calls carry the client-IP attestation (OG-36 M4)", () => {
	const sources = loadSources();
	const control = controlRoutePaths(
		readFileSync(
			join(REPO_ROOT, "crates/gateway/src/auth/capability.rs"),
			"utf8",
		),
	);

	it("parses a non-trivial control-route registry", () => {
		// A parser that finds nothing would make rule 2 vacuous.
		expect(control.size).toBeGreaterThan(20);
		expect(control.has("/v1/billing/ceiling")).toBe(true);
		expect(control.has("/v1/alerts/rules/{}")).toBe(true);
	});

	it("no file raw-fetches the gateway unless exempted with a reason", () => {
		const offenders = rawGatewayFetchers(sources).filter(
			(f) => !(f in RAW_FETCH_EXEMPT),
		);
		expect(offenders).toEqual([]);
	});

	it("no exempt raw fetcher names a control route", () => {
		const bad: string[] = [];
		for (const f of Object.keys(RAW_FETCH_EXEMPT)) {
			const src = sources.get(f);
			if (src === undefined) continue;
			for (const p of v1Paths(src)) if (control.has(p)) bad.push(`${f} → ${p}`);
		}
		expect(bad).toEqual([]);
	});

	it("every exemption is still a raw fetcher (no stale entries)", () => {
		const live = new Set(rawGatewayFetchers(sources));
		const stale = Object.keys(RAW_FETCH_EXEMPT).filter((f) => !live.has(f));
		expect(stale).toEqual([]);
	});

	it("the detector fires on a planted raw control fetch (selftest)", () => {
		const planted = new Map([
			[
				"app/api/x/route.ts",
				'import { gatewayBaseUrl } from "@/lib/gateway";\nawait fetch(`${gatewayBaseUrl()}/v1/alerts/rules/${encodeURIComponent(id)}`, { method: "DELETE" });',
			],
		]);
		expect(rawGatewayFetchers(planted)).toEqual(["app/api/x/route.ts"]);
		const paths = v1Paths(planted.get("app/api/x/route.ts") ?? "");
		expect([...paths].some((p) => control.has(p))).toBe(true);
	});
});
