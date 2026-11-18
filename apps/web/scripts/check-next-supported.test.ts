/**
 * B-614: the web app runs on a Next.js version the OpenNext Cloudflare adapter supports,
 * and the build never switches OpenNext's version refusal off again.
 *
 * Next.js 15 reached end of support on 2026-10-21; from then until B-614 every deploy ran
 * `opennextjs-cloudflare build --dangerouslyUseUnsupportedNextVersion`, i.e. an unpatched
 * framework in front of sign-in. These tests read the pinned versions and the INSTALLED
 * adapter's own peer range, so a later bump that OpenNext does not support fails here.
 */
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";

const pkg = JSON.parse(
	readFileSync(new URL("../package.json", import.meta.url), "utf8"),
) as {
	scripts: Record<string, string>;
	dependencies: Record<string, string>;
	devDependencies: Record<string, string>;
};
const require = createRequire(import.meta.url);
const must = (v: string | undefined, what: string): string => {
	if (v === undefined) throw new Error(`missing ${what}`);
	return v;
};
const nextPin = must(pkg.dependencies.next, "dependencies.next");
const cfBuild = must(pkg.scripts["cf:build"], "scripts.cf:build");

type V = [number, number, number];
const parse = (v: string): V => {
	const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(v.trim());
	if (!m) throw new Error(`not an exact x.y.z version: ${v}`);
	return [Number(m[1]), Number(m[2]), Number(m[3])];
};
const cmp = (a: V, b: V) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];

/** A small subset of semver ranges: `||` of space-separated `>= > <= < =` comparators. */
function satisfies(version: string, range: string): boolean {
	const v = parse(version);
	return range.split("||").some((set) =>
		set
			.trim()
			.split(/\s+/)
			.every((c) => {
				const m = /^(>=|<=|>|<|=)?(\d+)(?:\.(\d+))?(?:\.(\d+))?$/.exec(c);
				if (!m) throw new Error(`unsupported comparator "${c}" in "${range}"`);
				const b: V = [Number(m[2]), Number(m[3] ?? 0), Number(m[4] ?? 0)];
				const d = cmp(v, b);
				switch (m[1] ?? "=") {
					case ">=":
						return d >= 0;
					case ">":
						return d > 0;
					case "<=":
						return d <= 0;
					case "<":
						return d < 0;
					default:
						return d === 0;
				}
			}),
	);
}

// The adapter's `exports` map hides its package.json from require(), so read it from disk.
const openNextPeer = (): string =>
	(
		JSON.parse(
			readFileSync(
				new URL(
					"../node_modules/@opennextjs/cloudflare/package.json",
					import.meta.url,
				),
				"utf8",
			),
		) as { peerDependencies: Record<string, string> }
	).peerDependencies.next ?? "";

describe("Next.js is a version OpenNext supports (B-614)", () => {
	it("cf_build_has_no_unsupported_flag", () => {
		expect(cfBuild).not.toMatch(/dangerouslyUseUnsupported/i);
		expect(cfBuild).toMatch(/opennextjs-cloudflare build/);
	});

	it("deploy_script_never_passes_the_flag", () => {
		const webSh = readFileSync(
			new URL("../../../scripts/deploy/web.sh", import.meta.url),
			"utf8",
		);
		expect(webSh).not.toMatch(/dangerouslyUseUnsupported/i);
	});

	it("build_keeps_webpack_for_the_prod_e2e_stub", () => {
		// Next 16 builds with Turbopack by default, which skips next.config.ts's webpack() hook
		// that swaps the PGlite e2e harness for its stub in prod builds.
		expect(must(pkg.scripts.build, "scripts.build")).toMatch(
			/next build --webpack/,
		);
	});

	it("editor_isolation_still_runs", () => {
		expect(cfBuild).toMatch(/node scripts\/check-editor-isolation\.mjs/);
	});

	it("caret_range_on_next_fails", () => {
		expect(() => parse(nextPin)).not.toThrow();
		expect(() => parse("^16.4.6")).toThrow();
	});

	it("pinned_next_is_supported_by_opennext", () => {
		expect(satisfies(nextPin, openNextPeer())).toBe(true);
		const installed = (require("next/package.json") as { version: string })
			.version;
		expect(installed).toBe(nextPin);
	});

	it("next_is_a_supported_major", () => {
		// Next.js 15 left support on 2026-10-21; any 15.x pin is a regression of B-614.
		expect(parse(nextPin)[0]).toBeGreaterThanOrEqual(16);
	});

	it("unsupported_next_pin_fails", () => {
		expect(satisfies("15.5.24", ">=15.5.29 <16 || >=16.4.5")).toBe(false);
		expect(satisfies("16.3.9", ">=15.5.29 <16 || >=16.4.5")).toBe(false);
		expect(satisfies("16.4.6", ">=15.5.29 <16 || >=16.4.5")).toBe(true);
	});

	it("react_peer_mismatch_fails", () => {
		const peer = (
			require("next/package.json") as {
				peerDependencies: Record<string, string>;
			}
		).peerDependencies.react;
		expect(peer).toMatch(/\^19\.0\.0/);
		expect(parse(must(pkg.dependencies.react, "react"))[0]).toBe(19);
		expect(pkg.dependencies["react-dom"]).toBe(pkg.dependencies.react);
	});
});
