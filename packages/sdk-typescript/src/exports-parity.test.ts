/**
 * Publish-surface parity guard: every subpath declared in package.json
 * `exports` must have a matching tsup build entry (and vice versa), and every
 * entry's source file must exist. A declared-but-never-built subpath ships a
 * runtime import crash (the `./langchain` 2026-07 bug class).
 *
 * tsup.config.ts is parsed textually (its entry map is a literal object) so
 * this test has no coupling to tsconfig include paths.
 */

import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

// CJS-safe package-dir lookup (no import.meta under this tsconfig): vitest
// runs with cwd inside the package, so walk up to the @tracelanedev/sdk root.
function findPkgDir(): string {
	let dir = process.cwd();
	for (let i = 0; i < 6; i++) {
		const pj = join(dir, "package.json");
		if (existsSync(pj) && existsSync(join(dir, "tsup.config.ts"))) {
			const name = (JSON.parse(readFileSync(pj, "utf8")) as { name?: string })
				.name;
			if (name === "@tracelanedev/sdk") return dir;
		}
		const parent = resolve(dir, "..");
		if (parent === dir) break;
		dir = parent;
	}
	throw new Error(
		"could not locate the @tracelanedev/sdk package dir from cwd",
	);
}

const pkgDir = findPkgDir();

const pkg = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8")) as {
	exports: Record<string, unknown>;
};

const tsupSrc = readFileSync(join(pkgDir, "tsup.config.ts"), "utf8");
const entries: Record<string, string> = {};
for (const m of tsupSrc.matchAll(
	/"?((?:instrumentations\/)?[a-z0-9_]+)"?:\s*"(src\/[^"]+)"/g,
)) {
	const key = m[1];
	const src = m[2];
	if (key && src) entries[key] = src;
}

describe("package exports ↔ tsup build parity", () => {
	const subpaths = Object.keys(pkg.exports).filter((k) => k !== ".");

	it("parses a non-trivial tsup entry map", () => {
		expect(Object.keys(entries).length).toBeGreaterThan(10);
		expect(entries.index).toBe("src/index.ts");
	});

	it("every declared subpath export has a tsup entry", () => {
		for (const subpath of subpaths) {
			const entryKey = `instrumentations/${subpath.slice(2)}`;
			expect(
				entries[entryKey],
				`${subpath} is declared in package.json exports but has no tsup entry — it would never be built`,
			).toBeDefined();
		}
	});

	it("every tsup instrumentation entry is exported and its source exists", () => {
		for (const [key, src] of Object.entries(entries)) {
			expect(
				existsSync(join(pkgDir, src)),
				`tsup entry ${key} points at missing source ${src}`,
			).toBe(true);
			if (key === "index") continue;
			const subpath = `./${key.replace(/^instrumentations\//, "")}`;
			expect(
				pkg.exports[subpath],
				`tsup builds ${key} but package.json does not export ${subpath}`,
			).toBeDefined();
		}
	});

	// Node/bundlers pick the FIRST matching condition key in each conditions
	// object. A "types" sibling placed after "import"/"require" is never
	// reached (they always match first), so TypeScript falls back to the
	// fragile adjacent-.d.ts guess instead of the declared path — the
	// "condition never used" class of bug. "types" must sort first at every
	// level, and each format branch must point at its matching declaration
	// extension (.d.mts for import, .d.ts for require).
	it("every export condition resolves types before import/require, per format", () => {
		for (const [subpath, cond] of Object.entries(pkg.exports) as [
			string,
			Record<string, unknown>,
		][]) {
			for (const format of ["import", "require"] as const) {
				const branch = cond[format] as Record<string, string> | undefined;
				expect(
					branch,
					`${subpath} is missing a "${format}" condition`,
				).toBeDefined();
				if (!branch) continue;
				expect(
					Object.keys(branch)[0],
					`${subpath}.${format} must list "types" before "default" — Node/TS use the first matching key`,
				).toBe("types");
				const expectedExt = format === "import" ? ".d.mts" : ".d.ts";
				expect(
					branch.types,
					`${subpath}.${format}.types should end with ${expectedExt}`,
				).toMatch(new RegExp(`\\${expectedExt}$`));
			}
		}
	});
});
