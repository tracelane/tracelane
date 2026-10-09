import fs from "node:fs";
import path from "node:path";
import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * Vitest 3 identifies each test file by a 32-bit Java-style string hash of its
 * root-relative path (`generateFileHash` in @vitest/runner). Two files whose
 * hashes collide share one task id, and in a full run one of them silently
 * stops being reported (measured 2026-10-03: `pain-points/PP-OP2.eval.ts` and
 * `pain-points/PP-P12.eval.ts` collide, 318 -> 317 tests, no failure).
 * This turns that silent drop into a red test: rename one of the pair.
 */
function fileHash(rel: string): number {
	let h = 0;
	for (let i = 0; i < rel.length; i++) {
		h = ((h << 5) - h + rel.charCodeAt(i)) | 0;
	}
	return h;
}

function walk(dir: string, root: string, out: string[]): void {
	for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
		if (e.name === "node_modules" || e.name.startsWith(".")) continue;
		const p = path.join(dir, e.name);
		if (e.isDirectory()) walk(p, root, out);
		else if (e.name.endsWith(".eval.ts")) {
			out.push(path.relative(root, p).split(path.sep).join("/"));
		}
	}
}

describe("vitest file-id hashes are unique across the eval corpus", () => {
	it("no two *.eval.ts files collide on the vitest task-id hash", () => {
		const root = path.resolve(__dirname, "..");
		const files: string[] = [];
		walk(root, root, files);
		expect(files.length, "corpus must be non-empty").toBeGreaterThan(50);
		const byHash = new Map<number, string[]>();
		for (const f of files) {
			const h = fileHash(f);
			byHash.set(h, [...(byHash.get(h) ?? []), f]);
		}
		const collisions = [...byHash.values()].filter((v) => v.length > 1);
		expect(
			collisions.map((c) => c.join(" <-> ")).join("; "),
			"rename one file of each colliding pair",
		).toBe("");
	});

	it("the hash function detects the known colliding pair (guard is not vacuous)", () => {
		expect(fileHash("pain-points/PP-OP2.eval.ts")).toBe(
			fileHash("pain-points/PP-P12.eval.ts"),
		);
	});
});
