/**
 * B-587 (2026-09-27): nine pages rendered their own `<main>` inside the app shell's
 * `<main id="workspace-content">`, so every one of them carried two main landmarks —
 * screen-reader landmark navigation and the skip link had two targets. The shell owns
 * the ONE main; a page renders a `<div>`. This reads every component source so a new
 * page cannot quietly add a second one.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { expect, it } from "vitest";

const ROOT = join(__dirname, "..", "..");
const SHELL = "components/layout/AppShell.tsx";

function tsxFiles(dir: string): string[] {
	return readdirSync(dir).flatMap((name) => {
		const p = join(dir, name);
		if (statSync(p).isDirectory()) return tsxFiles(p);
		return p.endsWith(".tsx") && !p.endsWith(".test.tsx") ? [p] : [];
	});
}

it("only the app shell renders a <main> landmark", () => {
	const offenders = ["app", "components"]
		.flatMap((d) => tsxFiles(join(ROOT, d)))
		.map((p) => relative(ROOT, p))
		.filter((p) => p !== SHELL)
		.filter((p) => /<main[\s>]/.test(readFileSync(join(ROOT, p), "utf8")));
	expect(offenders).toEqual([]);
});

it("the shell still owns exactly one", () => {
	const src = readFileSync(join(ROOT, SHELL), "utf8");
	// Bare pages own their layout; both shell branches still render one main.
	expect(src.match(/<PageContainer[\s>]/g)?.length).toBe(1);
	expect(src.match(/<main[\s>]/g)?.length).toBe(1);
	const container = readFileSync(
		join(ROOT, "../../packages/ui/src/primitives/PageContainer.tsx"),
		"utf8",
	);
	expect(container.match(/<main[\s>]/g)?.length).toBe(1);
});
