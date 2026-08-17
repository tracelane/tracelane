/**
 * PLT-36 — proof for the legal web surface and its publication gate.
 *
 * Two things have to be true at once, and they pull in opposite directions:
 *
 *   A. TODAY nothing is served. `docs/legal/*.md` still carry the DRAFT marker
 *      and three founder-gated tokens, so `/legal/*` must 404. Publishing a
 *      contract with `[COMPANY LEGAL ENTITY NAME]` in it is worse than having
 *      no page — that is why the documents are classified RESTRICTED and
 *      export-denied in the first place.
 *
 *   B. The moment those tokens are filled and the DRAFT marker struck, the REAL
 *      documents render as real pages, with no code change.
 *
 * So the fixture is not hand-written prose: it is the actual shipped
 * `docs/legal/*.md`, run through exactly the edit the founder will make (fill
 * three tokens, strike the marker) into a temp directory. That makes (B) a
 * claim about the documents we will really publish, not about a stub.
 *
 * Negative tests come first throughout — for every "must serve", the matching
 * "must refuse".
 */

import {
	existsSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterAll, describe, expect, it } from "vitest";
import {
	KNOWN_PLACEHOLDERS,
	LEGAL_DOCS,
	loadPublishableDoc,
	publicationBlockers,
	readLegalMarkdown,
} from "./legal-source";
import { renderMarkdown } from "./markdown";

/** repo root from `apps/web/app/(legal)/`. */
const REPO = fileURLToPath(new URL("../../../../", import.meta.url));
const REAL_DIR = resolve(REPO, "docs/legal");

/** The founder's future edit, applied to the real text. */
function asExecuted(markdown: string): string {
	return markdown
		.replace(/<!--\s*DRAFT[\s\S]*?-->/g, "")
		.replaceAll("[COMPANY LEGAL ENTITY NAME]", "Tracelane Labs Private Limited")
		.replaceAll("[EFFECTIVE DATE]", "1 January 2027")
		.replaceAll("[CONTACT EMAIL]", "privacy@example.invalid");
}

/** A temp `docs/legal` holding the executed twins of the real documents. */
const executedDir = mkdtempSync(join(tmpdir(), "tracelane-legal-"));
for (const d of LEGAL_DOCS) {
	const src = readFileSync(resolve(REAL_DIR, d.file), "utf8");
	writeFileSync(join(executedDir, d.file), asExecuted(src));
}
afterAll(() => rmSync(executedDir, { recursive: true, force: true }));

const html = (md: string): string =>
	renderToStaticMarkup(createElement("div", null, renderMarkdown(md)));

// ── A. nothing is served while the documents are drafts ──────────────────────

describe("fail-closed: the gate refuses everything that is not executed text", () => {
	it("refuses ALL THREE real documents as they stand today", () => {
		for (const d of LEGAL_DOCS) {
			expect(
				loadPublishableDoc(d.slug, REAL_DIR),
				`${d.slug} must not be servable while it is a draft`,
			).toBeNull();
		}
	});

	it("names the real reason — the DRAFT marker and the three tokens", () => {
		const md = readLegalMarkdown("privacy-policy.md", REAL_DIR);
		expect(md).not.toBeNull();
		const reasons = publicationBlockers(md ?? "").join(" | ");
		expect(reasons).toMatch(/DRAFT marker/);
		for (const token of KNOWN_PLACEHOLDERS) expect(reasons).toContain(token);
	});

	it("refuses a document whose tokens are filled but is still marked DRAFT", () => {
		const stillDraft = readFileSync(resolve(REAL_DIR, "dpa.md"), "utf8")
			.replaceAll("[COMPANY LEGAL ENTITY NAME]", "Acme Ltd")
			.replaceAll("[EFFECTIVE DATE]", "1 January 2027")
			.replaceAll("[CONTACT EMAIL]", "legal@example.invalid");
		expect(publicationBlockers(stillDraft)).toEqual([
			"document still carries the DRAFT marker (legal review not complete)",
		]);
	});

	it("refuses a legal-reviewed document that still has ONE unfilled token", () => {
		const oneLeft = asExecuted(
			readFileSync(resolve(REAL_DIR, "terms-of-service.md"), "utf8"),
		).replace("Tracelane Labs Private Limited", "[COMPANY LEGAL ENTITY NAME]");
		expect(publicationBlockers(oneLeft).join(" ")).toContain(
			"[COMPANY LEGAL ENTITY NAME]",
		);
	});

	it("catches a placeholder nobody has thought of yet", () => {
		expect(
			publicationBlockers("Governed by the laws of [JURISDICTION].").join(" "),
		).toContain("[JURISDICTION]");
	});

	it("refuses an empty document", () => {
		expect(publicationBlockers("   \n ")).toEqual(["document is empty"]);
	});

	it("refuses an unknown slug", () => {
		expect(loadPublishableDoc("cookie-policy", executedDir)).toBeNull();
	});

	it("refuses when the source tree is absent — the public export's state", () => {
		// `docs/legal` is export-denied, so in the public mirror there is no file
		// to read. That must be a 404, not a crash and not a blank page.
		expect(
			readLegalMarkdown("privacy-policy.md", "/nonexistent-legal"),
		).toBeNull();
		for (const d of LEGAL_DOCS) {
			expect(loadPublishableDoc(d.slug, "/nonexistent-legal")).toBeNull();
		}
	});
});

// ── B. the executed documents become real pages ──────────────────────────────

describe("once executed, the REAL documents publish", () => {
	it("all three clear the gate", () => {
		for (const d of LEGAL_DOCS) {
			const loaded = loadPublishableDoc(d.slug, executedDir);
			expect(loaded, `${d.slug} must publish once executed`).not.toBeNull();
			expect(loaded?.doc.title).toBe(d.title);
		}
	});

	it("renders the privacy policy as a document, not a wall of text", () => {
		const md = loadPublishableDoc("privacy", executedDir)?.markdown ?? "";
		const out = html(md);
		// Real structure from the real source.
		expect(out).toContain("<h2");
		expect(out).toContain("Subprocessors");
		expect(out).toContain("<table");
		expect(out).toContain("Hetzner");
		expect(out).toContain("<ul");
		// The erasure promise a reader comes to this page for.
		expect(out).toContain("30-day soft-delete");
	});

	it("renders the DPA's SCC module and sub-processor table", () => {
		const out = html(loadPublishableDoc("dpa", executedDir)?.markdown ?? "");
		expect(out).toContain("Module Two");
		expect(out).toContain("Polar.sh");
		expect(out).toContain("<ol"); // the numbered processor obligations
	});

	it("renders the terms", () => {
		const out = html(loadPublishableDoc("terms", executedDir)?.markdown ?? "");
		expect(out).toContain("<h2");
		expect(out).toContain("Tracelane Labs Private Limited");
	});

	it("NEVER leaks a placeholder or the DRAFT banner into rendered output", () => {
		for (const d of LEGAL_DOCS) {
			const out = html(loadPublishableDoc(d.slug, executedDir)?.markdown ?? "");
			for (const token of KNOWN_PLACEHOLDERS) expect(out).not.toContain(token);
			expect(out).not.toMatch(/DRAFT/);
			// The classification comment is metadata, not content.
			expect(out).not.toContain("classification");
		}
	});
});

// ── the renderer itself: markup can only come from us ────────────────────────

describe("markdown renderer is inert to hostile document text", () => {
	it("escapes raw HTML instead of executing it", () => {
		const out = html("Hello <script>alert(1)</script> world");
		expect(out).not.toContain("<script>");
		expect(out).toContain("&lt;script&gt;");
	});

	it("drops a javascript: link but keeps its text", () => {
		const out = html("See [the policy](javascript:alert(1)) here.");
		expect(out).not.toContain("javascript:");
		expect(out).toContain("the policy");
		expect(out).not.toContain("<a ");
	});

	it("keeps https and mailto links", () => {
		expect(html("[site](https://tracelane.dev)")).toContain(
			'href="https://tracelane.dev"',
		);
		expect(html("[mail](mailto:a@b.co)")).toContain('href="mailto:a@b.co"');
	});

	it("renders bold, code, headings, rules and both list kinds", () => {
		const out = html(
			"# T\n\n## S\n\n---\n\nA **bold** and `code`.\n\n- one\n- two\n\n1. first\n2. second\n",
		);
		expect(out).toContain("<h1");
		expect(out).toContain("<h2");
		expect(out).toContain("<hr");
		expect(out).toContain("<strong");
		expect(out).toContain("<code");
		expect(out).toContain("<ul");
		expect(out).toContain("<ol");
	});

	it("renders a header-less `| | |` table as a grid with no empty head", () => {
		const out = html("| | |\n|---|---|\n| Term | Meaning |\n");
		expect(out).not.toContain("<thead");
		expect(out).toContain("Meaning");
	});
});

// ── the registry cannot silently point at nothing ────────────────────────────

describe("registry integrity", () => {
	it("every registered document exists in docs/legal", () => {
		for (const d of LEGAL_DOCS) {
			expect(existsSync(resolve(REAL_DIR, d.file)), d.file).toBe(true);
		}
	});

	it("covers privacy, terms and DPA with unique slugs", () => {
		expect(LEGAL_DOCS.map((d) => d.slug).sort()).toEqual([
			"dpa",
			"privacy",
			"terms",
		]);
	});
});
