/**
 * PLT-36 — the legal web surface, and the gate that decides whether a legal
 * document is fit to be served at all.
 *
 * ## Why the source is NOT in this tree
 *
 * `docs/legal/*.md` is the canonical text and it is deliberately export-DENIED
 * (`scripts/export/export-deny.txt:52` — "never draft legal text to a public
 * repo"). Copying the text into `apps/web/` would ship an unexecuted legal
 * instrument, carrying `[COMPANY LEGAL ENTITY NAME]`, into the public mirror —
 * which is the exact harm the deny entry and the RESTRICTED classification
 * exist to prevent. So the page reads the canonical file and never mirrors it.
 *
 * In the public export the file is simply absent, the read returns `null`, and
 * the route 404s. Correct by construction in both trees, with no config.
 *
 * ## Fail-CLOSED, twice over
 *
 * `publicationBlockers()` is the gate, and it is the security-shaped kind: it
 * must refuse by default and only ever open on positive evidence. A document is
 * servable ONLY when BOTH of these clear:
 *
 *   1. the `DRAFT — … legal review required` marker is gone, and
 *   2. no `[UPPERCASE PLACEHOLDER]` token remains anywhere in the body.
 *
 * Either one present ⇒ 404. An unreadable or missing file ⇒ 404. An unknown
 * slug ⇒ 404. There is no branch that serves a document the gate did not clear,
 * and no environment variable that relaxes it.
 *
 * ## What is still founder-gated
 *
 * The three tokens are a founder/legal decision, not an engineering one, and
 * this file will not guess them. When `[COMPANY LEGAL ENTITY NAME]`,
 * `[EFFECTIVE DATE]` and `[CONTACT EMAIL]` are filled in `docs/legal/*.md` and
 * the DRAFT marker is struck, all three pages go live on the next build with no
 * code change.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

export interface LegalDoc {
	/** URL segment: `/legal/<slug>`. */
	slug: string;
	/** Filename under `docs/legal/`. */
	file: string;
	/** Page + tab title. */
	title: string;
	/** One line under the title — what the document is for. */
	summary: string;
}

export const LEGAL_DOCS: readonly LegalDoc[] = [
	{
		slug: "privacy",
		file: "privacy-policy.md",
		title: "Privacy Policy",
		summary:
			"What we collect, where it is stored, who processes it, and how to have it erased.",
	},
	{
		slug: "terms",
		file: "terms-of-service.md",
		title: "Terms of Service",
		summary: "The agreement governing your use of Tracelane.",
	},
	{
		slug: "dpa",
		file: "dpa.md",
		title: "Data Processing Addendum",
		summary:
			"Our processor obligations when we handle personal data on your behalf.",
	},
];

/** The canonical text lives outside `apps/web`; see the module doc. */
const LEGAL_DIR = resolve(process.cwd(), "../../docs/legal");

/**
 * The DRAFT banner every unexecuted document carries. Its presence is a
 * self-declaration by the document that it is not fit to publish, and it is
 * checked independently of the placeholder scan — filling the tokens without
 * legal sign-off must not be enough to publish.
 */
const DRAFT_MARKER = /DRAFT\s*—.*legal review required/i;

/**
 * Any `[UPPERCASE TOKEN]` left in the body. Deliberately broader than the three
 * tokens we know about today, so a placeholder introduced tomorrow is caught
 * without editing this file. A false positive costs a 404, which is the safe
 * direction; a false negative would publish a blank in a contract.
 */
const PLACEHOLDER = /\[[A-Z][A-Z0-9 _/-]{2,}\]/g;

/** The tokens we know are founder-gated, named for the error message. */
export const KNOWN_PLACEHOLDERS = [
	"[COMPANY LEGAL ENTITY NAME]",
	"[EFFECTIVE DATE]",
	"[CONTACT EMAIL]",
] as const;

/**
 * Every reason this text must NOT be served, most important first. Empty means
 * publishable.
 *
 * Fail-CLOSED: callers treat a non-empty result as "404", and treat an
 * exception or an unreadable source the same way. Never invert this to a
 * "publishable" boolean with a default — a missing check would then read as
 * permission.
 */
export function publicationBlockers(markdown: string): string[] {
	const blockers: string[] = [];
	if (!markdown.trim()) {
		blockers.push("document is empty");
		return blockers;
	}
	if (DRAFT_MARKER.test(markdown)) {
		blockers.push(
			"document still carries the DRAFT marker (legal review not complete)",
		);
	}
	const found = [...new Set(markdown.match(PLACEHOLDER) ?? [])];
	if (found.length > 0) {
		blockers.push(`unfilled placeholder(s): ${found.sort().join(", ")}`);
	}
	return blockers;
}

/** The doc registered at `slug`, or `undefined`. */
export function legalDoc(slug: string): LegalDoc | undefined {
	return LEGAL_DOCS.find((d) => d.slug === slug);
}

/**
 * Raw canonical markdown, or `null` when the file is absent or unreadable —
 * which is the normal state in the public export, where `docs/legal/` is denied.
 *
 * # Errors
 * Fails OPEN in the availability sense (never throws) and CLOSED in the
 * disclosure sense (an unreadable source yields `null`, i.e. no page).
 */
export function readLegalMarkdown(
	file: string,
	dir = LEGAL_DIR,
): string | null {
	try {
		return readFileSync(resolve(dir, file), "utf8");
	} catch {
		return null;
	}
}

/**
 * The one entry point a route may call: the document at `slug`, but ONLY if the
 * gate cleared it. `null` in every other case — unknown slug, absent file,
 * DRAFT marker, or any remaining placeholder.
 *
 * # Errors
 * Fails CLOSED. There is no partial success: a page either has fully approved,
 * placeholder-free text or it does not exist.
 */
export function loadPublishableDoc(
	slug: string,
	dir = LEGAL_DIR,
): { doc: LegalDoc; markdown: string } | null {
	const doc = legalDoc(slug);
	if (!doc) return null;
	const markdown = readLegalMarkdown(doc.file, dir);
	if (markdown === null) return null;
	if (publicationBlockers(markdown).length > 0) return null;
	return { doc, markdown };
}
