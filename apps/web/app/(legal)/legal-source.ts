/**
 * Legal source publication gate. Canonical drafts stay outside the web bundle.
 * A known document that cannot pass the gate gets an interim page, never its
 * draft text. Unknown slugs stay unavailable. Publication requires removal of
 * both the DRAFT marker and every bracketed token after legal review.
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
 * Any bracketed token, including lowercase, Unicode and multiline placeholders.
 * Legal source must be free of unresolved brackets before publication. A false
 * positive keeps the interim page; a false negative could publish a blank in a
 * contract.
 */
const PLACEHOLDER = /\[[^\]]*\]/g;

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
 * Fail-CLOSED: callers withhold document text on a non-empty result, and treat an
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
 * placeholder-free text or its body is withheld.
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
