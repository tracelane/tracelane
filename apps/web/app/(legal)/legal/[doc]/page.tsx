import { PageHeader } from "@tracelanedev/ui";
/** Public legal document routes. Known unavailable documents show an interim
 * page; their draft bodies remain behind the publication gate. Unknown slugs 404.
 * Static generation reads canonical source only on the build machine.
 */

import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { LEGAL_DOCS, legalDoc, loadPublishableDoc } from "../../legal-source";
import { renderMarkdown } from "../../markdown";

interface Props {
	params: Promise<{ doc: string }>;
}

// Build-time file read + no per-request data: prerender, never run on request.
export const dynamic = "force-static";
// Only the three registered slugs exist; anything else 404s before this module.
export const dynamicParams = false;

export function generateStaticParams(): Array<{ doc: string }> {
	return LEGAL_DOCS.map((d) => ({ doc: d.slug }));
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
	const { doc } = await params;
	const meta = legalDoc(doc);
	if (!meta) return { title: "Not found" };
	return { title: meta.title, description: meta.summary };
}

export default async function LegalDocPage({ params }: Props) {
	const { doc } = await params;
	const meta = legalDoc(doc);
	if (!meta) notFound();
	const navigation = (
		<nav
			aria-label="Legal documents"
			className="mt-8 flex flex-wrap gap-4 text-sm underline"
		>
			<a href="/privacy">Privacy Policy</a>
			<a href="/terms">Terms of Service</a>
			<a href="/dpa">Data Processing Addendum</a>
		</nav>
	);
	const loaded = loadPublishableDoc(doc);
	if (!loaded) {
		return (
			<article className="mx-auto max-w-3xl px-4 py-10">
				<PageHeader title={meta.title} />
				<p className="mt-4 text-ink-2">
					This document is being finalised. The draft is not published here.
				</p>
				<p className="mt-4 text-ink-2">
					You can request the current terms through in-app support (sign-in
					required).
				</p>
				<a className="mt-4 inline-block underline" href="/support">
					Open support
				</a>
				{navigation}
			</article>
		);
	}

	return (
		<article className="mx-auto max-w-3xl px-4 py-10">
			<header className="border-line border-b pb-6">
				<PageHeader title={loaded.doc.title} />
				<p className="mt-2 text-ink-3 text-sm">{loaded.doc.summary}</p>
			</header>
			{/* The document's own `# Title` is dropped — the header above is it. */}
			<div className="pb-16">
				{renderMarkdown(loaded.markdown.replace(/^#\s+.*$/m, ""))}
			</div>
			{navigation}
		</article>
	);
}
