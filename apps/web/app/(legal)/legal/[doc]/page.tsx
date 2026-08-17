/**
 * `/legal/privacy` · `/legal/terms` · `/legal/dpa` — PLT-36's web surface.
 *
 * Prerendered at BUILD time (`force-static` + `generateStaticParams`), which is
 * what lets the canonical text stay in `docs/legal/` instead of being mirrored
 * into this public-exporting tree: the file read happens on the build machine,
 * never on the Worker. See `../../legal-source.ts` for why that matters.
 *
 * No `withAuth` — a privacy policy the reader must sign in to read is not
 * published. `authkitMiddleware()` runs with `middlewareAuth.enabled = false`,
 * so it refreshes a session if there is one and lets anonymous requests through.
 *
 * FAIL-CLOSED: a document that is missing, still marked DRAFT, or still carrying
 * an unfilled `[PLACEHOLDER]` is `notFound()`, not a page with a blank in a
 * contract. Until the founder fills the entity name, effective date and contact
 * email in `docs/legal/*.md` and strikes the DRAFT marker, all three URLs 404 —
 * by design. Nothing else has to change for them to go live.
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
	const loaded = loadPublishableDoc(doc);
	if (!loaded) notFound();

	return (
		<article className="mx-auto max-w-3xl px-4 py-10">
			<header className="border-line border-b pb-6">
				<h1 className="font-semibold text-3xl text-ink tracking-tight">
					{loaded.doc.title}
				</h1>
				<p className="mt-2 text-ink-3 text-sm">{loaded.doc.summary}</p>
			</header>
			{/* The document's own `# Title` is dropped — the header above is it. */}
			<div className="pb-16">
				{renderMarkdown(loaded.markdown.replace(/^#\s+.*$/m, ""))}
			</div>
		</article>
	);
}
