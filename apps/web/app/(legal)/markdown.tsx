/**
 * A deliberately tiny CommonMark subset renderer for the legal pages.
 *
 * Why not a markdown dependency: adding one would mean editing
 * `apps/web/package.json`, and the subset our legal documents actually use is
 * this short — headings, paragraphs, bullet and numbered lists, pipe tables,
 * horizontal rules, and inline bold / code / links. Anything outside the subset
 * degrades to plain text, never to markup.
 *
 * Security: output is React elements. There is no `dangerouslySetInnerHTML`
 * anywhere in this file, so the document text can never inject markup, and link
 * hrefs are allowlisted to `https:`, `mailto:` and same-site paths — a
 * `javascript:` URL renders as inert text.
 *
 * Styling is design tokens only (`text-ink`, `border-line`, …); no literal
 * colours.
 */

import type { ReactNode } from "react";

/** `<!-- … -->` blocks (the classification + DRAFT banners) are not content. */
function stripHtmlComments(md: string): string {
	return md.replace(/<!--[\s\S]*?-->/g, "");
}

/** Only these schemes become anchors; everything else stays literal text. */
function safeHref(href: string): string | null {
	const h = href.trim();
	if (/^https?:\/\//i.test(h) || /^mailto:/i.test(h)) return h;
	if (h.startsWith("/") && !h.startsWith("//")) return h;
	return null;
}

/** `**bold**`, `` `code` `` and `[text](href)` → elements; the rest is text. */
function inline(text: string, keyBase: string): ReactNode[] {
	const out: ReactNode[] = [];
	const pattern = /\*\*([^*]+)\*\*|`([^`]+)`|\[([^\]]+)\]\(([^)\s]+)\)/g;
	let last = 0;
	let m: RegExpExecArray | null = pattern.exec(text);
	let i = 0;
	while (m !== null) {
		if (m.index > last) out.push(text.slice(last, m.index));
		const key = `${keyBase}-i${i++}`;
		if (m[1] !== undefined) {
			out.push(
				<strong key={key} className="font-semibold text-ink">
					{m[1]}
				</strong>,
			);
		} else if (m[2] !== undefined) {
			out.push(
				<code
					key={key}
					className="rounded bg-surface-2 px-1 py-0.5 font-mono text-[0.9em] text-ink"
				>
					{m[2]}
				</code>,
			);
		} else if (m[3] !== undefined && m[4] !== undefined) {
			const href = safeHref(m[4]);
			out.push(
				href ? (
					<a
						key={key}
						href={href}
						className="text-action-ink underline underline-offset-2"
					>
						{m[3]}
					</a>
				) : (
					// Unsafe scheme: keep the author's text, drop the link.
					<span key={key}>{m[3]}</span>
				),
			);
		}
		last = m.index + m[0].length;
		m = pattern.exec(text);
	}
	if (last < text.length) out.push(text.slice(last));
	return out;
}

/** Split one `| a | b |` row into trimmed cells. */
function cells(row: string): string[] {
	return row
		.replace(/^\s*\|/, "")
		.replace(/\|\s*$/, "")
		.split("|")
		.map((c) => c.trim());
}

const isTableRow = (l: string) => /^\s*\|/.test(l);
const isSeparatorRow = (l: string) => /^\s*\|[\s:|-]+\|?\s*$/.test(l);

/**
 * Render a markdown subset as React elements.
 *
 * Unknown constructs fall through to paragraph text — the failure mode is
 * "reads plainly", never "renders as markup".
 */
export function renderMarkdown(markdown: string): ReactNode {
	const lines = stripHtmlComments(markdown).split("\n");
	const blocks: ReactNode[] = [];
	let i = 0;
	let k = 0;
	// Document order is fixed at build time — nothing is inserted, removed or
	// reordered, and no node holds state — so a monotonic id is a correct key.
	// It is NOT an array index: `nextKey` is unique across the whole document,
	// so two cells with identical text in different rows never collide.
	let uid = 0;
	const nextKey = (): string => `n${uid++}`;

	while (i < lines.length) {
		const line = lines[i] ?? "";

		if (!line.trim()) {
			i += 1;
			continue;
		}

		// ── horizontal rule ──────────────────────────────────────────────────
		if (/^\s*---+\s*$/.test(line)) {
			blocks.push(<hr key={`b${k++}`} className="my-8 border-line" />);
			i += 1;
			continue;
		}

		// ── heading ──────────────────────────────────────────────────────────
		const heading = line.match(/^(#{1,4})\s+(.*)$/);
		if (heading?.[1] && heading[2] !== undefined) {
			const level = heading[1].length;
			const key = `b${k++}`;
			const body = inline(heading[2], key);
			if (level === 1) {
				blocks.push(
					<h1
						key={key}
						className="mt-10 mb-4 font-semibold text-3xl text-ink tracking-tight first:mt-0"
					>
						{body}
					</h1>,
				);
			} else if (level === 2) {
				blocks.push(
					<h2
						key={key}
						className="mt-10 mb-3 font-semibold text-ink text-xl tracking-tight"
					>
						{body}
					</h2>,
				);
			} else {
				blocks.push(
					<h3 key={key} className="mt-6 mb-2 font-semibold text-base text-ink">
						{body}
					</h3>,
				);
			}
			i += 1;
			continue;
		}

		// ── table ────────────────────────────────────────────────────────────
		if (isTableRow(line)) {
			const rows: string[] = [];
			while (i < lines.length && isTableRow(lines[i] ?? "")) {
				rows.push(lines[i] ?? "");
				i += 1;
			}
			const key = `b${k++}`;
			const header = cells(rows[0] ?? "");
			const bodyRows = rows
				.slice(isSeparatorRow(rows[1] ?? "") ? 2 : 1)
				.map(cells);
			// A `| | |` header carries no labels — render the grid without a head.
			const hasHeader = header.some((c) => c.length > 0);
			blocks.push(
				<div key={key} className="my-6 overflow-x-auto">
					<table className="w-full border-collapse text-sm">
						{hasHeader && (
							<thead>
								<tr className="border-line border-b">
									{header.map((c) => {
										const ck = nextKey();
										return (
											<th
												key={ck}
												className="px-3 py-1.5 text-left font-semibold text-ink"
											>
												{inline(c, ck)}
											</th>
										);
									})}
								</tr>
							</thead>
						)}
						<tbody>
							{bodyRows.map((r) => (
								<tr key={nextKey()} className="border-line border-b">
									{r.map((c) => {
										const ck = nextKey();
										return (
											<td key={ck} className="px-3 py-2 align-top text-ink-2">
												{inline(c, ck)}
											</td>
										);
									})}
								</tr>
							))}
						</tbody>
					</table>
				</div>,
			);
			continue;
		}

		// ── unordered list ───────────────────────────────────────────────────
		if (/^\s*[-*]\s+/.test(line)) {
			const items: string[] = [];
			while (i < lines.length && /^\s*[-*]\s+/.test(lines[i] ?? "")) {
				items.push((lines[i] ?? "").replace(/^\s*[-*]\s+/, ""));
				i += 1;
			}
			const key = `b${k++}`;
			blocks.push(
				<ul key={key} className="my-4 list-disc space-y-2 pl-6 text-ink-2">
					{items.map((it) => {
						const lk = nextKey();
						return <li key={lk}>{inline(it, lk)}</li>;
					})}
				</ul>,
			);
			continue;
		}

		// ── ordered list ─────────────────────────────────────────────────────
		if (/^\s*\d+\.\s+/.test(line)) {
			const items: string[] = [];
			while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i] ?? "")) {
				items.push((lines[i] ?? "").replace(/^\s*\d+\.\s+/, ""));
				i += 1;
			}
			const key = `b${k++}`;
			blocks.push(
				<ol key={key} className="my-4 list-decimal space-y-2 pl-6 text-ink-2">
					{items.map((it) => {
						const lk = nextKey();
						return <li key={lk}>{inline(it, lk)}</li>;
					})}
				</ol>,
			);
			continue;
		}

		// ── paragraph (consecutive plain lines) ──────────────────────────────
		const para: string[] = [];
		while (i < lines.length) {
			const l = lines[i] ?? "";
			if (
				!l.trim() ||
				/^\s*---+\s*$/.test(l) ||
				/^#{1,4}\s+/.test(l) ||
				isTableRow(l) ||
				/^\s*[-*]\s+/.test(l) ||
				/^\s*\d+\.\s+/.test(l)
			) {
				break;
			}
			para.push(l.trim());
			i += 1;
		}
		const key = `b${k++}`;
		blocks.push(
			<p key={key} className="my-4 text-ink-2 leading-relaxed">
				{inline(para.join(" "), key)}
			</p>,
		);
	}

	return blocks;
}
