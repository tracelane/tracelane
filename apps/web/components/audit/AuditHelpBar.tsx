/**
 * AuditHelpBar — the self-service "User Guide / Help" surface at the top of the
 * Audit page (founder: "add it to top of the page … to download and self-serve").
 *
 * Free, for every tenant: open the User Guide (self-contained HTML) or download
 * its PDF — served as public static assets. Audit-SKU tenants (`exportEntitled`)
 * additionally get the Compliance & Evidence Handbook, gated at
 * `/api/audit/handbook`. No client JS — plain links.
 */

import Link from "next/link";

const linkCls =
	"inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface px-3 py-1.5 text-sm font-medium text-ink-2 transition-colors hover:border-line-2 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring";
// Present-but-locked affordance for the paid handbook — visible so the value is
// legible to non-SKU tenants (a hidden feature can't sell), links to billing.
const lockedCls =
	"inline-flex items-center gap-1.5 rounded-lg border border-dashed border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink-3 transition-colors hover:text-ink-2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring";

export function AuditHelpBar({ exportEntitled }: { exportEntitled: boolean }) {
	return (
		<div className="mb-5 flex flex-col gap-3 rounded-lg border border-line bg-surface-2 p-4 sm:flex-row sm:items-center sm:justify-between">
			<div className="flex items-start gap-3">
				{/* The chip is `bg-surface` + `border-line`, the same material as this
				    bar's own sibling links, NOT `bg-surface-inverse` (2026-08-22 contrast
				    audit). `--surface-inverse` gave a chip at 17.4:1 against the
				    `--surface-2` bar in light and 1.15:1 in dark — a hard black square in
				    one theme and nothing at all in the other, which is the P0.18 parity
				    break rather than a tone choice. `text-ink-inverse` went with it: the
				    glyph is a full-colour emoji, so the class was never doing any work.
				    The pair now steps UP from the well in both themes (1.09:1 / 1.07:1
				    fill, plus the hairline), which is quiet in both — and quiet-in-both is
				    the contract, for a decorative aria-hidden container. */}
				<span
					aria-hidden
					className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-line bg-surface text-base"
				>
					📘
				</span>
				<div>
					<div className="text-sm font-semibold text-ink">
						User Guide &amp; Help
					</div>
					<p className="text-xs text-ink-2">
						What the Audit Ledger is, how to verify integrity yourself, and what
						to do if a check ever fails.
					</p>
				</div>
			</div>
			<div className="flex flex-wrap items-center gap-2">
				<a
					href="/audit-user-guide"
					target="_blank"
					rel="noreferrer"
					className={linkCls}
				>
					Open guide ↗
				</a>
				<a href="/audit-user-guide.pdf" download className={linkCls}>
					Download PDF
				</a>
				{exportEntitled ? (
					<a href="/api/audit/handbook" className={linkCls}>
						Compliance Handbook (PDF)
					</a>
				) : (
					<Link
						href="/settings/billing"
						title="Auditor-formatted Compliance & Evidence Handbook — included with the $999/mo Audit add-on"
						className={lockedCls}
					>
						🔒 Compliance Handbook · Audit SKU
					</Link>
				)}
			</div>
		</div>
	);
}
