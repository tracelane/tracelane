/**
 * AuditHelpBar — the self-service "User Guide / Help" surface at the top of the
 * Audit page (founder: "add it to top of the page … to download and self-serve").
 *
 * Free, for every tenant: open the User Guide (self-contained HTML) or download
 * its PDF — served as public static assets. Audit-SKU tenants (`exportEntitled`)
 * additionally get the Compliance & Evidence Handbook, gated at
 * `/api/audit/handbook`. No client JS — plain links.
 */

const linkCls =
	"inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface px-3 py-1.5 text-[13px] font-medium text-ink-2 transition-colors hover:border-line-2 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal";

export function AuditHelpBar({ exportEntitled }: { exportEntitled: boolean }) {
	return (
		<div className="mb-5 flex flex-col gap-3 rounded-xl border border-line bg-surface-2/40 p-4 sm:flex-row sm:items-center sm:justify-between">
			<div className="flex items-start gap-3">
				<span
					aria-hidden
					className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-surface-inverse text-base text-ink-inverse"
				>
					📘
				</span>
				<div>
					<div className="text-[13.5px] font-semibold text-ink">
						User Guide &amp; Help
					</div>
					<p className="text-[12.5px] text-ink-2">
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
				{exportEntitled && (
					<a href="/api/audit/handbook" className={linkCls}>
						Compliance Handbook (PDF)
					</a>
				)}
			</div>
		</div>
	);
}
