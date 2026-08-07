/**
 * /settings/audit — the tenant's audit signing key (ADR-062 C2 trust channel).
 *
 * Shows the Ed25519 audit pubkey + SHA-256 fingerprint so an auditor can confirm
 * the `--tenant-pubkey` their offline verifier was handed genuinely belongs to
 * this workspace. Read-only, server-rendered from `tenant_audit_keys`.
 */

import { createHash } from "node:crypto";
import { CopyButton } from "@/components/trace-viewer/CopyButton";
import { db } from "@/db";
import { tenantAuditKeys, tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { Card } from "@tracelanedev/ui";
import { eq } from "drizzle-orm";
import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = { title: "Audit signing key — Settings" };
export const dynamic = "force-dynamic";

function fingerprint(b64: string): string {
	if (!b64) return "";
	try {
		return createHash("sha256")
			.update(Buffer.from(b64, "base64"))
			.digest("hex");
	} catch {
		return "";
	}
}

export default async function AuditKeyPage() {
	const session = await requireSession();
	const [tenantRow] = await db
		.select({ id: tenants.id })
		.from(tenants)
		.where(eq(tenants.workosOrgId, session.tenantId))
		.limit(1);

	let ed = "";
	if (tenantRow?.id) {
		const [row] = await db
			.select({ ed: tenantAuditKeys.publicKeyB64 })
			.from(tenantAuditKeys)
			.where(eq(tenantAuditKeys.tenantId, tenantRow.id))
			.limit(1);
		ed = row?.ed ?? "";
	}

	return (
		<div className="space-y-6">
			<div className="space-y-1">
				<h2 className="text-sm font-semibold text-ink">Audit signing key</h2>
				<p className="text-xs text-ink-2">
					Your workspace&apos;s Ed25519 key signs every audit batch&apos;s
					Merkle root. Hand this key to your offline verifier as{" "}
					<code className="font-mono text-ink">--tenant-pubkey</code> to check
					the ledger&apos;s signatures + public anchors yourself.
				</p>
			</div>

			{ed ? (
				<Card provenance className="space-y-3 p-5">
					<div>
						<div className="flex items-center justify-between gap-2">
							<div className="t-card-title">
								Ed25519 signing key (base64) — your trust root
							</div>
							<CopyButton value={ed} label="Copy key" />
						</div>
						<code className="mt-1 block break-all font-mono text-[12px] text-ink">
							{ed}
						</code>
						<div className="mt-1 font-mono text-[11px] text-ink-2">
							SHA-256 fingerprint: {fingerprint(ed)}
						</div>
					</div>

					{/* Non-cryptographer how-to — the trust channel in three steps. */}
					<div className="rounded-md border border-line bg-surface-2/30 p-3 text-[13px] text-ink-2">
						<div className="mb-1.5 font-medium text-ink">
							Give this to your auditor
						</div>
						<ol className="list-decimal space-y-1 pl-4">
							<li>Copy your tenant public key above — it is the trust root.</li>
							<li>
								<strong>Share it out-of-band</strong> — through a channel
								Tracelane does not control (your own email, a signed document,
								in person), never via a Tracelane link.
							</li>
							<li>
								Your auditor runs{" "}
								<code className="font-mono text-ink">
									tlane verify ./audit.ndjson --tenant-pubkey &lt;key&gt;
								</code>{" "}
								on the exported ledger — no Tracelane account needed.
							</li>
						</ol>
						<p className="mt-2 text-[12px] text-ink-3">
							<strong className="text-ink-2">Why out-of-band matters:</strong> a
							key fetched from us proves nothing — we could serve a forged one.
							A valid signature only means &ldquo;signed by the key you
							trusted,&rdquo; so the key must reach your auditor through a
							channel we can&apos;t touch. That independence is the whole point;
							it makes the ledger tamper-evident, not merely signed.
						</p>
					</div>
				</Card>
			) : (
				<Card className="p-5">
					<div className="text-sm font-medium text-ink">No signing key yet</div>
					<p className="mt-1 text-[13px] text-ink-2">
						Generated automatically on your first gateway-proxied batch, then
						shown here.
					</p>
				</Card>
			)}

			{/* How-to — written from the ADR-066 entitlement split, not marketing:
			    self-verify is default-granted on EVERY plan; only the Article-12
			    evidence-pack export is the $999 Audit add-on. The chain is
			    per-workspace (never per-trace) and tamper-evident (the chain
			    proves whether a record was altered). Every capability named below is built + live. */}
			<Card className="space-y-4 p-5">
				<div>
					<h3 className="text-sm font-semibold text-ink">
						How to verify your audit chain
					</h3>
					<p className="mt-1 text-[13px] leading-relaxed text-ink-2">
						Your workspace keeps one <strong>tamper-evident</strong> audit chain
						— a hash-linked, signed ledger of your audit events,{" "}
						<strong>per workspace</strong> (not per trace). Here is how to check
						it, and exactly what is free versus paid.
					</p>
				</div>

				<ol className="space-y-3 text-[13px] text-ink-2">
					<li className="flex gap-3">
						<span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-seal-soft font-mono text-[11px] font-semibold text-seal-ink">
							1
						</span>
						<span>
							<span className="font-medium text-ink">
								See &amp; verify in your browser — free, every plan.
							</span>{" "}
							Open the{" "}
							<Link
								href="/audit"
								className="font-medium text-accent-ink hover:underline"
							>
								Audit page
							</Link>
							: it loads your recent chain and runs the reference verifier right
							in your browser — signatures valid, hash chain unbroken, and any
							public anchors resolved. No trace ID needed; it verifies your
							whole recent chain within your plan&apos;s retention window.
						</span>
					</li>
					<li className="flex gap-3">
						<span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-seal-soft font-mono text-[11px] font-semibold text-seal-ink">
							2
						</span>
						<span>
							<span className="font-medium text-ink">
								Re-verify offline yourself — free.
							</span>{" "}
							The same bytes drive the open-source CLI. Run{" "}
							<code className="rounded bg-surface-2 px-1 py-0.5 font-mono text-[12px] text-ink">
								tlane verify ./audit.ndjson --tenant-pubkey &lt;key above&gt;
							</code>{" "}
							(add <code className="font-mono text-ink">--offline</code> to skip
							the Rekor network check). It reproduces the same verdict
							byte-for-byte — an independent check that needs no Tracelane
							account.
						</span>
					</li>
					<li className="flex gap-3">
						<span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-accent-soft font-mono text-[11px] font-semibold text-accent-ink">
							3
						</span>
						<span>
							<span className="font-medium text-ink">
								Export the Article-12 evidence pack — paid ($999/mo Audit
								add-on).
							</span>{" "}
							For a formatted, downloadable compliance deliverable (EU AI Act
							Article 12), enable the Audit add-on and the export appears on the
							Audit page. Self-verify (steps 1–2) stays free — only this filed
							export is the paid part.
						</span>
					</li>
				</ol>

				<div className="rounded-md border border-line bg-surface-2/40 p-3 text-[12.5px] leading-relaxed text-ink-2">
					<span className="font-medium text-ink">Worked example.</span> A
					customer disputes a run from last month. Open the Audit page, narrow
					to that window, and confirm the chain is green (signatures valid,
					chain unbroken). Hand your auditor the signing key above out-of-band;
					they reproduce the same green with{" "}
					<code className="font-mono text-ink">tlane verify</code> on their own
					machine. If they need a filed compliance pack, export it via the Audit
					add-on.
				</div>

				<Link
					href="/audit"
					className="inline-flex text-[13px] font-medium text-accent-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
				>
					Open the Audit page to verify now →
				</Link>
			</Card>
		</div>
	);
}
