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
	let anchor = "";
	if (tenantRow?.id) {
		const [row] = await db
			.select({
				ed: tenantAuditKeys.publicKeyB64,
				anchor: tenantAuditKeys.anchorPubkeySpkiB64,
			})
			.from(tenantAuditKeys)
			.where(eq(tenantAuditKeys.tenantId, tenantRow.id))
			.limit(1);
		ed = row?.ed ?? "";
		anchor = row?.anchor ?? "";
	}

	return (
		<div className="space-y-1">
			<h2 className="text-sm font-semibold text-ink">Audit signing key</h2>
			<p className="mb-6 text-xs text-ink-2">
				Your workspace&apos;s Ed25519 key signs every audit batch&apos;s Merkle
				root. Hand this key to your offline verifier as{" "}
				<code className="font-mono text-ink">--tenant-pubkey</code> to check the
				ledger&apos;s signatures + public anchors yourself.
			</p>

			{ed ? (
				<Card provenance className="space-y-3 p-5">
					<div>
						<div className="flex items-center justify-between gap-2">
							<div className="text-[11px] font-semibold uppercase tracking-wide text-ink-2">
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
					{anchor ? (
						<div className="font-mono text-[11px] text-ink-2">
							Rekor anchor key (ECDSA-P256) fingerprint: {fingerprint(anchor)}
						</div>
					) : null}
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
		</div>
	);
}
