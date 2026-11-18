import { CopyButton } from "@/components/trace-viewer/CopyButton";
import { Card } from "@tracelanedev/ui";

export type AnchorKeyState =
	| { status: "present"; spkiB64: string; fingerprint: string }
	| { status: "absent" }
	| { status: "error" };

export function AnchorKeyCard({ state }: { state: AnchorKeyState }) {
	return (
		<Card className="min-w-0 space-y-3 p-5">
			<div className="flex flex-wrap items-center justify-between gap-2">
				<h3 className="t-card-title">ECDSA-P256 anchor key (SPKI, base64)</h3>
				{state.status === "present" && (
					<CopyButton value={state.spkiB64} label="Copy anchor key" />
				)}
			</div>
			<p className="text-xs text-ink-2">
				This public key is used for Rekor anchoring. It is separate from the
				Ed25519 key used to sign audit batches.
			</p>
			{state.status === "present" ? (
				<div className="space-y-1">
					<code className="block break-all font-mono text-xs text-ink">
						{state.spkiB64}
					</code>
					<p className="break-all font-mono text-2xs text-ink-2">
						SHA-256 fingerprint: {state.fingerprint}
					</p>
					<p className="text-xs text-ink-3">
						Computed from the decoded SPKI DER bytes.
					</p>
				</div>
			) : state.status === "absent" ? (
				<div>
					<p className="text-sm font-medium text-ink">No anchor key yet</p>
					<p className="mt-1 text-sm text-ink-2">
						No anchor public key is stored for this workspace.
					</p>
				</div>
			) : (
				<div aria-live="polite">
					<p className="text-sm font-medium text-ink">
						Cannot determine anchor key
					</p>
					<p className="mt-1 text-sm text-ink-2">
						The workspace anchor key could not be read. Its presence cannot be
						confirmed.
					</p>
					<a
						href="/settings/audit"
						className="mt-2 inline-flex text-sm font-medium text-action-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
					>
						Reload audit keys
					</a>
				</div>
			)}
		</Card>
	);
}
