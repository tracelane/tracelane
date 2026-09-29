import { gatewayBaseUrl } from "@/lib/gateway";
import {
	TRACELANE_PLATFORM_PUBKEYS_B64,
	TRACELANE_PLATFORM_PUBKEY_B64,
} from "@tracelanedev/audit-verifier";

/** Decode only a complete Ed25519 public key; never read trust from ledger bytes. */
export function auditPublicKey(b64: string): Uint8Array {
	if (!/^[A-Za-z0-9+/]{43}=$/.test(b64))
		throw new Error("Invalid audit public key");
	const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
	if (bytes.length !== 32) throw new Error("Invalid audit public key length");
	return bytes;
}
export async function auditFingerprint(b64: string): Promise<string> {
	const digest = await crypto.subtle.digest(
		"SHA-256",
		auditPublicKey(b64) as Uint8Array<ArrayBuffer>,
	);
	return Array.from(new Uint8Array(digest), (b) =>
		b.toString(16).padStart(2, "0"),
	).join("");
}
export async function readPlatformTrustRoot() {
	// AUD-29 (security review M3): the TRUST ROOT is the key pinned in the verifier
	// release. The gateway endpoint is only a CROSS-CHECK — a DNS/CDN/gateway
	// compromise must not be able to substitute the root. Never a key from the evidence.
	const platformPubkeyB64 = TRACELANE_PLATFORM_PUBKEY_B64;
	let platformCrossCheck: "match" | "mismatch" | "unavailable" = "unavailable";
	try {
		const response = await fetch(
			`${gatewayBaseUrl()}/v1/audit/platform-pubkey`,
			{ next: { revalidate: 3600 }, signal: AbortSignal.timeout(10_000) },
		);
		if (response.ok) {
			const body = await response.json();
			platformCrossCheck = TRACELANE_PLATFORM_PUBKEYS_B64.includes(
				body.ed25519_pubkey_b64,
			)
				? "match"
				: "mismatch";
		}
	} catch {
		platformCrossCheck = "unavailable";
	}
	return {
		platformPubkeyB64,
		platformFingerprint: await auditFingerprint(platformPubkeyB64),
		platformKeySource: "pinned" as const,
		platformCrossCheck,
	};
}
