/**
 * CMK public-key fingerprinting — the ONE implementation for every route that
 * stores or compares a CMK fingerprint (create + rotate). Hashes the DECODED
 * SPKI DER bytes, NOT the armored PEM text, so the stored value reproduces
 * with `openssl pkey -pubin -outform DER | sha256sum` and matches the Audit
 * page's signing-key fingerprint regardless of PEM line-wrapping/whitespace.
 * (The rotate route previously hashed raw PEM text — irreproducible with
 * standard tooling, and the same key material could re-register as
 * "different"; 2026-07-22 audit.)
 */

/** Hex SHA-256 of the SPKI DER decoded from `pem`. */
export async function sha256Fingerprint(pem: string): Promise<string> {
	const b64 = pem
		.replace(/-----(BEGIN|END)[^-]*-----/g, "")
		.replace(/\s+/g, "");
	const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
	const hashBuf = await crypto.subtle.digest("SHA-256", der);
	return Array.from(new Uint8Array(hashBuf))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}
