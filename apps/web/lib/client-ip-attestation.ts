/**
 * Signed client-IP attestation for the gateway.
 *
 * The dashboard calls the gateway from a Worker, so the gateway sees the
 * Worker's address, not the browser's. The workspace admin IP allowlist needs
 * the browser's address, so the dashboard signs it:
 *
 *   x-tracelane-client-ip-attestation: v1;<ip>;<unix-seconds>;<hex HMAC-SHA256>
 *
 * HMAC key = UTF-8 bytes of TRACELANE_CLIENT_IP_ATTEST_SECRET (>= 32 bytes,
 * else disabled). Signed message = `v1|<ip>|<unix-seconds>|<hex SHA-256 of the
 * bearer token>`, binding the claim to one session token. Absent secret or
 * unusable IP -> `null` and the caller sends nothing (the gateway then uses its
 * own derivation).
 */

export const ATTESTATION_HEADER = "x-tracelane-client-ip-attestation";
const MIN_SECRET_BYTES = 32;

const enc = new TextEncoder();

function hex(buf: ArrayBuffer): string {
	return Array.from(new Uint8Array(buf), (b) =>
		b.toString(16).padStart(2, "0"),
	).join("");
}

/** Simple IPv4/IPv6 shape check (no zone ids). */
export function isValidIp(ip: string): boolean {
	const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
	if (v4) return v4.slice(1).every((o) => Number(o) <= 255);
	if (!ip.includes(":") || !/^[0-9a-fA-F:.]+$/.test(ip)) return false;
	try {
		return new URL(`http://[${ip}]/`).hostname !== "";
	} catch {
		return false;
	}
}

export async function attestationHeader(
	token: string,
	ip: string,
	nowSec: number,
	secret: string,
): Promise<string> {
	const tokenHash = hex(
		await crypto.subtle.digest("SHA-256", enc.encode(token)),
	);
	const key = await crypto.subtle.importKey(
		"raw",
		enc.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const message = `v1|${ip}|${nowSec}|${tokenHash}`;
	const mac = hex(await crypto.subtle.sign("HMAC", key, enc.encode(message)));
	return `v1;${ip};${nowSec};${mac}`;
}

/** Header value, or `null` when the secret is unset/short or the IP is invalid. */
export async function maybeAttestationHeader(
	token: string,
	ip: string | null | undefined,
	secret: string | undefined,
	nowSec: number = Math.floor(Date.now() / 1000),
): Promise<string | null> {
	if (!secret || enc.encode(secret).length < MIN_SECRET_BYTES) return null;
	if (!ip || !isValidIp(ip)) return null;
	return attestationHeader(token, ip, nowSec, secret);
}
