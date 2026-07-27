/**
 * CMK public-key algorithm detection.
 *
 * Parses a PEM with node:crypto to resolve the real key type, replacing the old
 * substring heuristic in the POST route that labeled every SPKI ("BEGIN PUBLIC
 * KEY") key — RSA included — as ed25519. Only the two algorithms the platform
 * supports (Ed25519, RSA-4096; see `cmkAlgorithmEnum`) are accepted; anything
 * else (wrong RSA size, EC, unparseable input) is rejected with a reason, so a
 * stored label can never misrepresent the real key.
 *
 * Lives in its own module (not `route.ts`) because Next.js route files may only
 * export route handlers — an extra named export fails the generated route-type
 * validator. Imported by `route.ts` and unit-tested directly.
 */

import { createPublicKey } from "node:crypto";
import type { cmkAlgorithmEnum } from "@/db/schema";

export type CmkAlgorithm = (typeof cmkAlgorithmEnum.enumValues)[number];

/**
 * Resolve the CMK algorithm from a PEM, or return an `error` string for the
 * caller to surface as a 422. Never returns a label that doesn't match the
 * actual parsed key.
 */
export function resolveCmkAlgorithm(
	pem: string,
): { algorithm: CmkAlgorithm } | { error: string } {
	let key: ReturnType<typeof createPublicKey>;
	try {
		key = createPublicKey(pem);
	} catch {
		return { error: "could not parse a public key from the provided PEM" };
	}
	switch (key.asymmetricKeyType) {
		case "ed25519":
			return { algorithm: "ed25519" };
		case "rsa": {
			const bits = key.asymmetricKeyDetails?.modulusLength;
			if (bits === 4096) return { algorithm: "rsa-4096" };
			return {
				error: `unsupported RSA key size${
					typeof bits === "number" ? ` (${bits}-bit)` : ""
				} — only RSA-4096 is supported`,
			};
		}
		default:
			return {
				error: `unsupported key type "${
					key.asymmetricKeyType ?? "unknown"
				}" — provide an Ed25519 or RSA-4096 public key`,
			};
	}
}
