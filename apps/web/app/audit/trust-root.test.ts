import { TRACELANE_PLATFORM_PUBKEY_B64 } from "@tracelanedev/audit-verifier";
import { afterEach, expect, it, vi } from "vitest";
import { auditFingerprint, readPlatformTrustRoot } from "./trust-root";
vi.mock("@/lib/gateway", () => ({
	gatewayBaseUrl: () => "http://fixture.invalid",
}));
afterEach(() => vi.unstubAllGlobals());

const json = (body: unknown, status = 200) =>
	new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json" },
	});

// AUD-29 (security review M3): the PINNED key is the trust root whatever the gateway
// says; the endpoint only cross-checks it. A gateway serving a different key must
// never become the root — it becomes a visible FAILED cross-check.
it("roots trust in the pinned key and cross-checks the gateway's published one", async () => {
	const read = vi
		.fn()
		.mockResolvedValue(
			json({ ed25519_pubkey_b64: TRACELANE_PLATFORM_PUBKEY_B64 }),
		);
	vi.stubGlobal("fetch", read);
	expect(await readPlatformTrustRoot()).toEqual({
		platformPubkeyB64: TRACELANE_PLATFORM_PUBKEY_B64,
		platformFingerprint: await auditFingerprint(TRACELANE_PLATFORM_PUBKEY_B64),
		platformKeySource: "pinned",
		platformCrossCheck: "match",
	});
	expect(read.mock.calls[0]?.[0]).toBe(
		"http://fixture.invalid/v1/audit/platform-pubkey",
	);
	expect(read.mock.calls[0]?.[1].headers).toBeUndefined();
});

it("never adopts a DIFFERENT key the gateway publishes — the cross-check fails loudly", async () => {
	vi.stubGlobal(
		"fetch",
		vi
			.fn()
			.mockResolvedValue(
				json({ ed25519_pubkey_b64: Buffer.alloc(32, 8).toString("base64") }),
			),
	);
	const root = await readPlatformTrustRoot();
	expect(root.platformPubkeyB64).toBe(TRACELANE_PLATFORM_PUBKEY_B64);
	expect(root.platformCrossCheck).toBe("mismatch");
});

it.each([
	["an error status", () => json({ error: "no_platform_key" }, 503)],
	["a network failure", () => Promise.reject(new Error("down"))],
])(
	"keeps the pinned root and says the cross-check is unavailable on %s",
	async (_, reply) => {
		vi.stubGlobal("fetch", vi.fn().mockImplementation(reply));
		const root = await readPlatformTrustRoot();
		expect(root.platformPubkeyB64).toBe(TRACELANE_PLATFORM_PUBKEY_B64);
		expect(root.platformCrossCheck).toBe("unavailable");
	},
);
