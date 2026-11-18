import { createHash, generateKeyPairSync } from "node:crypto";
import { writeFileSync } from "node:fs";
import { PGlite } from "@electric-sql/pglite";
import { type PgliteDatabase, drizzle } from "drizzle-orm/pglite";
import { renderToStaticMarkup } from "react-dom/server";
import { afterAll, beforeAll, beforeEach, expect, it, vi } from "vitest";
import AuditKeyPage from "./page";

const h = vi.hoisted(() => ({
	db: null as PgliteDatabase | null,
	org: "org_a",
	authError: false,
}));
vi.mock("@/db", () => ({
	get db() {
		return h.db;
	},
}));
vi.mock("@/lib/auth", () => ({
	requireSession: async () => {
		if (h.authError) throw new Error("NEXT_REDIRECT");
		return { tenantId: h.org };
	},
}));

// Public test key: P-256 generator point; expected hash computed independently.
const ANCHOR =
	"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==";
const DIGEST =
	"5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3";
const OTHER = generateKeyPairSync("ec", { namedCurve: "prime256v1" })
	.publicKey.export({ type: "spki", format: "der" })
	.toString("base64");
const ED = Buffer.alloc(32, 1).toString("base64");
const A = "00000000-0000-4000-8000-000000000001";
const B = "00000000-0000-4000-8000-000000000002";
let pg: PGlite;
beforeAll(async () => {
	pg = new PGlite();
	h.db = drizzle(pg);
	// Minimal real Postgres tables for the selected public columns. Selecting a
	// secret accidentally is observable because sentinel encrypted columns exist.
	await pg.exec(`CREATE TABLE tenants (id uuid PRIMARY KEY, workos_org_id text UNIQUE);
		CREATE TABLE tenant_audit_keys (tenant_id uuid UNIQUE, public_key_b64 text,
		anchor_pubkey_spki_b64 text, encrypted_private_key text, encrypted_anchor_key text);`);
});
afterAll(async () => {
	await pg.close();
});
beforeEach(async () => {
	h.org = "org_a";
	h.authError = false;
	await pg.exec("TRUNCATE tenants, tenant_audit_keys");
	await pg.query("INSERT INTO tenants VALUES ($1, 'org_a'), ($2, 'org_b')", [
		A,
		B,
	]);
	// Insert B first so deleting a tenant predicate cannot accidentally pass.
	await pg.query(
		"INSERT INTO tenant_audit_keys VALUES ($1, $2, $3, 'private-b', 'secret-b'), ($4, $2, $5, 'private-a', 'secret-a')",
		[B, ED, OTHER, A, ANCHOR],
	);
});
const html = async () => renderToStaticMarkup(await AuditKeyPage());
const anchor = async (value: string | null) =>
	pg.query(
		"UPDATE tenant_audit_keys SET anchor_pubkey_spki_b64 = $1 WHERE tenant_id = $2",
		[value, A],
	);
function unknown(text: string) {
	expect(text).toContain("Cannot determine anchor key");
	expect(text).not.toContain("No anchor key yet");
	expect(text).not.toContain('aria-label="Copy anchor key"');
	expect(text).not.toContain("private database details");
}

it("populated_anchor", async () => {
	const text = await html();
	expect(text).toContain(ANCHOR);
	if (process.env.AUD05_PROOF_DIR)
		writeFileSync(`${process.env.AUD05_PROOF_DIR}/populated.html`, text);
});
it("der_fingerprint", async () => {
	expect(await html()).toContain(DIGEST);
});
it("distinct_key_labels", async () => {
	const text = await html();
	expect(text).toContain("ECDSA-P256 anchor key (SPKI, base64)");
	expect(text).toContain("Ed25519 signing key (base64)");
});
it("signing_key_preserved", async () => {
	const text = await html();
	expect(text).toContain(ED);
	expect(text).toContain(
		createHash("sha256").update(Buffer.from(ED, "base64")).digest("hex"),
	);
});
it("null_anchor", async () => {
	await anchor(null);
	const text = await html();
	expect(text).toContain("No anchor key yet");
	expect(text).not.toContain("Cannot determine anchor key");
	expect(text).toContain(ED);
});
it("missing_key_row", async () => {
	await pg.query("DELETE FROM tenant_audit_keys WHERE tenant_id = $1", [A]);
	expect(await html()).toContain("No anchor key yet");
});
it("other_workspace_own_key", async () => {
	h.org = "org_b";
	expect(await html()).toContain(OTHER);
});
it("repeat_read_updates", async () => {
	expect(await html()).toContain(ANCHOR);
	await anchor(OTHER);
	const text = await html();
	expect(text).toContain(OTHER);
	expect(text).not.toContain(ANCHOR);
});
it("recovery_after_error", async () => {
	h.org = "unknown";
	unknown(await html());
	h.org = "org_a";
	expect(await html()).toContain(ANCHOR);
});
it("full_key_not_truncated", async () => {
	expect(await html()).toContain(`>${ANCHOR}</code>`);
});
it("tenant_a_cannot_see_b", async () => {
	const text = await html();
	expect(text).toContain(ANCHOR);
	expect(text).not.toContain(OTHER);
});
it("tenant_b_cannot_see_a", async () => {
	h.org = "org_b";
	const text = await html();
	expect(text).toContain(OTHER);
	expect(text).not.toContain(ANCHOR);
});
it("unknown_org", async () => {
	h.org = "org_a' OR 1=1 --";
	const text = await html();
	unknown(text);
	expect(text).not.toContain(ANCHOR);
	expect(text).not.toContain(OTHER);
});
it("tenant_lookup_failure", async () => {
	const spy = vi
		.spyOn(pg, "query")
		.mockRejectedValueOnce(new Error("private database details"));
	unknown(await html());
	spy.mockRestore();
});
it("key_lookup_failure", async () => {
	await pg.exec("ALTER TABLE tenant_audit_keys RENAME TO unavailable_keys");
	try {
		unknown(await html());
	} finally {
		await pg.exec("ALTER TABLE unavailable_keys RENAME TO tenant_audit_keys");
	}
});
it("empty_anchor_is_unknown", async () => {
	await anchor("");
	unknown(await html());
});
it("malformed_base64", async () => {
	await anchor(`${ANCHOR}!!`);
	unknown(await html());
});
it("no_private_material", async () => {
	const text = await html();
	expect(text).not.toMatch(/private-[ab]|secret-[ab]/);
});
it("auth_failure_propagates", async () => {
	h.authError = true;
	const spy = vi.spyOn(pg, "query");
	await expect(html()).rejects.toThrow("NEXT_REDIRECT");
	expect(spy).not.toHaveBeenCalled();
});
it("fingerprint_not_base64_text", async () => {
	const text = await html();
	expect(text).toContain(DIGEST);
	expect(text).not.toContain(createHash("sha256").update(ANCHOR).digest("hex"));
});
