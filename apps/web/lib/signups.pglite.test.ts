/**
 * SET-60 — `recordSignIn` against a REAL Postgres engine (PGlite) with the REAL
 * `0063_signups.sql` and the real schema, so a renamed column or a wrong ON CONFLICT
 * fails here instead of silently dropping the founder's signup list on Neon.
 *
 * Negative cases first (`.claude/rules/testing.md`): a sign-in the hook must NOT record
 * (impersonation) and a DB failure that must NOT surface are asserted before the happy path.
 */

import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as schema from "@/db/schema";
import { PGlite } from "@electric-sql/pglite";
import { eq, sql } from "drizzle-orm";
import { type PgliteDatabase, drizzle } from "drizzle-orm/pglite";
import { migrate } from "drizzle-orm/pglite/migrator";
import {
	afterAll,
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	vi,
} from "vitest";

const h = vi.hoisted(() => ({
	db: null as PgliteDatabase<typeof import("@/db/schema")> | null,
}));

const db = () => {
	if (!h.db) throw new Error("pglite harness not started");
	return h.db;
};

vi.mock("@/db", () => ({
	get db() {
		if (!h.db) throw new Error("pglite db not initialised (beforeAll failed)");
		return h.db;
	},
}));

vi.mock("@workos-inc/authkit-nextjs", () => ({
	withAuth: async () => ({
		user: { id: "user_01ABC", email: "ada@example.test" },
		organizationId: "org_01XYZ",
	}),
}));
vi.mock("@/lib/auth", () => ({
	requireSession: async () => ({
		tenantId: "org_01XYZ",
		userId: "user_01ABC",
		email: "ada@example.test",
	}),
	invalidateOrgArchivedCache: vi.fn(),
}));
vi.mock("@/lib/workos-org", () => ({
	listMemberships: async () => [
		{ user_id: "user_01ABC", role: { slug: "member" } },
		{ user_id: "user_other", role: { slug: "owner" } },
	],
	isPrivilegedRole: (role: string) => role === "owner",
}));
vi.mock("@/app/api/settings/team/owner-lock", () => ({
	withOwnerMutation: async (_org: string, work: () => Promise<unknown>) =>
		work(),
}));
import { DELETE } from "@/app/api/settings/account/route";
import type { NextRequest } from "next/server";

import { MAX_EMAIL, MAX_NAME, recordSignIn } from "./signups";

let pg: PGlite;

beforeAll(async () => {
	pg = new PGlite();
	h.db = drizzle(pg, { schema });
	const folder = path.resolve(
		path.dirname(fileURLToPath(import.meta.url)),
		"../db/migrations",
	);
	await migrate(h.db, { migrationsFolder: folder });
	const journaled = new Set<string>(
		(
			JSON.parse(
				readFileSync(path.join(folder, "meta/_journal.json"), "utf-8"),
			) as { entries: { tag: string }[] }
		).entries.map((e) => e.tag),
	);
	// Every hand-applied migration, in order (the same loader the other PGlite suites
	// use), so `users` and `signups` are the real shapes. 0010 only flips a default the
	// later ones do not depend on and is exercised by its own suite.
	for (const f of readdirSync(folder)
		.filter((n) => n.endsWith(".sql"))
		.filter((n) => !journaled.has(n.replace(/\.sql$/, "")))
		.filter((n) => !n.startsWith("0010_"))
		.sort()) {
		await pg.exec(readFileSync(path.join(folder, f), "utf-8"));
	}
}, 180_000);

afterAll(async () => {
	await pg.close();
});

beforeEach(async () => {
	await db().execute(sql`DELETE FROM account_deletions`);
	await db().execute(sql`DELETE FROM signups`);
	await db().execute(sql`DELETE FROM users`);
});

afterEach(() => {
	vi.restoreAllMocks();
});

function signIn(over: Record<string, unknown> = {}) {
	return {
		user: {
			id: "user_01ABC",
			email: "ada@example.test",
			firstName: "Ada",
			lastName: "Lovelace",
		},
		organizationId: "org_01XYZ",
		authenticationMethod: "GoogleOAuth",
		...over,
		// biome-ignore lint/suspicious/noExplicitAny: structural test fixture
	} as any;
}

async function seedMirror() {
	await db().execute(sql`
			INSERT INTO tenants (id, workos_org_id) VALUES ('11111111-2222-3333-4444-555555555555', 'org_01XYZ')
			ON CONFLICT DO NOTHING`);
	await db().insert(schema.users).values({
		userId: "99999999-2222-3333-4444-555555555555",
		tenantId: "11111111-2222-3333-4444-555555555555",
		email: "ada@example.test",
		workosUserId: "user_01ABC",
	});
}

const rows = () => db().select().from(schema.signups);

/** The single row, or a loud failure (noUncheckedIndexedAccess-safe). */
async function one() {
	const all = await rows();
	const r = all[0];
	if (all.length !== 1 || !r)
		throw new Error(`expected 1 row, got ${all.length}`);
	return r;
}

describe("recordSignIn — must NOT record / must NOT throw", () => {
	it("REJECT: an impersonated session writes no row", async () => {
		await recordSignIn(
			signIn({
				impersonator: { email: "admin@workos.test", reason: "support" },
			}),
		);
		expect(await rows()).toHaveLength(0);
	});

	it("REJECT: no email or no user id writes no row", async () => {
		await recordSignIn(signIn({ user: { id: "user_X", email: "" } }));
		await recordSignIn(signIn({ user: { id: "", email: "a@b.test" } }));
		expect(await rows()).toHaveLength(0);
	});

	it("a DB failure does NOT throw out of onSuccess, and the log line carries no email or name", async () => {
		const err = vi.spyOn(console, "error").mockImplementation(() => {});
		vi.spyOn(db(), "insert").mockImplementation(() => {
			throw new Error("boom: relation signups does not exist ada@example.test");
		});
		await expect(recordSignIn(signIn())).resolves.toBeUndefined();
		expect(err).toHaveBeenCalledTimes(1);
		const logged = JSON.stringify(err.mock.calls);
		expect(logged).toContain("[signups]");
		expect(logged).not.toContain("ada@example.test");
		expect(logged).not.toContain("Ada");
	});

	it("a failure on the users update does not stop the signups row", async () => {
		vi.spyOn(console, "error").mockImplementation(() => {});
		vi.spyOn(db(), "update").mockImplementation(() => {
			throw new Error("users table down");
		});
		await recordSignIn(signIn());
		expect(await rows()).toHaveLength(1);
	});
});

describe("recordSignIn — bounded input", () => {
	it("a long name is stored at MAX_NAME and a long email at MAX_EMAIL", async () => {
		await recordSignIn(
			signIn({
				user: {
					id: "user_LONG",
					email: `${"a".repeat(400)}@example.test`,
					firstName: "N".repeat(500),
					lastName: "Z",
				},
			}),
		);
		const r = await one();
		expect(r.name).toHaveLength(MAX_NAME);
		expect(r.email).toHaveLength(MAX_EMAIL);
	});

	it("truncation never splits a surrogate pair, and a NUL byte cannot reach Postgres", async () => {
		await recordSignIn(
			signIn({
				user: {
					id: "user_EMOJI",
					email: "e@example.test",
					firstName: `${"x".repeat(MAX_NAME - 1)}😀tail\u0000`,
					lastName: null,
				},
			}),
		);
		const r = await one();
		expect(r.name).not.toContain("\u0000");
		expect(Array.from(r.name ?? "").length).toBeLessThanOrEqual(MAX_NAME);
		// no lone surrogate
		expect(r.name).toBe(
			r.name ? Buffer.from(r.name, "utf8").toString("utf8") : r.name,
		);
	});

	it("a name with no first/last stores NULL, not an empty string", async () => {
		await recordSignIn(
			signIn({
				user: {
					id: "user_NN",
					email: "n@example.test",
					firstName: null,
					lastName: null,
				},
			}),
		);
		const r = await one();
		expect(r.name).toBeNull();
	});
});

describe("recordSignIn — rows", () => {
	it("first sign-in inserts the full row", async () => {
		await recordSignIn(signIn());
		const r = await one();
		expect(r.workosUserId).toBe("user_01ABC");
		expect(r.email).toBe("ada@example.test");
		expect(r.name).toBe("Ada Lovelace");
		expect(r.loginCount).toBe(1);
		expect(r.organizationId).toBe("org_01XYZ");
		expect(r.authMethod).toBe("GoogleOAuth");
		expect(r.firstSeenAt).toBeInstanceOf(Date);
		expect(r.lastLoginAt).toBeInstanceOf(Date);
	});

	it("repeat sign-in increments login_count, keeps first_seen_at, moves last_login_at", async () => {
		await recordSignIn(signIn());
		const first = await one();
		await new Promise((r) => setTimeout(r, 25));
		await recordSignIn(
			signIn({ authenticationMethod: "MagicAuth", organizationId: undefined }),
		);
		const r = await one();
		expect(r.loginCount).toBe(2);
		expect(r.firstSeenAt.getTime()).toBe(first.firstSeenAt.getTime());
		expect((r.lastLoginAt as Date).getTime()).toBeGreaterThan(
			(first.lastLoginAt as Date).getTime(),
		);
		expect(r.authMethod).toBe("MagicAuth");
		// name survives a sign-in that carries none
		const again = signIn({
			user: {
				id: "user_01ABC",
				email: "ada@example.test",
				firstName: null,
				lastName: null,
			},
		});
		await recordSignIn(again);
		expect((await one()).name).toBe("Ada Lovelace");
		expect((await one()).loginCount).toBe(3);
	});

	it("refreshes email and name when WorkOS reports new ones", async () => {
		await recordSignIn(signIn());
		await recordSignIn(
			signIn({
				user: {
					id: "user_01ABC",
					email: "ada@new.test",
					firstName: "Augusta",
					lastName: "King",
				},
			}),
		);
		const r = await one();
		expect(r.email).toBe("ada@new.test");
		expect(r.name).toBe("Augusta King");
	});

	it("also stamps users.last_login_at where a mirror row exists, and no-ops where none does", async () => {
		await seedMirror();
		await recordSignIn(signIn());
		const [u] = await db()
			.select({ at: schema.users.lastLoginAt })
			.from(schema.users)
			.where(eq(schema.users.workosUserId, "user_01ABC"));
		expect(u?.at).toBeInstanceOf(Date);
		// a user with no mirror row still gets a signups row, and nothing throws
		await recordSignIn(
			signIn({ user: { id: "user_NOMIRROR", email: "m@example.test" } }),
		);
		expect(await rows()).toHaveLength(2);
	});
});

it("deletion erases PII and a delayed callback cannot recreate it", async () => {
	await seedMirror();
	vi.stubEnv("WORKOS_API_KEY", "sk_test_workos_do_not_use");
	vi.stubGlobal(
		"fetch",
		vi.fn(async () => ({ ok: true })),
	);
	try {
		await recordSignIn(signIn());
		await db().execute(
			sql`UPDATE users SET name = 'Ada Lovelace' WHERE workos_user_id = 'user_01ABC'`,
		);
		const result = await DELETE({
			json: async () => ({ confirmEmail: "ada@example.test" }),
		} as NextRequest);
		expect(result.status).toBe(200);
		expect(await rows()).toHaveLength(0);
		await recordSignIn(signIn());
		expect(await rows()).toHaveLength(0);
		await db().execute(
			sql`UPDATE users SET email = 'restored@example.test', name = 'Restored' WHERE workos_user_id = 'user_01ABC'`,
		);
		const [mirror] = await db()
			.select()
			.from(schema.users)
			.where(eq(schema.users.workosUserId, "user_01ABC"));
		expect(mirror?.email).toBe("deleted-user_01ABC@tombstone.invalid");
		expect(mirror?.name).toBeNull();
		expect(mirror?.lastLoginAt).toBeNull();
		const markers = await db().select().from(schema.accountDeletions);
		expect(markers).toEqual([{ workosUserId: "user_01ABC" }]);
		// A retry is idempotent, including when WorkOS previously failed.
		await db().execute(sql`SELECT erase_account_pii('user_01ABC')`);
	} finally {
		vi.unstubAllGlobals();
		vi.unstubAllEnvs();
	}
});

it("local erasure rolls back PII and marker together on a mirror failure", async () => {
	await seedMirror();
	await recordSignIn(signIn());
	await db().execute(
		sql`UPDATE users SET name = 'Ada' WHERE workos_user_id = 'user_01ABC'`,
	);
	await pg.exec(`CREATE FUNCTION reject_mirror_erasure() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN RAISE EXCEPTION 'planted mirror failure'; END $$;
 CREATE TRIGGER reject_mirror_erasure BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION reject_mirror_erasure();`);
	try {
		await expect(
			db().execute(sql`SELECT erase_account_pii('user_01ABC')`),
		).rejects.toThrow();
		expect(await rows()).toHaveLength(1);
		expect(await db().select().from(schema.accountDeletions)).toHaveLength(0);
	} finally {
		await pg.exec(
			"DROP TRIGGER reject_mirror_erasure ON users; DROP FUNCTION reject_mirror_erasure();",
		);
	}
});
