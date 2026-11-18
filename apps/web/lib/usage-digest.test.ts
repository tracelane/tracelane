/**
 * PLT-54 — the daily usage digest: pure rendering and window logic, the cron runner's
 * fail-open paths, and the ONE count query against a real Postgres engine (PGlite) with the
 * real migrations, so a renamed column or a wrong window fails here and not silently on Neon.
 */

import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as schema from "@/db/schema";
import { PGlite } from "@electric-sql/pglite";
import { drizzle } from "drizzle-orm/pglite";
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
import { migrationSqlForTestDb } from "./test-migration-sql";
import {
	type SqlRunner,
	type UsageCounts,
	dayIso,
	idempotencyKey,
	queryCounts,
	recipient,
	render,
	runUsageDigest,
	windowEnd,
} from "./usage-digest";

const END = new Date("2026-11-16T04:00:00.000Z");
const COUNTS: UsageCounts = {
	peopleTotal: 14,
	peopleNew24h: 2,
	peopleNew7d: 5,
	logins24h: 3,
	logins7d: 7,
	workspacesTotal: 12,
	workspacesNew24h: 2,
	workspacesNew7d: 4,
	activeWorkspaces24h: 2,
	activeWorkspaces7d: 3,
	newPeople: ["b@example.com", "a@example.com"],
};

function setEnv(vars: Record<string, string | undefined>) {
	for (const [k, v] of Object.entries(vars)) {
		if (v === undefined) Reflect.deleteProperty(process.env, k);
		else process.env[k] = v;
	}
}

describe("usage digest — windows and keys", () => {
	it("ends every window at the day's send hour, whatever the tick time", () => {
		expect(windowEnd(new Date("2026-11-16T04:00:07Z")).toISOString()).toBe(
			END.toISOString(),
		);
		expect(windowEnd(new Date("2026-11-16T05:30:00Z")).toISOString()).toBe(
			END.toISOString(),
		);
	});
	it("gives the retry cron the same idempotency key as the send", () => {
		expect(idempotencyKey(windowEnd(new Date("2026-11-16T05:30:00Z")))).toBe(
			"usage-digest-2026-11-16",
		);
	});
	it("keys a different UTC day differently", () => {
		expect(
			idempotencyKey(windowEnd(new Date("2026-11-17T04:00:00Z"))),
		).not.toBe(idempotencyKey(END));
	});
	it("names the UTC date", () => {
		expect(dayIso(END)).toBe("2026-11-16");
	});
});

describe("usage digest — rendering", () => {
	it("renders every count with its window", () => {
		const { text } = render(END, COUNTS);
		for (const line of [
			"People: 14 total · 2 new in 24 h · 5 new in 7 d",
			"Logged in: 3 in 24 h · 7 in 7 d",
			"Workspaces: 12 total · 2 new in 24 h · 4 new in 7 d",
			"Workspaces that used the gateway: 2 in 24 h · 3 in 7 d",
			"Windows end 2026-11-16 04:00 UTC.",
		]) {
			expect(text).toContain(line);
		}
	});
	it("puts the UTC date in the subject", () => {
		expect(render(END, COUNTS).subject).toBe(
			"Tracelane usage — 2026-11-16 (UTC)",
		);
	});
	it("lists new people newest first", () => {
		const { text } = render(END, COUNTS);
		expect(text.indexOf("- b@example.com")).toBeLessThan(
			text.indexOf("- a@example.com"),
		);
		expect(text).not.toContain("more");
	});
	it("renders the same first-seen counts for both ticks of a day", () => {
		expect(render(windowEnd(new Date("2026-11-16T05:30:00Z")), COUNTS)).toEqual(
			render(END, COUNTS),
		);
	});
	it("still renders a digest with zero activity", () => {
		const zero: UsageCounts = {
			...COUNTS,
			peopleTotal: 0,
			peopleNew24h: 0,
			peopleNew7d: 0,
			newPeople: [],
		};
		const { text } = render(END, zero);
		expect(text).toContain("People: 0 total · 0 new in 24 h · 0 new in 7 d");
		expect(text).not.toContain("New people");
	});
	it("truncates the list and says how many more", () => {
		const many = {
			...COUNTS,
			peopleNew24h: 25,
			newPeople: ["p0@x.com", "p1@x.com", "p2@x.com", "p3@x.com"],
		};
		const { text } = render(END, many, 3);
		expect(text.match(/\n- /g)?.length).toBe(3);
		expect(text).toContain("…and 22 more");
	});
	it("cannot forge a row through a hostile address", () => {
		const hostile = {
			...COUNTS,
			newPeople: ["x@e.com\r\nPeople: 999 total\u202E"],
		};
		const { text } = render(END, hostile);
		expect(
			text.split("\n").filter((l) => l.startsWith("People: ")),
		).toHaveLength(1);
		expect(text).not.toMatch(/[\r\u202E]/);
	});
});

describe("usage digest — recipient", () => {
	it("defaults to the operator inbox and honours an override", () => {
		expect(recipient(undefined)).toBe("founder@tracelane.dev");
		expect(recipient("ops@example.com")).toBe("ops@example.com");
	});
	it("refuses anything but one plain address", () => {
		for (const bad of [
			"a@b.com,c@d.com",
			"Ops <ops@x.com>",
			"no-at",
			"a@b@c",
			"a b@c.com",
		]) {
			expect(recipient(bad)).toBeNull();
		}
	});
});

describe("usage digest — cron runner (fail-open)", () => {
	const fakeSql: SqlRunner = async () => [
		{ people_total: "1", people_new_24h: "1", new_people: ["n@example.com"] },
	];
	beforeEach(() => {
		setEnv({
			RESEND_API_KEY: "re_test_not_a_real_key",
			RESEND_FROM: "Tracelane <hello@tracelane.dev>",
			USAGE_DIGEST_TO: undefined,
			SIGNUP_ALERT_TO: undefined,
		});
		vi.spyOn(console, "warn").mockImplementation(() => {});
		vi.spyOn(console, "error").mockImplementation(() => {});
		vi.spyOn(console, "log").mockImplementation(() => {});
	});
	afterEach(() => {
		vi.restoreAllMocks();
		setEnv({ RESEND_API_KEY: undefined, RESEND_FROM: undefined });
	});

	it("sends one digest to the operator with the day's idempotency key", async () => {
		const send = vi.fn(async () => true);
		expect(
			await runUsageDigest(new Date("2026-11-16T04:00:02Z"), {
				sql: fakeSql,
				send,
			}),
		).toBe("sent");
		expect(send).toHaveBeenCalledTimes(1);
		const arg = (send.mock.calls[0] as unknown as [Record<string, string>])[0];
		expect(arg.to).toBe("founder@tracelane.dev");
		expect(arg.from).toBe("Tracelane <hello@tracelane.dev>");
		expect(arg.idempotencyKey).toBe("usage-digest-2026-11-16");
		expect(arg.text).toContain("- n@example.com");
		expect(arg.html).not.toContain("<script");
	});
	it("skips without querying or sending when Resend is not configured", async () => {
		setEnv({ RESEND_API_KEY: undefined });
		const sql = vi.fn(fakeSql);
		const send = vi.fn(async () => true);
		expect(await runUsageDigest(END, { sql, send })).toBe("skipped");
		expect(sql).not.toHaveBeenCalled();
		expect(send).not.toHaveBeenCalled();
	});
	it("skips when the configured recipient is not one plain address", async () => {
		setEnv({ USAGE_DIGEST_TO: "a@b.com,evil@x.com" });
		const send = vi.fn(async () => true);
		expect(await runUsageDigest(END, { sql: fakeSql, send })).toBe("skipped");
		expect(send).not.toHaveBeenCalled();
	});
	it("returns failed, never throws, when the query throws", async () => {
		const send = vi.fn(async () => true);
		const sql: SqlRunner = async () => {
			throw new Error("neon down");
		};
		await expect(runUsageDigest(END, { sql, send })).resolves.toBe("failed");
		expect(send).not.toHaveBeenCalled();
	});
	it("returns failed when Resend refuses", async () => {
		expect(
			await runUsageDigest(END, { sql: fakeSql, send: async () => false }),
		).toBe("failed");
	});
	it("logs no address", async () => {
		const log = vi.mocked(console.log);
		await runUsageDigest(END, { sql: fakeSql, send: async () => true });
		expect(JSON.stringify(log.mock.calls)).not.toContain("@");
	});
});

describe("usage digest — the count query on real Postgres (PGlite)", () => {
	let pg: PGlite;
	const run: SqlRunner = async (strings, ...values) => {
		let q = strings[0] ?? "";
		values.forEach((_, i) => {
			q += `$${i + 1}${strings[i + 1] ?? ""}`;
		});
		return (await pg.query(q, values)).rows as Record<string, unknown>[];
	};
	const h = (n: number) =>
		new Date(END.getTime() - n * 3_600_000).toISOString();

	beforeAll(async () => {
		pg = new PGlite();
		const db = drizzle(pg, { schema });
		const folder = path.resolve(
			path.dirname(fileURLToPath(import.meta.url)),
			"../db/migrations",
		);
		await migrate(db, { migrationsFolder: folder });
		const journaled = new Set<string>(
			(
				JSON.parse(
					readFileSync(path.join(folder, "meta/_journal.json"), "utf-8"),
				) as {
					entries: { tag: string }[];
				}
			).entries.map((e) => e.tag),
		);
		for (const f of readdirSync(folder)
			.filter((n) => n.endsWith(".sql"))
			.filter((n) => !journaled.has(n.replace(/\.sql$/, "")))
			.filter((n) => !n.startsWith("0010_"))
			.sort()) {
			await pg.exec(
				migrationSqlForTestDb(readFileSync(path.join(folder, f), "utf-8")),
			);
		}
	}, 180_000);
	afterAll(async () => {
		await pg.close();
	});
	beforeEach(async () => {
		await pg.exec(
			"DELETE FROM api_keys; DELETE FROM signups; DELETE FROM tenants;",
		);
	});

	async function person(
		first: string,
		login: string,
		email = `p-${Math.random()}@example.com`,
	) {
		await pg.query(
			"INSERT INTO signups (workos_user_id, email, first_seen_at, last_login_at) VALUES ($1,$2,$3,$4)",
			[`user_${Math.random()}`, email, first, login],
		);
		return email;
	}
	async function tenant(created: string): Promise<string> {
		const r = await pg.query<{ id: string }>(
			"INSERT INTO tenants (workos_org_id, name, created_at) VALUES ($1,'plt54',$2) RETURNING id",
			[`org_${Math.random()}`, created],
		);
		return r.rows[0]?.id as string;
	}
	async function key(t: string, used: string, revoked: string | null = null) {
		await pg.query(
			"INSERT INTO api_keys (tenant_id, name, key_hash, key_prefix, last_used_at, revoked_at) VALUES ($1,'plt54',$2,'test',$3,$4)",
			[t, `hash-${Math.random()}`, used, revoked],
		);
	}

	it("counts each window from seeded rows on both sides of the boundary", async () => {
		const fresh = await person(h(2), h(1));
		await person(h(72), h(30));
		const t1 = await tenant(h(3));
		const t2 = await tenant(h(100));
		await key(t1, h(1));
		await key(t1, h(2)); // same workspace: counted once
		await key(t2, h(50));
		const c = await queryCounts(run, END, 20);
		expect(c).toMatchObject({
			peopleTotal: 2,
			peopleNew24h: 1,
			peopleNew7d: 2,
			logins24h: 1,
			logins7d: 2,
			workspacesTotal: 2,
			workspacesNew24h: 1,
			workspacesNew7d: 2,
			activeWorkspaces24h: 1,
			activeWorkspaces7d: 2,
		});
		expect(c.newPeople).toEqual([fresh]);
	});
	it("excludes activity older than the windows", async () => {
		await person(h(24 * 9), h(24 * 8));
		const t = await tenant(h(24 * 9));
		await key(t, h(24 * 8));
		const c = await queryCounts(run, END, 20);
		expect(c).toMatchObject({
			peopleTotal: 1,
			peopleNew7d: 0,
			logins7d: 0,
			workspacesNew7d: 0,
			activeWorkspaces7d: 0,
		});
	});
	it("excludes activity after the window end, so a same-day retry is identical", async () => {
		const after = new Date(END.getTime() + 3_600_000).toISOString();
		await person(after, after);
		const t = await tenant(after);
		await key(t, after);
		const c = await queryCounts(run, END, 20);
		expect(c).toMatchObject({
			peopleTotal: 0,
			workspacesTotal: 0,
			activeWorkspaces24h: 0,
		});
		expect(c.newPeople).toEqual([]);
	});
	it("still counts a workspace whose key was used and then revoked", async () => {
		const t = await tenant(h(200));
		await key(t, h(1), h(0.5));
		expect((await queryCounts(run, END, 20)).activeWorkspaces24h).toBe(1);
	});
	it("returns at most max_listed + 1 addresses, newest first", async () => {
		for (let i = 0; i < 5; i++)
			await person(h(1 + i), h(1), `n${i}@example.com`);
		const c = await queryCounts(run, END, 2);
		expect(c.newPeople).toEqual([
			"n0@example.com",
			"n1@example.com",
			"n2@example.com",
		]);
	});
});

describe("usage digest — review fixes", () => {
	afterEach(() => {
		vi.restoreAllMocks();
		for (const k of ["RESEND_API_KEY", "RESEND_FROM", "DATABASE_URL"])
			Reflect.deleteProperty(process.env, k);
	});
	it("reads configuration from the cron env when process.env lacks it", async () => {
		for (const k of [
			"RESEND_API_KEY",
			"RESEND_FROM",
			"USAGE_DIGEST_TO",
			"SIGNUP_ALERT_TO",
		])
			Reflect.deleteProperty(process.env, k);
		vi.spyOn(console, "log").mockImplementation(() => {});
		const send = vi.fn(async () => true);
		const sql: SqlRunner = async () => [{}];
		const r = await runUsageDigest(END, {
			sql,
			send,
			env: {
				RESEND_API_KEY: "re_test_not_a_real_key",
				RESEND_FROM: "T <t@tracelane.dev>",
			},
		});
		expect(r).toBe("sent");
		expect(send).toHaveBeenCalledTimes(1);
	});
	it("treats Resend's 409 for a keyed send as already delivered (drifted retry body)", async () => {
		const { sendEmail } = await import("./email");
		process.env.RESEND_API_KEY = "re_test_not_a_real_key";
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => ({ ok: false, status: 409 }) as unknown as Response),
		);
		vi.spyOn(console, "error").mockImplementation(() => {});
		expect(
			await sendEmail({
				to: "o@x.com",
				subject: "s",
				html: "h",
				text: "t",
				idempotencyKey: "usage-digest-2026-11-16",
			}),
		).toBe(true);
		vi.unstubAllGlobals();
	});
	it("keeps a 409 without an idempotency key a failure", async () => {
		const { sendEmail } = await import("./email");
		process.env.RESEND_API_KEY = "re_test_not_a_real_key";
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => ({ ok: false, status: 409 }) as unknown as Response),
		);
		vi.spyOn(console, "error").mockImplementation(() => {});
		expect(
			await sendEmail({ to: "o@x.com", subject: "s", html: "h", text: "t" }),
		).toBe(false);
		vi.unstubAllGlobals();
	});
});
