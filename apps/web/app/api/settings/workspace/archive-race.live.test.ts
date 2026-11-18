/** Real DELETE/Drizzle writes and shared PostgreSQL advisory-lock race proof. */
import { randomUUID } from "node:crypto";
import { type Socket, connect } from "node:net";
import { Pool, neonConfig } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-serverless";
import { NextRequest } from "next/server";
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

const h = vi.hoisted(() => ({ db: null as unknown }));
vi.mock("@/db", () => ({
	get db() {
		return h.db;
	},
}));
vi.mock("@/lib/auth", () => ({
	requireSession: async () => ({
		tenantId: "org_ARCHIVE_RACE",
		userId: "owner",
	}),
	requireGatewayToken: async () => ({
		tenantId: "org_ARCHIVE_RACE",
		token: "unit-test-human-jwt",
	}),
	invalidateOrgArchivedCache: vi.fn(),
}));
vi.mock("@/lib/control-change", () => ({
	recordControlChange: async () => ({ ok: true }),
	recordControlChangeFailed: vi.fn(),
}));
vi.mock("@/lib/workos-org", () => ({ callerIsOrgAdmin: async () => true }));
import { DELETE } from "./route";

// Test-only transport: use the INSTALLED Neon protocol driver against local
// Postgres without requiring an external Neon account or a WebSocket proxy.
class LocalPostgresSocket {
	listeners: Record<string, Array<(event: unknown) => void>> = {};
	readyState = 0;
	socket: Socket;
	constructor(url: string) {
		const target = new URL(url);
		if (target.hostname !== "127.0.0.1")
			throw new Error("local Postgres required");
		this.socket = connect(
			{ host: target.hostname, port: Number(target.port) },
			() => {
				this.readyState = 1;
				this.emit("open", {});
			},
		);
		this.socket.on("data", (data) =>
			this.emit("message", {
				data: data.buffer.slice(
					data.byteOffset,
					data.byteOffset + data.byteLength,
				),
			}),
		);
		this.socket.on("error", (error) => this.emit("error", error));
		this.socket.on("close", () => {
			this.readyState = 3;
			this.emit("close", {});
		});
	}
	addEventListener(name: string, listener: (event: unknown) => void) {
		this.listeners[name] ??= [];
		this.listeners[name].push(listener);
	}
	emit(name: string, event: unknown) {
		for (const listener of this.listeners[name] ?? []) listener(event);
	}
	send(data: Uint8Array) {
		this.socket.write(Buffer.from(data));
	}
	close() {
		this.socket.end();
	}
}

const url = process.env.TEST_POSTGRES_URL;
const tenant = "00000000-0000-0000-0000-000000000001";
const other = "00000000-0000-0000-0000-000000000002";
const lock = "tracelane:owners:org_ARCHIVE_RACE";
const request = () =>
	new NextRequest("http://localhost/settings/workspace", {
		method: "DELETE",
		body: JSON.stringify({ confirmName: "Test" }),
	});
function deferred() {
	let resolve = () => {};
	const promise = new Promise<void>((r) => {
		resolve = r;
	});
	return { promise, resolve };
}

describe.skipIf(!url)(
	"workspace archive/mint serialization with real Postgres",
	() => {
		const saved = {
			webSocketConstructor: neonConfig.webSocketConstructor,
			wsProxy: neonConfig.wsProxy,
			useSecureWebSocket: neonConfig.useSecureWebSocket,
			pipelineConnect: neonConfig.pipelineConnect,
		};
		let pg: Pool;
		let schema: string;
		beforeAll(() => {
			neonConfig.webSocketConstructor = LocalPostgresSocket;
			neonConfig.wsProxy = (host, port) => `${host}:${port}`;
			neonConfig.useSecureWebSocket = false;
			neonConfig.pipelineConnect = false;
		});
		afterAll(() => {
			Object.assign(neonConfig, saved);
		});
		beforeEach(async () => {
			if (!url) throw new Error("TEST_POSTGRES_URL required");
			const base = new URL(url);
			if (base.hostname !== "127.0.0.1")
				throw new Error("local Postgres required");
			schema = `archive_race_${randomUUID().replaceAll("-", "")}`;
			const admin = new Pool({ connectionString: url });
			try {
				await admin.query(`CREATE SCHEMA ${schema}`);
			} finally {
				await admin.end();
			}
			base.searchParams.set("options", `-c search_path=${schema}`);
			pg = new Pool({ connectionString: base.toString() });
			vi.stubEnv("DATABASE_URL", base.toString());
			vi.stubEnv("WORKOS_API_KEY", "unit-test-workos-key");
			h.db = drizzle(pg);
			await pg.query(`CREATE TABLE tenants (id uuid, workos_org_id text, name text, archived_at timestamptz);
   CREATE TABLE api_keys (tenant_id uuid, minted_by text, revoked_at timestamptz);`);
			await pg.query(
				"INSERT INTO tenants VALUES ($1, 'org_ARCHIVE_RACE', 'Test', NULL)",
				[tenant],
			);
			await pg.query("INSERT INTO api_keys VALUES ($1, 'other', NULL)", [
				other,
			]);
			vi.stubGlobal(
				"fetch",
				vi.fn(async () => Response.json({ invalidated: true })),
			);
		});
		afterEach(async () => {
			if (pg) {
				await pg.query(`DROP SCHEMA ${schema} CASCADE`);
				await pg.end();
			}
			vi.unstubAllGlobals();
			vi.unstubAllEnvs();
		});
		// Match the gateway's lock_workspace_mints protocol: acquire the same lock,
		// then re-read archived_at using a fresh READ COMMITTED statement snapshot.
		async function mint() {
			const client = await pg.connect();
			try {
				await client.query("BEGIN");
				await client.query(
					"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
					[lock],
				);
				const row = await client.query(
					"SELECT 1 FROM tenants WHERE id = $1 AND archived_at IS NULL",
					[tenant],
				);
				if (!row.rowCount) {
					await client.query("ROLLBACK");
					return false;
				}
				await client.query("INSERT INTO api_keys VALUES ($1, 'owner', NULL)", [
					tenant,
				]);
				await client.query("COMMIT");
				return true;
			} finally {
				client.release();
			}
		}
		async function waitForContentionOrCompletion(completed: () => boolean) {
			for (let attempt = 0; !completed(); attempt++) {
				if (attempt > 1000)
					throw new Error("operation neither waited nor completed");
				const result = await pg.query(
					`SELECT EXISTS (
    SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND NOT granted
    AND classid::bigint = ((hashtextextended($1, 0) >> 32) & 4294967295)
    AND objid::bigint = (hashtextextended($1, 0) & 4294967295)
   ) AS waiting`,
					[lock],
				);
				if (result.rows[0].waiting) return;
			}
		}
		async function assertArchivedWithoutActiveKeys() {
			const result = await pg.query(
				"SELECT count(*)::int AS active FROM api_keys WHERE tenant_id = $1 AND (revoked_at IS NULL OR revoked_at > now())",
				[tenant],
			);
			expect(
				result.rows[0].active,
				"concurrent mint must not survive workspace deletion",
			).toBe(0);
			const archived = await pg.query(
				"SELECT archived_at IS NOT NULL AS archived FROM tenants WHERE id = $1",
				[tenant],
			);
			expect(archived.rows[0].archived).toBe(true);
			const untouched = await pg.query(
				"SELECT revoked_at IS NULL AS active FROM api_keys WHERE tenant_id = $1",
				[other],
			);
			expect(untouched.rows[0].active).toBe(true);
		}
		it("mint holds lock first: archive sweeps the mint after its commit", async () => {
			const client = await pg.connect();
			let complete = false;
			let pending: Promise<Response> | undefined;
			try {
				await client.query("BEGIN");
				await client.query(
					"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
					[lock],
				);
				await client.query("INSERT INTO api_keys VALUES ($1, 'owner', NULL)", [
					tenant,
				]);
				pending = DELETE(request()).then((response) => {
					complete = true;
					return response;
				});
				await waitForContentionOrCompletion(() => complete);
				await client.query("COMMIT");
				expect((await pending).status).toBe(200);
				await assertArchivedWithoutActiveKeys();
			} finally {
				await client.query("ROLLBACK");
				client.release();
				await pending;
			}
		});
		it("archive holds lock first: waiting mint sees archive and refuses insertion", async () => {
			const reachedAck = deferred();
			const releaseAck = deferred();
			vi.stubGlobal(
				"fetch",
				vi.fn(async () => {
					reachedAck.resolve();
					await releaseAck.promise;
					return Response.json({ invalidated: true });
				}),
			);
			const deletion = DELETE(request());
			let complete = false;
			let issuance: Promise<boolean> | undefined;
			try {
				await reachedAck.promise;
				issuance = mint().then((allowed) => {
					complete = true;
					return allowed;
				});
				await waitForContentionOrCompletion(() => complete);
			} finally {
				releaseAck.resolve();
			}
			expect((await deletion).status).toBe(200);
			const allowed = await issuance;
			await assertArchivedWithoutActiveKeys();
			expect(allowed, "post-archive issuance must fail closed").toBe(false);
		});
	},
);
