/** Real Postgres transaction/lock proof; WorkOS is a deterministic local double. */
import { type Socket, connect } from "node:net";
import { Pool, neonConfig } from "@neondatabase/serverless";
import type { NextRequest } from "next/server";
import {
	afterAll,
	afterEach,
	beforeAll,
	describe,
	expect,
	it,
	vi,
} from "vitest";

const h = vi.hoisted(() => ({ sessions: [] as string[] }));
vi.mock("@workos-inc/authkit-nextjs", () => ({
	withAuth: async () => ({
		user: { id: h.sessions.shift(), email: "unit-test@example.invalid" },
		organizationId: "org_OWNER_RACE_TEST",
	}),
}));
vi.mock("@/lib/auth", () => ({
	requireSession: vi.fn(async () => ({
		tenantId: "org_OWNER_RACE_TEST",
		userId: h.sessions.shift(),
		email: "unit-test@example.invalid",
	})),
}));
vi.mock("@/db", () => ({
	db: {
		execute: async () => undefined,
		update: () => ({ set: () => ({ where: async () => undefined }) }),
		select: () => ({
			from: () => ({ where: () => ({ limit: async () => [] }) }),
		}),
	},
}));
import { DELETE as deleteAccount } from "../../account/route";
import { DELETE, PATCH } from "./route";

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
describe.skipIf(!url)("serialized owner mutations with real Postgres", () => {
	const saved = {
		webSocketConstructor: neonConfig.webSocketConstructor,
		wsProxy: neonConfig.wsProxy,
		useSecureWebSocket: neonConfig.useSecureWebSocket,
		pipelineConnect: neonConfig.pipelineConnect,
	};
	beforeAll(() => {
		if (!url) throw new Error("TEST_POSTGRES_URL required");
		vi.stubEnv("DATABASE_URL", url);
		vi.stubEnv("WORKOS_API_KEY", "unit-test-workos-only");
		neonConfig.webSocketConstructor = LocalPostgresSocket;
		neonConfig.wsProxy = (host, port) => `${host}:${port}`;
		neonConfig.useSecureWebSocket = false;
		neonConfig.pipelineConnect = false;
	});
	afterAll(() => {
		Object.assign(neonConfig, saved);
		vi.unstubAllEnvs();
	});
	afterEach(() => vi.unstubAllGlobals());

	it.each(["team", "account"])(
		"%s fails closed before WorkOS when the lock database is unavailable",
		async (kind) => {
			const fetcher = vi.fn();
			vi.stubGlobal("fetch", fetcher);
			vi.stubEnv("DATABASE_URL", "");
			h.sessions = ["a"];
			try {
				const response =
					kind === "account"
						? await deleteAccount({
								json: async () => ({
									confirmEmail: "unit-test@example.invalid",
								}),
							} as NextRequest)
						: await DELETE({} as NextRequest, {
								params: Promise.resolve({ membershipId: "b" }),
							});
				expect(response.status).toBe(503);
				expect((await response.json()).error).toBe(
					"membership_change_unavailable",
				);
				expect(fetcher).not.toHaveBeenCalled();
			} finally {
				vi.stubEnv("DATABASE_URL", url ?? "");
			}
		},
	);

	it.each(["remove", "demote", "account", "mixed"])(
		"concurrent %s mutations retain an owner",
		async (kind) => {
			let members = [
				{
					id: "a",
					user_id: "a",
					organization_id: "org_OWNER_RACE_TEST",
					role: { slug: "owner" },
				},
				{
					id: "b",
					user_id: "b",
					organization_id: "org_OWNER_RACE_TEST",
					role: { slug: "owner" },
				},
			];
			if (kind === "account" || kind === "mixed")
				members.push({
					id: "member",
					user_id: "member",
					organization_id: "org_OWNER_RACE_TEST",
					role: { slug: "member" },
				});
			h.sessions = ["a", "b"];
			const writes: string[] = [];
			let reads = 0;
			let releaseRead = () => {};
			let firstRead = () => {};
			const heldRead = new Promise<void>((resolve) => {
				releaseRead = resolve;
			});
			const started = new Promise<void>((resolve) => {
				firstRead = resolve;
			});

			vi.stubGlobal(
				"fetch",
				vi.fn(async (raw: string, init?: RequestInit) => {
					if ((init?.method ?? "GET") === "GET") {
						const snapshot = structuredClone(members);
						reads++;
						firstRead();
						await heldRead;
						return Response.json({ data: snapshot });
					}
					const id = raw.split("/").at(-1) ?? "";
					writes.push(id);
					if (init?.method === "DELETE")
						members = members.filter((m) => m.id !== id);
					else
						members = members.map((m) =>
							m.id === id ? { ...m, role: { slug: "member" } } : m,
						);
					return new Response(null, { status: 200 });
				}),
			);
			const call = (id: string) =>
				kind === "account" || (kind === "mixed" && id === "a")
					? deleteAccount({
							json: async () => ({ confirmEmail: "unit-test@example.invalid" }),
						} as NextRequest)
					: kind === "remove"
						? DELETE({} as NextRequest, {
								params: Promise.resolve({ membershipId: id }),
							})
						: PATCH({ json: async () => ({ role: "member" }) } as NextRequest, {
								params: Promise.resolve({ membershipId: id }),
							});
			const pending = Promise.all(
				kind === "remove" ? [call("b"), call("a")] : [call("a"), call("b")],
			);
			// Hold the first external read until the second request either waits
			// on the REAL lock or reaches WorkOS too (the planted no-lock case).
			// No sleep: observe Postgres lock state on a separate connection.
			const observer = new Pool({ connectionString: url });
			try {
				await started;
				for (let attempts = 0; reads < 2; attempts++) {
					if (attempts > 1000)
						throw new Error("second request never contended");
					const result = await observer.query(
						`SELECT EXISTS (
						SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND NOT granted
						AND classid::bigint = ((hashtextextended($1, 0) >> 32) & 4294967295)
						AND objid::bigint = (hashtextextended($1, 0) & 4294967295)
					) AS waiting`,
						["tracelane:owners:org_OWNER_RACE_TEST"],
					);
					if (result.rows[0].waiting) break;
				}
			} finally {
				releaseRead();
				await observer.end();
			}
			const responses = await pending;
			expect(
				members.filter((m) => m.role.slug === "owner").length,
				"at least one owner must remain after both requests settle",
			).toBe(1);
			expect(writes).toHaveLength(1);
			expect(responses.filter((r) => r.status === 200)).toHaveLength(1);
			const refusal = responses.find((r) => r.status !== 200);
			if (!refusal) throw new Error("one mutation must be refused");
			expect([403, 409]).toContain(refusal.status);
			const body = await refusal.json();
			expect(body.message ?? body.detail).toMatch(/owner/);
		},
	);
});
