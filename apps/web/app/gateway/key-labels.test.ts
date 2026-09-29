import { describe, expect, it, vi } from "vitest";

vi.mock("@/db", () => ({ db: {} }));
vi.mock("@/lib/auth", () => ({ requireSession: vi.fn() }));
vi.mock("@/lib/tenant", () => ({ upsertTenantId: vi.fn() }));

import { toKeyLabels } from "./key-labels";

const now = Date.parse("2026-09-28T00:00:00Z");
const k = (over: Partial<Parameters<typeof toKeyLabels>[0][number]>) => ({
	id: "k",
	name: "ci",
	keyPrefix: "tlane_ab",
	revokedAt: null,
	expiresAt: null,
	...over,
});

describe("toKeyLabels (SET-38 B5)", () => {
	it("a live key has no suffix", () => {
		expect(toKeyLabels([k({})], now).k).toEqual({
			name: "ci",
			prefix: "tlane_ab",
			state: null,
		});
	});
	it("a past revoked_at is revoked; a FUTURE one is retiring (rotation grace)", () => {
		expect(
			toKeyLabels([k({ revokedAt: new Date(now - 1) })], now).k?.state,
		).toBe("revoked");
		expect(
			toKeyLabels([k({ revokedAt: new Date(now + 3_600_000) })], now).k?.state,
		).toBe("retiring");
	});
	it("a past expires_at is expired; revoked wins over expired", () => {
		expect(
			toKeyLabels([k({ expiresAt: new Date(now - 1) })], now).k?.state,
		).toBe("expired");
		expect(
			toKeyLabels(
				[k({ revokedAt: new Date(now - 1), expiresAt: new Date(now - 1) })],
				now,
			).k?.state,
		).toBe("revoked");
	});
});
