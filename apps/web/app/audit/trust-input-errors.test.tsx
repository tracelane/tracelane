// @vitest-environment jsdom
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
	ANCHORED_NDJSON,
	TRUSTED_PUBKEY_B64,
} from "@/e2e/fixtures/audit-fixture-data";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import * as verifier from "@tracelanedev/audit-verifier";
import {
	Children,
	type ReactElement,
	type ReactNode,
	cloneElement,
	isValidElement,
} from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import AuditPage from "./page";

vi.mock("@/db", () => ({ db: { select: vi.fn() } }));
vi.mock("@/lib/auth", () => ({
	requireSession: async () => ({ tenantId: "org_test" }),
}));
vi.mock("@/lib/entitlements", () => ({
	resolveEntitlements: async () => ({
		audit_self_verify: true,
		audit_ledger: true,
	}),
}));
vi.mock("@/lib/e2e-audit-fixture", () => ({
	e2eAuditFixture: async () => null,
}));
vi.mock("@/lib/gateway", async (original) => ({
	...(await original<typeof import("@/lib/gateway")>()),
	gatewayGet: vi.fn(),
}));
vi.mock("./trust-root", async (original) => ({
	...(await original<typeof import("./trust-root")>()),
	readPlatformTrustRoot: vi.fn(),
}));
vi.mock("@tracelanedev/audit-verifier", async (original) => {
	const actual = await original<typeof verifier>();
	return { ...actual, verifyLedgerText: vi.fn(actual.verifyLedgerText) };
});

import { db } from "@/db";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { readPlatformTrustRoot } from "./trust-root";

const meta = JSON.parse(
	readFileSync(
		resolve("../../evals/audit-ledger/platform-key-vectors.meta.json"),
		"utf8",
	),
);
const vector = (name: string) =>
	readFileSync(resolve(`../../evals/audit-ledger/${name}.ndjson`), "utf8");
const platform = vector("platform-only");
const mixed = vector("platform-then-workspace");
// Complete signed batches on either side of takeover (seq 5).
const windowRows = (text: string, from: number, to: number) =>
	text
		.split("\n")
		.filter(Boolean)
		.filter((line) => {
			const record = JSON.parse(line);
			return record.type === "anchor"
				? record.batch_start_seq >= from && record.batch_end_seq <= to
				: record.seq >= from && record.seq <= to;
		})
		.join("\n");

let key: unknown;
let boundary: unknown;
let bytes: string;
let failure: "key" | "boundary" | "key-sync" | "boundary-sync" | undefined;
let evidenceError: Error | undefined;
let inventoryError: boolean;

beforeEach(() => {
	key = {
		pubkey: meta.workspace_ed25519_pubkey_b64,
		createdAt: new Date("2026-09-01"),
	};
	boundary = [{ since: 5 }];
	bytes = platform;
	failure = undefined;
	evidenceError = undefined;
	inventoryError = false;
	vi.mocked(readPlatformTrustRoot).mockResolvedValue({
		platformPubkeyB64: meta.platform_ed25519_pubkey_b64,
		platformFingerprint: "fixture-platform-fingerprint",
		platformKeySource: "pinned",
		platformCrossCheck: "match",
	});
	let query = 0;
	vi.mocked(db.select).mockImplementation(() => {
		const index = query++ % 3;
		if (
			(index === 1 && failure === "key-sync") ||
			(index === 2 && failure === "boundary-sync")
		)
			throw new Error("private database details");
		const result = () => {
			if (
				(index === 1 && failure === "key") ||
				(index === 2 && failure === "boundary")
			)
				return Promise.reject(new Error("private database details"));
			return Promise.resolve(
				index === 0
					? [{ id: "tenant_test", plan: "enterprise" }]
					: index === 1
						? key
							? [key]
							: []
						: boundary,
			);
		};
		const builder = Object.assign(result(), {
			from: () => builder,
			where: () => builder,
			limit: () => builder,
		});
		return builder as unknown as ReturnType<typeof db.select>;
	});
	vi.mocked(gatewayGet).mockImplementation(async (path) => {
		if (path.includes("self-verify")) {
			if (evidenceError) throw evidenceError;
			return {
				chain_ndjson: bytes,
				window: {
					since: "2026-08-01T00:00:00Z",
					until: "2026-10-01T00:00:00Z",
				},
			};
		}
		if (inventoryError) throw new Error("inventory unavailable");
		return { total: 10, from: 0, to: 9 };
	});
});
afterEach(cleanup);

// Resolve server components, then mount the real client tree and verifier in a DOM.
async function serverTree(node: ReactNode): Promise<ReactNode> {
	if (!isValidElement(node)) return node;
	const element = node as ReactElement<{ children?: ReactNode }>;
	if (
		typeof element.type === "function" &&
		element.type.constructor.name === "AsyncFunction"
	) {
		const component = element.type as (props: unknown) => Promise<ReactNode>;
		return serverTree(await component(element.props));
	}
	if (element.props.children === undefined) return element;
	return cloneElement(
		element,
		{},
		...(await Promise.all(
			Children.toArray(element.props.children).map(serverTree),
		)),
	);
}
async function showPage() {
	return render(
		await serverTree(await AuditPage({ searchParams: Promise.resolve({}) })),
	);
}
async function checked() {
	await waitFor(() => expect(verifier.verifyLedgerText).toHaveBeenCalled());
	const result = await vi.mocked(verifier.verifyLedgerText).mock.results.at(-1)
		?.value;
	expect(result.errors).toEqual([]);
	expect(result.trust_established).toBe(true);
	await waitFor(() => expect(screen.queryByText("Checking…")).toBeNull());
	return result;
}
function blocked() {
	expect(
		screen.getByRole("heading", { name: "Cannot verify this evidence" }),
	).toBeTruthy();
	expect(screen.getByText("CANNOT DETERMINE")).toBeTruthy();
	expect(
		screen
			.getByRole("link", { name: "Retry verification" })
			.getAttribute("href"),
	).toBe("/audit");
	expect(verifier.verifyLedgerText).not.toHaveBeenCalled();
	expect(document.body.textContent).not.toContain("tlane verify");
	expect(document.body.textContent).not.toContain("private database details");
	expect(document.body.textContent).not.toContain("Verified — platform-signed");
}

it("absent_workspace_key", async () => {
	key = undefined;
	await showPage();
	const result = await checked();
	expect(result.anchors_unverified).toBe(2);
	expect(
		vi.mocked(verifier.verifyLedgerText).mock.calls[0]?.[1]?.tenantPubkey,
	).toBeUndefined();
});
it("no_workspace_signed_batch", async () => {
	boundary = [{ since: null }];
	await showPage();
	await checked();
	expect(
		vi.mocked(verifier.verifyLedgerText).mock.calls[0]?.[1]
			?.workspaceKeySinceSeq,
	).toBeUndefined();
});
it("zero_takeover_boundary", async () => {
	boundary = [{ since: 0 }];
	bytes = ANCHORED_NDJSON;
	key = { pubkey: TRUSTED_PUBKEY_B64, createdAt: new Date() };
	boundary = [{ since: 0 }];
	await showPage();
	await checked();
	expect(
		vi.mocked(verifier.verifyLedgerText).mock.calls[0]?.[1]
			?.workspaceKeySinceSeq,
	).toBe(0);
	expect(document.body.textContent).toContain("--workspace-key-since-seq 0");
});
it("valid_platform_prefix", async () => {
	bytes = windowRows(mixed, 0, 4);
	await showPage();
	expect((await checked()).platform_signed_batches).toBe(1);
});
it("valid_workspace_window", async () => {
	bytes = ANCHORED_NDJSON;
	key = { pubkey: TRUSTED_PUBKEY_B64, createdAt: new Date() };
	boundary = [{ since: 0 }];
	await showPage();
	expect((await checked()).platform_signed_batches).toBe(0);
});
it("valid_mixed_window", async () => {
	bytes = mixed;
	await showPage();
	expect((await checked()).platform_signed_batches).toBe(1);
});
it("offline_command_with_boundary", async () => {
	bytes = mixed;
	await showPage();
	await checked();
	expect(document.body.textContent).toContain(
		`tlane verify ./audit.ndjson --tenant-pubkey '${meta.workspace_ed25519_pubkey_b64}' --workspace-key-since-seq 5`,
	);
});
it("offline_command_without_boundary", async () => {
	boundary = [{ since: null }];
	await showPage();
	await checked();
	expect(document.body.textContent).toContain("tlane verify ./audit.ndjson");
	expect(document.body.textContent).not.toContain("--workspace-key-since-seq");
});
it("inventory_error_preserves_verification", async () => {
	inventoryError = true;
	bytes = mixed;
	await showPage();
	await checked();
	expect(document.body.textContent).toContain(
		"workspace inventory read is unavailable",
	);
});
it("retry_recovers_verification", async () => {
	failure = "boundary";
	const view = await showPage();
	blocked();
	view.unmount();
	failure = undefined;
	bytes = mixed;
	await showPage();
	await checked();
	expect(
		screen.queryByRole("heading", { name: "Cannot verify this evidence" }),
	).toBeNull();
});

it("workspace_key_rejection", async () => {
	failure = "key";
	await showPage();
	blocked();
});
it("takeover_boundary_rejection", async () => {
	failure = "boundary";
	await showPage();
	blocked();
});
it("workspace_key_sync_failure", async () => {
	failure = "key-sync";
	await showPage();
	blocked();
});
it("takeover_boundary_sync_failure", async () => {
	failure = "boundary-sync";
	await showPage();
	blocked();
});
it("empty_workspace_key", async () => {
	key = { pubkey: "", createdAt: new Date() };
	await showPage();
	blocked();
});
it("malformed_workspace_key", async () => {
	key = { pubkey: "not-a-key", createdAt: new Date() };
	await showPage();
	blocked();
});
it.each([-1, 1.5, Number.MAX_SAFE_INTEGER + 1, Number.NaN, "5"])(
	"invalid_takeover_boundary (%s)",
	async (since) => {
		boundary = [{ since }];
		await showPage();
		blocked();
	},
);
it("missing_takeover_result", async () => {
	boundary = [];
	await showPage();
	blocked();
});
it("evidence_read_failure", async () => {
	evidenceError = new Error("private database details");
	await showPage();
	expect(
		screen.getByRole("heading", { name: "We couldn’t check your evidence" }),
	).toBeTruthy();
	expect(verifier.verifyLedgerText).not.toHaveBeenCalled();
	expect(document.body.textContent).not.toContain("tlane verify");
});
it.each([401, 403])("evidence_permission_failure (%s)", async (status) => {
	evidenceError = new GatewayError(status, "private database details");
	await showPage();
	expect(document.body.textContent).toContain(
		status === 401 ? "Sign in again" : "does not have permission",
	);
	expect(verifier.verifyLedgerText).not.toHaveBeenCalled();
	expect(document.body.textContent).not.toContain("tlane verify");
});

// The attack fixture is valid under weaker context, but the known boundary rejects it.
it("known_takeover_refuses_platform_window", async () => {
	await showPage();
	await waitFor(() => expect(verifier.verifyLedgerText).toHaveBeenCalled());
	const report = await vi.mocked(verifier.verifyLedgerText).mock.results[0]
		?.value;
	expect(report.errors.map((error: { kind: string }) => error.kind)).toContain(
		"platform_key_after_workspace_key",
	);
	await waitFor(() =>
		expect(document.body.textContent).toContain(
			"Platform key used after workspace signing began",
		),
	);
	expect(document.body.textContent).not.toContain("This window passed");
});
