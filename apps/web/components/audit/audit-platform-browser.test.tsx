// @vitest-environment jsdom
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { AuditLedgerView } from "./AuditLedgerView";
const meta = JSON.parse(
	readFileSync(
		resolve("../../evals/audit-ledger/platform-key-vectors.meta.json"),
		"utf8",
	),
);
const ndjson = readFileSync(
	resolve("../../evals/audit-ledger/platform-then-workspace.ndjson"),
	"utf8",
);
afterEach(cleanup);
it("passes the independent platform root to the real verifier and invalidates a report when it changes", async () => {
	const props = {
		ndjson,
		tenantPubkeyB64: meta.workspace_ed25519_pubkey_b64,
		platformPubkeyB64: meta.platform_ed25519_pubkey_b64,
		ledgerRange: { total: 10, from: 0, to: 9 },
	};
	const view = render(<AuditLedgerView {...props} />);
	await waitFor(() =>
		expect(
			screen.queryByRole("heading", {
				name: "Verified — part platform-signed",
			}),
		).not.toBeNull(),
	);
	view.rerender(
		<AuditLedgerView
			{...props}
			platformPubkeyB64={meta.unrelated_ed25519_pubkey_b64}
		/>,
	);
	await waitFor(() =>
		expect(
			screen.queryByRole("heading", {
				name: "Batch signing key does not match",
			}),
		).not.toBeNull(),
	);
	expect(
		screen.queryByRole("heading", { name: "Verified — part platform-signed" }),
	).toBeNull();
});
