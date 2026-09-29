import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import Loading from "@/app/audit/loading";
import { verifyLedgerText } from "@tracelanedev/audit-verifier";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { AuditLedgerView } from "./AuditLedgerView";
const meta = JSON.parse(
	readFileSync(
		resolve("../../evals/audit-ledger/platform-key-vectors.meta.json"),
		"utf8",
	),
);
const workspace = meta.workspace_ed25519_pubkey_b64;
const platform = meta.platform_ed25519_pubkey_b64;
const vector = (name: string) =>
	readFileSync(resolve("../../evals/audit-ledger", `${name}.ndjson`), "utf8");
const options = {
	tenantPubkey: Uint8Array.from(Buffer.from(workspace, "base64")),
	platformPubkey: Uint8Array.from(Buffer.from(platform, "base64")),
};
const extra = {
	platformPubkeyB64: platform,
	platformKeySource: "gateway" as const,
	workspaceKeyCreatedAt: "2026-09-20T03:00:57Z",
	workspaceFingerprint: "workspace-fingerprint",
	platformFingerprint: "platform-fingerprint",
};
async function renderVector(name: string) {
	const ndjson = vector(name);
	const initialReport = await verifyLedgerText(ndjson, options);
	return {
		report: initialReport,
		html: renderToStaticMarkup(
			<AuditLedgerView
				ndjson={ndjson}
				initialReport={initialReport}
				tenantPubkeyB64={workspace}
				ledgerRange={{ total: 10, from: 0, to: 9 }}
				{...extra}
			/>,
		),
	};
}
describe("audit workflow trust labels", () => {
	it("shows a real platform prefix as amber, with both roots and the offline command", async () => {
		const { report, html } = await renderVector("platform-then-workspace");
		expect(report.signatures_valid).toBe(true);
		for (const step of ["1 · Collect", "2 · Link", "3 · Sign", "4 · Anchor"])
			expect(html).toContain(step);
		expect(html).toContain("Verified — part platform-signed");
		expect(html).toContain("Verified — platform-signed");
		expect(html).toContain("bg-warn-soft");
		expect(html).toContain("20 Sep 2026");
		expect(html).toContain("workspace-fingerprint");
		expect(html).toContain("platform-fingerprint");
		expect(html).toContain("--tenant-pubkey");
		// AUD-29 M3: the pinned platform key is the default — the command must not
		// teach an auditor to override the root with a value fetched at run time.
		expect(html).not.toContain("--platform-pubkey");
		expect(html).not.toContain("Action required");
		expect(html).toContain("Signed-only");
		expect(html.indexOf("Your evidence")).toBeLessThan(
			html.indexOf("Batch evidence"),
		);
	});
	it("keeps a platform downgrade red with its own explanation", async () => {
		const { report, html } = await renderVector("workspace-then-platform");
		expect(
			report.errors.some((e) => e.kind === "platform_key_after_workspace_key"),
		).toBe(true);
		expect(html).toContain("Platform key used after workspace signing began");
		expect(html).toContain("bg-danger-soft");
		expect(html).not.toContain("Verified — part platform-signed");
	});
	it("labels an entirely platform-signed window amber", async () => {
		const { html } = await renderVector("platform-only");
		expect(html).toContain("Verified — platform-signed");
		expect(html).not.toContain("Verified — part platform-signed");
	});
	it("renders the exact demo counts from a presentation-only report", async () => {
		const ndjson = vector("platform-then-workspace");
		const real = await verifyLedgerText(ndjson, options);
		// Presentation fixture only: cryptographic acceptance is tested above on real vectors.
		const report = {
			...real,
			rows_seen: 434,
			rekor_anchors_seen: 12,
			rekor_anchors_resolved: 12,
			anchors_included: 3,
			platform_signed_batches: 9,
			platform_signed_ranges: [{ start_seq: 0, end_seq: 387 }],
		};
		const records = ndjson
			.trim()
			.split("\n")
			.map((line) => JSON.parse(line));
		const demoBytes = [
			...records.filter((r) => r.type !== "anchor"),
			...Array.from({ length: 12 }, (_, i) => ({
				...records.find((r) => r.type === "anchor"),
				batch_start_seq: i,
				batch_end_seq: i,
			})),
		]
			.map((r) => JSON.stringify(r))
			.join("\n");
		const html = renderToStaticMarkup(
			<AuditLedgerView
				ndjson={demoBytes}
				initialReport={report}
				tenantPubkeyB64={workspace}
				ledgerRange={{ total: 10, from: 0, to: 9 }}
				{...extra}
			/>,
		);
		expect(html).toContain(
			"9 batches (seq 0–387) signed by Tracelane’s platform key before your workspace key was created on 20 Sep 2026; 3 batches signed by your key",
		);
		expect(html).toContain("3 of 12 batches publicly anchored");
	});
	it("waits on the first event without a green verification", () => {
		const html = renderToStaticMarkup(
			<AuditLedgerView ndjson="" ledgerRange={{ total: 0 }} />,
		);
		expect(html.match(/Waits for the first recorded event/g)).toHaveLength(3);
		expect(html).not.toContain("bg-seal-soft");
	});
	it("has one loading skeleton per step", () => {
		const html = renderToStaticMarkup(<Loading />);
		for (const step of ["Collect", "Link", "Sign", "Anchor"])
			expect(html).toContain(step);
		expect(html).not.toContain("bg-seal-soft");
	});
	it("shows unknown inventory and missing keys without claiming failure", async () => {
		const ndjson = vector("platform-then-workspace");
		const report = await verifyLedgerText(ndjson);
		const html = renderToStaticMarkup(
			<AuditLedgerView ndjson={ndjson} initialReport={report} />,
		);
		expect(html).toContain("CANNOT DETERMINE");
		expect(html).not.toContain("Action required");
	});
});

it("marks every dependent step unknown after an evidence read failure", async () => {
	const { AuditWorkflow } = await import("./AuditWorkflow");
	const html = renderToStaticMarkup(
		<AuditWorkflow report={null} rows={0} batches={0} readError />,
	);
	expect(html.match(/CANNOT DETERMINE/g)).toHaveLength(4);
	expect(html).not.toContain("bg-ok-soft");
	expect(html).not.toContain("bg-danger-soft");
});
