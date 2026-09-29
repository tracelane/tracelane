import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
	ANCHORED_NDJSON,
	TRUSTED_PUBKEY_B64,
} from "@/e2e/fixtures/audit-fixture-data";
import {
	type VerifyReport,
	verifyLedgerText,
} from "@tracelanedev/audit-verifier";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeAll, describe, expect, it } from "vitest";
import { AuditLedgerView } from "./AuditLedgerView";

const key = Uint8Array.from(Buffer.from(TRUSTED_PUBKEY_B64, "base64"));
const vector = (name: string) =>
	readFileSync(resolve("../../evals/audit-ledger", name), "utf8");
const render = (ndjson: string, initialReport?: VerifyReport, extra = {}) =>
	renderToStaticMarkup(
		createElement(AuditLedgerView, {
			ndjson,
			initialReport,
			tenantPubkeyB64: TRUSTED_PUBKEY_B64,
			...extra,
		}),
	);
type TestAnchor = {
	batch_end_seq: number;
	anchor_state: string;
	merkle_root: string;
	ed25519: { pubkey: string; signature: string };
	rekor?: { checkpoint: { envelope: string } };
};
function mutateAnchor(fn: (a: TestAnchor) => void) {
	return ANCHORED_NDJSON.split("\n")
		.filter(Boolean)
		.map((line) => {
			const a = JSON.parse(line);
			if (a.type === "anchor") fn(a);
			return JSON.stringify(a);
		})
		.join("\n");
}
let healthy: VerifyReport;
beforeAll(async () => {
	healthy = await verifyLedgerText(ANCHORED_NDJSON, { tenantPubkey: key });
});

describe("evidence result follows real verifier bytes", () => {
	it("verifies a genuine public proof and limits the claim to its window", () => {
		expect(healthy.hash_chain_valid).toBe(true);
		expect(healthy.anchors_included).toBe(1);
		const html = render(ANCHORED_NDJSON, healthy, {
			ledgerRange: { total: 4, from: 0, to: 3 },
		});
		expect(html).toContain("This window passed");
		expect(html).toContain("these rows only");
		expect(html).toContain("Not established by this check");
		expect(html).toContain("0 rows outside this check");
		expect(html).not.toContain("CLAIM 1");
		expect(html).not.toContain("Chain head");
	});
	it("anchor-only failure never tells the customer the row hashes do not match", async () => {
		const bytes = mutateAnchor((a) => {
			if (a.rekor) a.rekor.checkpoint.envelope = "invalid-checkpoint";
		});
		const report = await verifyLedgerText(bytes, { tenantPubkey: key });
		expect(report.hash_chain_valid).toBe(true);
		expect(report.signatures_valid).toBe(false);
		const html = render(bytes, report);
		expect(html).not.toContain("Something altered the events");
		expect(html).toContain("Public proof check failed");
		expect(html).toContain("Match from sequence 0");
		expect(html).toContain(
			"Ask support to investigate the batch’s public proof",
		);
		expect(html).not.toContain("repair a broken chain");
	});
	it("a tampered row gets incident advice and cannot claim a passing check", async () => {
		const bytes = vector("tampered.ndjson");
		const report = await verifyLedgerText(bytes);
		expect(report.hash_chain_valid).toBe(false);
		const html = render(bytes, report);
		expect(html).toContain("Record integrity check failed");
		expect(html).toContain("Nothing in the app can repair a broken chain");
		expect(html).toContain("Save the check report before reloading");
		expect(html).not.toContain("This window passed");
	});
	it.each([
		[
			"stripped",
			(a: TestAnchor) => {
				a.rekor = undefined;
			},
			"A public proof is missing",
			"investigate the missing batch proof",
		],
		[
			"fingerprint",
			(a: TestAnchor) => {
				a.merkle_root = "00".repeat(32);
			},
			"Batch fingerprint check failed",
			"compare the batch record",
		],
		[
			"wrong key",
			(a: TestAnchor) => {
				a.ed25519.pubkey = Buffer.alloc(32, 1).toString("base64");
			},
			"Batch signing key does not match",
			"Do not replace your trusted key",
		],
		[
			"signature",
			(a: TestAnchor) => {
				a.ed25519.signature = Buffer.alloc(64, 1).toString("base64");
			},
			"Batch signature check failed",
			"investigate the batch signature",
		],
	])(
		"%s has its own explanation and next step",
		async (_name, mutate, heading, next) => {
			const bytes = mutateAnchor(mutate);
			const report = await verifyLedgerText(bytes, { tenantPubkey: key });
			const html = render(bytes, report);
			expect(html).toContain(heading);
			expect(html).toContain(next);
			expect(html).not.toContain("This window passed");
		},
	);
	it("missing trust key is unknown, never a false signature failure or empty state", async () => {
		const report = await verifyLedgerText(ANCHORED_NDJSON);
		expect(report.anchors_unverified).toBe(1);
		const html = render(ANCHORED_NDJSON, report, { tenantPubkeyB64: "" });
		expect(html).toContain("A trusted signing key is missing");
		expect(html).toContain("Public proof attached");
		expect(html).not.toContain("No events in this ledger");
		expect(html).not.toContain("This window passed");
	});
	it("an unrooted view never calls skipped row hashes a match", async () => {
		const bytes = vector("good.ndjson")
			.split("\n")
			.filter(Boolean)
			.slice(1)
			.join("\n");
		const report = await verifyLedgerText(bytes);
		expect(report.trust_established).toBe(false);
		const html = render(bytes, report);
		expect(html).toContain("This window has no verified starting point");
		expect(html).not.toContain("Match from sequence");
	});
	it("invalid evidence does not accuse the stored chain of being altered", async () => {
		const report = await verifyLedgerText("malformed JSON");
		const html = render("malformed JSON", report);
		expect(html).toContain("Evidence could not be verified");
		expect(html).not.toContain("Record integrity check failed");
	});
	it("hash consistency without a public anchor is explicitly qualified", async () => {
		const bytes = vector("good.ndjson");
		const report = await verifyLedgerText(bytes);
		const html = render(bytes, report);
		expect(html).toContain("Hashes match. Public proof is not established.");
		expect(html).not.toContain("This window passed");
	});
	it("a recorded batch with no public anchor stays distinct from no batch records", () => {
		const signed = mutateAnchor((a) => {
			a.anchor_state = "unanchored";
			a.rekor = undefined;
		});
		expect(render(signed)).toContain("Signed record · no public anchor");
		expect(render(vector("good.ndjson"))).toContain(
			"No batch records were returned",
		);
	});
	it("buried coverage holes stay indeterminate and have a remedy", () => {
		const report = { ...healthy, rows_uncovered_by_anchors: 100 };
		const html = render(ANCHORED_NDJSON, report);
		expect(html).toContain("There is a gap in batch coverage");
		expect(html).toContain("100 loaded rows");
		expect(html).toContain("If the gap remains");
		expect(html).not.toContain("This window passed");
	});
	it("windowed verification names the real start and does not claim earlier rows", () => {
		const html = render(ANCHORED_NDJSON, { ...healthy, verified_from_seq: 2 });
		expect(html).toContain("Match from sequence 2");
		expect(html).toContain(
			"Loaded rows before that starting point are not verified",
		);
	});
	it("missing batch rows get coverage advice, not an accusation", async () => {
		const bytes = mutateAnchor((a) => {
			a.batch_end_seq = 100;
		});
		const report = await verifyLedgerText(bytes, { tenantPubkey: key });
		const html = render(bytes, report);
		expect(html).toContain("The proof needs rows outside this window");
		expect(html).not.toContain("Record integrity check failed");
	});
});

describe("bounded view and honest totals", () => {
	it("a billion-row count never turns four checked rows into a workspace pass", () => {
		const html = render(ANCHORED_NDJSON, healthy, {
			ledgerRange: { total: 1_000_000_000, from: 0, to: 999_999_999 },
		});
		expect(html).toContain("1,000,000,000");
		expect(html).toContain("999,999,996 rows outside this check");
		expect(html).toContain("Not established by this check");
		expect(html).not.toContain("complete chain from genesis");
		expect(html).not.toContain("Download the complete ledger");
	});
	it("an unavailable count never substitutes the loaded row count", () => {
		const html = render(ANCHORED_NDJSON, healthy);
		expect(html).toContain("Unavailable");
		expect(html).toContain("Rows outside this window are not counted here");
		expect(html).not.toContain("0 rows outside");
	});
	it("inconsistent snapshots cannot claim a total smaller than the loaded set", () => {
		expect(
			render(ANCHORED_NDJSON, healthy, { ledgerRange: { total: 2, to: 1 } }),
		).toContain("Unavailable");
	});
	it("only a measured empty inventory gets onboarding", () => {
		expect(render("", undefined, { ledgerRange: { total: 0 } })).toContain(
			"No events in this ledger",
		);
		for (const ledgerRange of [undefined, { total: 10, to: 9 }]) {
			const html = render("", undefined, { ledgerRange });
			expect(html).toContain("No evidence loaded. Integrity is unknown.");
			expect(html).not.toContain("No events in this ledger");
		}
	});
	it("does not render payloads until an event is opened for inspection", () => {
		const html = render(ANCHORED_NDJSON, healthy);
		expect(html).not.toContain("prev_hash");
		expect(html).toContain("Inspect individual events");
	});
	it("renders at most eight loaded batch entries", () => {
		const a = JSON.parse(
			ANCHORED_NDJSON.split("\n").filter(Boolean).at(-1) ?? "{}",
		);
		const bytes = Array.from({ length: 20 }, (_, i) =>
			JSON.stringify({
				...a,
				batch_start_seq: i * 100,
				batch_end_seq: i * 100 + 99,
			}),
		).join("\n");
		const html = render(bytes);
		expect(html).toContain("Showing 1–8 of 20 loaded batch records");
		expect(html).not.toContain("900–999");
	});
	it("export entitlement changes the download, never access to the check report", () => {
		const free = render(ANCHORED_NDJSON, healthy, { canExport: false });
		expect(free).toContain("Save check report");
		expect(free).toContain("View Enterprise plan");
		expect(free).not.toContain("Download selected dates");
		const paid = render(ANCHORED_NDJSON, healthy, { canExport: true });
		expect(paid).toContain("Download selected dates (NDJSON)");
		expect(paid).toContain("does not prove completeness or integrity");
	});
});

describe("review: scope, incidents and activity", () => {
	it("a successful subset uses a neutral coverage headline", () => {
		const html = render(ANCHORED_NDJSON, healthy, {
			ledgerRange: { total: 1_000_000_000, from: 0, to: 999_999_999 },
		});
		expect(html).toContain("4 of 1,000,000,000 rows checked");
		expect(html).not.toContain("bg-seal-soft");
		expect(html).not.toContain("This window passed");
	});
	it("an unknown total cannot produce a full green hero", () => {
		expect(render(ANCHORED_NDJSON, healthy)).not.toContain("bg-seal-soft");
	});
	it("public inclusion cannot look like a half-pass beside tampered anchored rows", async () => {
		const records = ANCHORED_NDJSON.split("\n")
			.filter(Boolean)
			.map((line) => JSON.parse(line));
		records[1].payload += "_TAMPERED";
		const bytes = records.map((row) => JSON.stringify(row)).join("\n");
		const report = await verifyLedgerText(bytes, { tenantPubkey: key });
		expect(report.anchors_included).toBe(1);
		expect(report.hash_chain_valid).toBe(false);
		const html = render(bytes, report);
		expect(html).toContain("The anchored root no longer matches these rows");
		expect(html).not.toContain("1 verified");
		expect(html).toContain('href="#audit-event-1"');
	});
	it("freshness is sourced from the range response, with explicit unknowns", () => {
		const html = render(ANCHORED_NDJSON, healthy, {
			ledgerRange: {
				total: 4,
				from: 0,
				to: 3,
				latest_event_at: "2026-09-24T12:00:00Z",
				latest_anchor_at: "2026-09-24T11:55:00Z",
			},
		});
		expect(html).toContain("Last event recorded");
		expect(html).toContain('dateTime="2026-09-24T12:00:00Z"');
		expect(html).toContain("Last anchored");
		expect(html).toContain('dateTime="2026-09-24T11:55:00Z"');
		const unknown = render(ANCHORED_NDJSON, healthy);
		expect(unknown).toMatch(/Last event recorded[\s\S]*Unknown/);
		expect(unknown).toMatch(/Last anchored[\s\S]*Unknown/);
	});
	it("offers one refresh-and-check action in customer language", () => {
		const html = render(ANCHORED_NDJSON, healthy);
		expect(html).toContain("Refresh &amp; check latest");
		expect(html).not.toContain("Workspace count snapshot");
		expect(html).not.toMatch(/loaded window/i);
		expect(html).not.toContain("Recheck loaded window");
		expect(html).not.toContain("Load fresh evidence");
	});
});
