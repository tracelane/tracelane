/**
 * Reference verifier for Tracelane tamper-evident audit ledgers.
 *
 * Mirrors the Rust verifier in `packages/verifier-rust` and the Python
 * verifier in `packages/verifier-python`. See `evals/audit-ledger/` for
 * shared conformance vectors.
 *
 * Each row may carry a `format` marker selecting its verification path;
 * unmarked rows fall back to the `formatVersion` option (default `"v2"`).
 *
 * - **v2.1 (ADR-050, current)**: `payload` is the **verbatim stored
 *   canonical JSON string** (the exact `row_hash` preimage). It is SHA-256'd
 *   byte-for-byte and NEVER re-derived. Because no component re-canonicalizes,
 *   the Rust / Python / TypeScript verifiers are **identical by construction**
 * - **v2 (legacy re-derive)**: length-prefixed, domain-separated framing per
 *   `crates/gateway/src/audit_format/mod.rs::row_hash_v2`, RFC 6962 §2.1 Merkle
 *   tree — but `payload` is a nested object this verifier re-canonicalizes.
 *   `JSON.parse`/`stringify` is lossy for JS-unsafe numbers (`1.0`, `>2^53`,
 *   read-only for pre-ADR-050 exports.
 * - **v1 (legacy)**: pipe-separated row hash; vulnerable to field-boundary
 *   attacks. Kept for migration of pre-Phase-3 ledgers.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

export type FormatVersion = "v2.1" | "v2" | "v1";

/** v2 and v2.1 share identical framing — they differ only in how the
 * canonical payload string is obtained (verbatim vs re-derived). */
function isV2Family(f: FormatVersion): boolean {
	return f === "v2" || f === "v2.1";
}

/**
 * The effective format for a single row. The per-row `format` marker is
 * authoritative (the export self-describes — ADR-050: branch on the marker,
 * never type-sniff); unmarked rows fall back to the caller default.
 */
function resolveFormat(
	format: unknown,
	fallback: FormatVersion,
): FormatVersion {
	if (format === "v2.1" || format === "v2" || format === "v1") {
		return format;
	}
	return fallback;
}

export interface VerifyOptions {
	formatVersion?: FormatVersion;
	/** Skip resolving Rekor anchors over the network. */
	offline?: boolean;
	/** Rekor transparency-log base URL. */
	rekorUrl?: string;
	/** Per-request HTTP timeout for Rekor resolution, in milliseconds. */
	rekorTimeoutMs?: number;
	/** 32-byte Ed25519 pubkey to pin every Rekor anchor against (R1 H2). */
	pinnedPubkey?: Uint8Array;
	/** ADR-062 C2: the TRUSTED tenant Ed25519 pubkey (32 raw bytes), obtained
	 * out-of-band from Tracelane's TLS-authenticated domain (dashboard
	 * `/settings/audit` or `GET /v1/audit/pubkey`). Anchor records whose embedded
	 * pubkey differs are REJECTED (fail closed). Absent → chain-only mode:
	 * signatures/anchors are reported UNVERIFIED (never green). */
	tenantPubkey?: Uint8Array;
}

export interface VerifyError {
	seq: number | null;
	kind: string;
	detail: string;
}

export interface VerifyReport {
	ledger_path: string;
	rows_seen: number;
	hash_chain_valid: boolean;
	signatures_valid: boolean;
	rekor_anchors_seen: number;
	rekor_anchors_resolved: number;
	/** Anchors whose FULL public-inclusion proof + checkpoint verified (Layer 2+3). */
	anchors_included: number;
	/** True if any anchor committed to "anchored" but its rekor bundle is absent
	 * (a strip/downgrade attack). ADR-062 H3. */
	strip_detected: boolean;
	errors: VerifyError[];
}

interface AuditRow {
	/** Per-row wire-format marker (ADR-050): "v2.1" | "v2" | "v1". Absent on
	 * pre-ADR-050 exports → the caller's default format applies. */
	format?: string;
	tenant_id: string;
	seq: number;
	event_time: string;
	event_type: string;
	actor: string;
	/** For "v2.1" this is a JSON string (the verbatim canonical payload); for
	 * "v2"/"v1" it is the nested payload object. */
	payload: unknown;
	prev_hash: string;
	row_hash: string;
	rekor_entry_id?: string | null;
}

// ---------------------------------------------------------------------
// v2 hashing
// ---------------------------------------------------------------------

const DOMAIN_ROW_V2 = new TextEncoder().encode("tracelane-audit-row-v2\0");
const DOMAIN_GENESIS_V2 = new TextEncoder().encode(
	"tracelane-audit-v2-genesis\0",
);
const MERKLE_LEAF_PREFIX = 0x00;
const MERKLE_NODE_PREFIX = 0x01;

// ADR-062 Amendment 1 — FROZEN anchor domain tags + pinned log trust anchor.
const DOMAIN_ANCHOR = new TextEncoder().encode("tracelane-anchor-ecdsa-v1\0");
const DOMAIN_ATTEST = new TextEncoder().encode("tracelane-audit-ed25519-v1\0");
/** The public Rekor v2 log this verifier trusts — HARDCODED, never read from the
 * bundle (ADR-062 H5). Rotation = a new verifier release + ADR. Source: Sigstore
 * TUF trusted_root (`tlogs[log2025-1].publicKey`). */
const LOG_HOST = "log2025-1.rekor.sigstore.dev";
/** log2025-1 Ed25519 checkpoint key, raw 32 bytes. */
const LOG_ED25519_PUBKEY = base64Decode(
	"t8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=",
);

/** One exported anchor record (ADR-062) — the per-batch offline bundle. */
interface AnchorRecord {
	type: string;
	tenant_id: string;
	batch_start_seq: number;
	batch_end_seq: number;
	merkle_root: string;
	anchor_state: string;
	ed25519: { signature: string; pubkey: string };
	rekor?: {
		log_url: string;
		log_index: string;
		canonicalized_body: string;
		inclusion_proof: { log_index: string; tree_size: string; hashes: string[] };
		checkpoint: { envelope: string };
	};
}

function uuidBytes(tenantId: string): Uint8Array {
	const cleaned = tenantId.replace(/-/g, "");
	if (cleaned.length !== 32) {
		throw new Error(`tenant_id is not a UUID: ${tenantId}`);
	}
	return hexToBytes(cleaned);
}

function u64be(n: number | bigint): Uint8Array {
	const bn = typeof n === "bigint" ? n : BigInt(n);
	const buf = new Uint8Array(8);
	const view = new DataView(buf.buffer);
	view.setBigUint64(0, bn, false);
	return buf;
}

function writeLp(parts: Uint8Array[], bytes: Uint8Array): void {
	parts.push(u64be(bytes.length));
	parts.push(bytes);
}

function concat(parts: Uint8Array[]): Uint8Array {
	let total = 0;
	for (const p of parts) {
		total += p.length;
	}
	const out = new Uint8Array(total);
	let off = 0;
	for (const p of parts) {
		out.set(p, off);
		off += p.length;
	}
	return out;
}

function rowHashV2(
	prev: Uint8Array,
	tenantUuid: Uint8Array,
	seq: number,
	eventType: string,
	actor: string,
	canonicalPayload: string,
): Uint8Array {
	const enc = new TextEncoder();
	const parts: Uint8Array[] = [DOMAIN_ROW_V2];
	writeLp(parts, tenantUuid);
	parts.push(u64be(seq));
	writeLp(parts, enc.encode(eventType));
	writeLp(parts, enc.encode(actor));
	writeLp(parts, enc.encode(canonicalPayload));
	writeLp(parts, prev);
	return sha256(concat(parts));
}

function genesisV2(tenantUuid: Uint8Array): Uint8Array {
	return sha256(concat([DOMAIN_GENESIS_V2, tenantUuid]));
}

function merkleRootV2(leaves: Uint8Array[]): Uint8Array {
	if (leaves.length === 0) {
		return sha256(new Uint8Array(0));
	}
	let level: Uint8Array[] = leaves.map((leaf) => {
		const buf = new Uint8Array(1 + leaf.length);
		buf[0] = MERKLE_LEAF_PREFIX;
		buf.set(leaf, 1);
		return sha256(buf);
	});
	while (level.length > 1) {
		const next: Uint8Array[] = [];
		let i = 0;
		while (i + 1 < level.length) {
			const left = level[i] as Uint8Array;
			const right = level[i + 1] as Uint8Array;
			const buf = new Uint8Array(1 + left.length + right.length);
			buf[0] = MERKLE_NODE_PREFIX;
			buf.set(left, 1);
			buf.set(right, 1 + left.length);
			next.push(sha256(buf));
			i += 2;
		}
		if (i < level.length) {
			next.push(level[i] as Uint8Array); // lone-odd: promote
		}
		level = next;
	}
	return level[0] as Uint8Array;
}

function canonicalPayloadV2(value: unknown): string {
	return JSON.stringify(sortKeysDeep(value));
}

function sortKeysDeep(value: unknown): unknown {
	if (Array.isArray(value)) {
		return value.map(sortKeysDeep);
	}
	if (value !== null && typeof value === "object") {
		const out: Record<string, unknown> = {};
		const obj = value as Record<string, unknown>;
		for (const k of Object.keys(obj).sort()) {
			out[k] = sortKeysDeep(obj[k]);
		}
		return out;
	}
	return value;
}

// ---------------------------------------------------------------------
// v1 (legacy)
// ---------------------------------------------------------------------

/**
 * supported for pre-Phase-3 ledger migration only.
 */
export function computeRowHash(
	prevHash: string,
	tenantId: string,
	seq: number,
	eventType: string,
	actor: string,
	payloadJson: string,
): string {
	const input = `${tenantId}|${seq}|${eventType}|${actor}|${payloadJson}|${prevHash}`;
	return bytesToHex(sha256(new TextEncoder().encode(input)));
}

function canonicalPayloadV1(value: unknown): string {
	return JSON.stringify(sortKeysDeep(value));
}

// ---------------------------------------------------------------------
// ADR-062 Amendment 1 — offline anchor crypto (Rekor v2 has no online lookup;
// the inclusion proof + checkpoint are bundled in the export).
// ---------------------------------------------------------------------

function base64Decode(b64: string): Uint8Array {
	// Node has Buffer; the browser has atob. Pick the one available.
	if (typeof Buffer !== "undefined") {
		return Uint8Array.from(Buffer.from(b64, "base64"));
	}
	const bin = atob(b64);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) {
		out[i] = bin.charCodeAt(i);
	}
	return out;
}

function nodeHash(l: Uint8Array, r: Uint8Array): Uint8Array {
	return sha256(concat([new Uint8Array([MERKLE_NODE_PREFIX]), l, r]));
}

/** P-256 SPKI (91 bytes) → raw uncompressed point (65 bytes, `0x04‖X‖Y`). */
function spkiToPoint(spki: Uint8Array): Uint8Array {
	if (spki.length !== 91 || spki[26] !== 0x04) {
		throw new Error("not a P-256 SubjectPublicKeyInfo");
	}
	return spki.slice(26);
}

/** `anchor_commitment` (ADR-062): `null`→`[0x00]`;
 * anchored→`0x01 ‖ SHA256(ecdsa_spki) ‖ SHA256(log_url) ‖ u64be(log_index)`. */
function anchorCommitment(
	anchored: { ecdsaSpki: Uint8Array; logUrl: string; logIndex: number } | null,
): Uint8Array {
	if (!anchored) return new Uint8Array([0x00]);
	const enc = new TextEncoder();
	return concat([
		new Uint8Array([0x01]),
		sha256(anchored.ecdsaSpki),
		sha256(enc.encode(anchored.logUrl)),
		u64be(anchored.logIndex),
	]);
}

/** RFC 6962 §2.1.1 inclusion-proof root recomputation. `leaf` is already the
 * RFC6962 leaf hash `SHA256(0x00 ‖ body)`. Throws on a malformed proof. */
function rfc6962Root(
	leaf: Uint8Array,
	index: number,
	size: number,
	proof: Uint8Array[],
): Uint8Array {
	if (index >= size) throw new Error("leaf index >= tree size");
	let fn = index;
	let sn = size - 1;
	let r = leaf;
	for (const p of proof) {
		if (sn === 0) throw new Error("inclusion proof too long");
		if ((fn & 1) === 1 || fn === sn) {
			r = nodeHash(p, r);
			while (fn !== 0 && (fn & 1) === 0) {
				fn >>= 1;
				sn >>= 1;
			}
		} else {
			r = nodeHash(r, p);
		}
		fn >>= 1;
		sn >>= 1;
	}
	if (sn !== 0) throw new Error("inclusion proof too short");
	return r;
}

/** Parse + verify a C2SP signed-note checkpoint against the PINNED log key
 * (ADR-062 H5 — never a bundle-supplied key). Returns `{treeSize, root}`. */
function verifyCheckpoint(envelope: string): {
	treeSize: number;
	root: Uint8Array;
} {
	const sep = envelope.indexOf("\n\n");
	if (sep < 0) throw new Error("checkpoint has no signature separator");
	// Signed text = the body up to (and including the \n before) the blank line.
	const bodyText = envelope.slice(0, sep + 1);
	const sigBlock = envelope.slice(sep + 2);
	const bodyLines = bodyText.split("\n");
	const origin = bodyLines[0] ?? "";
	const treeSize = Number.parseInt(bodyLines[1] ?? "", 10);
	const rootB64 = bodyLines[2] ?? "";
	if (origin !== LOG_HOST) {
		throw new Error(`checkpoint origin ${origin} != pinned ${LOG_HOST}`);
	}
	const sigLine = sigBlock.split("\n").find((l) => l.startsWith("— "));
	if (!sigLine) throw new Error("checkpoint has no signature line");
	const sigBlob = base64Decode(sigLine.split(" ")[2] ?? "");
	if (sigBlob.length !== 4 + 64)
		throw new Error("checkpoint sig blob wrong length");
	const keyhint = sigBlob.slice(0, 4);
	const sig = sigBlob.slice(4);
	const enc = new TextEncoder();
	// keyhint = SHA256(name ‖ 0x0A ‖ 0x01 ‖ pubkey)[:4] (C2SP signed-note, Ed25519).
	const expectHint = sha256(
		concat([
			enc.encode(LOG_HOST),
			new Uint8Array([0x0a, 0x01]),
			LOG_ED25519_PUBKEY,
		]),
	).slice(0, 4);
	if (!bytesEqual(keyhint, expectHint)) {
		throw new Error("checkpoint key hint != pinned log key");
	}
	if (!ed25519.verify(sig, enc.encode(bodyText), LOG_ED25519_PUBKEY)) {
		throw new Error("checkpoint signature invalid");
	}
	return { treeSize, root: base64Decode(rootB64) };
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) {
		return false;
	}
	let diff = 0;
	for (let i = 0; i < a.length; i++) {
		diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
	}
	return diff === 0;
}

// ---------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------

/**
 * Verify an audit ledger from its NDJSON TEXT (no filesystem) — browser-runnable.
 * Recomputes every row hash (SHA-256, domain-separated, RFC-6962 framing) and
 * checks the prev-hash chain + seq order; on a break, `errors[]` names the exact
 * `seq` and `kind` (row_hash_mismatch / prev_hash_mismatch / seq_out_of_order).
 * Ed25519 signature + Merkle-root verification runs only against resolvable Rekor
 * anchors (see `rekor_anchors_resolved`); with 0 anchors `signatures_valid` is
 * vacuously true — callers MUST gate any "signature verified" claim on
 * `rekor_anchors_resolved > 0`, never on `signatures_valid` alone.
 */
export async function verifyLedgerText(
	text: string,
	options: VerifyOptions & { label?: string } = {},
): Promise<VerifyReport> {
	const formatVersion: FormatVersion = options.formatVersion ?? "v2";

	const report: VerifyReport = {
		ledger_path: options.label ?? "ledger",
		rows_seen: 0,
		hash_chain_valid: true,
		signatures_valid: true,
		rekor_anchors_seen: 0,
		rekor_anchors_resolved: 0,
		anchors_included: 0,
		strip_detected: false,
		errors: [],
	};

	// Split records: row records (no `type`) vs anchor records (`type:"anchor"`).
	const rows: AuditRow[] = [];
	const anchors: AnchorRecord[] = [];
	const lines = text.split(/\r?\n/);
	for (let i = 0; i < lines.length; i++) {
		const raw = lines[i];
		if (!raw || raw.trim() === "") {
			continue;
		}
		let rec: Record<string, unknown>;
		try {
			rec = JSON.parse(raw) as Record<string, unknown>;
		} catch (err) {
			report.errors.push({
				seq: null,
				kind: "parse_error",
				detail: `line ${i + 1}: ${(err as Error).message}`,
			});
			report.hash_chain_valid = false;
			continue;
		}
		if (rec.type === "anchor") {
			anchors.push(rec as unknown as AnchorRecord);
		} else {
			rows.push(rec as unknown as AuditRow);
		}
	}
	report.rows_seen = rows.length;

	verifyChain(report, rows, formatVersion);

	// ADR-062 Amendment 1: OFFLINE anchor verification from the bundle (Rekor v2
	// has no online lookup). The trusted tenant pubkey is the single external trust
	// root; absent → chain-only (anchors reported UNVERIFIED, never green).
	verifyAnchorsOffline(report, rows, anchors, options.tenantPubkey);

	return report;
}

function verifyChain(
	report: VerifyReport,
	rows: AuditRow[],
	formatVersion: FormatVersion,
): void {
	const state = new Map<string, { seq: number; prev: Uint8Array }>();

	for (const row of rows) {
		// Per-row format: the `format` marker wins; else the caller default.
		const fmt = resolveFormat(row.format, formatVersion);
		const v2Family = isV2Family(fmt);

		let tenantUuid: Uint8Array;
		try {
			tenantUuid = uuidBytes(row.tenant_id);
		} catch (e) {
			report.errors.push({
				seq: row.seq,
				kind: "bad_tenant_id",
				detail: (e as Error).message,
			});
			report.hash_chain_valid = false;
			continue;
		}

		let entry = state.get(row.tenant_id);
		if (!entry) {
			const initialPrev = v2Family ? genesisV2(tenantUuid) : new Uint8Array(0);
			entry = { seq: 0, prev: initialPrev };
			state.set(row.tenant_id, entry);
		}

		if (row.seq !== entry.seq) {
			report.errors.push({
				seq: row.seq,
				kind: "seq_out_of_order",
				detail: `tenant ${row.tenant_id}: expected seq ${entry.seq}, got ${row.seq}`,
			});
			report.hash_chain_valid = false;
		}

		let prevOk = false;
		if (v2Family) {
			if (row.seq === 0 && row.prev_hash === "") {
				prevOk = true;
			} else {
				try {
					const decoded = hexToBytes(row.prev_hash);
					prevOk = bytesEqual(decoded, entry.prev);
				} catch {
					prevOk = false;
				}
			}
		} else {
			const expected = row.seq === 0 ? "" : bytesToHex(entry.prev);
			prevOk = row.prev_hash === expected;
		}

		if (!prevOk) {
			report.errors.push({
				seq: row.seq,
				kind: "prev_hash_mismatch",
				detail: `tenant ${row.tenant_id}: prev_hash does not chain`,
			});
			report.hash_chain_valid = false;
		}

		// Obtain the canonical payload STRING (the row_hash preimage).
		//   v2.1 — the payload IS the verbatim canonical string; hash it
		//   v2   — re-canonicalize the object (legacy; JSON.parse/stringify is
		//   v1   — legacy pipe format.
		let canon: string | null;
		if (fmt === "v2.1") {
			if (typeof row.payload === "string") {
				canon = row.payload;
			} else {
				report.errors.push({
					seq: row.seq,
					kind: "v2_1_payload_not_string",
					detail: `tenant ${row.tenant_id}: v2.1 payload must be the verbatim canonical JSON string, not a re-parsed object/number`,
				});
				report.hash_chain_valid = false;
				canon = null;
			}
		} else if (fmt === "v2") {
			canon = canonicalPayloadV2(row.payload);
		} else {
			canon = canonicalPayloadV1(row.payload);
		}

		let stored: Uint8Array;
		try {
			stored = hexToBytes(row.row_hash);
		} catch {
			report.errors.push({
				seq: row.seq,
				kind: "bad_row_hash_encoding",
				detail: `row_hash is not hex: ${row.row_hash}`,
			});
			report.hash_chain_valid = false;
			continue;
		}

		if (canon !== null) {
			let recomputed: Uint8Array;
			if (v2Family) {
				recomputed = rowHashV2(
					entry.prev,
					tenantUuid,
					row.seq,
					row.event_type,
					row.actor,
					canon,
				);
			} else {
				const hex = computeRowHash(
					row.prev_hash,
					row.tenant_id,
					row.seq,
					row.event_type,
					row.actor,
					canon,
				);
				recomputed = hexToBytes(hex);
			}

			if (!bytesEqual(recomputed, stored)) {
				report.errors.push({
					seq: row.seq,
					kind: "row_hash_mismatch",
					detail: `tenant ${row.tenant_id}: expected row_hash ${bytesToHex(recomputed)}, got ${row.row_hash}`,
				});
				report.hash_chain_valid = false;
			}
		}

		// Advance chain state with the CLAIMED stored hash even if an error fired
		// above (v2_1_payload_not_string / row_hash_mismatch). Deliberate
		// continue-on-error so every downstream break is reported; it cannot hide
		// a break because `hash_chain_valid` is already false and consumers gate on
		// that boolean (see verifyLedgerText docs), never on errors.length.
		entry.seq = row.seq + 1;
		entry.prev = stored;
	}
}

/**
 * ADR-062 Amendment 1 — OFFLINE anchor verification. For each anchor record:
 *   0. recompute the batch Merkle root over the chain rows [start..end];
 *   2. trusted-key gate (C2) — the bundle Ed25519 pubkey MUST equal the trusted
 *      `tenantPubkey`, else fail closed; absent `tenantPubkey` → chain-only;
 *   3. bound Ed25519 attestation over `DOMAIN_ATTEST ‖ root ‖ anchor_commitment`
 *      (catches strip / swap / downgrade — the attacker lacks the tenant key);
 *   when anchored also: 1. ECDSA entry sig binds the root; 2. RFC6962 inclusion
 *   proof; 3'. C2SP checkpoint sig against the PINNED log key.
 * Any failure flips `signatures_valid` false; chain-only mode asserts nothing
 * (callers gate a green "signed/anchored" claim on `rekor_anchors_resolved > 0`
 * and `anchors_included > 0`, never on `signatures_valid` alone).
 */
function verifyAnchorsOffline(
	report: VerifyReport,
	rows: AuditRow[],
	anchors: AnchorRecord[],
	tenantPubkey?: Uint8Array,
): void {
	if (anchors.length === 0) return;

	const rowHashByKey = new Map<string, Uint8Array>();
	for (const row of rows) {
		try {
			rowHashByKey.set(`${row.tenant_id}/${row.seq}`, hexToBytes(row.row_hash));
		} catch {
			/* a bad row_hash is already flagged by verifyChain */
		}
	}

	for (const a of anchors) {
		const committed = a.anchor_state === "anchored";
		const label = `batch ${a.batch_start_seq}-${a.batch_end_seq}`;

		// H3: committed-anchored but no bundle = a strip/downgrade.
		if (committed && !a.rekor) {
			report.strip_detected = true;
			report.errors.push({
				seq: null,
				kind: "anchor_stripped",
				detail: `${label}: claims anchored but the rekor bundle is absent`,
			});
			report.signatures_valid = false;
			continue;
		}

		// Layer 0: recompute the batch Merkle root over the chain rows.
		const leaves: Uint8Array[] = [];
		let missing = false;
		for (let seq = a.batch_start_seq; seq <= a.batch_end_seq; seq++) {
			const h = rowHashByKey.get(`${a.tenant_id}/${seq}`);
			if (!h) {
				missing = true;
				break;
			}
			leaves.push(h);
		}
		if (missing) {
			report.errors.push({
				seq: null,
				kind: "anchor_rows_missing",
				detail: `${label}: not all covered rows are present`,
			});
			report.signatures_valid = false;
			continue;
		}
		const root = merkleRootV2(leaves);
		let claimedRoot: Uint8Array;
		try {
			claimedRoot = hexToBytes(a.merkle_root);
		} catch {
			report.errors.push({
				seq: null,
				kind: "bad_merkle_root",
				detail: `${label}: merkle_root is not hex`,
			});
			report.signatures_valid = false;
			continue;
		}
		if (!bytesEqual(root, claimedRoot)) {
			report.errors.push({
				seq: null,
				kind: "merkle_root_mismatch",
				detail: `${label}: recomputed root != anchor.merkle_root`,
			});
			report.signatures_valid = false;
			continue;
		}

		// Layer 2 (trusted-key gate, C2). No trusted key → chain-only: assert
		// nothing (never green), do not count as seen/resolved.
		if (!tenantPubkey) continue;
		let bundlePubkey: Uint8Array;
		try {
			bundlePubkey = base64Decode(a.ed25519.pubkey);
		} catch {
			report.errors.push({
				seq: null,
				kind: "bad_tenant_pubkey",
				detail: `${label}: ed25519.pubkey is not base64`,
			});
			report.signatures_valid = false;
			continue;
		}
		if (!bytesEqual(bundlePubkey, tenantPubkey)) {
			report.errors.push({
				seq: null,
				kind: "untrusted_tenant_key",
				detail: `${label}: anchor Ed25519 pubkey != trusted --tenant-pubkey (rejected — ADR-062 C2)`,
			});
			report.signatures_valid = false;
			continue;
		}

		// Extract ECDSA material from the canonicalized body (anchored only).
		let anchoredMeta: {
			ecdsaSpki: Uint8Array;
			logUrl: string;
			logIndex: number;
		} | null = null;
		let artifactHash: Uint8Array | null = null;
		let entrySig: Uint8Array | null = null;
		let entryPoint: Uint8Array | null = null;
		if (committed && a.rekor) {
			try {
				const decoded = JSON.parse(
					new TextDecoder().decode(base64Decode(a.rekor.canonicalized_body)),
				) as Record<string, unknown>;
				const spec = ((decoded.spec as Record<string, unknown>)
					?.hashedRekordV002 ?? {}) as Record<string, unknown>;
				const data = (spec.data ?? {}) as Record<string, unknown>;
				const sigb = (spec.signature ?? {}) as Record<string, unknown>;
				const verifier = (sigb.verifier ?? {}) as Record<string, unknown>;
				const pk = (verifier.publicKey ?? {}) as Record<string, unknown>;
				if (verifier.keyDetails !== "PKIX_ECDSA_P256_SHA_256") {
					throw new Error(
						`unexpected keyDetails ${String(verifier.keyDetails)}`,
					);
				}
				const ecdsaSpki = base64Decode(String(pk.rawBytes));
				artifactHash = sha256(concat([DOMAIN_ANCHOR, root]));
				if (!bytesEqual(base64Decode(String(data.digest)), artifactHash)) {
					throw new Error("entry digest != SHA256(anchor artifact)");
				}
				entrySig = base64Decode(String(sigb.content));
				entryPoint = spkiToPoint(ecdsaSpki);
				anchoredMeta = {
					ecdsaSpki,
					logUrl: a.rekor.log_url,
					logIndex: Number.parseInt(a.rekor.log_index, 10),
				};
			} catch (e) {
				report.errors.push({
					seq: null,
					kind: "anchor_body_invalid",
					detail: `${label}: ${(e as Error).message}`,
				});
				report.signatures_valid = false;
				continue;
			}
		}

		// Layer 3 (bound Ed25519 attestation) — the load-bearing check.
		const commitment = anchorCommitment(anchoredMeta);
		const msg = concat([DOMAIN_ATTEST, root, commitment]);
		let attSig: Uint8Array;
		try {
			attSig = base64Decode(a.ed25519.signature);
		} catch {
			report.errors.push({
				seq: null,
				kind: "bad_attestation_sig",
				detail: `${label}: ed25519.signature is not base64`,
			});
			report.signatures_valid = false;
			continue;
		}
		if (!ed25519.verify(attSig, msg, tenantPubkey)) {
			report.errors.push({
				seq: null,
				kind: "attestation_invalid",
				detail: `${label}: bound Ed25519 attestation failed (tamper/strip/downgrade)`,
			});
			report.signatures_valid = false;
			continue;
		}

		if (!committed || !a.rekor || !entrySig || !entryPoint || !artifactHash) {
			// Honest signed-but-unanchored batch: attestation verified, nothing more.
			continue;
		}
		report.rekor_anchors_seen += 1;

		// Layer 1: ECDSA entry signature over the anchor-artifact hash. Rekor's
		// signatures are DER; convert to the compact form p256.verify accepts, and
		// allow high-S (Rekor does not enforce low-S on submission).
		let ecdsaOk = false;
		try {
			const compactSig = p256.Signature.fromDER(entrySig).toCompactRawBytes();
			ecdsaOk = p256.verify(compactSig, artifactHash, entryPoint, {
				lowS: false,
			});
		} catch {
			ecdsaOk = false;
		}
		if (!ecdsaOk) {
			report.errors.push({
				seq: null,
				kind: "entry_signature_invalid",
				detail: `${label}: Rekor entry ECDSA sig did not verify over the anchor artifact`,
			});
			report.signatures_valid = false;
			continue;
		}
		report.rekor_anchors_resolved += 1;

		// Layer 2 (inclusion proof) + Layer 3' (checkpoint sig, pinned key).
		try {
			const body = base64Decode(a.rekor.canonicalized_body);
			const leaf = sha256(concat([new Uint8Array([MERKLE_LEAF_PREFIX]), body]));
			const idx = Number.parseInt(a.rekor.inclusion_proof.log_index, 10);
			const treeSize = Number.parseInt(a.rekor.inclusion_proof.tree_size, 10);
			const proof = a.rekor.inclusion_proof.hashes.map((h) => base64Decode(h));
			const computedRoot = rfc6962Root(leaf, idx, treeSize, proof);
			const cp = verifyCheckpoint(a.rekor.checkpoint.envelope);
			if (cp.treeSize !== treeSize) {
				throw new Error(
					`checkpoint tree_size ${cp.treeSize} != proof ${treeSize}`,
				);
			}
			if (!bytesEqual(cp.root, computedRoot)) {
				throw new Error("inclusion-proof root != verified checkpoint root");
			}
			report.anchors_included += 1;
		} catch (e) {
			report.errors.push({
				seq: null,
				kind: "inclusion_proof_invalid",
				detail: `${label}: ${(e as Error).message}`,
			});
			report.signatures_valid = false;
		}
	}
}
