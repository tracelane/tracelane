// TS reference-verifier wrapper for the cross-verifier round-trip (ADR-062).
// argv: <dist/index.js> <ledger.ndjson> <tenant-pubkey-b64|"">
// Prints one JSON line: {hash_chain_valid, signatures_valid, anchors_included}.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const [distPath, ledger, pk] = process.argv.slice(2);
const { verifyLedgerText } = await import(pathToFileURL(distPath).href);
const tenantPubkey = pk ? Uint8Array.from(Buffer.from(pk, "base64")) : undefined;
const r = await verifyLedgerText(readFileSync(ledger, "utf8"), { tenantPubkey });
console.log(
  JSON.stringify({
    hash_chain_valid: r.hash_chain_valid,
    signatures_valid: r.signatures_valid,
    anchors_included: r.anchors_included,
  }),
);
