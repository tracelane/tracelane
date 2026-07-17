// Regenerates apps/web/e2e/fixtures/audit-fixture-data.ts from the committed
// anchored conformance vector. Run: node scripts/gen/audit-e2e-fixture.mjs
import { readFileSync, writeFileSync } from "node:fs";
const ndjson = readFileSync("evals/audit-ledger/anchored.v1.ndjson", "utf8");
const rows = ndjson.split("\n").filter(Boolean).map((l) => JSON.parse(l));
const anchor = rows.find((x) => x.type === "anchor");
const out = `// AUTO-GENERATED from evals/audit-ledger/anchored.v1.ndjson — do not hand-edit.
// A REAL ADR-062 anchored ledger vector (public Rekor v2 entry, logIndex ${anchor.rekor.log_index}) used
// ONLY by the E2E audit-fixture seam (lib/e2e-audit-fixture.ts), which is gated
// on the dev/test-only e2e auth bypass. Never reachable in a production build.
// Regenerate: node scripts/gen/audit-e2e-fixture.mjs
export const ANCHORED_NDJSON = ${JSON.stringify(ndjson)};
// The tenant TRUSTED Ed25519 anchor pubkey for ANCHORED_NDJSON (the out-of-band root).
export const TRUSTED_PUBKEY_B64 = ${JSON.stringify(anchor.ed25519.pubkey)};
`;
writeFileSync("apps/web/e2e/fixtures/audit-fixture-data.ts", out);
console.log("regenerated audit-fixture-data.ts");
