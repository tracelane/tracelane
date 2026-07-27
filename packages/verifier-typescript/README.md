# @tracelanedev/audit-verifier (TypeScript)

Reference TypeScript verifier for Tracelane tamper-evident audit ledgers.

Mirrors the Rust verifier (`packages/verifier-rust`) and the Python verifier
(`packages/verifier-python`). All three produce identical `VerifyReport` JSON
for the same input — conformance vectors live in `evals/audit-ledger/`.

## Install

```bash
pnpm -F @tracelanedev/audit-verifier install
```

## Usage

```typescript
import { verifyLedger } from "@tracelanedev/audit-verifier";

const report = await verifyLedger("audit.ndjson", { offline: true });
console.assert(report.hash_chain_valid, "ledger tampered");
```

## Test

```bash
pnpm -F @tracelanedev/audit-verifier test
```
