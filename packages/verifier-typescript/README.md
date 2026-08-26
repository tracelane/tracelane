<!-- tracelane:classification: PUBLIC -->
# @tracelanedev/audit-verifier (TypeScript)

Reference TypeScript verifier for Tracelane tamper-evident audit ledgers.

Mirrors the Rust verifier (`packages/verifier-rust`) and the Python verifier
(`packages/verifier-python`). All three agree verdict-for-verdict
on the same input — conformance vectors live in `evals/audit-ledger/`.

## Install

```bash
npm install @tracelanedev/audit-verifier
```

To work on it from a checkout instead:

```bash
pnpm -F @tracelanedev/audit-verifier install
```

## Usage

```typescript
import { verifyLedger } from "@tracelanedev/audit-verifier/node";

const report = await verifyLedger("audit.ndjson", { offline: true });
console.assert(report.hash_chain_valid, "ledger tampered");
```

## Test

```bash
pnpm -F @tracelanedev/audit-verifier test
```
