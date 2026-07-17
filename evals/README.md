# evals

Tracelane's eval suite — the merge gate for all claims.

## Philosophy

Every marketing claim on tracelane.dev is backed by a runnable eval.
CI fails if any eval regresses. The website auto-disables claims whose
evals are red on `main`.

## Structure

```
evals/
├── pain-points/       # 50 pain-point assertions (PP-G1 to PP-PR12)
├── fault-tolerance/   # 8 chaos-style fault tolerance evals (FT-01 to FT-08)
├── gateway-correctness/  # Provider translation correctness across 30+ providers
├── ingest-schema/     # Schema evolution backwards compatibility
├── pii-redaction/     # PII recall tests (100% recall on synthetic patterns)
├── prompt-injection/  # Lethal-trifecta telemetry evals
├── src/harness.ts     # Shared eval harness (painPoint(), chaosEval())
├── FLAKY.md           # Registry of intermittently-failing evals
└── README.md          # This file
```

## Running evals

```bash
pnpm eval:run --suite=all          # Full suite (merge gate)
pnpm eval:run --suite=pain-points  # Pain-point evals only
pnpm eval:run --suite=fault-tolerance  # Chaos evals only
pnpm eval:run --filter=PP-G3       # Single eval by ID
```

## Eval status legend

- 🟢 Green on main — claim is live on website
- 🟡 Written, mock passes — eval exists, integration pending
- 🔴 Not yet written — claim not yet testable

## Week 9 targets

- All 50 pain-point evals: 🟢
- All 8 fault-tolerance evals: 🟢
- PII recall: 🟢 (100% recall on synthetic patterns)
- Gateway correctness: 🟢 (all 30+ providers)
