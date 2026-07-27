# Gateway Correctness Eval Index

Structural and integration tests for the Rust gateway layer.

| ID | File | Description | Status |
|---|---|---|---|
| GC-001 | GC-001.eval.ts | Anthropic SSE streaming correctness | 🟡 structural |
| GC-002 | GC-002.eval.ts | Provider registry — native + OpenAI-compatible providers | 🟡 structural |
| GC-003 | GC-003.eval.ts | Tenant isolation invariants | 🟡 structural |
| GC-004 | GC-004.eval.ts | OTLP span emission correctness | 🟡 structural |
| GC-005 | GC-005.eval.ts | Predictive layer — all 8 predictors registered | 🟡 structural |

**Status legend:** 🟢 green on main | 🟡 structural assertions pass, integration .skip | 🔴 not yet written

Integration tests (`.skip`) activate when live gateway infra is available (Week 8).
