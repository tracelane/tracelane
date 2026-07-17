# Tracelane Reliability Benchmark v1.0

**URL:** https://tracelane.dev/benchmarks  
**Cadence:** Updated monthly  
**Last run:** Pending V1 launch

This page is the citation-grade public scoreboard for AI gateway and predictive
guardrail performance. Updated on the first Monday of each month.

> **No measured performance figures are published until the first V1.0 run (pending V1
> launch).** Numbers shown below are **internal CI targets**, not measured results;
> measured columns read `TBD` until the benchmark runs on identical hardware.

---

## Methodology

All benchmarks run on identical hardware (Hetzner CX52: 16 vCPU, 32 GB RAM, NVMe)
against mock LLM providers (no real API calls — latency is pure infrastructure cost).

Source: [`bench/arb-1/`](../bench/arb-1/) — ARB-1 (Agent Reliability Benchmark v1).
Full methodology: [`decisions/ADR-006-arb-1-methodology.md`](../decisions/ADR-006-arb-1-methodology.md).

---

## Gateway overhead (excl. provider time)

Measured as added latency from proxy hop, predictive layer inline.

| Gateway | p50 | p95 | p99 | Notes |
|---|---|---|---|---|
| **Tracelane v0.1.0** | TBD | TBD | TBD | Internal target <5/<15/<25ms; measured at V1 launch |
| LiteLLM v1.83.7 | TBD | TBD | TBD | Post-CVE hardened version |
| Helicone gateway | TBD | TBD | TBD | Maintenance mode — last public release |
| Portkey | TBD | TBD | TBD | |

---

## Predictive guardrail latency

Inline at gateway — includes all 10 predictors running sequentially. Figures below are
internal targets; measured results publish with the V1.0 run.

| Predictor set (internal target) | p50 | p95 | p99 |
|---|---|---|---|
| Tier 1 only (hash + taint + stuck-loop) | <5ms | <10ms | <15ms |
| Tier 1 + Tier 2 (prompt injection, A2A/A2UI validators) | <15ms | <25ms | <35ms |
| Full stack (all 10 predictors, SLM judge) | <30ms | <50ms | <100ms |

Budget: p99 < 100ms for full stack. Hard budget enforced by `benchmark-runner` subagent.

---

## Ingest throughput

Single-node sustained write rate to ClickHouse.

| Metric | Target | Measured |
|---|---|---|
| Spans/sec (single-node) | ≥50,000 | TBD |
| Spans/sec (3-node) | ≥200,000 | TBD |
| End-to-end latency p50 | <1s | TBD |
| End-to-end latency p99 | <5s | TBD |

---

## Jailbreak catch rate

Per framework, using the eval corpus in `ml/eval_corpus/`.

| Framework | Jailbreak catch rate | False positive rate |
|---|---|---|
| LangGraph (default) | TBD | TBD |
| CrewAI | TBD | TBD |
| Mastra | TBD | TBD |
| PydanticAI | TBD | TBD |
| OpenAI Agents SDK | TBD | TBD |

---

## Historical results

Results will be published here monthly starting at V1 launch.

---

*Benchmark source code: [`bench/arb-1/`](https://github.com/tracelane/tracelane/tree/main/bench/arb-1)*  
*Reproduce locally: `pnpm bench:gateway && pnpm bench:ingest && pnpm bench:predictive`*
