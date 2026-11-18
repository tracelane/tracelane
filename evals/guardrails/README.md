<!-- tracelane:classification: PUBLIC -->
# Local labelled guardrail evaluation

This synthetic, hand-labelled challenge set measures the existing R1–R7 Rust cores. It does not call a provider or a model, use production data, or measure competitors. The corpus commits explicit labels and rationales for review. Published example identifiers, telephone text and test card numbers are synthetic fixture inputs; they are not evidence about real people or accounts.

Run from the repository root:

```sh
CARGO_BUILD_JOBS=4 cargo test --locked -p gateway --bin gateway guardrail::labelled_eval -- --nocapture --test-threads=1
```

Each `GUARDRAIL_EVAL` line is JSON with the corpus BLAKE3, case predictions and per-profile counts. Record the source commit, date and command with captured output. A passing evaluator means the cases ran and accounting checks passed; it does **not** mean the detector made no mistakes.

## Labels and interpretation

`positive: true` means a risk/format violation is present under the case's stated task and rationale. `false` is a benign control. Warn, Redact and Block count as detected; Allow, NotApplicable and FailOpen do not. Report TP/FP/TN/FN, FPR=FP/(FP+TN), FNR=FN/(FN+TP), and inactive/fail-open counts separately. Undefined denominators are JSON null. Inactive positive cases remain false negatives rather than disappearing from the denominator.

Some labelled challenges intentionally exceed a documented detector subset: names/addresses beyond structured PII, nested/enum/minimum schema constraints, punctuation/paraphrased prompt disclosures, and semantic topic paraphrases. These measure task coverage limits, not necessarily implementation defects. Do not claim a broad security recall rate from this small synthetic set. No representative prevalence, random sampling, multilingual benchmark or independent human adjudication is claimed. Fixtures are visible to developers; this is not a held-out training benchmark.

## Fixture configuration and production boundaries

- `request` is decoded into the real ChatRequest and GuardrailContext. R1 `input_tokens` supplies a measured-count surrogate rather than running a tokenizer. `repeat_calls` expands the single declared tool-call template with unique IDs; `vary_calls` varies arguments. Session-call cases explicitly supply state unavailable from production's fresh-session constructor. R1 response cases supply usage.
- R2 runs the shared detector through its request, response and relay-egress carrier seams. The response is a complete buffer, not an SSE transport test. The default PII class policy is used.
- R3 `schema` uses the schema/injection rail. `pinning_approved` registers the original tool definition then optionally mutates its description; `pinning_unconfigured` intentionally has no baseline. Pinning uses its observe default and does not read deployment environment switches.
- R4 profiles distinguish configured versus empty registries, with explicitly supplied session taint. Configured tools: `send` can exfiltrate; `local` has no dangerous capabilities; unknown tools use the real conservative fallback. These are core-state fixtures, not evidence of a live session accumulator.
- R5 declares JSON and optional schemas directly; R6 uses the fixture system prompt and complete response with the current default minimum-token threshold.
- R7 `default` is the production empty-list configuration. `configured` uses the existing test-only constructor with denied phrase `restricted fixture topic` and competitor `AcmeFixture`. A configured-core result is not proof that tenants can configure production R7.
- Direct core calls deliberately bypass dispatcher policy and entitlement resolution. Existing tenant/absent-cache/streaming integration tests remain required separately. No paid feature is enabled by this test module.

## Reproduction and change control

`cases.json` has one JSON case per line for review. Preserve labels when addressing findings. Any future label correction needs an explicit rationale and a newly versioned result, not silent replacement of the old measurement. Corpus hash links predictions to exact fixture bytes. A panic or malformed corpus fails the test run; never publish a truncated run as complete.

`baseline-2026-11-15.json` records the measured run. `initial-profile-review-2026-11-15.json` preserves the earlier recorded run before R2 profiles were grouped by carrier. Case labels and detector outcomes did not change between those runs.
