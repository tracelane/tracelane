//! `EVL-05` — the `eval_runs` writer, and the one execution engine behind it.
//!
//! ## Why this module exists
//!
//! `ClickHouseEvalGate` has read `tracelane.eval_runs` since ADR-009 and **nothing
//! has ever written it**. On prod that shows up as `eval_runs = 0 rows` against 5
//! `promotion_decisions` rows, every one `manual_override` with `eval_run_id`
//! NULL: the honest promotion path has never once completed in production, and
//! the only way through has been a recorded bypass.
//!
//! ## One engine, not three
//!
//! The founder's Sprint 2 asks for a playground, promotion, and this writer;
//! Sprint 3 then asks for datasets, experiments, judges and online evals. Those
//! are **one execution engine with different fan-outs**, and building them as one
//! is the difference between four sprints and twelve:
//!
//! ```text
//!    1 case, live      ┌──────────────────────────┐──► EVL-03 Playground
//!    N cases + asserts │  execute_case()          │──► EVL-05 eval run  ← THIS
//!    N cases × 2 vers  └──────────────────────────┘──► EVL-02 Experiments (S3)
//! ```
//!
//! ## The four reliability properties, and what each costs if dropped
//!
//! 1. **It spends real money.** One run per `(tenant, prompt)`; a second start is
//!    a `409` naming the running id, so a client retry cannot double-spend.
//! 2. **It gates a production routing change.** The status vocabulary is EXACTLY
//!    the four strings `ClickHouseEvalGate::status` maps. A fifth string makes the
//!    gate return `None`, which blocks promotion — silently and permanently.
//!    [`EvalStatus`] is the only thing that can write the column, so a fifth
//!    string is unrepresentable rather than merely discouraged.
//! 3. **A crashed run must not be invisible OR permanent.** The gate treats
//!    `running` as blocked, so an orphaned `running` row is a promotion wedged
//!    shut forever. Two layers, because they fail differently: [`RunGuard`] writes
//!    a terminal status on panic or early return, and [`PromptEvalEngine::reconcile_stale_runs`]
//!    sweeps rows left `running` past the wall-clock cap at boot. **The second
//!    layer exists because `prev_production` shipped without its boot rebuild and
//!    silently disarmed auto-rollback after every deploy** — the same shape, in
//!    the same feature, fixed the same day this was written.
//! 4. **A provider failure is not a bad prompt.** An upstream error makes a case
//!    `errored`, never `failed`, and the pass rate excludes errors from its
//!    denominator. Otherwise an upstream outage reads as a quality regression and
//!    someone reverts a good prompt.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result, bail};
use clickhouse::Client as ClickhouseClient;
use futures::StreamExt as _;
use serde::{Deserialize, Serialize};
use tracelane_shared::{ChatRequest, Message, MessageContent, Role, TenantId};
use uuid::Uuid;

use crate::prompt_router::PromptRouter;
use crate::providers::{ProviderEvent, ProviderRegistry};

/// Hard ceilings. Every one is refused with a typed error naming the limit.
pub mod limits {
    /// Cases per run. An eval run is N real provider calls; this is the ceiling
    /// on what one request can spend.
    pub const MAX_CASES: usize = 200;
    /// Concurrent provider calls within a run — bounded so a run cannot become
    /// its own load test against the tenant's provider quota.
    pub const CASE_CONCURRENCY: usize = 4;
    /// Per-case wall clock. That case is `errored`; the run continues.
    pub const CASE_TIMEOUT_SECS: u64 = 60;
    /// Whole-run wall clock. Past this the run is `errored` with partial results
    /// kept — and this is the same number `reconcile_stale_runs` uses to decide a
    /// row was orphaned, so the two cannot disagree.
    pub const RUN_TIMEOUT_SECS: u64 = 30 * 60;
    /// `results_json` ceiling. Per-case output is truncated with a marker IN the
    /// JSON, never silently.
    pub const RESULTS_JSON_BYTES: usize = 1024 * 1024;
    /// Per-case captured output before truncation.
    pub const CASE_OUTPUT_BYTES: usize = 8 * 1024;
}

/// The status column, and the ONLY thing that may write it.
///
/// `ClickHouseEvalGate::status` maps exactly four strings and returns `None` for
/// anything else — and `None` means `BlockedByEval`. So an unrecognised status is
/// not a cosmetic bug: it is a promotion blocked forever with no error anywhere.
/// Making the vocabulary an enum means a fifth string cannot be written by
/// accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalStatus {
    Running,
    Passed,
    Failed,
    Errored,
}

impl EvalStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Errored => "errored",
        }
    }
}

/// `EVL-23` (Sprint 3 item 10) — LLM-as-judge: the rubrics, the response
/// contract, and the two-stage validator that makes the contract binding.
///
/// ## Why this is a submodule and not a second engine
///
/// A judge is **a rule in the scorer that happens to make a provider call**. It
/// reuses [`PromptEvalEngine::execute_case`] verbatim, so it inherits BYOK key
/// resolution, SSRF-guarded dispatch, pricing and span emission with no second
/// code path. The one thing it does NOT inherit is trust in the answer.
///
/// ## `CLAUDE.md` §21 binds this module directly, not by analogy
///
/// The judge's score gates a promotion, so the judge is a **decider**: its
/// output is untrusted input that must be validated against a declared schema —
/// *types AND ranges* — and refused loudly on non-conformance. §21 named the
/// live violation this replaces: `Assertion::JsonValid` decided pass/fail from
/// `serde_json::from_str(..).is_ok()`, i.e. parseability alone.
///
/// **Two stages, because the reuse only covers one of them.**
/// [`crate::predictive::tool_schema_validator::validate_call`] implements exactly
/// `required`, per-property `type` and `additionalProperties:false` — there is no
/// `enum`, no `minimum`, no `maximum` and no `maxLength` anywhere in that file
/// (verified by grep, 2026-08-24). So structure is reused and **range is written
/// here**; treating the reuse as sufficient would satisfy the letter of §21 and
/// miss its point, since `{"score": 1.7}` is structurally perfect.
pub mod judge {
    use serde::{Deserialize, Serialize};

    /// Max `reason` length. A longer one is NON-CONFORMANCE, never a truncation:
    /// a judge that ignores its output contract has not been understood, and
    /// silently cutting its prose would hide that. It is also what keeps
    /// [`super::limits::RESULTS_JSON_BYTES`] off the critical path.
    pub const MAX_REASON_CHARS: usize = 2000;

    /// At most ONE judge assertion per run. **This is the only cap that bounds
    /// the spend multiplier**: with N judges a run costs `cases × (1 + N)`
    /// provider calls, and the customer discovers that on their provider bill.
    pub const MAX_JUDGES_PER_RUN: usize = 1;

    /// The output contract, appended to EVERY rubric — built-in or tenant-authored.
    ///
    /// **A rubric never supplies its own output contract.** The contract belongs
    /// to the validator; letting a custom rubric state it would let a tenant
    /// weaken the thing that makes the score interpretable.
    pub const OUTPUT_CONTRACT: &str = "\n\n\
---\n\
Respond with a single JSON object and nothing else. No prose before or after it, \
no markdown fence.\n\
\n\
{\"score\": <number 0.0 to 1.0>, \"verdict\": \"pass\" or \"fail\", \"reason\": \"<one or two sentences>\"}\n\
\n\
`score` must be a number between 0.0 and 1.0 inclusive. `verdict` must be exactly \
\"pass\" or \"fail\", lowercase. `reason` must be between 1 and 2000 characters. \
Include no other keys.";

    const ANSWERS_THE_QUESTION: &str = "You are grading whether a response answers the question it was asked.\n\
\n\
Read the user's message and the assistant's response. Score how directly and \
completely the response addresses what was actually asked.\n\
\n\
1.0 — answers the question fully and directly.\n\
0.5 — partially answers it, or answers a narrower or adjacent question.\n\
0.0 — does not answer it: it restates the question, refuses without cause, \
changes the subject, or answers something else.\n\
\n\
Grade only whether the question was ANSWERED. Do not grade style, tone, length, \
or whether you agree with the answer.";

    const GROUNDEDNESS: &str = "You are grading whether a response is grounded in the material it was given.\n\
\n\
Read the user's message (including any context or documents in it) and the \
assistant's response. Score the proportion of the response's factual claims that \
are supported by that material.\n\
\n\
1.0 — every factual claim is supported by the provided material.\n\
0.5 — the main claims are supported but some details are not, or the response \
generalises beyond what the material states.\n\
0.0 — the response asserts facts the material does not support.\n\
\n\
A claim you cannot check against the provided material is UNSUPPORTED. Do not use \
your own knowledge to supply support the material does not give. Opinions, \
hedges and questions are not factual claims and are not graded.";

    const INSTRUCTION_FOLLOWING: &str = "You are grading whether a response obeys the constraints it was given.\n\
\n\
Read the system instruction and the assistant's response. Identify every explicit \
constraint the instruction states — format, length, language, what to include, \
what to avoid, what persona to hold — and score the proportion the response obeys.\n\
\n\
1.0 — every stated constraint is obeyed.\n\
0.5 — the response obeys the main constraints and violates a minor one.\n\
0.0 — the response violates a constraint the instruction states explicitly.\n\
\n\
Grade only against constraints the instruction ACTUALLY STATES. Do not invent a \
constraint you think ought to have been there, and do not grade correctness — a \
wrong answer in the required format obeys its instructions.";

    /// The three built-ins, by wire name.
    ///
    /// **All three are reference-FREE, and that is the sequencing constraint, not
    /// a preference.** Production capture records INPUT ONLY, so a trace-derived
    /// dataset item has no `expected_output` — a reference-based scorer over one
    /// would score nothing. These three need input + output and nothing else.
    #[must_use]
    pub fn built_in(name: &str) -> Option<&'static str> {
        match name {
            "answers_the_question" => Some(ANSWERS_THE_QUESTION),
            "groundedness" => Some(GROUNDEDNESS),
            "instruction_following" => Some(INSTRUCTION_FOLLOWING),
            _ => None,
        }
    }

    /// Every built-in name, for the error message that names them.
    pub const BUILT_IN_NAMES: [&str; 3] = [
        "answers_the_question",
        "groundedness",
        "instruction_following",
    ];

    /// `JUDGE_RESPONSE_SCHEMA_V1`. Built rather than parsed so a typo is a
    /// compile error instead of a runtime one.
    ///
    /// Only the three keys the validator can actually enforce appear here; the
    /// RANGES live in [`validate`], because the reused validator has no keyword
    /// for them and a schema carrying `minimum` would read as though something
    /// checked it.
    #[must_use]
    pub fn response_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "score":   { "type": "number" },
                "verdict": { "type": "string" },
                "reason":  { "type": "string" },
            },
            "required": ["score", "verdict", "reason"],
            "additionalProperties": false,
        })
    }

    /// A conforming judge response.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct JudgeVerdict {
        pub score: f64,
        pub verdict: String,
        pub reason: String,
    }

    /// Strip at most ONE leading/trailing markdown fence pair.
    ///
    /// **This is the whole extraction budget, deliberately.** There is no regex
    /// scavenge for the first `{…}` in prose: guessing which brace was the answer
    /// is exactly the "gate that guesses at an uninterpretable result" §21
    /// forbids, and a fabricated pass is the worst thing an evidence product can
    /// emit. A model that will not emit JSON has not been understood.
    fn strip_one_fence(s: &str) -> &str {
        let s = s.trim();
        let Some(rest) = s.strip_prefix("```") else {
            return s;
        };
        // ```json / ```JSON / ``` — drop the language tag, which is the rest of
        // that first line.
        let rest = rest.split_once('\n').map_or("", |(_, tail)| tail);
        rest.trim_end().strip_suffix("```").unwrap_or(rest).trim()
    }

    /// Parse and validate a raw judge response. **Fail CLOSED.**
    ///
    /// # Errors
    /// Any non-conformance, with a message naming the field and the offending
    /// value — the case becomes `errored`, never `failed`. An uninterpretable
    /// judge response is not a bad prompt, and reporting it as one would send
    /// someone to debug the wrong thing.
    pub fn validate(raw: &str) -> std::result::Result<JudgeVerdict, String> {
        let candidate = strip_one_fence(raw);
        if candidate.is_empty() {
            return Err("judge response did not conform: the response was empty".into());
        }
        let parsed: serde_json::Value = serde_json::from_str(candidate).map_err(|e| {
            format!(
                "judge response did not conform: could not parse a JSON object ({e}); \
                 the response began {:?}",
                candidate.chars().take(80).collect::<String>()
            )
        })?;

        // ── Stage 1 — STRUCTURAL, reused rather than re-derived. ────────────
        let violations = crate::predictive::tool_schema_validator::validate_call(
            "judge_response",
            &response_schema(),
            &parsed,
        );
        if !violations.is_empty() {
            return Err(format!(
                "judge response did not conform: {}",
                violations
                    .iter()
                    .map(|v| format!("{v:?}"))
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }

        // ── Stage 2 — RANGE AND DOMAIN, and it is NOT free with the reuse. ──
        //
        // `validate_call` checks JSON TYPE TOKENS only. `{"score": 1.7}` passes
        // stage 1 perfectly: 1.7 IS a number. §21 says "types and ranges, not
        // merely did the parse succeed", so this half is mandatory.
        let score = parsed
            .get("score")
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(|| {
                // Reachable: JSON allows a number too large for f64.
                "judge response did not conform: `score` is not a representable number".to_string()
            })?;
        if !score.is_finite() || !(0.0..=1.0).contains(&score) {
            return Err(format!(
                "judge response did not conform: `score` {score} is outside 0.0–1.0"
            ));
        }
        let verdict = parsed
            .get("verdict")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if verdict != "pass" && verdict != "fail" {
            return Err(format!(
                "judge response did not conform: `verdict` {verdict:?} is not \"pass\" or \"fail\""
            ));
        }
        let reason = parsed
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let reason_chars = reason.chars().count();
        if reason_chars == 0 || reason_chars > MAX_REASON_CHARS {
            return Err(format!(
                "judge response did not conform: `reason` is {reason_chars} chars (allowed 1–{MAX_REASON_CHARS})"
            ));
        }

        Ok(JudgeVerdict {
            score,
            verdict: verdict.to_string(),
            reason: reason.to_string(),
        })
    }
}

/// Which rubric the judge grades against.
///
/// **A tenant's own rubric is a MANAGED PROMPT VERSION, not a file in this
/// repo.** `EVL-19`'s literal wording asked for templates in `evals/judges/`;
/// that directory does not exist and would be the wrong home if it did — a repo
/// path has no per-tenant versioning and ships in the public export. Reusing the
/// prompt store gives tenant isolation, version history and promotion for free,
/// with zero new storage, and the ownership check is the SAME
/// `version_for_tenant` call `prepare_run` already makes on the prompt under
/// test: a version id from a request body is not evidence the caller owns it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum JudgeRubric {
    /// One of [`judge::BUILT_IN_NAMES`], versioned with the gateway binary.
    BuiltIn { name: String },
    /// The tenant's OWN rubric, as a managed prompt version.
    PromptVersion {
        #[serde(with = "uuid::serde::simple")]
        prompt_version_id: Uuid,
    },
}

impl JudgeRubric {
    /// Short label for `results_json`, so a reader can tell which rubric scored.
    fn label(&self) -> String {
        match self {
            Self::BuiltIn { name } => name.clone(),
            Self::PromptVersion { prompt_version_id } => {
                format!("prompt_version:{prompt_version_id}")
            }
        }
    }
}

/// What one judge call produced, recorded beside the assertion it scored.
///
/// **Serialized into `AssertionResult`, which lands in the `results_json String`
/// column** — so this is additive with no migration, and every `results_json`
/// already on disk still deserializes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JudgeDetail {
    /// The judge's own number, `0.0..=1.0`, range-checked before it got here.
    pub score: f64,
    /// The judge's own word, recorded **ADVISORY ONLY**.
    ///
    /// When `verdict == "pass"` but `score < min_score`, **`score` wins**. One
    /// field decides and it is the numeric one, because `min_score` is the
    /// author's declared threshold and a model's English adjective is not.
    /// Erroring on the disagreement instead would make every run hostage to a
    /// model's word choice.
    pub verdict: String,
    /// The judge's prose. **Never parsed by anything** — displayed only.
    pub reason: String,
    /// The model that judged, recorded because a score is not comparable across
    /// judge models and a reader must be able to see which one produced it.
    pub model: String,
    /// Which rubric graded, for the same reason.
    pub rubric: String,
    /// The JUDGE call's own cost, kept SEPARATE from the case's `cost_usd` so the
    /// judge's price is visible rather than folded into what it measured. `None`
    /// renders as "unpriced", never `$0.00`.
    pub cost_usd: Option<f64>,
    /// Wall clock of the judge provider call only.
    pub latency_ms: u64,
}

/// An assertion over one case's output.
///
/// **Item 10 (`EVL-23`) added the judge and three code evaluators, and DELETED
/// `JsonValid`.** `json_valid` decided pass/fail from
/// `serde_json::from_str(..).is_ok()` — parseability alone — which `CLAUDE.md`
/// §21 names as the repo's live violation of *"a consumer of LLM output that
/// makes a decision enforces a schema and fails closed"*. It is REMOVED rather
/// than deprecated beside its replacement: leaving it in the vocabulary leaves a
/// way to drive the promotion gate from parseability, sitting next to its own
/// fix, and the graduation ladder (§12) calls that debt. Parseability-only stays
/// expressible honestly as `{"kind":"json_schema","schema":{}}` — the author now
/// has to WRITE the empty schema.
///
/// **Reference-FREE vs reference-BASED, and the ordering is not a preference.**
/// Production capture records INPUT ONLY (`server.rs` publishes the span before
/// the response-side guardrail seam so a blocked request still produces one), so
/// a trace-derived dataset item has no `expected`. `LlmJudge`, `JsonSchema`,
/// `Regex`, `LengthBounds`, `Contains`, `NotContains`, `MaxLatencyMs` and
/// `MaxCostUsd` score such an item; `ExactMatch` cannot, and says so with a typed
/// error rather than scoring an absent reference as an empty string.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Assertion {
    Contains {
        value: String,
    },
    NotContains {
        value: String,
    },
    Regex {
        value: String,
    },
    MaxLatencyMs {
        value: u64,
    },
    MaxCostUsd {
        value: f64,
    },
    /// **Replaces `JsonValid`** — `CLAUDE.md` §21's prescribed fix, reusing
    /// `predictive::tool_schema_validator::validate_call`, which is what R5
    /// already uses. `{}` accepts anything that parses, deliberately.
    JsonSchema {
        schema: serde_json::Value,
    },
    /// Reference-free length bounds, in CHARACTERS not bytes — a byte bound on
    /// multi-byte output measures the encoding, not the answer.
    LengthBounds {
        #[serde(default)]
        min_chars: Option<usize>,
        #[serde(default)]
        max_chars: Option<usize>,
    },
    /// Reference-BASED exact match. `value` is the inline reference; omit it to
    /// use the case's own `expected`, which is what a dataset item carries.
    ExactMatch {
        #[serde(default)]
        value: Option<String>,
        /// Compare with surrounding whitespace trimmed. Defaults to `true` —
        /// a trailing newline from a provider is not a wrong answer.
        #[serde(default = "default_true")]
        trim: bool,
    },
    /// **THE ROW.** An LLM grades the output against a rubric and returns a
    /// schema-validated `{score, verdict, reason}`; the case passes this rule iff
    /// `score >= min_score`.
    LlmJudge {
        rubric: JudgeRubric,
        /// The judging model. Defaults to the model under test — which is
        /// usually NOT what you want, and is why it is settable.
        #[serde(default)]
        model: Option<String>,
        min_score: f64,
    },
}

const fn default_true() -> bool {
    true
}

impl Assertion {
    /// Human label used in `results_json`, so a failure says which rule failed.
    ///
    /// **It is also the SCORER KEY** in `CaseResult::scores`, so two assertions
    /// with the same label are one scorer asked twice.
    fn label(&self) -> String {
        match self {
            Self::Contains { value } => format!("contains({value:?})"),
            Self::NotContains { value } => format!("not_contains({value:?})"),
            Self::Regex { value } => format!("regex({value:?})"),
            Self::MaxLatencyMs { value } => format!("max_latency_ms({value})"),
            Self::MaxCostUsd { value } => format!("max_cost_usd({value})"),
            Self::JsonSchema { .. } => "json_schema".into(),
            Self::LengthBounds {
                min_chars,
                max_chars,
            } => format!(
                "length_bounds({}..{})",
                min_chars.map(|n| n.to_string()).unwrap_or_default(),
                max_chars.map(|n| n.to_string()).unwrap_or_default(),
            ),
            Self::ExactMatch { value, .. } => match value {
                Some(v) => format!("exact_match({v:?})"),
                None => "exact_match(expected)".into(),
            },
            Self::LlmJudge {
                rubric, min_score, ..
            } => format!("llm_judge({}, >={min_score:.2})", rubric.label()),
        }
    }

    /// Is this the judge? Used to bound the spend multiplier at `start_run`,
    /// before a cent is spent.
    pub(crate) const fn is_judge(&self) -> bool {
        matches!(self, Self::LlmJudge { .. })
    }

    /// Evaluate against one case outcome.
    ///
    /// `judged` is this assertion's judge result when it IS a judge — computed
    /// upstream in `execute_run`, because a provider call cannot happen in a
    /// synchronous scorer. **Keeping `score` synchronous is deliberate**: it is
    /// the pure function every scoring test drives, and making it async to
    /// accommodate one variant would put the whole scoring contract behind a
    /// runtime.
    ///
    /// # Errors
    /// A malformed `Regex`, a non-conforming judge response, or a reference-based
    /// rule with no reference. All three are the AUTHOR's or the JUDGE's problem,
    /// not the prompt's, so they are ERRORS — reporting them as "the prompt
    /// failed" would send someone to debug the wrong thing.
    fn evaluate(
        &self,
        case: &EvalCase,
        out: &CaseOutcome,
        judged: Option<&std::result::Result<JudgeDetail, String>>,
    ) -> Result<bool> {
        Ok(match self {
            Self::Contains { value } => out.output.contains(value.as_str()),
            Self::NotContains { value } => !out.output.contains(value.as_str()),
            Self::Regex { value } => regex::Regex::new(value)
                .with_context(|| format!("assertion regex {value:?} does not compile"))?
                .is_match(&out.output),
            Self::MaxLatencyMs { value } => out.latency_ms <= *value,
            // An UNPRICED model must not silently satisfy a cost ceiling. `None`
            // means "we could not measure", which is not "it was cheap".
            Self::MaxCostUsd { value } => match out.cost_usd {
                Some(c) => c <= *value,
                None => false,
            },
            // Conformance, not parseability. A schema that declares nothing
            // accepts anything that parses — the honest replacement for the
            // deleted `json_valid`, and the author had to write it.
            Self::JsonSchema { schema } => {
                let parsed: serde_json::Value = serde_json::from_str(out.output.trim())
                    .context("assertion json_schema: the output is not JSON")?;
                crate::predictive::tool_schema_validator::validate_call(
                    "json_schema",
                    schema,
                    &parsed,
                )
                .is_empty()
            }
            // CHARACTERS, not bytes.
            Self::LengthBounds {
                min_chars,
                max_chars,
            } => {
                let n = out.output.chars().count();
                min_chars.is_none_or(|lo| n >= lo) && max_chars.is_none_or(|hi| n <= hi)
            }
            Self::ExactMatch { value, trim } => {
                // The inline reference wins; otherwise the case's own `expected`,
                // which is what item 8's dataset items carry. A JSON string
                // reference compares as its CONTENT, not as `"quoted"`.
                let reference = match value {
                    Some(v) => v.clone(),
                    None => match case.expected.as_ref() {
                        Some(serde_json::Value::String(s)) => s.clone(),
                        Some(v) => v.to_string(),
                        // NEVER an empty-string reference. An absent reference is
                        // UNKNOWN, and a rule that cannot be evaluated is an
                        // error, not a failure — scoring it as a miss would
                        // manufacture a regression nobody measured.
                        None => bail!(
                            "assertion exact_match has no reference: this case carries no \
                             `expected`, so pass `value` inline or use a dataset item that \
                             has one"
                        ),
                    },
                };
                if *trim {
                    out.output.trim() == reference.trim()
                } else {
                    out.output == reference
                }
            }
            Self::LlmJudge { min_score, .. } => match judged {
                Some(Ok(d)) => d.score >= *min_score,
                // The validator already named the field and the value.
                Some(Err(e)) => bail!("{e}"),
                // Unreachable: `execute_run` produces one slot per assertion.
                // Stated as an error rather than a silent `false`, because a
                // missing judge result read as "did not pass" is a fabricated
                // verdict — the exact class §21 exists to stop.
                None => {
                    bail!("assertion llm_judge produced no result — the judge was never called")
                }
            },
        })
    }
}

/// One input case.
///
/// **A dataset item and an inline case are the SAME SHAPE** — `EVL-04` §2.1,
/// deliberately, so the engine gains a reproducible case source without gaining
/// a second definition of "a case". `expected` and `metadata` arrived with
/// [`CaseSource::Dataset`]; both are `#[serde(default)]` because the alternative
/// is that every inline caller written before them breaks, and every
/// `results_json` already on disk stops deserializing — a run whose own record
/// has become unreadable is the opposite of an audit product.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalCase {
    pub name: String,
    pub messages: Vec<Message>,
    /// The reference answer, when the item has one.
    ///
    /// **`None` is the normal state on prod**, and that is a measured fact rather
    /// than an oversight: a trace-derived item always has `expected_output = NULL`
    /// because the capture path records input only (`server.rs:3466-3479` says why
    /// — the span is published before the response-side guardrail seam). So
    /// reference-based scoring is *unavailable* for such an item and must say so,
    /// never score an absent reference as an empty string that passes nothing and
    /// fails nothing.
    ///
    /// Nothing in this module consumes it yet — reference-based assertions are
    /// Sprint 3 item 10, which `EVL-04` §6 puts out of scope. It is carried now so
    /// the reference survives the trip from the frozen snapshot into the run
    /// instead of being dropped silently at the boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<serde_json::Value>,
    /// Item labels, carried through untouched. Written by whoever created the
    /// item (the one-click trace conversion, a CSV import, an inline caller); this
    /// module never reads or interprets it, so a customer-chosen key can never
    /// collide with something the engine means.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Where the cases come from.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum CaseSource {
    /// Caller-supplied. Always available.
    Inline { items: Vec<EvalCase> },
    /// Resolved from the tenant's recorded production traces.
    ///
    /// **Returns a typed error, never an empty list, when the workspace records
    /// no prompt content.** Prod carries `gen_ai_input_messages` on 0 of 9,433
    /// spans because `TRACELANE_TRACE_CONTENT` is off by default for privacy
    /// (`shared/src/span.rs:104-106`). "No traces matched your filter" and "this
    /// workspace does not record prompt content" are different facts; rendering
    /// them identically is the zero-vs-unknown failure.
    Traces {
        #[serde(default)]
        since_hours: Option<u32>,
        #[serde(default)]
        model: Option<String>,
        #[serde(default)]
        limit: Option<u32>,
    },
    /// A FROZEN dataset snapshot — the only reproducible case source there is.
    ///
    /// `Inline` means the caller re-types the cases on every run and `Traces`
    /// reads a window that slides, so neither can promise run A and run B saw the
    /// same inputs — and a comparison whose inputs moved means nothing. A
    /// snapshot is a plain `MergeTree` copy of the items (`EVL-04` §2.4):
    /// immutable **by ENGINE, not by convention**, so nothing in the codebase can
    /// rewrite it under a run without a mutation nobody writes.
    ///
    /// **Resolution reads `dataset_snapshot_items`, NEVER `dataset_items`.** The
    /// mutable table is a `ReplacingMergeTree`; a later write for the same
    /// `item_id` replaces the row a run thought it had read, and nothing errors.
    /// That is the same argument that makes a dataset item copy the span's
    /// content rather than reference it, applied one level up.
    ///
    /// **An omitted `snapshot_id` means "take the dataset's newest snapshot, and
    /// write down which one you took"** — the resolved id goes into the run's own
    /// `results_json` (`dataset_snapshot_id`). Resolving "latest" without
    /// recording the answer would hand back exactly the moving target this
    /// variant exists to replace.
    Dataset {
        dataset_id: Uuid,
        #[serde(default)]
        snapshot_id: Option<Uuid>,
    },
}

/// Why a [`CaseSource::Dataset`] yielded no cases — **one variant per FACT**.
///
/// `Traces` set this discipline first: it returns a typed refusal rather than an
/// empty list when the workspace records no content, because "nothing matched
/// your filter" and "nothing is recorded at all" are different facts with
/// different remedies, and rendering them identically is the zero-vs-unknown
/// failure this repo has paid for repeatedly. A dataset has four such facts, and
/// the remedies really are four different actions — check the dataset id, check
/// the snapshot id, freeze a snapshot, add items and freeze again. Collapse any
/// pair and someone spends an afternoon fixing the wrong thing.
///
/// **Typed rather than a bare message, so the route layer can map it.** Each one
/// reaches `prompt_routes.rs` inside the `anyhow::Error` from
/// [`PromptEvalEngine::start_run`]; `err.downcast_ref::<DatasetCaseError>()`
/// recovers it and [`Self::http_status`] is the mapping. Without that downcast
/// the handler's default is `400`, and an unknown dataset has to be a **404** —
/// never a 500, and never an empty case list.
///
/// **`UnknownDataset` is deliberately one answer for three situations** — never
/// existed, tombstoned, belongs to another workspace. Naming which of the three
/// it was would confirm to a stranger that the id exists somewhere, which is the
/// discipline already written down for the trace-compare route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DatasetCaseError {
    #[error(
        "dataset {dataset_id} does not exist in this workspace. Check the id, or create the \
         dataset first — a dataset belonging to another workspace reads exactly the same way \
         here, on purpose."
    )]
    UnknownDataset { dataset_id: Uuid },
    #[error(
        "snapshot {snapshot_id} is not a snapshot of dataset {dataset_id}. List the dataset's \
         snapshots, or omit `snapshot_id` to take the newest one."
    )]
    UnknownSnapshot { dataset_id: Uuid, snapshot_id: Uuid },
    #[error(
        "dataset {dataset_id} has never been frozen, so there is no immutable item set to run. \
         Freeze a snapshot first — a run against the live item list could not be reproduced, \
         which is the only reason to run one."
    )]
    NeverFrozen { dataset_id: Uuid },
    #[error(
        "snapshot {snapshot_id} of dataset {dataset_id} holds no items, so there is nothing to \
         run. Add items to the dataset and freeze a new snapshot — a frozen snapshot is never \
         amended in place."
    )]
    EmptySnapshot { dataset_id: Uuid, snapshot_id: Uuid },
}

impl DatasetCaseError {
    /// Stable slug for the response body and for the dashboard's error state,
    /// which renders the gateway's code verbatim so the user has something to act
    /// on. Stable means: changing one of these is a customer-visible break.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::UnknownDataset { .. } => "dataset_not_found",
            Self::UnknownSnapshot { .. } => "snapshot_not_found",
            Self::NeverFrozen { .. } => "dataset_never_frozen",
            Self::EmptySnapshot { .. } => "snapshot_empty",
        }
    }

    /// The status the route layer must return.
    ///
    /// `404` for the two "that id is not yours" facts. `422` for the two "the
    /// request is well-formed but the workspace is not in a state that can serve
    /// it" facts — the same code `EVL-04` §4 gives the sibling content-capture
    /// refusals, which are the same shape: nothing is malformed, the data simply
    /// is not there yet.
    #[must_use]
    pub fn http_status(self) -> u16 {
        match self {
            Self::UnknownDataset { .. } | Self::UnknownSnapshot { .. } => 404,
            Self::NeverFrozen { .. } | Self::EmptySnapshot { .. } => 422,
        }
    }
}

/// The facts one dataset resolution gathered, held apart from the queries that
/// gathered them.
///
/// **The split is the only reason the refusals are TESTED rather than asserted.**
/// A refusal that can be observed only against a live ClickHouse is a refusal
/// nobody has ever watched fire, and `CLAUDE.md` §1 is explicit that a control
/// never observed blocking is not a guard. [`Self::verdict`] is pure, so
/// `cargo test` watches each one block, and watches the happy path NOT block —
/// a probe that refuses unconditionally would pass a refusal test by
/// construction while telling you nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DatasetProbe {
    dataset_id: Uuid,
    /// Is there a LIVE (non-tombstoned) dataset with this id for the caller's
    /// tenant? Read under the validated claim, so `false` covers "never existed",
    /// "deleted" and "someone else's" — one answer, deliberately (see
    /// [`DatasetCaseError`]).
    dataset_exists: bool,
    /// The snapshot the CALLER named, if any. Keeping this apart from
    /// `snapshot_resolved` is the whole mechanism that separates "you named a
    /// snapshot that is not here" from "this dataset has never been frozen" —
    /// two zero-row queries, two different things to do about it.
    snapshot_named: Option<Uuid>,
    /// What the resolution settled on: the named snapshot when it belongs to this
    /// dataset, otherwise the newest one frozen.
    snapshot_resolved: Option<Uuid>,
    /// Rows actually read out of `dataset_snapshot_items`.
    items_read: usize,
}

impl DatasetProbe {
    /// Turn the gathered facts into the one refusal that fits, or into the
    /// snapshot id the run will cite.
    ///
    /// # Errors
    /// One per fact — see [`DatasetCaseError`]. Fail-CLOSED in the sense that
    /// matters here: every path that produced no cases produces a *reason*, and
    /// none of them can return an empty case list.
    fn verdict(self) -> std::result::Result<Uuid, DatasetCaseError> {
        // Order is load-bearing. An unknown dataset must be reported BEFORE
        // anything about its snapshots: "this dataset has no snapshots" confirms
        // the dataset exists, which is precisely what a 404 for a foreign id is
        // meant not to reveal.
        if !self.dataset_exists {
            return Err(DatasetCaseError::UnknownDataset {
                dataset_id: self.dataset_id,
            });
        }
        let Some(snapshot_id) = self.snapshot_resolved else {
            return Err(match self.snapshot_named {
                Some(snapshot_id) => DatasetCaseError::UnknownSnapshot {
                    dataset_id: self.dataset_id,
                    snapshot_id,
                },
                None => DatasetCaseError::NeverFrozen {
                    dataset_id: self.dataset_id,
                },
            });
        };
        if self.items_read == 0 {
            return Err(DatasetCaseError::EmptySnapshot {
                dataset_id: self.dataset_id,
                snapshot_id,
            });
        }
        Ok(snapshot_id)
    }
}

/// One case, plus the PROVENANCE the case body is not allowed to carry.
///
/// **`dataset_item_id` is deliberately NOT a field on [`EvalCase`]**, and the
/// reason is the same one `dataset_routes` writes down for `source_trace_id`: a
/// caller that merely *mentions* an id does not get to claim one. `EvalCase` is
/// deserialized straight out of a request body on the `Inline` path, so a field
/// there would be client-settable, and `eval_run_items.dataset_item_id` would
/// stop meaning "this case came from that frozen item" the moment anyone posted
/// one. Carrying it in a wrapper the body cannot reach makes the claim
/// unforgeable by construction rather than by validation.
///
/// **A struct rather than a parallel `Vec<Option<Uuid>>`**: two vectors that
/// must stay the same length and the same order is a misalignment waiting for a
/// `filter`, and a misaligned provenance id is worse than an absent one — it
/// attributes a result to the wrong test case, silently.
#[derive(Debug, Clone)]
struct ResolvedCase {
    case: EvalCase,
    /// `Some` only for [`CaseSource::Dataset`]. `None` for `Inline` and
    /// `Traces`, which have no frozen item behind them — and that absence is a
    /// fact worth keeping, not a zero to fill in.
    dataset_item_id: Option<Uuid>,
}

impl ResolvedCase {
    /// An `Inline`/`Traces` case: no frozen item, and it says so.
    fn unsourced(case: EvalCase) -> Self {
        Self {
            case,
            dataset_item_id: None,
        }
    }
}

/// What a case source resolved to, and — for a dataset — WHICH item set.
struct ResolvedCases {
    cases: Vec<ResolvedCase>,
    /// The snapshot the run actually read, recorded so the run can say what it
    /// ran against. `None` for `Inline` and `Traces`, and saying that plainly is
    /// the point: those sources have no immutable item set to name, so a run from
    /// one of them is not reproducible and must not be recorded as though it
    /// were.
    snapshot_id: Option<Uuid>,
}

/// One row of `dataset_snapshot_items`, as this reader projects it.
///
/// **Every field is a `String` because every column is cast to one at the
/// server.** RowBinary is width-sensitive, so a `u32` here against a `UInt64`
/// column is a runtime decode failure rather than a compile error — and the
/// migration that defines those widths lands separately from this reader. Casting
/// at the server removes the whole class; what remains is the column NAMES, which
/// a wrong guess fails loudly on rather than silently.
#[derive(Deserialize, clickhouse::Row)]
struct SnapshotItemRow {
    ordinal_label: String,
    /// `toString(item_id)`, so this reader is width-agnostic against the `UUID`
    /// column. It is the PROVENANCE key `eval_run_items.dataset_item_id` carries,
    /// and the only reason item 9's diff can align two arms exactly instead of
    /// heuristically — both arms ran the same frozen set, so this id is shared by
    /// construction.
    item_id_label: String,
    input: String,
    /// `''` means absent. The column is `Nullable(String)` and `ifNull` flattens
    /// it, which also means this reader works unchanged if the snapshot table
    /// stores a non-nullable `String DEFAULT ''` instead.
    expected_output: String,
    metadata: String,
}

/// What one case produced.
#[derive(Debug, Clone, Default)]
pub struct CaseOutcome {
    pub output: String,
    pub latency_ms: u64,
    pub cost_usd: Option<f64>,
    pub input_tokens: u32,
    pub output_tokens: u32,
}

/// Per-case record written into `results_json`.
#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    pub name: String,
    pub status: EvalStatus,
    pub output: String,
    pub output_truncated: bool,
    pub latency_ms: u64,
    pub cost_usd: Option<f64>,
    pub assertions: Vec<AssertionResult>,
    /// `{scorer_label → Float64 in [0,1]}`. **`EVL-02` §3 defines `score` ONCE,
    /// and this map is that definition's storage.**
    ///
    /// Today every scorer is an [`Assertion`], so each contributes exactly `1.0`
    /// or `0.0` and the mean is the assertion pass fraction. Item 10's
    /// LLM-as-judge contributes a continuous value into this same map and
    /// nothing else changes — **a judge is not a second scoring path**, which is
    /// the whole reason the map exists before there is anything continuous to
    /// put in it.
    ///
    /// A `BTreeMap` rather than a `HashMap`: this is serialized into a durable
    /// ClickHouse column, and a map whose key order changes between runs makes
    /// two identical results produce different bytes — which turns any future
    /// content hash or byte-diff of a stored result into noise.
    pub scores: std::collections::BTreeMap<String, f64>,
    /// The arithmetic mean over the scorers PRESENT. `None` means **UNKNOWN** —
    /// no scorer produced a number — and it is never `0.0`.
    ///
    /// The distinction is the single most load-bearing thing on the compare
    /// surface: an errored item has no score, and rendering that as `0.00`
    /// manufactures a regression that did not happen. The column is
    /// `Nullable(Float64)` for exactly this reason
    /// (`infra/dev/clickhouse/migrations/18_datasets_and_experiments.sql`).
    pub score: Option<f64>,
    /// Present only for `Errored` — the upstream or harness reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionResult {
    pub rule: String,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// `EVL-23` — present only for a `llm_judge` rule that produced a CONFORMING
    /// response. A non-conforming judge leaves this `None` and puts the reason in
    /// `error`, so the surface can never render a score that was never validated.
    ///
    /// **Additive to a struct serialized into a `String` column** — no migration,
    /// and every `results_json` already on disk deserializes unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judge: Option<JudgeDetail>,
}

/// The `eval_runs` row. Field order and types mirror
/// `infra/dev/clickhouse/migrations/03_prompt_promotion.sql:50-70` exactly.
#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
struct EvalRunRow {
    tenant_id: String,
    #[serde(with = "clickhouse::serde::uuid")]
    eval_run_id: ::uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    prompt_version_id: ::uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    eval_suite_id: ::uuid::Uuid,
    /// `DateTime64(3)` — MILLIS. Never `timestamp_micros()`; see
    /// `clickhouse_query::datetime64_millis_now`, which exists because this
    /// exact mistake shipped twice on the sibling tables.
    started_at: i64,
    /// `Nullable(DateTime64(3))`. A plain `Option<i64>` needs no serde helper —
    /// only the UUID columns do.
    completed_at: Option<i64>,
    status: String,
    pass_count: u32,
    fail_count: u32,
    error_count: u32,
    duration_ms: u32,
    results_json: String,
}

/// Stable `eval_suite_id` from `(tenant, prompt, suite)` — same UUIDv5 convention
/// as `prompt_router::prompt_id_for`, so two runs of one suite group together
/// with no suites table.
const EVAL_SUITE_NAMESPACE: Uuid = Uuid::from_u128(0x4e5a_1d33_9c07_4f21_bd18_5a6e_0c94_7f30);

#[must_use]
pub fn eval_suite_id_for(tenant_id: &TenantId, prompt_name: &str, suite: &str) -> Uuid {
    Uuid::new_v5(
        &EVAL_SUITE_NAMESPACE,
        format!("{tenant_id}:{prompt_name}:{suite}").as_bytes(),
    )
}

/// The engine.
pub struct PromptEvalEngine {
    ch: ClickhouseClient,
    providers: Arc<ProviderRegistry>,
    router: Arc<PromptRouter>,
    /// `(tenant, prompt_name)` pairs with a run in flight. One per pair — an
    /// eval run spends real money and two at once spends it twice, invisibly.
    in_flight: Mutex<HashSet<(TenantId, String)>>,
    /// R81. `None` only when capture is disabled for the whole process; then a case
    /// runs and its span is COUNTED AS DROPPED rather than silently skipped, exactly
    /// as the chat path treats the same condition.
    nats: Option<Arc<async_nats::Client>>,
}

impl PromptEvalEngine {
    pub fn new(
        ch: ClickhouseClient,
        providers: Arc<ProviderRegistry>,
        router: Arc<PromptRouter>,
        nats: Option<Arc<async_nats::Client>>,
    ) -> Self {
        Self {
            ch,
            providers,
            router,
            in_flight: Mutex::new(HashSet::new()),
            nats,
        }
    }

    /// Claim the one in-flight slot for `(tenant, prompt)`.
    ///
    /// # Errors
    /// Already running for this pair.
    fn claim(&self, tenant_id: &TenantId, prompt_name: &str) -> Result<()> {
        let mut g = self.in_flight.lock().expect("in_flight poisoned");
        if !g.insert((tenant_id.clone(), prompt_name.to_string())) {
            bail!("an eval run is already in flight for this prompt");
        }
        Ok(())
    }

    /// The engine's ClickHouse handle, for callers that must run a query on the
    /// SAME connection settings the engine writes through — the spend seed being
    /// the one that exists. Exposed rather than rebuilt at the call site: a
    /// second client for the same server is a second place for a URL or a
    /// database name to drift.
    #[must_use]
    pub fn clickhouse(&self) -> &ClickhouseClient {
        &self.ch
    }

    /// The prompt registry this engine resolves versions through.
    ///
    /// Exposed so a caller that must perform the SAME object-level authorization
    /// (`version_for_tenant`) does it against the SAME registry — a second
    /// `Arc<PromptRouter>` handed to the experiment surface could be a different
    /// instance with a different load state, and "is this version yours" would
    /// then have two answers.
    #[must_use]
    pub fn router(&self) -> &Arc<PromptRouter> {
        &self.router
    }

    fn release(&self, tenant_id: &TenantId, prompt_name: &str) {
        self.in_flight
            .lock()
            .expect("in_flight poisoned")
            .remove(&(tenant_id.clone(), prompt_name.to_string()));
    }
}

/// Writes a TERMINAL status if the run body panics or returns early.
///
/// The gate treats `running` as blocked, so a row abandoned in `running` is a
/// promotion wedged shut with no error anywhere — the failure is invisible and
/// permanent at the same time. This covers the panic case; process death is
/// covered by [`PromptEvalEngine::reconcile_stale_runs`] at boot, because a
/// `Drop` impl cannot run if the process is gone.
struct RunGuard {
    ch: ClickhouseClient,
    tenant_id: String,
    run: EvalRunRow,
    /// Set once a terminal status has been written by the happy path.
    finished: bool,
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // Best-effort: we are possibly unwinding, so this cannot await. Hand the
        // write to the runtime and make the abandonment LOUD either way — a
        // silent abandonment is exactly what this guard exists to prevent.
        tracing::error!(
            eval_run_id = %self.run.eval_run_id,
            tenant_id = %self.tenant_id,
            "eval run abandoned without a terminal status — marking errored"
        );
        let ch = self.ch.clone();
        let tenant_id = self.tenant_id.clone();
        let id = self.run.eval_run_id;
        let started = self.run.started_at;
        let suite = self.run.eval_suite_id;
        let version = self.run.prompt_version_id;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let row = EvalRunRow {
                    tenant_id,
                    eval_run_id: id,
                    prompt_version_id: version,
                    eval_suite_id: suite,
                    started_at: started,
                    completed_at: Some(crate::clickhouse_query::datetime64_millis_now()),
                    status: EvalStatus::Errored.as_str().to_string(),
                    pass_count: 0,
                    fail_count: 0,
                    error_count: 0,
                    duration_ms: 0,
                    results_json:
                        r#"{"error":"the run was abandoned before completing (panic or shutdown)"}"#
                            .into(),
                };
                if let Err(e) = insert_run(&ch, &row).await {
                    tracing::error!(error = %e, "could not record the abandoned eval run");
                }
            });
        }
    }
}

/// Insert (or, via `ReplacingMergeTree` on `(tenant_id, eval_run_id)`, replace)
/// one `eval_runs` row.
///
/// The table is a VERSION-LESS `ReplacingMergeTree`, so the last write for an id
/// wins after merge, and the gate's `ORDER BY completed_at DESC LIMIT 1` picks
/// the newest even before merging. Verified against the live server: with a
/// `running` row (NULL `completed_at`) and a later `passed` row present, that
/// query returns `passed` — ClickHouse orders NULLs LAST in `DESC`.
/// One `eval_run_items` row. **Field order and types mirror
/// `infra/dev/clickhouse/migrations/18_datasets_and_experiments.sql` exactly.**
///
/// RowBinary is POSITIONAL and WIDTH-SENSITIVE — it carries no field names — so a
/// reordered field or a wrong-width type does not error at the mismatched
/// column. It desynchronises the stream and the server reports a byte-count
/// mismatch on a LATER row, or accepts garbage. That is B-273/B-274 exactly, and
/// it is why this struct is written against the DDL line by line and covered by
/// a REAL-ClickHouse round trip (`scripts/ci/run-clickhouse-integration.sh`)
/// rather than by a mock that stores what it is handed.
#[derive(Debug, Clone, Serialize, Deserialize, clickhouse::Row)]
pub(crate) struct EvalRunItemRow {
    pub(crate) tenant_id: String,
    #[serde(with = "clickhouse::serde::uuid")]
    pub(crate) eval_run_id: ::uuid::Uuid,
    pub(crate) item_ordinal: u32,
    /// The frozen `dataset_snapshot_items.item_id` this case came from.
    ///
    /// **`Uuid::nil()` for an inline or trace-sourced case**, as migration 18's
    /// own comment declares — the column is a non-nullable `UUID` and this is
    /// the value it names. A reader must test against nil EXPLICITLY and must
    /// not render it as an id.
    #[serde(with = "clickhouse::serde::uuid")]
    pub(crate) dataset_item_id: ::uuid::Uuid,
    /// `NULL` = this run had no dataset behind it (`Inline` / `Traces`), which is
    /// a DIFFERENT fact from "the dataset is gone".
    #[serde(with = "clickhouse::serde::uuid::option")]
    pub(crate) dataset_id: Option<::uuid::Uuid>,
    #[serde(with = "clickhouse::serde::uuid::option")]
    pub(crate) dataset_snapshot_id: Option<::uuid::Uuid>,
    pub(crate) case_name: String,
    pub(crate) status: String,
    pub(crate) output: String,
    pub(crate) output_truncated: u8,
    /// The `scores` map, JSON-encoded. Stored as TEXT so ClickHouse holds the
    /// exact bytes; the read path re-parses. `'{}'` means "no scorer ran", which
    /// pairs with a NULL `score` — the two must agree or one of them is lying.
    pub(crate) scores: String,
    /// `NULL` = UNKNOWN, never `0.0`. See [`CaseResult::score`].
    pub(crate) score: Option<f64>,
    pub(crate) latency_ms: u32,
    /// `NULL` = unpriced model, never `0.0`. Summing an unknown cost as zero is
    /// the exact coercion that made the spend tile under-report silently
    /// (`infra/dev/clickhouse/migrations/16_span_cost_attribution.sql:25-32`).
    pub(crate) cost_usd: Option<f64>,
    /// Present iff `status = 'errored'`.
    pub(crate) error: Option<String>,
    /// `DateTime64(3)` — MILLIS. Never `timestamp_micros()`.
    pub(crate) started_at: i64,
}

/// Write a run's per-item block. **ONE insert for the whole run, deliberately.**
///
/// At most [`limits::MAX_CASES`] rows is a single insert block and therefore
/// atomic: either every item row for this run is durable or none is. A per-item
/// insert would make "the run is complete but four of its items are missing" a
/// reachable state, and the run row is the completion marker — so a reader would
/// see a terminal run with an incomplete item set and no way to tell.
///
/// # Errors
/// Any ClickHouse failure. The caller MUST treat that as fatal to the run
/// (`errored`), never write `passed` behind it.
pub(crate) async fn insert_run_items(ch: &ClickhouseClient, rows: &[EvalRunItemRow]) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut insert = ch
        .insert("eval_run_items")
        .context("clickhouse eval_run_items insert init")?;
    for r in rows {
        insert
            .write(r)
            .await
            .context("clickhouse eval_run_items insert write")?;
    }
    insert
        .end()
        .await
        .context("clickhouse eval_run_items insert end")
}

async fn insert_run(ch: &ClickhouseClient, row: &EvalRunRow) -> Result<()> {
    let mut insert = ch
        .insert("eval_runs")
        .context("clickhouse eval_runs insert init")?;
    insert
        .write(row)
        .await
        .context("clickhouse eval_runs insert write")?;
    insert
        .end()
        .await
        .context("clickhouse eval_runs insert end")
}

/// Which half of an eval run a span came from.
///
/// **A closed enum rather than a `&str`**, because this string is the
/// discriminator `/v1/costs` splits on: a typo would put judge spend in neither
/// bucket, and the totals would still add up — the failure would be invisible on
/// the one surface it breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalSpanRole {
    /// The prompt under test.
    Case,
    /// The judge grading it (`EVL-23`).
    Judge,
}

impl EvalSpanRole {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Case => "case",
            Self::Judge => "judge",
        }
    }
}

impl PromptEvalEngine {
    /// Resolve the case set, and — when it came from a dataset — the snapshot it
    /// came from.
    ///
    /// # Errors
    /// - `Traces` when the workspace records no prompt content — a TYPED error
    ///   naming `TRACELANE_TRACE_CONTENT`, never an empty list.
    /// - `Dataset` when the dataset or snapshot is not the caller's, has never
    ///   been frozen, or is empty — four typed refusals, never an empty list.
    ///   See [`DatasetCaseError`].
    /// - more than [`limits::MAX_CASES`] cases.
    async fn resolve_cases(
        &self,
        tenant_id: &TenantId,
        source: &CaseSource,
    ) -> Result<ResolvedCases> {
        let (cases, snapshot_id) = match source {
            CaseSource::Inline { items } => (
                items.iter().cloned().map(ResolvedCase::unsourced).collect(),
                None,
            ),
            CaseSource::Traces {
                since_hours,
                model,
                limit,
            } => (
                self.cases_from_traces(tenant_id, *since_hours, model.as_deref(), *limit)
                    .await?
                    .into_iter()
                    .map(ResolvedCase::unsourced)
                    .collect::<Vec<_>>(),
                None,
            ),
            CaseSource::Dataset {
                dataset_id,
                snapshot_id,
            } => {
                let (cases, resolved) = self
                    .cases_from_dataset(tenant_id, *dataset_id, *snapshot_id)
                    .await?;
                (cases, Some(resolved))
            }
        };
        // Kept as a backstop for `Inline`, whose emptiness nobody else checks.
        // `Traces` and `Dataset` both refuse with a reason well before here, and
        // that is the point — this message names no fact and no remedy, so it is
        // the WORST of the available answers, not the default one.
        if cases.is_empty() {
            bail!("no cases to run");
        }
        if cases.len() > limits::MAX_CASES {
            bail!(
                "{} cases requested; the limit is {}",
                cases.len(),
                limits::MAX_CASES
            );
        }
        Ok(ResolvedCases { cases, snapshot_id })
    }

    /// Build cases from a FROZEN dataset snapshot (`EVL-04` §2.4).
    ///
    /// Three keyed lookups on the happy path, and the ORDER is deliberate: the
    /// dataset is authorized **before** any of its content is touched. That is
    /// the same rule `start_run` states for `prompt_version_id` — an id arriving
    /// in a request body is not evidence the caller owns it — and doing the
    /// authorization last would mean reading another workspace's snapshot rows
    /// before deciding not to return them.
    ///
    /// Every query filters on `tenant_id` from the validated claim, and every one
    /// runs under the tightest ADR-031 tier for the reason `cases_from_traces`
    /// writes out: resolving an eval's case set is background work and must never
    /// out-consume the interactive dashboard queries of the same workspace.
    ///
    /// # Errors
    /// - The four typed refusals of [`DatasetCaseError`] — unknown dataset,
    ///   unknown snapshot, never frozen, empty snapshot. Never an empty list.
    /// - A frozen item whose stored `input` does not parse, or holds no messages.
    ///   This FAILS the whole resolution rather than skipping the item, and the
    ///   asymmetry with `cases_from_traces` is intentional: a trace is raw
    ///   production data where one unparsable row is noise, whereas a snapshot is
    ///   a validated, immutable set that a run cites *by id*. Quietly running 11
    ///   of its 12 items would make two runs that claim the same snapshot
    ///   disagree — which is the one property snapshots exist to provide.
    async fn cases_from_dataset(
        &self,
        tenant_id: &TenantId,
        dataset_id: Uuid,
        snapshot_named: Option<Uuid>,
    ) -> Result<(Vec<ResolvedCase>, Uuid)> {
        let dataset_exists = self.dataset_is_live(tenant_id, dataset_id).await?;
        let snapshot_resolved = if dataset_exists {
            self.resolve_snapshot(tenant_id, dataset_id, snapshot_named)
                .await?
        } else {
            None
        };
        let rows = match snapshot_resolved {
            Some(snapshot_id) => self.read_snapshot_items(tenant_id, snapshot_id).await?,
            None => Vec::new(),
        };

        // ONE decision point for all four refusals. Building the facts here and
        // judging them there is what lets the judgement be unit-tested without a
        // ClickHouse — see [`DatasetProbe`].
        let snapshot_id = DatasetProbe {
            dataset_id,
            dataset_exists,
            snapshot_named,
            snapshot_resolved,
            items_read: rows.len(),
        }
        .verdict()?;

        let mut cases = Vec::with_capacity(rows.len());
        let mut unreadable_metadata = 0usize;
        for r in rows {
            let messages: Vec<Message> = serde_json::from_str(&r.input).with_context(|| {
                format!(
                    "snapshot {snapshot_id} item {ordinal} stores an `input` that is not a \
                         message list, so this snapshot cannot be reproduced. Freeze a new one \
                         from the dataset.",
                    ordinal = r.ordinal_label
                )
            })?;
            if messages.is_empty() {
                bail!(
                    "snapshot {snapshot_id} item {} holds no messages, so it cannot be sent to a \
                     provider. Freeze a new snapshot from the dataset.",
                    r.ordinal_label
                );
            }
            // `metadata` is ours to write and JSON by construction, so a parse
            // failure here is OUR bug, not the customer's — and it does not make
            // the test case invalid. Drop it and COUNT it; the one summary line
            // below is the log this deserves (`.claude/rules/logging.md`: a
            // repeating condition gets a counter, not a line per occurrence).
            let metadata = if r.metadata.trim().is_empty() {
                None
            } else {
                match serde_json::from_str::<serde_json::Value>(&r.metadata) {
                    Ok(v) => Some(v),
                    Err(_) => {
                        unreadable_metadata += 1;
                        None
                    }
                }
            };
            // The column is a `String` and we do NOT guess at JSON. A reference
            // that is literally `42` must not silently become a number, and a
            // reference is prose far more often than it is a document. The one
            // consumer that will need structure — item 10's `JsonSchema`
            // assertion — knows the schema and can parse at that point.
            // Whitespace-only counts as ABSENT, matching how `EVL-04` §3 counts
            // "scorable with a reference": an empty reference is not a reference.
            let expected = if r.expected_output.trim().is_empty() {
                None
            } else {
                Some(serde_json::Value::String(r.expected_output))
            };
            cases.push(ResolvedCase {
                case: EvalCase {
                    // `ordinal` is the item's identity WITHIN a snapshot, and the
                    // snapshot is immutable, so it never moves. It is also the column
                    // `eval_run_items` keys on (`item_ordinal`), so naming the case
                    // after it lines the run's summary up with its per-item rows
                    // without a join table. Mirrors `trace:{id}` above.
                    name: format!("item:{}", r.ordinal_label),
                    messages,
                    expected,
                    metadata,
                },
                // A frozen item id that does not parse is dropped to `None`
                // rather than faked: the case still runs, and the per-item row
                // records "no frozen item" instead of an id that resolves to
                // nothing. Silently writing a zero UUID here would make the diff
                // align two arms on a key that means "unknown".
                dataset_item_id: Uuid::parse_str(&r.item_id_label).ok(),
            });
        }
        if unreadable_metadata > 0 {
            tracing::warn!(
                snapshot_id = %snapshot_id,
                items = unreadable_metadata,
                "frozen dataset items carry metadata that is not JSON — the cases still ran, but \
                 whatever wrote those items wrote something we cannot read back"
            );
        }
        Ok((cases, snapshot_id))
    }

    /// Is there a live dataset with this id for this tenant?
    ///
    /// `FINAL` because `datasets` is a `ReplacingMergeTree` — without it a
    /// renamed dataset's old and new rows both exist until a merge, and a
    /// tombstoned one still shows its pre-delete row. `deleted = 0` makes a
    /// tombstoned dataset indistinguishable from one that never existed, which is
    /// the same answer a foreign id gets, deliberately.
    async fn dataset_is_live(&self, tenant_id: &TenantId, dataset_id: Uuid) -> Result<bool> {
        let sql = crate::clickhouse_query::TenantQuery::new(
            "SELECT count() FROM datasets FINAL \
             WHERE tenant_id = ? AND dataset_id = ? AND deleted = 0",
            crate::clickhouse_query::PlanTier::Builder,
        )
        .sql_with_settings();
        let n: u64 = self
            .ch
            .query(&sql)
            .bind(tenant_id.to_string())
            .bind(dataset_id)
            .fetch_one()
            .await
            .context("checking that the dataset belongs to this workspace")?;
        Ok(n > 0)
    }

    /// The snapshot to run against: the named one if it belongs to this dataset,
    /// otherwise the newest one frozen. `None` for BOTH "you named one that is
    /// not here" and "nothing has ever been frozen" — [`DatasetProbe`] is what
    /// tells those two apart, using whether the caller named one at all.
    ///
    /// The `? = '' OR …` shape is the same optional-filter idiom
    /// `cases_from_traces` uses for `model`: one statement, one plan, no branch
    /// that could drift from its twin.
    async fn resolve_snapshot(
        &self,
        tenant_id: &TenantId,
        dataset_id: Uuid,
        snapshot_named: Option<Uuid>,
    ) -> Result<Option<Uuid>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row {
            snapshot_id: String,
        }
        let named = snapshot_named.map(|s| s.to_string()).unwrap_or_default();
        let sql = crate::clickhouse_query::TenantQuery::new(
            "SELECT toString(snapshot_id) AS snapshot_id FROM dataset_snapshots \
             WHERE tenant_id = ? AND dataset_id = ? \
               AND (? = '' OR toString(snapshot_id) = ?) \
             ORDER BY created_at DESC \
             LIMIT 1",
            crate::clickhouse_query::PlanTier::Builder,
        )
        .sql_with_settings();
        let rows = self
            .ch
            .query(&sql)
            .bind(tenant_id.to_string())
            .bind(dataset_id)
            .bind(named.as_str())
            .bind(named.as_str())
            .fetch_all::<Row>()
            .await
            .context("resolving the dataset snapshot to run against")?;
        match rows.into_iter().next() {
            Some(r) => Ok(Some(Uuid::parse_str(&r.snapshot_id).with_context(
                || {
                    format!(
                        "dataset_snapshots returned an unparsable snapshot_id {:?}",
                        r.snapshot_id
                    )
                },
            )?)),
            None => Ok(None),
        }
    }

    /// The frozen items, in their frozen order.
    ///
    /// **`dataset_snapshot_items`, never `dataset_items`** — see
    /// [`CaseSource::Dataset`]. Every projected column is cast to `String` at the
    /// server, so this reader cannot break on the exact integer width the
    /// migration chose for `ordinal`; the only coupling left is the column names
    /// themselves. Note `ordinal_label` is aliased away from `ordinal` on
    /// purpose: `ORDER BY ordinal` must sort the NUMBER, and an alias shadowing
    /// it would sort the string, putting item 10 before item 2.
    ///
    /// `LIMIT` is [`limits::MAX_CASES`] **plus one** so an oversized snapshot is
    /// visible as a breach to the caller's cap check rather than being silently
    /// trimmed to exactly the cap — a run that quietly dropped items would still
    /// cite the snapshot id, and the citation would be false.
    async fn read_snapshot_items(
        &self,
        tenant_id: &TenantId,
        snapshot_id: Uuid,
    ) -> Result<Vec<SnapshotItemRow>> {
        let limit = u32::try_from(limits::MAX_CASES.saturating_add(1)).unwrap_or(u32::MAX);
        let sql = crate::clickhouse_query::TenantQuery::new(
            "SELECT toString(ordinal) AS ordinal_label, \
                    toString(item_id) AS item_id_label, \
                    input, \
                    ifNull(expected_output, '') AS expected_output, \
                    ifNull(metadata, '{}') AS metadata \
             FROM dataset_snapshot_items \
             WHERE tenant_id = ? AND snapshot_id = ? \
             ORDER BY ordinal \
             LIMIT ?",
            crate::clickhouse_query::PlanTier::Builder,
        )
        .sql_with_settings();
        self.ch
            .query(&sql)
            .bind(tenant_id.to_string())
            .bind(snapshot_id)
            .bind(limit)
            .fetch_all::<SnapshotItemRow>()
            .await
            .context("reading the frozen items of a dataset snapshot")
    }

    /// Build cases from recorded production traces.
    ///
    /// **Distinguishes "nothing matched" from "nothing is recorded".** They look
    /// identical in the data — both are zero rows — and only one is actionable
    /// by changing the filter.
    async fn cases_from_traces(
        &self,
        tenant_id: &TenantId,
        since_hours: Option<u32>,
        model: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Vec<EvalCase>> {
        let hours = since_hours.unwrap_or(168).clamp(1, 24 * 90);
        let want = u32::try_from(limits::MAX_CASES).unwrap_or(u32::MAX);
        let limit = limit.unwrap_or(50).clamp(1, want);

        #[derive(Deserialize, clickhouse::Row)]
        struct Row {
            trace_id: String,
            input_messages: String,
        }

        // ADR-031 caps, at the TIGHTEST tier deliberately. This is the one query
        // in this module that scans `spans` — the largest table — on
        // caller-supplied filters, which is exactly what the per-tier caps
        // exist for. It uses `Builder` rather than the tenant's real tier
        // because an eval case-fetch is BACKGROUND work: it must never be able
        // to out-consume the interactive dashboard queries of the same
        // workspace, let alone another tenant's. Conservative by construction,
        // and it needs no entitlement plumbing to stay that way.
        let sql = crate::clickhouse_query::TenantQuery::new(
            "SELECT toString(trace_id) AS trace_id, \
                    JSONExtractRaw(attributes, 'gen_ai_input_messages') AS input_messages \
             FROM spans \
             WHERE tenant_id = ? \
               AND start_time > now() - INTERVAL ? HOUR \
               AND JSONHas(attributes, 'gen_ai_input_messages') \
               AND (? = '' OR JSONExtractString(attributes, 'gen_ai_request_model') = ?) \
             ORDER BY start_time DESC \
             LIMIT ?",
            crate::clickhouse_query::PlanTier::Builder,
        )
        .sql_with_settings();
        let rows = self
            .ch
            .query(&sql)
            .bind(tenant_id.to_string())
            .bind(hours)
            .bind(model.unwrap_or(""))
            .bind(model.unwrap_or(""))
            .bind(limit)
            .fetch_all::<Row>()
            .await
            .context("reading case inputs from spans")?;

        if rows.is_empty() {
            // Is the workspace recording content AT ALL? If not, no filter the
            // user can type will ever match, and telling them "no traces matched"
            // sends them to tune a filter that cannot work.
            let recorded: u64 = self
                .ch
                .query(
                    "SELECT count() FROM spans \
                     WHERE tenant_id = ? AND JSONHas(attributes, 'gen_ai_input_messages')",
                )
                .bind(tenant_id.to_string())
                .fetch_one()
                .await
                .unwrap_or(0);
            if recorded == 0 {
                bail!(
                    "this workspace records no prompt content, so no trace can be replayed as a \
                     test case. Content capture (`TRACELANE_TRACE_CONTENT`) is off by default for \
                     privacy — traces keep model, tokens, cost and latency but not the messages. \
                     Supply cases inline (`\"source\":\"inline\"`) or enable content capture."
                );
            }
            bail!("no traces matched this filter in the last {hours}h");
        }

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let Ok(messages) = serde_json::from_str::<Vec<Message>>(&r.input_messages) else {
                // A span whose recorded messages do not parse is skipped rather
                // than failing the whole run — but it is NOT silent.
                tracing::warn!(trace_id = %r.trace_id, "skipping a trace whose input messages do not parse");
                continue;
            };
            if messages.is_empty() {
                continue;
            }
            out.push(EvalCase {
                name: format!("trace:{}", r.trace_id),
                messages,
                // A production trace carries no reference answer and no item
                // labels — capture records input only (`server.rs:3466-3479`).
                // Stated here rather than left to `Default` so nobody later reads
                // the absence as an oversight and "fixes" it with an empty
                // string, which would score as a reference that is always wrong.
                expected: None,
                metadata: None,
            });
        }

        Ok(out)
    }

    /// Build and publish one eval case's span, marked `tracelane_eval_run_id`.
    ///
    /// Fire-and-forget, like the chat path: a publish failure must not fail the
    /// case. A case that ran and scored is a real result, and losing its span is a
    /// capture problem, not an eval problem — so it is COUNTED (`note_span_dropped_no_nats`
    /// / `note_span_publish_failed`) rather than swallowed. A repeating condition
    /// gets a counter, not a line per occurrence (`.claude/rules/logging.md`).
    #[allow(clippy::too_many_arguments)]
    fn emit_case_span(
        &self,
        tenant_id: &TenantId,
        model: &str,
        eval_run_id: Uuid,
        experiment_id: Option<Uuid>,
        out: &CaseOutcome,
        started_at: chrono::DateTime<chrono::Utc>,
        role: EvalSpanRole,
    ) {
        let Some(ref nats) = self.nats else {
            crate::otlp_emit::note_span_dropped_no_nats();
            return;
        };
        let mut span = crate::server::build_gateway_span(
            tenant_id,
            // Each case is its OWN trace. An eval run is N independent requests, not
            // one conversation, and forcing them under a shared trace id would render
            // as a 200-span tree that never happened.
            Uuid::new_v4(),
            model,
            None,
            None,
            None,
            started_at,
            out.input_tokens,
            out.output_tokens,
            None,
            crate::server::SpanUsageMeta {
                cache_read_input_tokens: None,
                cache_creation_input_tokens: None,
                stream: false,
                cost_usd: out.cost_usd,
            },
            None,
            None,
            None,
            None,
            None,
        );
        span.attributes.tracelane_eval_run_id = Some(eval_run_id.to_string());
        // `EVL-02` §2.3. Set ONLY for an arm — a standalone run has no experiment,
        // and writing an empty string here would make
        // `JSONHas(attributes,'tracelane_experiment_id')` true for every eval span
        // ever emitted, which is precisely the discriminator the compare and cost
        // surfaces filter on.
        span.attributes.tracelane_experiment_id = experiment_id.map(|id| id.to_string());
        // `EVL-23` — set on EVERY eval span, both halves, so the split is exact
        // in both directions rather than "judge, or whatever is left over".
        span.attributes.tracelane_eval_role = Some(role.as_str().to_string());
        let nats = Arc::clone(nats);
        tokio::spawn(async move {
            if let Err(e) = crate::otlp_emit::publish_span(&nats, &span).await {
                crate::otlp_emit::note_span_publish_failed();
                tracing::warn!(error = %e, "eval case span NATS publish failed");
            }
        });
    }
}

impl PromptEvalEngine {
    /// Run ONE case through the same dispatch the chat path uses.
    ///
    /// The prompt version's content becomes the system instruction; the case
    /// supplies the messages. Non-streaming: an eval wants the whole answer, and
    /// the streaming path has no text accumulator anyway.
    #[allow(clippy::too_many_arguments)]
    async fn execute_case(
        &self,
        tenant_id: &TenantId,
        model: &str,
        system: &str,
        case: &EvalCase,
        eval_run_id: Uuid,
        experiment_id: Option<Uuid>,
        role: EvalSpanRole,
    ) -> Result<CaseOutcome> {
        let Some(provider_id) = ProviderRegistry::provider_id_for_model(model) else {
            bail!("unroutable model '{model}': no provider configured");
        };
        let env_var = ProviderRegistry::env_var_for_provider_id(provider_id);
        let key = match crate::server::resolve_provider_key(tenant_id, provider_id, env_var).await {
            crate::server::ProviderKey::Found(k) => k,
            crate::server::ProviderKey::NotConfigured => bail!(
                "no provider key configured for '{provider_id}' — add one in Settings → LLM Providers"
            ),
            crate::server::ProviderKey::Unusable => bail!(
                "the stored '{provider_id}' key could not be decrypted — rotate it in Settings → LLM Providers"
            ),
        };

        let request = ChatRequest {
            model: model.to_string(),
            messages: case.messages.clone(),
            tools: None,
            max_tokens: None,
            temperature: None,
            stream: Some(false),
            system: (!system.is_empty()).then(|| system.to_string()),
            metadata: None,
        };

        let started = std::time::Instant::now();
        // R81: wall-clock start, for the span. `Instant` cannot be turned into a
        // timestamp, so the two clocks are taken together rather than derived.
        let span_started_at = chrono::Utc::now();
        let mut stream =
            crate::server::dispatch_to_provider(&self.providers, request, &key, model, tenant_id)
                .await?;

        let mut out = CaseOutcome::default();
        while let Some(ev) = stream.next().await {
            match ev? {
                ProviderEvent::StreamChunk { delta } => out.output.push_str(&delta),
                ProviderEvent::UsageUpdate {
                    input_tokens,
                    output_tokens,
                    cost_usd,
                    ..
                } => {
                    out.input_tokens = input_tokens;
                    out.output_tokens = output_tokens;
                    out.cost_usd = cost_usd;
                }
                ProviderEvent::Done { response } => {
                    // Prefer the final response's text when the provider sends
                    // one. NOT every provider emits `Done` — the failover comment
                    // in `server.rs` names Gemini — so the accumulator above is
                    // the fallback, not the other way round.
                    if let Some(choice) = response.choices.first() {
                        if let MessageContent::Text(t) = &choice.message.content {
                            if !t.is_empty() {
                                out.output = t.clone();
                            }
                        }
                    }
                    if let Some(u) = response.usage {
                        out.input_tokens = u.input_tokens;
                        out.output_tokens = u.output_tokens;
                    }
                }
                ProviderEvent::Error { message, code } => {
                    bail!(
                        "provider error{}: {message}",
                        code.map(|c| format!(" [{c}]")).unwrap_or_default()
                    );
                }
                _ => {}
            }
        }
        out.latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

        // The provider priced it, or our own catalog can. `None` stays `None` —
        // an unpriced model must not be reported as costing zero, and
        // `MaxCostUsd` treats `None` as a FAILURE rather than a free pass.
        if out.cost_usd.is_none() {
            out.cost_usd = crate::pricing::cost_usd(
                model,
                &tracelane_shared::Usage {
                    input_tokens: out.input_tokens,
                    output_tokens: out.output_tokens,
                    cache_read_input_tokens: None,
                    cache_creation_input_tokens: None,
                },
            );
        }

        // ── R81: EMIT THE SPAN. ─────────────────────────────────────────────
        //
        // `EVL-05` §2.4b promised this and the code did not do it: `execute_case`
        // dispatches through `dispatch_to_provider` DIRECTLY, bypassing
        // `chat_completions_handler`, which is where every other span is built and
        // published. So an eval run produced NO span at all — confirmed at the
        // widest scope on prod (`JSONHas(attributes,'tracelane_eval_run_id')` = 0)
        // and independently by three spec drafters.
        //
        // WHY IT IS NOT COSMETIC. `/v1/costs` reads spans, so eval spend was
        // invisible on the exact surface a customer checks before an invoice — and
        // `record_key_spend` also reads the SPAN, so the budget that is supposed to
        // stop a runaway run never saw a cent of it either. Item 11 (online evals)
        // makes that acute rather than untidy: judge spend scales linearly with
        // traffic.
        //
        // The SAME builder and the SAME publish path as the chat path, deliberately
        // (`build_gateway_span` is `pub(crate)` for exactly this). A second span
        // builder for eval traffic would be a second definition of "a gateway span"
        // and the two would drift on the next column added.
        self.emit_case_span(
            tenant_id,
            model,
            eval_run_id,
            experiment_id,
            &out,
            span_started_at,
            role,
        );

        Ok(out)
    }
}

impl PromptEvalEngine {
    /// Render the judge's user message: the instruction under test, the case's
    /// own input, and the output to grade — delimited so a judge can tell them
    /// apart from each other and from the rubric.
    ///
    /// **The FULL output, never the truncated copy.** `CaseResult.output` is cut
    /// at [`limits::CASE_OUTPUT_BYTES`] for display; scoring the display copy
    /// would make the number a lie about a response the model actually gave.
    fn judge_prompt(system: &str, case: &EvalCase, out: &CaseOutcome) -> String {
        let mut s = String::with_capacity(out.output.len() + 512);
        if !system.is_empty() {
            s.push_str("<system_instruction>\n");
            s.push_str(system);
            s.push_str("\n</system_instruction>\n\n");
        }
        s.push_str("<input>\n");
        for m in &case.messages {
            // Multi-part content is FLATTENED to its text parts. A part with no
            // text (an image) is named rather than dropped: a judge that cannot
            // see an image must know one was there, or it grades a response to a
            // question it only half read.
            let text = match &m.content {
                MessageContent::Text(t) => t.clone(),
                MessageContent::Parts(parts) => parts
                    .iter()
                    .map(|p| match p {
                        tracelane_shared::ContentPart::Text { text, .. } => text.clone(),
                        _ => "[non-text content part]".to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join("\n"),
            };
            s.push_str(&format!("{}: {}\n", role_str(&m.role), text));
        }
        s.push_str("</input>\n\n<output>\n");
        s.push_str(&out.output);
        s.push_str("\n</output>");
        s
    }

    /// Resolve every judge assertion for ONE case, in order.
    ///
    /// Returns a slot per assertion, positionally aligned: `None` for a non-judge
    /// rule, `Some(Ok)` for a conforming judge, `Some(Err)` for one that was not
    /// understood. **Never a panic and never a silent skip** — a missing slot
    /// would be read by `evaluate` as "the judge was never called", which is an
    /// error there for exactly this reason.
    ///
    /// Runs INSIDE the case's `CASE_TIMEOUT_SECS` budget and inside its
    /// `CASE_CONCURRENCY` slot, so a run is still at most four concurrent
    /// provider calls and a judge slower than the model it grades surfaces as a
    /// case timeout rather than as silence.
    #[allow(clippy::too_many_arguments)]
    async fn run_judges(
        &self,
        tenant_id: &TenantId,
        case: &EvalCase,
        outcome: &CaseOutcome,
        assertions: &[Assertion],
        system: &str,
        case_model: &str,
        eval_run_id: Uuid,
        experiment_id: Option<Uuid>,
    ) -> Vec<Option<std::result::Result<JudgeDetail, String>>> {
        let mut slots = Vec::with_capacity(assertions.len());
        for a in assertions {
            let Assertion::LlmJudge {
                rubric,
                model,
                min_score: _,
            } = a
            else {
                slots.push(None);
                continue;
            };
            slots.push(Some(
                self.run_one_judge(
                    tenant_id,
                    case,
                    outcome,
                    rubric,
                    model.as_deref().unwrap_or(case_model),
                    system,
                    eval_run_id,
                    experiment_id,
                )
                .await,
            ));
        }
        slots
    }

    /// One judge call, from rubric resolution to a validated verdict.
    #[allow(clippy::too_many_arguments)]
    async fn run_one_judge(
        &self,
        tenant_id: &TenantId,
        case: &EvalCase,
        outcome: &CaseOutcome,
        rubric: &JudgeRubric,
        judge_model: &str,
        system: &str,
        eval_run_id: Uuid,
        experiment_id: Option<Uuid>,
    ) -> std::result::Result<JudgeDetail, String> {
        // ── Rubric resolution, with OBJECT-LEVEL AUTHORIZATION on the custom
        // path. `version_for_tenant` is the SAME check `prepare_run` makes on the
        // prompt under test: a version id from a request body is not evidence the
        // caller owns it, and a rubric is a prompt like any other. Tenant B naming
        // tenant A's version gets the refusal, and A's rubric text never appears
        // in B's response body.
        let rubric_text = match rubric {
            JudgeRubric::BuiltIn { name } => judge::built_in(name)
                .ok_or_else(|| {
                    format!(
                        "unknown built-in judge rubric {name:?} — available: {}",
                        judge::BUILT_IN_NAMES.join(", ")
                    )
                })?
                .to_string(),
            JudgeRubric::PromptVersion { prompt_version_id } => self
                .router
                .version_for_tenant(tenant_id, *prompt_version_id)
                .ok_or_else(|| {
                    format!(
                        "prompt version {prompt_version_id} is not a registered version for \
                         this tenant"
                    )
                })?
                .content
                .clone(),
        };

        // The contract is APPENDED BY US, never supplied by the rubric — so a
        // tenant's own rubric cannot weaken the thing that makes the score
        // interpretable.
        let judge_system = format!("{rubric_text}{}", judge::OUTPUT_CONTRACT);

        let judge_case = EvalCase {
            name: format!("{}::judge", case.name),
            messages: vec![Message {
                role: Role::User,
                content: MessageContent::Text(Self::judge_prompt(system, case, outcome)),
                tool_calls: None,
                tool_call_id: None,
            }],
            expected: None,
            metadata: None,
        };

        let judged = self
            .execute_case(
                tenant_id,
                judge_model,
                &judge_system,
                &judge_case,
                eval_run_id,
                experiment_id,
                EvalSpanRole::Judge,
            )
            .await
            .map_err(|e| format!("the judge call failed: {e:#}"))?;

        let verdict = judge::validate(&judged.output)?;
        Ok(JudgeDetail {
            score: verdict.score,
            verdict: verdict.verdict,
            reason: verdict.reason,
            model: judge_model.to_string(),
            rubric: rubric.label(),
            cost_usd: judged.cost_usd,
            latency_ms: judged.latency_ms,
        })
    }
}

/// Wire name for a message role, for the judge's rendered input.
fn role_str(r: &Role) -> &'static str {
    match r {
        Role::System => "system",
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Tool => "tool",
    }
}

impl PromptEvalEngine {
    /// Score one case against the assertions.
    ///
    /// `judged` is positionally aligned with `assertions` — slot `i` carries the
    /// judge result for `assertions[i]`, or `None` for every non-judge rule.
    /// **Positional and not a map**, because two judge assertions with identical
    /// bodies would collide on any key derived from the body, and the collision
    /// would silently score one case with another's judgement.
    ///
    /// **Still synchronous, deliberately.** The provider call happens upstream in
    /// `execute_run`; this stays the pure function every scoring test drives.
    fn score(
        case: &EvalCase,
        outcome: &CaseOutcome,
        assertions: &[Assertion],
        judged: &[Option<std::result::Result<JudgeDetail, String>>],
    ) -> CaseResult {
        let mut results = Vec::with_capacity(assertions.len());
        let mut all_passed = true;
        let mut any_error = false;
        for (i, a) in assertions.iter().enumerate() {
            let j = judged.get(i).and_then(Option::as_ref);
            match a.evaluate(case, outcome, j) {
                Ok(passed) => {
                    all_passed &= passed;
                    results.push(AssertionResult {
                        rule: a.label(),
                        passed,
                        error: None,
                        judge: j.and_then(|r| r.as_ref().ok()).cloned(),
                    });
                }
                Err(e) => {
                    // A broken ASSERTION is the author's bug, not the prompt's —
                    // and so is a judge that would not answer in its own contract.
                    any_error = true;
                    results.push(AssertionResult {
                        rule: a.label(),
                        passed: false,
                        error: Some(format!("{e:#}")),
                        // Deliberately NOT carried on the error path: a
                        // non-conforming judge has no validated score, and
                        // rendering an unvalidated one beside the error is how a
                        // number nobody checked reaches a customer.
                        judge: None,
                    });
                }
            }
        }
        let (output, truncated) = truncate(&outcome.output, limits::CASE_OUTPUT_BYTES);
        let status = if any_error {
            EvalStatus::Errored
        } else if all_passed {
            EvalStatus::Passed
        } else {
            EvalStatus::Failed
        };
        // ── The scores map (`EVL-02` §3) ────────────────────────────────────
        //
        // An assertion that ERRORED contributes NOTHING to the map — not a
        // `0.0`. A broken regex is the author's bug and we have no measurement
        // of the prompt, so scoring it zero would report a prompt failure we
        // never observed. It is the same zero-vs-unknown rule the `Option<f64>`
        // below carries, applied one level down.
        //
        // A DUPLICATE LABEL OVERWRITES, and that is stated rather than left to
        // the map: two identical assertions are the same scorer asked twice, so
        // one entry with the last result is the honest shape. It also means
        // `scores.len()` is a count of DISTINCT scorers, which is what the mean
        // must divide by.
        //
        // **`EVL-23`: a judge contributes its CONTINUOUS score, not 1.0/0.0.**
        // This is what `CaseResult::scores` was built for before there was
        // anything continuous to put in it — a judge is not a second scoring
        // path. The rule's own pass/fail (`score >= min_score`) still decides
        // the CASE status; the map keeps the number that produced it, because a
        // 0.68 that missed a 0.70 threshold and a 0.02 that missed it are the
        // same `failed` and very different results.
        let mut scores = std::collections::BTreeMap::new();
        for r in &results {
            if r.error.is_none() {
                let v = r
                    .judge
                    .as_ref()
                    .map_or_else(|| f64::from(u8::from(r.passed)), |d| d.score);
                scores.insert(r.rule.clone(), v);
            }
        }
        // `None` when the map is empty — a run with no scorer produced no score,
        // which is not the same as a score of zero. `sum / len` on an empty map
        // is NaN, and a NaN reaching a `Nullable(Float64)` column would be a
        // third state nobody designed for.
        let score = if scores.is_empty() {
            None
        } else {
            #[allow(clippy::cast_precision_loss)]
            let n = scores.len() as f64;
            Some(scores.values().sum::<f64>() / n)
        };
        CaseResult {
            name: case.name.clone(),
            status,
            output,
            output_truncated: truncated,
            latency_ms: outcome.latency_ms,
            cost_usd: outcome.cost_usd,
            assertions: results,
            scores,
            score,
            error: None,
        }
    }
}

/// Truncate on a CHAR boundary and say so. A silently-cut output read as the
/// model's actual answer is how a passing assertion becomes a lie.
fn truncate(s: &str, max: usize) -> (String, bool) {
    if s.len() <= max {
        return (s.to_string(), false);
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    (s[..end].to_string(), true)
}

/// What `POST /v1/prompts/{name}/evals` accepted, kept so the run is
/// reproducible from its own record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalRunRequest {
    pub prompt_version_id: Uuid,
    #[serde(default = "default_suite")]
    pub suite_name: String,
    pub cases: CaseSource,
    #[serde(default)]
    pub assertions: Vec<Assertion>,
    /// Model to run against. Defaults to the version's `model_pin` when it has
    /// one; an explicit value wins.
    #[serde(default)]
    pub model: Option<String>,
}

impl EvalRunRequest {
    /// Does this run ask for an LLM judge?
    ///
    /// **The entitlement question, and it is asked about the JUDGE rather than
    /// about the route.** `start_eval_handler`'s own doc says measuring is free
    /// and only promoting is the paid act, and the module header's Team+
    /// enumeration (`prompt_routes.rs:9-10`) lists promote / rollback / observe
    /// and NOT evals. So gating the whole eval route would be a breaking
    /// authorization change to a shipped surface, argued from a misreading of
    /// that header. The judge is the new paid capability, so the judge is what is
    /// gated — an unjudged run behaves exactly as it did yesterday.
    #[must_use]
    pub fn uses_judge(&self) -> bool {
        self.assertions.iter().any(Assertion::is_judge)
    }
}

fn default_suite() -> String {
    "default".into()
}

/// What the caller gets back immediately.
#[derive(Debug, Clone, Serialize)]
pub struct EvalRunStarted {
    pub eval_run_id: Uuid,
    pub eval_suite_id: Uuid,
    pub status: EvalStatus,
    pub cases: usize,
    /// The snapshot this run resolved to, when the source was a dataset and the
    /// caller left `snapshot_id` off. **Returned rather than merely stored** so
    /// the caller can pin the next run to the same item set without guessing at
    /// what "latest" meant a minute ago. Absent for `Inline` and `Traces`, which
    /// have no immutable item set to name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dataset_snapshot_id: Option<Uuid>,
    /// `EVL-23` — `cases x (1 + judge_count)`: what this run WILL spend, returned
    /// BEFORE it spends it.
    ///
    /// **This is the whole answer to "a big bill that looked like a small one".**
    /// A judged run costs twice what an unjudged one does, and the only honest
    /// place to say so is the 202 the caller reads before anything has happened.
    /// It is a CALL count, not a dollar figure, and not a promise about retries:
    /// a run that stops early — timeout, budget ceiling — spends fewer, and the
    /// final `results_json` carries what actually ran.
    pub provider_calls: usize,
}

/// The experiment an arm belongs to, or nothing.
///
/// Carried as ONE optional struct rather than two loose `Option<Uuid>`s so a
/// caller cannot supply an experiment id without the arm id it is meaningless
/// without — the compiler enforces the pair.
#[derive(Debug, Clone, Copy)]
pub struct ArmContext {
    pub experiment_id: Uuid,
    pub arm_id: Uuid,
}

/// What the CALLER knows that the engine cannot look up for itself.
///
/// Both fields come from outside this module on purpose. The workspace budget
/// lives in the entitlement cache, which the engine deliberately does not hold —
/// giving a money-spending executor its own entitlement handle is how a second
/// resolution path appears and the two disagree. The arm linkage is known only
/// to the experiment runner. So both arrive as data.
#[derive(Debug, Clone, Copy, Default)]
pub struct RunContext {
    /// The workspace's monthly ceiling in USD, or `None` for uncapped —
    /// **matching `SpendTracker::check`'s own semantics and the column's**
    /// (`NULL` = uncapped), so no caller has to remember a second convention.
    pub budget_usd: Option<f64>,
    /// `Some` iff this run is an experiment arm.
    pub arm: Option<ArmContext>,
}

/// Everything one run needs, assembled once by [`PromptEvalEngine::prepare_run`]
/// and consumed by `execute_run`.
///
/// **A struct rather than a longer argument list**, and not for tidiness:
/// `execute_run` already carried eight positional parameters behind
/// `#[allow(clippy::too_many_arguments)]`, four of which were `String`s and two
/// `Option<Uuid>`. Adding the experiment and budget context positionally is how
/// two same-typed arguments get transposed at one call site and nothing
/// complains — and a transposed `dataset_id`/`snapshot_id` would write
/// provenance that resolves to the wrong frozen set.
struct RunPlan {
    tenant_id: TenantId,
    prompt_name: String,
    row: EvalRunRow,
    cases: Vec<ResolvedCase>,
    assertions: Vec<Assertion>,
    model: String,
    system: String,
    /// The dataset behind the snapshot. `None` for `Inline` / `Traces`.
    dataset_id: Option<Uuid>,
    dataset_snapshot_id: Option<Uuid>,
    /// `Some` iff this run is an experiment arm.
    arm: Option<ArmContext>,
    /// The workspace's monthly ceiling in USD, resolved ONCE at start.
    ///
    /// `None` means uncapped, matching `SpendTracker::check`'s own semantics —
    /// and matching the column, where `NULL` is uncapped. It is resolved at start
    /// rather than re-read per item because the entitlement cache is the only
    /// source and a per-item read would be a Postgres round trip per provider
    /// call. **The ceiling cannot move mid-run; the SPEND can, and that is the
    /// half the mid-run check actually needs to see.**
    budget_usd: Option<f64>,
}

/// What a completed run produced. Returned by `execute_run` so an experiment can
/// react to its arm without re-reading ClickHouse for a row it just wrote.
#[derive(Debug, Clone, Copy)]
pub struct RunOutcome {
    pub eval_run_id: Uuid,
    pub status: EvalStatus,
    pub pass_count: u32,
    pub fail_count: u32,
    pub error_count: u32,
    /// Per-item rows durably written. **`0` with a terminal status means the
    /// item write FAILED**, and the run is `errored` for that reason — it never
    /// means "the run had no items", because a run with no cases is refused
    /// before it starts.
    pub items_written: u32,
}

impl PromptEvalEngine {
    /// Validate, claim the slot, write the `running` row, and spawn the work.
    ///
    /// Returns as soon as the row is durable, because a 200-case run against a
    /// real provider takes minutes and an HTTP request should not hold that open.
    /// **The row is written BEFORE any provider call**: the alternative is
    /// spending the tenant's money with no record that a run started, which is
    /// invisible in exactly the way an audit product must never be.
    ///
    /// # Errors
    /// Unknown/foreign version, a run already in flight, an empty or oversized
    /// case set, or no assertions.
    pub async fn start_run(
        self: &Arc<Self>,
        tenant_id: TenantId,
        prompt_name: &str,
        req: EvalRunRequest,
        ctx: RunContext,
    ) -> Result<EvalRunStarted> {
        let (plan, started) = self.prepare_run(tenant_id, prompt_name, req, ctx).await?;
        let engine = Arc::clone(self);
        tokio::spawn(async move {
            engine.execute_run(plan).await;
        });
        Ok(started)
    }

    /// Run ONE arm to completion and hand back what it produced.
    ///
    /// **The awaited twin of [`Self::start_run`], not a second engine.** An
    /// experiment needs its arms SEQUENTIAL (founder ruling R82) and needs each
    /// arm's outcome before it decides anything about the next, so it cannot use
    /// the spawn-and-forget path. Everything else — validation, the claim, the
    /// `running` row, the executor — is the same code; only the join point
    /// differs.
    ///
    /// # Errors
    /// Whatever [`Self::start_run`] refuses on. A refusal here means the arm never
    /// started and NOTHING was spent.
    pub async fn run_arm<F, Fut>(
        self: &Arc<Self>,
        tenant_id: TenantId,
        prompt_name: &str,
        req: EvalRunRequest,
        ctx: RunContext,
        on_started: F,
    ) -> Result<RunOutcome>
    where
        F: FnOnce(Uuid) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let (plan, started) = self.prepare_run(tenant_id, prompt_name, req, ctx).await?;
        // ANNOUNCED HERE, and the position is the whole point: the durable
        // `running` row exists and NO provider has been called yet. An arm that is
        // executing must not read as `pending`, whose honest copy is "queued" —
        // for the minutes an arm takes, that is a small lie in the direction that
        // makes someone reload.
        //
        // A hook rather than a store handle on the engine: the engine writes
        // `eval_runs`, and giving it a second table to know about would make it
        // the owner of a linkage that belongs to the experiment surface.
        on_started(started.eval_run_id).await;
        Ok(Arc::clone(self).execute_run(plan).await)
    }

    /// Validate, claim the slot and write the `running` row — everything that
    /// must happen BEFORE a provider is called, and nothing that happens after.
    ///
    /// # Errors
    /// Unknown/foreign version, a run already in flight, an empty or oversized
    /// case set, or no assertions.
    async fn prepare_run(
        self: &Arc<Self>,
        tenant_id: TenantId,
        prompt_name: &str,
        req: EvalRunRequest,
        ctx: RunContext,
    ) -> Result<(RunPlan, EvalRunStarted)> {
        // OBJECT-LEVEL AUTHORIZATION, before anything is claimed or spent. The
        // same check `promote` performs: a version id from a request body is not
        // evidence the caller owns it.
        let Some(version) = self
            .router
            .version_for_tenant(&tenant_id, req.prompt_version_id)
        else {
            bail!(
                "prompt version {} is not a registered version for this tenant",
                req.prompt_version_id
            );
        };
        if req.assertions.is_empty() {
            bail!("at least one assertion is required — a run with none can only ever pass");
        }
        // ── `EVL-23`: BOUND THE SPEND MULTIPLIER, before a cent is spent. ────
        //
        // Each judge assertion adds ONE provider call PER CASE, so N judges cost
        // `cases × (1 + N)`. Refused here rather than capped silently: a customer
        // who asked for three judges and got one would discover the difference on
        // their provider bill, which is the wrong place to learn it.
        let judges = req.assertions.iter().filter(|a| a.is_judge()).count();
        if judges > judge::MAX_JUDGES_PER_RUN {
            bail!(
                "at most {} `llm_judge` assertion per run — each one adds a provider call per \
                 case; you asked for {judges}, which would be {}x the calls",
                judge::MAX_JUDGES_PER_RUN,
                judges + 1
            );
        }
        // A built-in name that does not exist is the AUTHOR's typo, and it is
        // caught here rather than N cases later: resolving it inside the run
        // would spend the whole case set's money to discover a misspelling.
        for a in &req.assertions {
            if let Assertion::LlmJudge {
                rubric: JudgeRubric::BuiltIn { name },
                ..
            } = a
            {
                if judge::built_in(name).is_none() {
                    bail!(
                        "unknown built-in judge rubric {name:?} — available: {}",
                        judge::BUILT_IN_NAMES.join(", ")
                    );
                }
            }
        }
        let model = req
            .model
            .clone()
            .or_else(|| version.model_pin.clone())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no model to run against: this version has no `model_pin`, so pass `model`"
                )
            })?;

        let ResolvedCases {
            cases,
            snapshot_id: dataset_snapshot_id,
        } = self.resolve_cases(&tenant_id, &req.cases).await?;

        // Claim LAST among the fallible steps, so a validation failure does not
        // leave the slot held.
        self.claim(&tenant_id, prompt_name)?;

        let eval_run_id = Uuid::new_v4();
        let eval_suite_id = eval_suite_id_for(&tenant_id, prompt_name, &req.suite_name);
        let started_at = crate::clickhouse_query::datetime64_millis_now();
        let row = EvalRunRow {
            tenant_id: tenant_id.to_string(),
            eval_run_id,
            prompt_version_id: req.prompt_version_id,
            eval_suite_id,
            started_at,
            completed_at: None,
            status: EvalStatus::Running.as_str().to_string(),
            pass_count: 0,
            fail_count: 0,
            error_count: 0,
            duration_ms: 0,
            results_json: String::new(),
        };
        if let Err(e) = insert_run(&self.ch, &row).await {
            self.release(&tenant_id, prompt_name);
            return Err(e);
        }

        let n = cases.len();
        // The dataset behind the snapshot, taken from the REQUEST rather than
        // re-derived: `resolve_cases` returns the snapshot it settled on, and the
        // dataset id is the one the caller named and we already authorized. A
        // second lookup here could only disagree with the first.
        let dataset_id = match &req.cases {
            CaseSource::Dataset { dataset_id, .. } => Some(*dataset_id),
            CaseSource::Inline { .. } | CaseSource::Traces { .. } => None,
        };
        let plan = RunPlan {
            tenant_id,
            prompt_name: prompt_name.to_string(),
            row,
            cases,
            assertions: req.assertions.clone(),
            model,
            system: version.content.clone(),
            dataset_id,
            dataset_snapshot_id,
            arm: ctx.arm,
            budget_usd: ctx.budget_usd,
        };

        Ok((
            plan,
            EvalRunStarted {
                eval_run_id,
                eval_suite_id,
                status: EvalStatus::Running,
                cases: n,
                dataset_snapshot_id,
                provider_calls: n * (1 + judges),
            },
        ))
    }

    /// The run body. Always writes a terminal status — the [`RunGuard`] covers
    /// the panic path.
    async fn execute_run(self: Arc<Self>, plan: RunPlan) -> RunOutcome {
        let RunPlan {
            tenant_id,
            prompt_name,
            row,
            cases,
            assertions,
            model,
            system,
            dataset_id,
            dataset_snapshot_id,
            arm,
            budget_usd,
        } = plan;
        // R81: captured BEFORE `row` moves into the guard. Every case's span carries
        // this, which is what makes eval traffic separable in `/v1/costs` and
        // excludable from the tenant's own dashboards.
        let eval_run_id = row.eval_run_id;
        let experiment_id = arm.map(|a| a.experiment_id);
        let mut guard = RunGuard {
            ch: self.ch.clone(),
            tenant_id: tenant_id.to_string(),
            run: EvalRunRow { ..clone_row(&row) },
            finished: false,
        };
        let started = std::time::Instant::now();
        let deadline = std::time::Duration::from_secs(limits::RUN_TIMEOUT_SECS);

        // ── The money cap (spec §5 "Budget, MID-RUN", founder ruling R83.2) ──
        //
        // Seeded ONCE from the durable ClickHouse total, for reason: an
        // in-memory counter alone is not a cap, because a redeploy forgives every
        // dollar accrued before it. Seeding is skipped entirely when the workspace
        // has no ceiling — there is then nothing to compare against, and a
        // ClickHouse round trip per run to populate a counter nobody reads is
        // pure cost.
        let subject = crate::spend::Subject::Workspace(*tenant_id.as_uuid());
        if budget_usd.is_some() {
            crate::spend::seed_workspace(&self.ch, &tenant_id).await;
        }

        let mut results: Vec<CaseResult> = Vec::with_capacity(cases.len());
        let mut stopped_early: Option<String> = None;

        for chunk in cases.chunks(limits::CASE_CONCURRENCY) {
            if started.elapsed() > deadline {
                stopped_early = Some(format!(
                    "run exceeded its {}s wall clock; {} of {} cases ran",
                    limits::RUN_TIMEOUT_SECS,
                    results.len(),
                    cases.len()
                ));
                break;
            }
            // THE MID-RUN CEILING. Checked BETWEEN chunks, so the run stops at the
            // ceiling rather than at the end — spec §4b(2). This is exact only
            // because arms are SEQUENTIAL: with `arms` runs in flight the cap could
            // be crossed by every one of them before any observed it, and the
            // guarantee would degrade from "we stop at the ceiling" to "we stop
            // within `arms` calls of it", on someone else's provider bill.
            if let crate::spend::BudgetDecision::Exceeded {
                budget_usd,
                spent_usd,
            } = crate::spend::tracker().check(subject, budget_usd)
            {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    %eval_run_id,
                    budget_usd,
                    spent_usd,
                    "eval run stopped mid-flight: the workspace is at its monthly budget"
                );
                // The partial result is KEPT and rendered. Hiding work already
                // paid for is worse than showing it, and the reason names both
                // numbers so the surface never has to guess why it stopped.
                stopped_early = Some(format!(
                    "this workspace reached its monthly budget (${spent_usd:.2} of \
                     ${budget_usd:.2}); {} of {} cases ran",
                    results.len(),
                    cases.len()
                ));
                break;
            }
            let mut futs = Vec::with_capacity(chunk.len());
            for resolved in chunk {
                let engine = Arc::clone(&self);
                let t = tenant_id.clone();
                let m = model.clone();
                let sys = system.clone();
                let c = resolved.case.clone();
                let asserts = assertions.clone();
                let rid = eval_run_id;
                let xid = experiment_id;
                futs.push(async move {
                    let r = tokio::time::timeout(
                        std::time::Duration::from_secs(limits::CASE_TIMEOUT_SECS),
                        // `EVL-23`: the case call and its judge share ONE timeout
                        // and ONE concurrency slot. Both properties are load-bearing
                        // — a judge outside the budget would let a run exceed its
                        // own wall clock silently, and a judge outside the slot
                        // would double a run's concurrent pressure on the tenant's
                        // provider rate limit, which is exactly how GWY-24's
                        // measurement destroyed itself.
                        async {
                            // R81: the run id travels WITH the case so every span
                            // this run emits is attributable to it. Passed rather
                            // than read from `self`, because the engine is shared
                            // across runs.
                            let outcome = engine
                                .execute_case(&t, &m, &sys, &c, rid, xid, EvalSpanRole::Case)
                                .await?;
                            let judged = engine
                                .run_judges(&t, &c, &outcome, &asserts, &sys, &m, rid, xid)
                                .await;
                            Ok::<_, anyhow::Error>((outcome, judged))
                        },
                    )
                    .await;
                    (c, r)
                });
            }
            for (case, r) in futures::future::join_all(futs).await {
                match r {
                    Ok(Ok((outcome, judged))) => {
                        // Record BEFORE scoring, so a scorer that panics cannot
                        // lose the fact that money was spent. `record` ignores a
                        // `None` cost rather than adding zero — an unpriced model
                        // is not a free one, and the counter simply has no
                        // information about it.
                        crate::spend::tracker().record(subject, outcome.cost_usd);
                        // `EVL-23`: the JUDGE's spend is recorded too, and
                        // separately, because it is a second real provider call on
                        // the tenant's own key. Folding it into the case's cost
                        // would make the mid-run budget ceiling under-count by
                        // half on a judged run — the cap would stop at 2x its
                        // stated number.
                        for d in judged.iter().flatten().filter_map(|r| r.as_ref().ok()) {
                            crate::spend::tracker().record(subject, d.cost_usd);
                        }
                        results.push(Self::score(&case, &outcome, &assertions, &judged));
                    }
                    // An upstream failure is ERRORED, never FAILED — a broken
                    // provider must not read as a bad prompt.
                    Ok(Err(e)) => results.push(errored_case(&case.name, format!("{e:#}"))),
                    Err(_) => results.push(errored_case(
                        &case.name,
                        format!("case exceeded its {}s timeout", limits::CASE_TIMEOUT_SECS),
                    )),
                }
            }
        }

        let pass = count_status(&results, EvalStatus::Passed);
        let fail = count_status(&results, EvalStatus::Failed);
        let err = count_status(&results, EvalStatus::Errored);

        // ── THE PER-ITEM ROWS, WRITTEN BEFORE THE TERMINAL RUN ROW ──────────
        //
        // Order is the whole property (spec §2.3): the `eval_runs` row is the
        // COMPLETION MARKER, so the items must be durable first. Reversed, a
        // reader would see a terminal run with an incomplete item set and no way
        // to tell that anything was missing — and item 13's CI gate compares a
        // pass rate derived from exactly these rows.
        let item_rows = build_item_rows(
            &tenant_id,
            eval_run_id,
            dataset_id,
            dataset_snapshot_id,
            row.started_at,
            &cases,
            &results,
        );
        let items_expected = u32::try_from(item_rows.len()).unwrap_or(u32::MAX);
        let (items_written, item_write_error) = match insert_run_items(&self.ch, &item_rows).await {
            Ok(()) => (items_expected, None),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    %eval_run_id,
                    tenant_id = %tenant_id,
                    "eval_run_items write failed — the run is ERRORED, not passed"
                );
                (0, Some(format!("{e:#}")))
            }
        };

        // A run that could not complete is ERRORED even if every case that DID
        // run passed — reporting `passed` on a partial run would open the
        // promotion gate on evidence that was never gathered. A failed ITEM write
        // is the same class: the per-item rows are what the compare surface and
        // the CI gate read, so a run whose detail was lost must never present as
        // a clean pass.
        let status = if stopped_early.is_some() || err > 0 || item_write_error.is_some() {
            EvalStatus::Errored
        } else if fail > 0 {
            EvalStatus::Failed
        } else {
            EvalStatus::Passed
        };

        let payload = serde_json::json!({
            "cases": results,
            "requested_cases": cases.len(),
            "stopped_early": stopped_early,
            "model": model,
            // WHICH immutable item set this run read, or `null` for a source that
            // has none. `eval_runs` has no column for it, so the run's own record
            // is the only place it can live — and a run that cannot name its item
            // set is not reproducible, which is the entire reason snapshots
            // exist. `eval_run_items` now carries the same two ids per row; this
            // stays because a run whose item write FAILED still has to be able to
            // say what it ran against.
            "dataset_snapshot_id": dataset_snapshot_id,
            "dataset_id": dataset_id,
            "experiment_id": experiment_id,
            "arm_id": arm.map(|a| a.arm_id),
            // `null` = the item rows are durable. A STRING here is the ClickHouse
            // failure that made this run `errored`, and it is recorded rather than
            // only logged: the log line is gone in a week and the run row is the
            // permanent record of why a reader will find no items behind it.
            "item_write_error": item_write_error,
        });
        let (results_json, truncated) = truncate(
            &serde_json::to_string(&payload).unwrap_or_else(|_| "{}".into()),
            limits::RESULTS_JSON_BYTES,
        );
        let results_json = if truncated {
            // `serde_json` is built here WITHOUT `preserve_order`, so the payload
            // serialises its keys alphabetically and `dataset_snapshot_id` sits
            // behind the whole `cases` array. A 1 MiB cut would therefore throw
            // away the one field that makes the run reproducible, in exactly the
            // runs big enough to care. Restate it outside the truncated blob.
            let snapshot =
                serde_json::to_string(&dataset_snapshot_id).unwrap_or_else(|_| "null".to_string());
            format!(
                r#"{{"truncated":true,"dataset_snapshot_id":{snapshot},"partial":{results_json:?}}}"#
            )
        } else {
            results_json
        };

        let final_row = EvalRunRow {
            completed_at: Some(crate::clickhouse_query::datetime64_millis_now()),
            status: status.as_str().to_string(),
            pass_count: u32::try_from(pass).unwrap_or(u32::MAX),
            fail_count: u32::try_from(fail).unwrap_or(u32::MAX),
            error_count: u32::try_from(err).unwrap_or(u32::MAX),
            duration_ms: u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX),
            results_json,
            ..clone_row(&row)
        };
        match insert_run(&self.ch, &final_row).await {
            Ok(()) => guard.finished = true,
            Err(e) => {
                // Leave `finished = false` so the guard still tries. A run whose
                // RESULT could not be recorded must not look complete.
                tracing::error!(error = %e, eval_run_id = %row.eval_run_id, "eval run result not recorded");
            }
        }
        self.release(&tenant_id, &prompt_name);

        RunOutcome {
            eval_run_id,
            status,
            pass_count: u32::try_from(pass).unwrap_or(u32::MAX),
            fail_count: u32::try_from(fail).unwrap_or(u32::MAX),
            error_count: u32::try_from(err).unwrap_or(u32::MAX),
            items_written,
        }
    }
}

/// Turn `(cases, results)` into the per-item rows.
///
/// **Pure, and that is the point.** The alignment between a case and its result
/// is positional — `results[i]` is `cases[i]` because `join_all` preserves order
/// and every chunk is drained before the next is dispatched — and a positional
/// alignment that is only asserted in prose is exactly the misalignment
/// [`ResolvedCase`] exists to prevent one level up. Being pure means a unit test
/// watches it hold, including for a run that stopped early, where
/// `results.len() < cases.len()`.
///
/// A result with no matching case is IMPOSSIBLE and is dropped rather than
/// fabricated: `zip` stops at the shorter side, so a future refactor that
/// produced more results than cases loses rows loudly (the counts disagree)
/// instead of writing an item row attributed to a case that never existed.
fn build_item_rows(
    tenant_id: &TenantId,
    eval_run_id: Uuid,
    dataset_id: Option<Uuid>,
    dataset_snapshot_id: Option<Uuid>,
    started_at: i64,
    cases: &[ResolvedCase],
    results: &[CaseResult],
) -> Vec<EvalRunItemRow> {
    cases
        .iter()
        .zip(results.iter())
        .enumerate()
        .map(|(i, (resolved, r))| EvalRunItemRow {
            tenant_id: tenant_id.to_string(),
            eval_run_id,
            item_ordinal: u32::try_from(i).unwrap_or(u32::MAX),
            // `Uuid::nil()` for an inline or trace-sourced case, as migration 18's
            // own comment declares. The column is a non-nullable `UUID`; a reader
            // must test against nil EXPLICITLY and must never render it as an id.
            dataset_item_id: resolved.dataset_item_id.unwrap_or_else(Uuid::nil),
            dataset_id,
            dataset_snapshot_id,
            case_name: r.name.clone(),
            status: r.status.as_str().to_string(),
            output: r.output.clone(),
            output_truncated: u8::from(r.output_truncated),
            // `'{}'` when no scorer ran, which pairs with a NULL `score`. The two
            // must agree or one of them is lying.
            scores: serde_json::to_string(&r.scores).unwrap_or_else(|_| "{}".to_string()),
            score: r.score,
            latency_ms: u32::try_from(r.latency_ms).unwrap_or(u32::MAX),
            cost_usd: r.cost_usd,
            error: r.error.clone(),
            // THE RUN's start, not the item's. It is the PARTITION key
            // (`toYYYYMM(started_at)`), so deriving it per item would let one
            // run's items straddle a month boundary into two partitions — and on
            // a `ReplacingMergeTree` parts merge only WITHIN a partition, so a
            // retried item could never collapse against its original.
            started_at,
        })
        .collect()
}

fn clone_row(r: &EvalRunRow) -> EvalRunRow {
    EvalRunRow {
        tenant_id: r.tenant_id.clone(),
        eval_run_id: r.eval_run_id,
        prompt_version_id: r.prompt_version_id,
        eval_suite_id: r.eval_suite_id,
        started_at: r.started_at,
        completed_at: r.completed_at,
        status: r.status.clone(),
        pass_count: r.pass_count,
        fail_count: r.fail_count,
        error_count: r.error_count,
        duration_ms: r.duration_ms,
        results_json: r.results_json.clone(),
    }
}

fn errored_case(name: &str, reason: String) -> CaseResult {
    CaseResult {
        name: name.to_string(),
        status: EvalStatus::Errored,
        output: String::new(),
        output_truncated: false,
        latency_ms: 0,
        cost_usd: None,
        assertions: Vec::new(),
        // EMPTY map and a NULL score, never `{}`-with-a-zero. An errored case
        // was not measured; `EVL-02` §3b's `Δ score` column is `null` when
        // either side is unknown, and that column can only be right if the
        // unknown starts here.
        scores: std::collections::BTreeMap::new(),
        score: None,
        error: Some(reason),
    }
}

fn count_status(rs: &[CaseResult], want: EvalStatus) -> usize {
    rs.iter().filter(|r| r.status == want).count()
}

/// One row as the dashboard and the CLI see it.
#[derive(Debug, Clone, Serialize, Deserialize, clickhouse::Row)]
pub struct EvalRunSummary {
    #[serde(with = "clickhouse::serde::uuid")]
    pub eval_run_id: ::uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    pub prompt_version_id: ::uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    pub eval_suite_id: ::uuid::Uuid,
    pub status: String,
    pub pass_count: u32,
    pub fail_count: u32,
    pub error_count: u32,
    pub duration_ms: u32,
    pub started_at_ms: i64,
}

impl PromptEvalEngine {
    /// Runs for one tenant, newest first.
    ///
    /// `FINAL` because `eval_runs` is a version-less `ReplacingMergeTree`: until
    /// a background merge collapses them, the `running` row and its terminal
    /// replacement BOTH exist, and a list without `FINAL` would show a finished
    /// run as still running. The gate's single-row lookup does not need it
    /// (its `ORDER BY completed_at DESC LIMIT 1` already picks the newest, and
    /// ClickHouse sorts NULLs last in `DESC` — verified on the live server); a
    /// LIST does.
    pub async fn list_runs(&self, tenant_id: &TenantId, limit: u32) -> Result<Vec<EvalRunSummary>> {
        let limit = limit.clamp(1, 200);
        self.ch
            .query(
                "SELECT eval_run_id, prompt_version_id, eval_suite_id, status, \
                        pass_count, fail_count, error_count, duration_ms, \
                        toUnixTimestamp64Milli(started_at) AS started_at_ms \
                 FROM eval_runs FINAL \
                 WHERE tenant_id = ? \
                 ORDER BY started_at DESC \
                 LIMIT ?",
            )
            .bind(tenant_id.to_string())
            .bind(limit)
            .fetch_all::<EvalRunSummary>()
            .await
            .context("listing eval runs")
    }

    /// One run, with its per-case detail.
    pub async fn get_run(
        &self,
        tenant_id: &TenantId,
        eval_run_id: Uuid,
    ) -> Result<Option<serde_json::Value>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row {
            status: String,
            pass_count: u32,
            fail_count: u32,
            error_count: u32,
            duration_ms: u32,
            results_json: String,
            started_at_ms: i64,
            completed_at_ms: Option<i64>,
        }
        let rows = self
            .ch
            .query(
                "SELECT status, pass_count, fail_count, error_count, duration_ms, results_json, \
                        toUnixTimestamp64Milli(started_at) AS started_at_ms, \
                        toUnixTimestamp64Milli(completed_at) AS completed_at_ms \
                 FROM eval_runs FINAL \
                 WHERE tenant_id = ? AND eval_run_id = ? \
                 LIMIT 1",
            )
            .bind(tenant_id.to_string())
            .bind(eval_run_id)
            .fetch_all::<Row>()
            .await
            .context("reading an eval run")?;
        let Some(r) = rows.into_iter().next() else {
            return Ok(None);
        };
        Ok(Some(serde_json::json!({
            "eval_run_id": eval_run_id,
            "status": r.status,
            "pass_count": r.pass_count,
            "fail_count": r.fail_count,
            "error_count": r.error_count,
            "duration_ms": r.duration_ms,
            "started_at_ms": r.started_at_ms,
            "completed_at_ms": r.completed_at_ms,
            "results": serde_json::from_str::<serde_json::Value>(&r.results_json)
                .unwrap_or(serde_json::Value::Null),
        })))
    }

    /// Mark runs abandoned by a process death as `errored`, at boot.
    ///
    /// **This is the layer `RunGuard` cannot be.** A `Drop` impl does not run
    /// when the process is killed, so without this a restart mid-run leaves the
    /// row `running` forever — and because the gate maps `running` to
    /// `BlockedByEval`, that is a promotion silently wedged shut with no error
    /// anywhere to explain it.
    ///
    /// The precedent is not hypothetical: `prev_production` shipped without its
    /// boot rebuild and silently disarmed auto-rollback after every deploy, in
    /// this same feature, fixed the same day this was written. A restart is a
    /// normal event; state that only survives a promotion is state that does not
    /// survive.
    ///
    /// Fail-OPEN: a reconciliation failure logs and the gateway starts anyway.
    /// It is a cleanup, not a security control.
    pub async fn reconcile_stale_runs(&self) {
        // The cutoff is the run wall clock, so a run still legitimately in
        // flight is never touched and the two numbers cannot disagree.
        let cutoff_secs = limits::RUN_TIMEOUT_SECS;
        #[derive(Deserialize, clickhouse::Row)]
        struct Stale {
            tenant_id: String,
            #[serde(with = "clickhouse::serde::uuid")]
            eval_run_id: ::uuid::Uuid,
            #[serde(with = "clickhouse::serde::uuid")]
            prompt_version_id: ::uuid::Uuid,
            #[serde(with = "clickhouse::serde::uuid")]
            eval_suite_id: ::uuid::Uuid,
            started_at_ms: i64,
        }
        let rows = self
            .ch
            .query(
                "SELECT tenant_id, eval_run_id, prompt_version_id, eval_suite_id, \
                        toUnixTimestamp64Milli(started_at) AS started_at_ms \
                 FROM eval_runs FINAL \
                 WHERE status = 'running' AND started_at < now() - INTERVAL ? SECOND",
            )
            .bind(cutoff_secs)
            .fetch_all::<Stale>()
            .await;
        let rows = match rows {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "eval-run reconciliation failed — a run orphaned by a restart may still \
                     read as `running`, which the promotion gate treats as blocked"
                );
                return;
            }
        };
        if rows.is_empty() {
            return;
        }
        let n = rows.len();
        for st in rows {
            let row = EvalRunRow {
                tenant_id: st.tenant_id,
                eval_run_id: st.eval_run_id,
                prompt_version_id: st.prompt_version_id,
                eval_suite_id: st.eval_suite_id,
                started_at: st.started_at_ms,
                completed_at: Some(crate::clickhouse_query::datetime64_millis_now()),
                status: EvalStatus::Errored.as_str().to_string(),
                pass_count: 0,
                fail_count: 0,
                error_count: 0,
                duration_ms: 0,
                results_json: format!(
                    r#"{{"error":"this run was still `running` {cutoff_secs}s after it started, so the process that owned it is gone; marked errored at boot"}}"#
                ),
            };
            if let Err(e) = insert_run(&self.ch, &row).await {
                tracing::warn!(error = %e, eval_run_id = %st.eval_run_id, "could not reconcile a stale eval run");
            }
        }
        tracing::warn!(
            reconciled = n,
            "eval runs orphaned by a restart were marked errored — promotion is unblocked for them"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(output: &str, latency_ms: u64, cost: Option<f64>) -> CaseOutcome {
        CaseOutcome {
            output: output.into(),
            latency_ms,
            cost_usd: cost,
            input_tokens: 1,
            output_tokens: 1,
        }
    }

    fn tid(n: u128) -> TenantId {
        TenantId::from_jwt_claim(Uuid::from_u128(n))
    }

    /// Adapters so the pre-`EVL-23` scoring tests read unchanged.
    ///
    /// **They pass NO judge slots**, which is the honest default for every rule
    /// that is not a judge — and it is also what proves the judge is additive:
    /// each of these tests scored the same before item 10 and scores the same
    /// after.
    fn ev(a: &Assertion, o: &CaseOutcome) -> Result<bool> {
        a.evaluate(&case("t"), o, None)
    }
    fn sc(c: &EvalCase, o: &CaseOutcome, a: &[Assertion]) -> CaseResult {
        PromptEvalEngine::score(c, o, a, &vec![None; a.len()])
    }

    fn case(name: &str) -> EvalCase {
        EvalCase {
            name: name.into(),
            messages: vec![],
            expected: None,
            metadata: None,
        }
    }

    const DS: Uuid = Uuid::from_u128(0xd0);
    const SNAP: Uuid = Uuid::from_u128(0x5a);

    /// A probe that found everything it looked for.
    fn healthy_probe() -> DatasetProbe {
        DatasetProbe {
            dataset_id: DS,
            dataset_exists: true,
            snapshot_named: Some(SNAP),
            snapshot_resolved: Some(SNAP),
            items_read: 3,
        }
    }

    /// The status vocabulary IS the contract with `ClickHouseEvalGate`. It maps
    /// exactly these four and returns `None` for anything else — and `None`
    /// blocks promotion. A fifth string would wedge the gate shut silently.
    #[test]
    fn status_strings_match_the_gate_vocabulary_exactly() {
        assert_eq!(EvalStatus::Running.as_str(), "running");
        assert_eq!(EvalStatus::Passed.as_str(), "passed");
        assert_eq!(EvalStatus::Failed.as_str(), "failed");
        assert_eq!(EvalStatus::Errored.as_str(), "errored");
    }

    #[test]
    fn assertions_evaluate() {
        let o = outcome(r#"{"order":"ORDER-123456"}"#, 900, Some(0.004));
        assert!(
            ev(
                &Assertion::Contains {
                    value: "ORDER-".into()
                },
                &o,
            )
            .unwrap()
        );
        assert!(
            ev(
                &Assertion::NotContains {
                    value: "I cannot".into()
                },
                &o,
            )
            .unwrap()
        );
        // `EVL-23`: `json_valid` is DELETED. `json_schema` with an empty schema
        // is its honest replacement — it accepts anything that parses, and the
        // author had to write the schema to get that.
        assert!(
            ev(
                &Assertion::JsonSchema {
                    schema: serde_json::json!({}),
                },
                &o
            )
            .unwrap()
        );
        assert!(
            ev(
                &Assertion::Regex {
                    value: "ORDER-[0-9]{6}".into()
                },
                &o
            )
            .unwrap()
        );
        assert!(ev(&Assertion::MaxLatencyMs { value: 1000 }, &o).unwrap());
        assert!(!ev(&Assertion::MaxLatencyMs { value: 100 }, &o).unwrap());
    }

    /// A model `pricing.rs` cannot price yields `cost_usd = None`. That must FAIL
    /// a cost ceiling, not satisfy it: "we could not measure" is not "it was
    /// cheap", and treating unknown as zero would let an unpriced model pass
    /// every budget assertion silently.
    #[test]
    fn an_unpriced_case_fails_a_cost_ceiling_rather_than_passing_it() {
        let unpriced = outcome("hi", 10, None);
        assert!(
            !ev(&Assertion::MaxCostUsd { value: 1.0 }, &unpriced).unwrap(),
            "unknown cost must not satisfy a cost ceiling"
        );
        let priced = outcome("hi", 10, Some(0.5));
        assert!(ev(&Assertion::MaxCostUsd { value: 1.0 }, &priced).unwrap());
    }

    /// A malformed regex is the ASSERTION AUTHOR's bug. Reporting it as a failed
    /// case would send someone to debug the prompt instead of their own rule.
    #[test]
    fn a_broken_regex_is_an_error_not_a_failure() {
        let o = outcome("anything", 1, None);
        let broken = Assertion::Regex {
            value: "([unclosed".into(),
        };
        assert!(ev(&broken, &o).is_err());

        let case = case("c");
        let scored = sc(&case, &o, &[broken]);
        assert_eq!(
            scored.status,
            EvalStatus::Errored,
            "a broken assertion makes the case ERRORED, never FAILED"
        );
        assert!(scored.assertions[0].error.is_some());
    }

    #[test]
    fn scoring_separates_pass_fail() {
        let case = case("c");
        let o = outcome("hello world", 5, Some(0.001));
        assert_eq!(
            sc(
                &case,
                &o,
                &[Assertion::Contains {
                    value: "hello".into()
                }]
            )
            .status,
            EvalStatus::Passed
        );
        assert_eq!(
            sc(
                &case,
                &o,
                &[Assertion::Contains {
                    value: "goodbye".into()
                }]
            )
            .status,
            EvalStatus::Failed
        );
    }

    /// Truncation must be VISIBLE. An output silently cut short and then asserted
    /// against is how a passing assertion becomes a lie.
    #[test]
    fn truncation_is_flagged_and_utf8_safe() {
        let (s, cut) = truncate("short", 100);
        assert!(!cut);
        assert_eq!(s, "short");

        // Multi-byte characters straddling the cut must not panic or split.
        let wide = "é".repeat(50);
        let (s, cut) = truncate(&wide, 11);
        assert!(cut);
        assert!(s.len() <= 11);
        assert!(std::str::from_utf8(s.as_bytes()).is_ok());
    }

    /// `eval_suite_id` groups runs of one suite with no suites table, so it must
    /// be stable per (tenant, prompt, suite) and distinct across tenants —
    /// otherwise two workspaces' runs collide in the same suite.
    #[test]
    fn suite_id_is_stable_and_tenant_scoped() {
        let a = eval_suite_id_for(&tid(1), "p", "regression");
        assert_eq!(a, eval_suite_id_for(&tid(1), "p", "regression"));
        assert_ne!(a, eval_suite_id_for(&tid(2), "p", "regression"));
        assert_ne!(a, eval_suite_id_for(&tid(1), "other", "regression"));
        assert_ne!(a, eval_suite_id_for(&tid(1), "p", "smoke"));
    }

    /// An eval run is N real provider calls. Two concurrent runs for one prompt
    /// spend the tenant's money twice, invisibly — a client retry must not be
    /// able to cause it.
    #[test]
    fn only_one_run_per_prompt_may_be_in_flight() {
        let engine = PromptEvalEngine {
            ch: clickhouse::Client::default(),
            providers: Arc::new(ProviderRegistry::new().expect("registry")),
            router: Arc::new(PromptRouter::new()),
            // R81: no NATS in tests — the span emit then COUNTS a drop rather
            // than publishing, which is the same branch a capture-disabled process
            // takes, so the tests exercise the real code path and not a stub.
            nats: None,
            in_flight: Mutex::new(HashSet::new()),
        };
        engine.claim(&tid(7), "p").expect("first claim succeeds");
        assert!(
            engine.claim(&tid(7), "p").is_err(),
            "a second run for the same prompt must be refused"
        );
        // A DIFFERENT prompt, and a different tenant, are unaffected.
        engine
            .claim(&tid(7), "other")
            .expect("other prompt is free");
        engine.claim(&tid(8), "p").expect("other tenant is free");
        // Releasing frees it again.
        engine.release(&tid(7), "p");
        engine
            .claim(&tid(7), "p")
            .expect("released slot is reusable");
    }

    /// **The refusals must DISCRIMINATE.** Zero rows is the answer to all four
    /// questions — is this dataset yours, is that snapshot in it, has anything
    /// ever been frozen, does the frozen thing hold items — and each has a
    /// different action attached to it. A source that reported "no cases" for all
    /// four, or one code for all four, would pass every other test in this file.
    ///
    /// Falsified before it was trusted (`CLAUDE.md` §1): collapsing
    /// `DatasetProbe::verdict` to a single `UnknownDataset` for every unhappy
    /// input, and separately making it return `Ok` on an empty snapshot, were both
    /// run and both fail here.
    #[test]
    fn the_dataset_refusals_are_distinguishable_not_one_generic_emptiness() {
        // 1. The dataset is not this workspace's — never existed, tombstoned, or
        //    someone else's. All three answer the same, on purpose.
        let unknown_dataset = DatasetProbe {
            dataset_exists: false,
            ..healthy_probe()
        }
        .verdict()
        .expect_err("a dataset that is not this tenant's must refuse");
        assert_eq!(unknown_dataset.code(), "dataset_not_found");
        assert_eq!(
            unknown_dataset.http_status(),
            404,
            "an unknown dataset is a 404 — never a 500, and never an empty case list"
        );

        // 2. The caller NAMED a snapshot that is not in this dataset.
        let unknown_snapshot = DatasetProbe {
            snapshot_named: Some(SNAP),
            snapshot_resolved: None,
            items_read: 0,
            ..healthy_probe()
        }
        .verdict()
        .expect_err("a snapshot that is not in this dataset must refuse");
        assert_eq!(unknown_snapshot.code(), "snapshot_not_found");
        assert_eq!(unknown_snapshot.http_status(), 404);

        // 3. The caller named NOTHING and the dataset has never been frozen. Same
        //    zero rows as case 2, different fact, different remedy: freeze one.
        let never_frozen = DatasetProbe {
            snapshot_named: None,
            snapshot_resolved: None,
            items_read: 0,
            ..healthy_probe()
        }
        .verdict()
        .expect_err("a dataset with no snapshots must refuse");
        assert_eq!(never_frozen.code(), "dataset_never_frozen");

        // 4. The snapshot resolved and holds nothing.
        let empty_snapshot = DatasetProbe {
            items_read: 0,
            ..healthy_probe()
        }
        .verdict()
        .expect_err("an empty snapshot must refuse");
        assert_eq!(empty_snapshot.code(), "snapshot_empty");

        // THE PROPERTY, stated over the labels rather than the labels themselves:
        // four facts in, four distinct codes and four distinct sentences out.
        let all = [
            unknown_dataset,
            unknown_snapshot,
            never_frozen,
            empty_snapshot,
        ];
        let codes: HashSet<&str> = all.iter().map(|e| e.code()).collect();
        assert_eq!(codes.len(), 4, "two refusals share a code: {codes:?}");
        let messages: HashSet<String> = all.iter().map(std::string::ToString::to_string).collect();
        assert_eq!(
            messages.len(),
            4,
            "two refusals read identically to a user, which is the whole failure"
        );
        // Every one of them says what to DO. A code with no remedy is a 404 the
        // user cannot act on.
        for e in &all {
            let m = e.to_string();
            assert!(
                m.contains("Check")
                    || m.contains("List")
                    || m.contains("Freeze")
                    || m.contains("Add"),
                "refusal {:?} names no remedy: {m}",
                e.code()
            );
        }
    }

    /// The other half of the same guard, and the half that is easy to forget: a
    /// probe that refuses everything would satisfy the test above by
    /// construction while telling you nothing. This is the case that must NOT
    /// refuse.
    #[test]
    fn a_snapshot_that_resolved_and_holds_items_is_not_refused() {
        assert_eq!(
            healthy_probe()
                .verdict()
                .expect("a live snapshot with items must resolve"),
            SNAP,
            "the verdict returns the snapshot the run will cite"
        );
        // ...and it resolves the same way when the caller named nothing, because
        // "latest" resolved to something real.
        assert_eq!(
            DatasetProbe {
                snapshot_named: None,
                ..healthy_probe()
            }
            .verdict()
            .expect("an unnamed snapshot resolves to the newest"),
            SNAP
        );
    }

    /// `expected` and `metadata` are additive, and the cost of getting that wrong
    /// is not hypothetical: an `EvalCase` shape that no longer parses without them
    /// makes every inline caller written before this row fail, and every
    /// `results_json` already on disk unreadable.
    ///
    /// **What this test does and does NOT prove, measured rather than assumed.**
    /// Deleting `#[serde(default)]` from `expected` and re-running leaves this
    /// GREEN — serde already deserializes an absent `Option<T>` field as `None`,
    /// so the attribute is belt-and-braces here rather than the thing holding the
    /// property up. It was kept anyway because it states the intent at the site
    /// and survives the field ever becoming non-`Option`. What the test DOES
    /// discriminate is the regression that matters: making either field
    /// **required**. Falsified by typing `expected` as a bare
    /// `serde_json::Value`, which fails here with `missing field 'expected'`.
    #[test]
    fn an_eval_case_written_before_expected_and_metadata_still_parses() {
        let before = r#"{"name":"c","messages":[{"role":"user","content":"hi"}]}"#;
        let parsed: EvalCase =
            serde_json::from_str(before).expect("the pre-EVL-04 case shape must still parse");
        assert_eq!(parsed.name, "c");
        assert_eq!(parsed.messages.len(), 1);
        assert!(
            parsed.expected.is_none(),
            "an absent reference is None, never an empty string that scores as always-wrong"
        );
        assert!(parsed.metadata.is_none());

        // The same, one level up: a whole pre-existing `Inline` request body.
        let src: CaseSource = serde_json::from_str(
            r#"{"source":"inline","items":[{"name":"c","messages":[{"role":"user","content":"hi"}]}]}"#,
        )
        .expect("the pre-EVL-04 inline source must still parse");
        let CaseSource::Inline { items } = src else {
            panic!("inline source parsed as something else");
        };
        assert_eq!(items.len(), 1);
        assert!(items[0].expected.is_none());

        // And they round-trip when they ARE present, so carrying them is real
        // rather than a field that quietly drops its value.
        let with: EvalCase = serde_json::from_str(
            r#"{"name":"c","messages":[],"expected":"TRANSFER","metadata":{"src":"csv"}}"#,
        )
        .expect("a case WITH a reference must parse");
        assert_eq!(with.expected, Some(serde_json::json!("TRANSFER")));
        assert_eq!(with.metadata, Some(serde_json::json!({"src": "csv"})));
    }

    /// An omitted `snapshot_id` must mean "the newest", not "malformed request".
    /// It is the shape the one-click path sends, and a `#[serde(default)]` missing
    /// here would turn the common case into a 400.

    // ── `EVL-02` §3 — the scores map, and zero vs unknown ───────────────────

    #[test]
    fn every_assertion_contributes_one_or_zero_and_the_score_is_their_mean() {
        let out = outcome("hello world", 10, None);
        let r = sc(
            &case("c"),
            &out,
            &[
                Assertion::Contains {
                    value: "hello".into(),
                },
                Assertion::Contains {
                    value: "absent".into(),
                },
            ],
        );
        assert_eq!(r.scores.len(), 2);
        assert_eq!(
            r.scores.values().copied().collect::<Vec<_>>(),
            vec![0.0, 1.0]
        );
        assert_eq!(r.score, Some(0.5), "the mean over the scorers PRESENT");
        assert_eq!(r.status, EvalStatus::Failed);
    }

    #[test]
    fn a_broken_assertion_contributes_nothing_rather_than_a_zero() {
        // A regex that does not compile is the AUTHOR's bug. Scoring it 0 would
        // report a prompt failure we never observed.
        let out = outcome("anything", 10, None);
        let r = sc(
            &case("c"),
            &out,
            &[
                Assertion::Contains {
                    value: "any".into(),
                },
                Assertion::Regex {
                    value: "([unclosed".into(),
                },
            ],
        );
        assert_eq!(r.status, EvalStatus::Errored);
        assert_eq!(
            r.scores.len(),
            1,
            "the broken assertion must NOT appear in the map"
        );
        assert_eq!(
            r.score,
            Some(1.0),
            "the mean divides by the scorers that actually produced a number"
        );
    }

    #[test]
    fn a_run_with_no_scorer_has_an_unknown_score_never_zero() {
        let out = outcome("x", 1, None);
        let r = sc(&case("c"), &out, &[]);
        assert!(r.scores.is_empty());
        assert_eq!(
            r.score, None,
            "an empty map is UNKNOWN — `sum/len` would be NaN and 0.0 would be a lie"
        );
    }

    #[test]
    fn an_errored_case_carries_an_empty_map_and_no_score() {
        let r = errored_case("c", "upstream 500".into());
        assert!(r.scores.is_empty());
        assert_eq!(r.score, None);
        assert_eq!(r.status, EvalStatus::Errored);
    }

    #[test]
    fn a_duplicate_assertion_label_is_one_scorer_not_two() {
        let out = outcome("hello", 1, None);
        let a = Assertion::Contains {
            value: "hello".into(),
        };
        let r = sc(&case("c"), &out, &[a.clone(), a]);
        assert_eq!(
            r.scores.len(),
            1,
            "the same scorer asked twice is one entry, so the mean divides by 1"
        );
        assert_eq!(r.score, Some(1.0));
    }

    // ── The per-item rows ───────────────────────────────────────────────────

    fn resolved(name: &str, item: Option<Uuid>) -> ResolvedCase {
        ResolvedCase {
            case: case(name),
            dataset_item_id: item,
        }
    }

    #[test]
    fn item_rows_align_positionally_and_carry_the_frozen_item_id() {
        let t = tid(7);
        let run = Uuid::new_v4();
        let d = Uuid::new_v4();
        let snap = Uuid::new_v4();
        let i0 = Uuid::new_v4();
        let i1 = Uuid::new_v4();
        let cases = vec![resolved("a", Some(i0)), resolved("b", Some(i1))];
        let results = vec![
            sc(&case("a"), &outcome("ok", 5, Some(0.01)), &[]),
            errored_case("b", "boom".into()),
        ];
        let rows = build_item_rows(&t, run, Some(d), Some(snap), 1_700, &cases, &results);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].item_ordinal, 0);
        assert_eq!(rows[0].dataset_item_id, i0);
        assert_eq!(rows[0].case_name, "a");
        assert_eq!(rows[0].status, "passed");
        assert_eq!(rows[0].cost_usd, Some(0.01));
        assert_eq!(rows[1].item_ordinal, 1);
        assert_eq!(rows[1].dataset_item_id, i1);
        assert_eq!(rows[1].status, "errored");
        assert_eq!(rows[1].error.as_deref(), Some("boom"));
        assert_eq!(rows[1].score, None, "an errored item has NO score");
        assert_eq!(rows[1].scores, "{}");
        // The PARTITION key is the RUN's start, identical on every row, so one
        // run's items can never straddle a month boundary into two partitions.
        assert!(rows.iter().all(|r| r.started_at == 1_700));
        assert!(rows.iter().all(|r| r.tenant_id == t.to_string()));
    }

    #[test]
    fn a_run_that_stopped_early_writes_only_the_items_that_ran() {
        let t = tid(7);
        let cases = vec![
            resolved("a", Some(Uuid::new_v4())),
            resolved("b", Some(Uuid::new_v4())),
            resolved("c", Some(Uuid::new_v4())),
        ];
        // Budget abort after one chunk: one result for three cases.
        let results = vec![sc(&case("a"), &outcome("ok", 5, None), &[])];
        let rows = build_item_rows(&t, Uuid::new_v4(), None, None, 1, &cases, &results);
        assert_eq!(
            rows.len(),
            1,
            "zip stops at the shorter side — a partial run writes only what it measured"
        );
        assert_eq!(rows[0].case_name, "a");
    }

    #[test]
    fn an_inline_case_writes_the_nil_item_id_never_a_fabricated_one() {
        let t = tid(7);
        let cases = vec![resolved("inline", None)];
        let results = vec![sc(&case("inline"), &outcome("ok", 5, None), &[])];
        let rows = build_item_rows(&t, Uuid::new_v4(), None, None, 1, &cases, &results);
        assert!(
            rows[0].dataset_item_id.is_nil(),
            "an inline case has no frozen item; the column's own comment names nil"
        );
        assert_eq!(rows[0].dataset_id, None);
        assert_eq!(rows[0].dataset_snapshot_id, None);
    }

    /// **R81 — an eval span carries `tracelane_eval_run_id`; an ordinary span omits it.**
    ///
    /// BOTH DIRECTIONS, and the negative one is the load-bearing half. Before R81 the
    /// engine emitted NO span at all, so "eval spans are unmarked" and "there are no
    /// eval spans" were indistinguishable from any query filtering on the attribute —
    /// which is how a prod count of 0 read for months as "quiet" rather than "absent".
    #[test]
    fn an_eval_span_is_marked_and_an_ordinary_span_is_not() {
        let plain = tracelane_shared::span::SpanAttributes::default();
        assert!(
            plain.tracelane_eval_run_id.is_none(),
            "an ordinary gateway span must not claim to belong to an eval run"
        );
        // It must OMIT the key, not emit a null: a ClickHouse
        // `JSONHas(attributes,'tracelane_eval_run_id')` is what separates the two
        // populations, and a null would make it match every span ever written.
        let plain_json = serde_json::to_string(&plain).expect("plain serialize");
        assert!(
            !plain_json.contains("tracelane_eval_run_id"),
            "unmarked span must omit the key entirely, or JSONHas matches everything: {plain_json}"
        );

        let rid = Uuid::new_v4();
        let attrs = tracelane_shared::span::SpanAttributes {
            tracelane_eval_run_id: Some(rid.to_string()),
            ..Default::default()
        };
        // It must survive the wire. The span reaches ClickHouse as JSON, and a field
        // that serialises away is indistinguishable from one that was never set.
        let json = serde_json::to_string(&attrs).expect("attrs serialize");
        assert!(
            json.contains("tracelane_eval_run_id"),
            "marker must reach the wire: {json}"
        );
        let back: tracelane_shared::span::SpanAttributes =
            serde_json::from_str(&json).expect("attrs round-trip");
        assert_eq!(back.tracelane_eval_run_id, Some(rid.to_string()));
    }

    #[test]
    fn a_dataset_source_parses_with_and_without_a_snapshot_id() {
        let pinned: CaseSource = serde_json::from_str(
            r#"{"source":"dataset","dataset_id":"00000000-0000-0000-0000-0000000000d0","snapshot_id":"00000000-0000-0000-0000-00000000005a"}"#,
        )
        .expect("a pinned dataset source must parse");
        assert!(matches!(
            pinned,
            CaseSource::Dataset { dataset_id, snapshot_id: Some(s) } if dataset_id == DS && s == SNAP
        ));

        let latest: CaseSource = serde_json::from_str(
            r#"{"source":"dataset","dataset_id":"00000000-0000-0000-0000-0000000000d0"}"#,
        )
        .expect("an unpinned dataset source must parse and mean `newest`");
        assert!(matches!(
            latest,
            CaseSource::Dataset {
                dataset_id,
                snapshot_id: None
            } if dataset_id == DS
        ));
    }

    // ────────────────────────────────────────────────────────────────────────
    // `EVL-23` — the judge. `CLAUDE.md` §21 binds these directly: the judge is a
    // consumer of LLM output that makes a decision, so a non-conforming response
    // must be REFUSED, not interpreted.
    // ────────────────────────────────────────────────────────────────────────

    fn jd(score: f64) -> JudgeDetail {
        JudgeDetail {
            score,
            verdict: if score >= 0.5 { "pass" } else { "fail" }.into(),
            reason: "because".into(),
            model: "claude-haiku-4-5".into(),
            rubric: "answers_the_question".into(),
            cost_usd: Some(0.0004),
            latency_ms: 412,
        }
    }

    fn judge_assertion(min_score: f64) -> Assertion {
        Assertion::LlmJudge {
            rubric: JudgeRubric::BuiltIn {
                name: "answers_the_question".into(),
            },
            model: None,
            min_score,
        }
    }

    /// The happy path, and the shape the whole contract rests on.
    #[test]
    fn a_conforming_judge_response_parses_to_its_three_fields() {
        let v = judge::validate(r#"{"score": 0.83, "verdict": "pass", "reason": "Answers it."}"#)
            .expect("a conforming response must parse");
        assert!((v.score - 0.83).abs() < f64::EPSILON);
        assert_eq!(v.verdict, "pass");
        assert_eq!(v.reason, "Answers it.");
    }

    /// **THE §21 PROOF.** `{"score": 1.7}` is STRUCTURALLY PERFECT — all three
    /// keys present, `score` genuinely a number — and the reused structural
    /// validator passes it. Only the range check written in stage 2 refuses it.
    ///
    /// This test is the reason stage 2 exists: deleting the range check makes
    /// this case report a PASSING judge with a score above its own scale, which
    /// would open a promotion gate on a number that cannot mean anything.
    #[test]
    fn an_out_of_range_score_is_refused_even_though_it_is_structurally_valid() {
        // First prove the structural half really does accept it, so the test
        // cannot pass for the wrong reason.
        let parsed: serde_json::Value =
            serde_json::from_str(r#"{"score": 1.7, "verdict": "pass", "reason": "ok"}"#).unwrap();
        assert!(
            crate::predictive::tool_schema_validator::validate_call(
                "judge_response",
                &judge::response_schema(),
                &parsed,
            )
            .is_empty(),
            "the STRUCTURAL validator must accept this — if it rejects it, this test is \
             not testing the range check"
        );

        let e = judge::validate(r#"{"score": 1.7, "verdict": "pass", "reason": "ok"}"#)
            .expect_err("1.7 is outside 0.0–1.0 and must be refused");
        assert!(e.contains("1.7"), "the message must name the value: {e}");
        assert!(
            e.contains("0.0–1.0"),
            "the message must name the range: {e}"
        );

        for bad in [
            r#"{"score": -0.2, "verdict": "fail", "reason": "ok"}"#,
            r#"{"score": 1.0000001, "verdict": "pass", "reason": "ok"}"#,
        ] {
            assert!(judge::validate(bad).is_err(), "must refuse {bad}");
        }
    }

    /// Prose is NOT rescued. There is deliberately no regex scavenge for the
    /// first `{…}` — guessing which brace was the answer is the "gate that
    /// guesses at an uninterpretable result" §21 forbids.
    #[test]
    fn prose_is_refused_and_no_regex_scavenge_rescues_it() {
        let e =
            judge::validate("I think this is a good answer.").expect_err("prose must not parse");
        assert!(e.contains("could not parse a JSON object"), "{e}");

        // A JSON object EMBEDDED in prose is still a refusal — this is the case a
        // scavenger would have "rescued", and rescuing it is the bug.
        let e = judge::validate(
            r#"Sure! Here is my grade: {"score": 0.9, "verdict": "pass", "reason": "good"} Hope that helps."#,
        )
        .expect_err("an embedded object must NOT be scavenged out of prose");
        assert!(e.contains("could not parse a JSON object"), "{e}");
    }

    /// One markdown fence pair IS stripped — the single most common way a model
    /// wraps JSON, and the whole extraction budget.
    #[test]
    fn exactly_one_markdown_fence_pair_is_stripped() {
        let v = judge::validate(
            "```json\n{\"score\": 0.5, \"verdict\": \"fail\", \"reason\": \"partial\"}\n```",
        )
        .expect("a fenced object must parse");
        assert!((v.score - 0.5).abs() < f64::EPSILON);
        // A bare fence with no language tag too.
        assert!(
            judge::validate("```\n{\"score\": 0.5, \"verdict\": \"fail\", \"reason\": \"p\"}\n```")
                .is_ok()
        );
    }

    /// Every other way the contract can be broken, refused with the field named.
    #[test]
    fn the_judge_contract_is_refused_field_by_field() {
        let cases: [(&str, &str); 6] = [
            (r#"{"verdict": "pass", "reason": "ok"}"#, "score"),
            (r#"{"score": 0.9, "reason": "ok"}"#, "verdict"),
            (r#"{"score": 0.9, "verdict": "pass"}"#, "reason"),
            (
                r#"{"score": "0.9", "verdict": "pass", "reason": "ok"}"#,
                "score",
            ),
            (
                r#"{"score": 0.9, "verdict": "PASS", "reason": "ok"}"#,
                "verdict",
            ),
            (
                r#"{"score": 0.9, "verdict": "pass", "reason": ""}"#,
                "reason",
            ),
        ];
        for (body, field) in cases {
            let e = judge::validate(body).expect_err(&format!("must refuse {body}"));
            assert!(
                e.contains(field),
                "the refusal must name `{field}`, got: {e} (for {body})"
            );
        }
        // An undeclared key is a refusal too — `additionalProperties: false`.
        assert!(
            judge::validate(
                r#"{"score": 0.9, "verdict": "pass", "reason": "ok", "confidence": 0.4}"#
            )
            .is_err(),
            "an undeclared key must be refused"
        );
        // A 2001-char reason is NON-CONFORMANCE, never a truncation.
        let long = format!(
            r#"{{"score": 0.9, "verdict": "pass", "reason": "{}"}}"#,
            "x".repeat(judge::MAX_REASON_CHARS + 1)
        );
        let e = judge::validate(&long).expect_err("an over-long reason must be refused");
        assert!(e.contains("2001"), "the message must name the length: {e}");
    }

    /// A judge that did not conform makes the case **ERRORED, never FAILED** —
    /// and carries NO `judge` object, so no unvalidated number can reach a
    /// surface beside the error.
    #[test]
    fn a_non_conforming_judge_errors_the_case_and_renders_no_score() {
        let a = judge_assertion(0.7);
        let r = PromptEvalEngine::score(
            &case("c"),
            &outcome("anything", 10, Some(0.01)),
            std::slice::from_ref(&a),
            &[Some(Err(
                "judge response did not conform: `score` 1.7 is outside 0.0–1.0".into(),
            ))],
        );
        assert_eq!(
            r.status,
            EvalStatus::Errored,
            "a judge that was not understood is not a bad prompt"
        );
        assert!(r.assertions[0].error.is_some());
        assert!(
            r.assertions[0].judge.is_none(),
            "an unvalidated judge response must never be rendered as a detail"
        );
        assert!(
            r.scores.is_empty() && r.score.is_none(),
            "an errored rule contributes NOTHING — never a 0.0 that reads as measured"
        );
    }

    /// **The judge contributes its CONTINUOUS score to the map, not 1.0/0.0.**
    /// This is what `CaseResult::scores` was built for; flattening it would make
    /// a 0.68 that just missed a 0.70 gate indistinguishable from a 0.02.
    #[test]
    fn a_judge_contributes_its_continuous_score_not_a_pass_flag() {
        let a = judge_assertion(0.7);
        let r = PromptEvalEngine::score(
            &case("c"),
            &outcome("out", 10, Some(0.01)),
            std::slice::from_ref(&a),
            &[Some(Ok(jd(0.68)))],
        );
        assert_eq!(r.status, EvalStatus::Failed, "0.68 < 0.70 fails the rule");
        assert_eq!(
            r.score,
            Some(0.68),
            "the MAP must carry 0.68, not the 0.0 a pass-flag would give"
        );
        assert_eq!(r.assertions[0].judge.as_ref().unwrap().score, 0.68);

        let r = PromptEvalEngine::score(
            &case("c"),
            &outcome("out", 10, Some(0.01)),
            std::slice::from_ref(&a),
            &[Some(Ok(jd(0.83)))],
        );
        assert_eq!(r.status, EvalStatus::Passed);
        assert_eq!(r.score, Some(0.83));
    }

    /// **`score` decides, `verdict` is advisory.** A judge that says "pass" while
    /// scoring below the author's threshold does not open the gate — the author's
    /// declared number wins over a model's adjective.
    #[test]
    fn the_numeric_score_decides_and_the_judges_own_word_does_not() {
        let a = judge_assertion(0.7);
        let mut d = jd(0.4);
        d.verdict = "pass".into(); // the judge disagrees with its own number
        let r = PromptEvalEngine::score(
            &case("c"),
            &outcome("out", 10, Some(0.01)),
            std::slice::from_ref(&a),
            &[Some(Ok(d))],
        );
        assert_eq!(
            r.status,
            EvalStatus::Failed,
            "0.4 < 0.7 fails regardless of the judge saying \"pass\""
        );
        assert_eq!(
            r.assertions[0].judge.as_ref().unwrap().verdict,
            "pass",
            "the disagreement is RECORDED, not erased — it is advisory, not absent"
        );
    }

    /// A judge slot that never arrived is an ERROR, never a silent `false`. A
    /// missing result read as "did not pass" is a fabricated verdict.
    #[test]
    fn a_judge_with_no_result_errors_rather_than_failing_silently() {
        let a = judge_assertion(0.7);
        let r = PromptEvalEngine::score(
            &case("c"),
            &outcome("out", 10, Some(0.01)),
            std::slice::from_ref(&a),
            &[None],
        );
        assert_eq!(r.status, EvalStatus::Errored);
        assert!(
            r.assertions[0]
                .error
                .as_ref()
                .unwrap()
                .contains("the judge was never called")
        );
    }

    /// Judge slots are POSITIONAL. Two judges with identical bodies would collide
    /// on any body-derived key, and the collision would score one case with
    /// another's judgement.
    #[test]
    fn judge_slots_align_positionally_with_their_assertions() {
        let asserts = vec![
            Assertion::Contains { value: "ok".into() },
            judge_assertion(0.5),
        ];
        let r = PromptEvalEngine::score(
            &case("c"),
            &outcome("ok", 10, Some(0.01)),
            &asserts,
            &[None, Some(Ok(jd(0.9)))],
        );
        assert!(
            r.assertions[0].judge.is_none(),
            "slot 0 is a `contains` rule and must carry no judge detail"
        );
        assert_eq!(r.assertions[1].judge.as_ref().unwrap().score, 0.9);
        // The mean is over BOTH scorers: contains=1.0, judge=0.9.
        assert_eq!(r.score, Some(0.95));
    }

    // ── The code evaluators ────────────────────────────────────────────────

    /// `json_schema` checks CONFORMANCE, which is the whole point of deleting
    /// `json_valid`: the old rule passed anything that parsed.
    #[test]
    fn json_schema_checks_conformance_where_json_valid_checked_only_parseability() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": { "order": { "type": "string" } },
            "required": ["order"],
        });
        let a = Assertion::JsonSchema {
            schema: schema.clone(),
        };
        assert!(ev(&a, &outcome(r#"{"order":"ORDER-1"}"#, 1, None)).unwrap());
        assert!(
            !ev(&a, &outcome(r#"{"nope":1}"#, 1, None)).unwrap(),
            "a missing required key must FAIL — `json_valid` would have passed this"
        );
        assert!(
            !ev(&a, &outcome(r#"{"order":123}"#, 1, None)).unwrap(),
            "a wrong type must FAIL — `json_valid` would have passed this too"
        );
        // Output that is not JSON at all is the AUTHOR's expectation being wrong
        // about the prompt, so it is an ERROR with a reason, not a bare false.
        assert!(ev(&a, &outcome("not json", 1, None)).is_err());
    }

    /// Length bounds are in CHARACTERS, not bytes. A byte bound on multi-byte
    /// output measures the encoding rather than the answer.
    #[test]
    fn length_bounds_count_characters_not_bytes() {
        let five_chars_ten_bytes = "héllo"; // 5 chars, 6 bytes
        let a = Assertion::LengthBounds {
            min_chars: Some(5),
            max_chars: Some(5),
        };
        assert!(
            ev(&a, &outcome(five_chars_ten_bytes, 1, None)).unwrap(),
            "5 chars must satisfy a 5..=5 bound even though it is 6 bytes"
        );
        assert!(
            !ev(
                &Assertion::LengthBounds {
                    min_chars: Some(6),
                    max_chars: None,
                },
                &outcome(five_chars_ten_bytes, 1, None)
            )
            .unwrap()
        );
        // An open bound on either side is honoured.
        assert!(
            ev(
                &Assertion::LengthBounds {
                    min_chars: None,
                    max_chars: Some(99),
                },
                &outcome(five_chars_ten_bytes, 1, None)
            )
            .unwrap()
        );
    }

    /// `exact_match` with no reference is an **ERROR**, never a failure.
    ///
    /// This is the founder's sequencing constraint made executable: production
    /// captures input only, so a trace-derived item has no `expected`. Scoring an
    /// absent reference as a miss would manufacture a regression nobody measured.
    #[test]
    fn exact_match_without_a_reference_errors_rather_than_scoring_a_miss() {
        let a = Assertion::ExactMatch {
            value: None,
            trim: true,
        };
        let no_reference = case("from-a-trace"); // `expected: None`
        let e = a
            .evaluate(&no_reference, &outcome("anything", 1, None), None)
            .expect_err("an absent reference is UNKNOWN, not a failure");
        assert!(format!("{e:#}").contains("no reference"), "{e:#}");
    }

    /// With a reference — inline or from the item — it compares, and the item's
    /// own `expected` is used when no inline value is given. That is what makes a
    /// hand-authored dataset item scoreable.
    #[test]
    fn exact_match_reads_the_items_expected_when_no_inline_value_is_given() {
        let mut authored = case("hand-written");
        authored.expected = Some(serde_json::json!("PARIS"));
        let a = Assertion::ExactMatch {
            value: None,
            trim: true,
        };
        assert!(
            a.evaluate(&authored, &outcome("  PARIS\n", 1, None), None)
                .unwrap(),
            "trim defaults on: a trailing newline from a provider is not a wrong answer"
        );
        assert!(
            !a.evaluate(&authored, &outcome("LONDON", 1, None), None)
                .unwrap()
        );
        // A JSON string reference compares as its CONTENT, never as `"quoted"`.
        assert!(
            !a.evaluate(&authored, &outcome("\"PARIS\"", 1, None), None)
                .unwrap(),
            "the reference is PARIS, not \\\"PARIS\\\""
        );
        // An inline value WINS over the item's own expected.
        let inline = Assertion::ExactMatch {
            value: Some("LONDON".into()),
            trim: true,
        };
        assert!(
            inline
                .evaluate(&authored, &outcome("LONDON", 1, None), None)
                .unwrap()
        );
        // trim: false is exact.
        let strict = Assertion::ExactMatch {
            value: Some("PARIS".into()),
            trim: false,
        };
        assert!(
            !strict
                .evaluate(&authored, &outcome("PARIS\n", 1, None), None)
                .unwrap()
        );
    }

    /// The wire names are the API. A rename here is a breaking change to a
    /// documented body, so it is pinned rather than left to `rename_all`.
    #[test]
    fn the_assertion_wire_names_are_pinned() {
        let cases: [(&str, serde_json::Value); 4] = [
            (
                "json_schema",
                serde_json::json!({"kind": "json_schema", "schema": {}}),
            ),
            (
                "length_bounds",
                serde_json::json!({"kind": "length_bounds", "max_chars": 10}),
            ),
            (
                "exact_match",
                serde_json::json!({"kind": "exact_match", "value": "x"}),
            ),
            (
                "llm_judge",
                serde_json::json!({
                    "kind": "llm_judge",
                    "rubric": {"source": "built_in", "name": "groundedness"},
                    "min_score": 0.7
                }),
            ),
        ];
        for (name, body) in cases {
            let a: Assertion = serde_json::from_value(body)
                .unwrap_or_else(|e| panic!("`{name}` must deserialize: {e}"));
            assert!(
                a.label().starts_with(name.split('_').next().unwrap()),
                "`{name}` produced label {:?}",
                a.label()
            );
        }
        // `json_valid` is GONE from the wire, not merely undocumented.
        assert!(
            serde_json::from_value::<Assertion>(serde_json::json!({"kind": "json_valid"})).is_err(),
            "`json_valid` must no longer deserialize — it was DELETED (CLAUDE.md §21)"
        );
    }

    /// `trim` defaults to `true` when the field is absent, so an existing body
    /// that omits it gets the forgiving comparison rather than `false`.
    #[test]
    fn exact_match_trim_defaults_to_true_when_the_field_is_absent() {
        let a: Assertion =
            serde_json::from_value(serde_json::json!({"kind": "exact_match", "value": "x"}))
                .unwrap();
        let Assertion::ExactMatch { trim, .. } = a else {
            panic!("wrong variant")
        };
        assert!(trim, "an omitted `trim` must default to true");
    }

    /// An `AssertionResult` written BEFORE item 10 still deserializes — the
    /// `judge` field is additive, so no `results_json` already on disk becomes
    /// unreadable. A run whose own record has stopped parsing is the opposite of
    /// an audit product.
    #[test]
    fn an_assertion_result_written_before_the_judge_still_deserializes() {
        let old = r#"{"rule":"contains(\"x\")","passed":true}"#;
        let r: AssertionResult = serde_json::from_str(old).expect("old rows must still parse");
        assert!(r.passed);
        assert!(r.judge.is_none());
    }

    /// The three built-in rubric names resolve, and an unknown one does not —
    /// caught at `start_run`, before a cent is spent on N cases.
    #[test]
    fn the_built_in_rubrics_resolve_and_an_unknown_name_does_not() {
        for n in judge::BUILT_IN_NAMES {
            let text = judge::built_in(n).unwrap_or_else(|| panic!("`{n}` must resolve"));
            assert!(text.len() > 100, "`{n}` must be a real rubric, not a stub");
        }
        assert!(judge::built_in("vibes").is_none());
        // The contract is OURS, appended to every rubric — a tenant's own rubric
        // cannot weaken it, so no built-in may already contain it.
        for n in judge::BUILT_IN_NAMES {
            assert!(
                !judge::built_in(n).unwrap().contains("\"verdict\""),
                "`{n}` must not state its own output contract"
            );
        }
    }

    /// The judge's prompt carries the instruction, the input and the FULL output,
    /// delimited. It scores the full output rather than the truncated display
    /// copy — scoring the display copy would make the number a lie.
    #[test]
    fn the_judge_prompt_carries_the_full_untruncated_output() {
        let big = "z".repeat(limits::CASE_OUTPUT_BYTES + 500);
        let out = outcome(&big, 1, None);
        let p = PromptEvalEngine::judge_prompt("be terse", &case("c"), &out);
        assert!(p.contains("<system_instruction>\nbe terse\n</system_instruction>"));
        assert!(p.contains("<input>"), "{}", &p[..200]);
        assert!(
            p.contains(&big),
            "the judge must see the FULL output, not the {}-byte display copy",
            limits::CASE_OUTPUT_BYTES
        );
        // No system instruction ⇒ no empty block.
        let p = PromptEvalEngine::judge_prompt("", &case("c"), &out);
        assert!(!p.contains("<system_instruction>"));
    }
}
