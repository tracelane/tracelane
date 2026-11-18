//! Offline synthetic evaluation of real rail cores, not routing or enforcement.
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use serde_json::{Value, json};
use tracelane_shared::{ChatRequest, ContentPart, TenantId};
use ulid::Ulid;
use uuid::Uuid;

use super::capability::{CapabilityRegistry, CapabilitySet};
use super::context::{ExpectedFormat, GuardrailContext, ResponseBuffer, SessionState};
use super::outcome::{Outcome, RailOutcome};
use super::rails::{
    r1_cost::R1Cost,
    r2_secrets_pii::R2SecretsPii,
    r3_tool_safety::{R3Pinning, R3Schema},
    r4_trifecta::R4Trifecta,
    r5_format::R5Format,
    r6_sysprompt_leak::R6SysPromptLeak,
    r7_topic_competitor::{R7Config, R7TopicCompetitor},
};

fn corpus_text() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../evals/guardrails/cases.json"
    ))
    .expect("committed labelled corpus must exist")
}

fn corpus() -> Vec<Value> {
    serde_json::from_str(&corpus_text()).expect("labelled corpus must be valid JSON")
}

#[test]
fn corpus_has_unique_labels_and_all_rails() {
    let cases = corpus();
    let mut ids = HashSet::new();
    let rails = ["R1", "R2", "R3", "R4", "R5", "R6", "R7"];
    for case in &cases {
        assert!(ids.insert(case["id"].as_str().unwrap()));
        assert!(!case["rationale"].as_str().unwrap().is_empty());
        assert!(case["positive"].is_boolean());
        assert!(rails.contains(&case["rail"].as_str().unwrap()));
    }
    for rail in rails {
        for label in [true, false] {
            assert!(
                cases
                    .iter()
                    .any(|c| c["rail"] == rail && c["positive"] == label)
            );
        }
    }
    for (rail, profile) in [
        ("R1", "session_calls_supplied"),
        ("R1", "response_usage_supplied"),
        ("R2", "request"),
        ("R2", "response"),
        ("R2", "relay_egress"),
        ("R2", "custom"),
        ("R3", "schema"),
        ("R3", "pinning_approved"),
        ("R4", "configured_session_supplied"),
        ("R4", "empty_registry_session_supplied"),
        ("R7", "default"),
        ("R7", "configured"),
    ] {
        for label in [true, false] {
            assert!(
                cases.iter().any(|c| c["rail"] == rail
                    && c["profile"] == profile
                    && c["positive"] == label)
            );
        }
    }
}

fn evaluate(case: &Value) -> RailOutcome {
    let tenant = TenantId::from_jwt_claim(Uuid::from_u128(0x58));
    let mut request: ChatRequest = serde_json::from_value(case["request"].clone()).unwrap();
    if let Some(count) = case["repeat_calls"].as_u64() {
        assert!((1..=200).contains(&count), "fixture repetition is bounded");
        let template = request.messages[0].clone();
        request.messages = (0..count)
            .map(|i| {
                let mut message = template.clone();
                if let tracelane_shared::MessageContent::Parts(parts) = &mut message.content
                    && let ContentPart::ToolUse { id, input, .. } = &mut parts[0]
                {
                    *id = format!("c{i}");
                    if case["vary_calls"] == true {
                        *input = json!({"n": i});
                    }
                }
                message
            })
            .collect();
    }
    let mut registry = CapabilityRegistry::new();
    if case["registered"] == true {
        registry.register("send", CapabilitySet::CAN_EXFILTRATE);
        registry.register("local", CapabilitySet::empty());
    }
    if case["pin"] == true {
        let tool = &request.tools.as_ref().unwrap()[0];
        registry.register_pinned(
            &tool.name,
            CapabilitySet::empty(),
            super::capability::def_hash(
                &tool.name,
                &tool.input_schema,
                tool.description.as_deref().unwrap_or(""),
            ),
        );
    }
    if case["drift"] == true {
        request.tools.as_mut().unwrap()[0].description =
            Some("Changed fixture definition.".to_owned());
    }
    let mut session = SessionState::fresh(None);
    session.calls_in_window = u32::try_from(case["session_calls"].as_u64().unwrap_or(0)).unwrap();
    session.taint.tainted = case["tainted"] == true;
    session.taint.private_data_read = case["private_read"] == true;
    let mut ctx = GuardrailContext::from_request(
        &tenant,
        None,
        Ulid::from_parts(1, 1),
        &request,
        &registry,
        Vec::new(),
        session,
    );
    if let Some(tokens) = case["input_tokens"].as_u64() {
        ctx.est_input_tokens = u32::try_from(tokens).unwrap();
    }
    let mut buf = ResponseBuffer::new();
    if let Some(response) = case["response"].as_str() {
        buf.push_chunk(response);
        ctx.response_buf = Some(&buf);
    }
    ctx.egress_json = case.get("egress_json");
    let usage = tracelane_shared::Usage {
        input_tokens: 0,
        output_tokens: u32::try_from(case["output_tokens"].as_u64().unwrap_or(0)).unwrap(),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    };
    if case.get("output_tokens").is_some() {
        ctx.usage = Some(&usage);
    }
    let fmt = ExpectedFormat {
        json: true,
        schema: case.get("schema").filter(|v| !v.is_null()).cloned(),
    };
    match case["rail"].as_str().unwrap() {
        "R1" => R1Cost::new().evaluate_sync(&ctx),
        "R2" if case["profile"] == "custom" => {
            // GWY-63: one workspace pattern, the shape a customer writes (word-bounded).
            ctx.policy = crate::guardrail::policy::Policy::parse(&json!({"rails":{"R2_secrets_pii":{
                "pii":{"classes":{},"custom":[{"name":"employee_id","pattern":r"(?-u:\b)EMP-[0-9]{6}(?-u:\b)","action":"redact"}]}}}}))
            .expect("custom fixture policy");
            R2SecretsPii::new().evaluate_sync(&ctx)
        }
        "R2" => R2SecretsPii::new().evaluate_sync(&ctx),
        "R3" if case["profile"].as_str().unwrap().starts_with("pinning_") => {
            R3Pinning::new().evaluate_sync(&ctx)
        }
        "R3" => R3Schema::new().evaluate_sync(&ctx),
        "R4" => R4Trifecta::new().evaluate_sync(&ctx),
        "R5" => {
            ctx.expected_format = Some(&fmt);
            R5Format::new().evaluate_sync(&ctx)
        }
        "R6" => R6SysPromptLeak::new().evaluate_sync(&ctx),
        "R7" => {
            let config = match case["profile"].as_str().unwrap() {
                "default" => R7Config::default(),
                "configured" => R7Config::new(&["restricted fixture topic"], &["AcmeFixture"]),
                profile => panic!("unknown R7 profile: {profile}"),
            };
            R7TopicCompetitor::with_config(Arc::new(config)).evaluate_sync(&ctx)
        }
        rail => panic!("unknown rail: {rail}"),
    }
}

#[derive(Default, serde::Serialize)]
struct Counts {
    tp: u64,
    fp: u64,
    tn: u64,
    r#fn: u64,
    not_applicable: u64,
    fail_open: u64,
}

impl Counts {
    fn record(&mut self, positive: bool, outcome: Outcome) {
        let detected = matches!(outcome, Outcome::Warn | Outcome::Redact | Outcome::Block);
        match (positive, detected) {
            (true, true) => self.tp += 1,
            (false, true) => self.fp += 1,
            (false, false) => self.tn += 1,
            (true, false) => self.r#fn += 1,
        }
        self.not_applicable += u64::from(outcome == Outcome::NotApplicable);
        self.fail_open += u64::from(outcome == Outcome::FailOpen);
    }
    fn total(&self) -> u64 {
        self.tp + self.fp + self.tn + self.r#fn
    }
}

fn rate(n: u64, d: u64) -> Option<f64> {
    (d != 0).then(|| n as f64 / d as f64)
}

fn measure(rail: &str) {
    let mut profiles: BTreeMap<String, Counts> = BTreeMap::new();
    let mut predictions = Vec::new();
    for case in corpus().iter().filter(|c| c["rail"] == rail) {
        let out = evaluate(case);
        let positive = case["positive"].as_bool().unwrap();
        let profile = case["profile"].as_str().unwrap_or("core");
        profiles
            .entry(profile.to_owned())
            .or_default()
            .record(positive, out.outcome);
        predictions.push(
            json!({"id":case["id"], "positive":positive, "profile":profile,
            "outcome":out.outcome, "reason":out.reason_code}),
        );
    }
    assert!(!predictions.is_empty());
    let summaries: Vec<Value> = profiles
        .iter()
        .map(|(name, c)| {
            json!({
                "profile":name, "n":c.total(), "counts":c,
                "false_positive_rate":rate(c.fp, c.fp+c.tn),
                "false_negative_rate":rate(c.r#fn, c.r#fn+c.tp)
            })
        })
        .collect();
    assert_eq!(
        profiles.values().map(Counts::total).sum::<u64>(),
        predictions.len() as u64
    );
    println!(
        "GUARDRAIL_EVAL {}",
        json!({"rail":rail,
        "corpus_blake3":blake3::hash(corpus_text().as_bytes()).to_hex().to_string(),
        "profiles":summaries, "predictions":predictions})
    );
}

#[test]
fn labelled_r1() {
    measure("R1");
}
#[test]
fn labelled_r2() {
    measure("R2");
}
#[test]
fn labelled_r3() {
    measure("R3");
}
#[test]
fn labelled_r4() {
    measure("R4");
}
#[test]
fn labelled_r5() {
    measure("R5");
}
#[test]
fn labelled_r6() {
    measure("R6");
}
#[test]
fn labelled_r7() {
    measure("R7");
}

#[test]
fn confusion_counts_all_four_cells() {
    let mut c = Counts::default();
    for (label, outcome) in [
        (true, Outcome::Warn),
        (false, Outcome::Redact),
        (false, Outcome::Allow),
        (true, Outcome::Allow),
    ] {
        c.record(label, outcome);
    }
    assert_eq!((c.tp, c.fp, c.tn, c.r#fn, c.total()), (1, 1, 1, 1, 4));
    assert_eq!(rate(c.fp, c.fp + c.tn), Some(0.5));
    assert_eq!(rate(c.r#fn, c.tp + c.r#fn), Some(0.5));
}

#[test]
fn positive_not_applicable_is_false_negative() {
    let mut c = Counts::default();
    c.record(true, Outcome::NotApplicable);
    c.record(true, Outcome::FailOpen);
    assert_eq!((c.r#fn, c.not_applicable, c.fail_open), (2, 1, 1));
}

#[test]
fn empty_denominator_is_unknown() {
    assert_eq!(rate(0, 0), None);
}
