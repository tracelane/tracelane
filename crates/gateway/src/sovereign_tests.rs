//! `GWY-80` scenarios. Named cases per state, then an invariant sweep over every
//! combination of configuration, request content, requested model and provider.

use super::*;
use serde_json::json;

// A Luhn-valid test card, an AWS-shaped key, an SSN shape, an email, a phone, an IPv4.
const CARD: &str = "pay with 4111 1111 1111 1111 today";
// Split so secret scanners do not flag a test fixture; the detector sees the joined text.
const SECRET: &str = concat!("key AKIA", "TESTONLYDONOTUSE here");
const SSN: &str = "ssn 123-45-6789 on file";
const EMAIL: &str = "mail jane.doe@example.com please";
const PHONE: &str = "call (415) 555-0100 now";
const IP: &str = "host 10.20.30.40 is down";
const CLEAN: &str = "what is the capital of France?";

/// A fake canonical resolver: `ollama/*` → ollama, `nvidia/*` → nvidia, `gpt-*` → openai,
/// `claude-*` → anthropic, anything else unroutable.
fn resolve(model: &str) -> Option<&'static str> {
    if model.starts_with("ollama/") {
        Some("ollama")
    } else if model.starts_with("nvidia/") {
        Some("nvidia")
    } else if model.starts_with("gpt-") {
        Some("openai")
    } else if model.starts_with("claude-") {
        Some("anthropic")
    } else {
        None
    }
}

fn cfg(classes: Option<&str>) -> SovereignConfig {
    SovereignConfig::build("ollama", "ollama/llama3.3", classes).expect("valid block")
}

fn body(text: &str) -> Value {
    json!({"model": "gpt-4o", "messages": [{"role": "user", "content": text}]})
}

// ── Config: build ───────────────────────────────────────────────────────────

#[test]
fn build_accepts_a_minimal_block_and_defaults_to_every_class() {
    let c = cfg(None);
    assert!(c.is_sovereign("ollama"));
    assert!(!c.is_sovereign("openai"));
    assert_eq!(c.model(), "ollama/llama3.3");
    assert_eq!(c.classes.len(), CLASSES.len());
}

#[test]
fn build_accepts_several_providers_and_trims() {
    let c = SovereignConfig::build(
        " ollama , nvidia ",
        " ollama/x ",
        Some("secret, credit_card"),
    )
    .expect("valid");
    assert_eq!(c.providers().collect::<Vec<_>>(), vec!["nvidia", "ollama"]);
    assert_eq!(c.model(), "ollama/x");
    assert_eq!(c.classes.len(), 2);
}

#[test]
fn build_refuses_a_native_adapter() {
    for native in [
        "anthropic",
        "google",
        "vertex",
        "bedrock",
        "azure",
        "cohere",
    ] {
        let e = SovereignConfig::build(native, "m", None).expect_err(native);
        assert!(
            e.to_string().contains("not an OpenAI-compatible"),
            "{native}: {e}"
        );
    }
}

#[test]
fn build_refuses_an_unknown_provider() {
    assert!(SovereignConfig::build("my-bank-llm", "m", None).is_err());
}

#[test]
fn build_refuses_an_empty_or_duplicate_provider() {
    assert!(SovereignConfig::build("", "m", None).is_err());
    assert!(SovereignConfig::build("ollama,", "m", None).is_err());
    assert!(SovereignConfig::build("ollama,ollama", "m", None).is_err());
}

#[test]
fn build_refuses_an_empty_model() {
    assert!(SovereignConfig::build("ollama", "  ", None).is_err());
}

#[test]
fn build_refuses_an_unknown_duplicate_or_empty_class() {
    assert!(SovereignConfig::build("ollama", "m", Some("iban")).is_err());
    assert!(SovereignConfig::build("ollama", "m", Some("Secret")).is_err());
    assert!(SovereignConfig::build("ollama", "m", Some("secret,secret")).is_err());
    assert!(SovereignConfig::build("ollama", "m", Some("")).is_err());
    assert!(SovereignConfig::build("ollama", "m", Some("unscannable")).is_err());
}

// ── Config: boot check ──────────────────────────────────────────────────────

fn env_with(var: &'static str, val: &'static str) -> impl Fn(&str) -> Option<String> {
    move |k| (k == var).then(|| val.to_owned())
}

#[test]
fn boot_passes_when_repointed_and_the_model_resolves_to_a_sovereign_provider() {
    cfg(None)
        .check_boot(
            resolve,
            env_with("OLLAMA_BASE_URL", "https://llm.bank.example"),
        )
        .expect("boots");
}

#[test]
fn boot_refuses_when_the_base_url_is_unset_blank_or_the_default() {
    let c = cfg(None);
    assert!(c.check_boot(resolve, |_| None).is_err());
    assert!(
        c.check_boot(resolve, env_with("OLLAMA_BASE_URL", "  "))
            .is_err()
    );
    assert!(
        c.check_boot(
            resolve,
            env_with("OLLAMA_BASE_URL", "http://localhost:11434")
        )
        .is_err(),
        "the catalog default is not the operator's own endpoint"
    );
}

#[test]
fn boot_refuses_the_default_spelled_differently() {
    // L1: the catalog-default check compares the parsed URL, not the string.
    let c = cfg(None);
    for same in [
        "http://LOCALHOST:11434",
        "http://localhost:11434/",
        "HTTP://localhost:11434//",
        "http://localhost",
    ] {
        let r = c.check_boot(resolve, move |k| {
            (k == "OLLAMA_BASE_URL").then(|| same.to_owned())
        });
        // `http://localhost` (port 80) is a different endpoint from the default's :11434.
        if same == "http://localhost" {
            assert!(r.is_ok(), "{same} is a different endpoint");
        } else {
            assert!(r.is_err(), "{same} is still the catalog default");
        }
    }
}

#[test]
fn boot_refuses_a_base_url_that_is_not_a_url() {
    let c = cfg(None);
    assert!(
        c.check_boot(resolve, env_with("OLLAMA_BASE_URL", "llm.bank.internal"))
            .is_err()
    );
}

#[test]
fn boot_refuses_alongside_a_control_plane_or_hosted_identity() {
    // L2: a `sovereign:` block is a single-tenant self-host control. With a control plane
    // (hosted, multi-tenant) one operator block would govern every tenant. Every signal the
    // self-host guard knows counts, and a variable that is SET counts even when empty (the
    // Postgres pool init treats it the same way).
    let c = cfg(None);
    for var in tracelane_shared::self_host::MULTI_TENANT_SIGNAL_ENVS {
        for value in ["db.example", ""] {
            let r = c.check_boot(resolve, move |k| match k {
                "OLLAMA_BASE_URL" => Some("https://llm.bank.example".to_owned()),
                k if k == *var => Some(value.to_owned()),
                _ => None,
            });
            let e = r.expect_err(var);
            assert!(e.to_string().contains(var), "{var}={value:?}: {e}");
        }
    }
}

#[test]
fn boot_refuses_a_prompt_guard_that_is_not_on_this_machine() {
    // M-A: the sidecar is sent recent request text for EVERY chat request before
    // classification. Off-box it is an egress the block would not see.
    let c = cfg(None);
    let with = |guard: &'static str| {
        c.check_boot(resolve, move |k| match k {
            "OLLAMA_BASE_URL" => Some("https://llm.bank.example".to_owned()),
            "PROMPT_GUARD_URL" => Some(guard.to_owned()),
            _ => None,
        })
    };
    for ok in [
        "http://127.0.0.1:8080",
        "http://localhost:8080/",
        "HTTP://LOCALHOST:9",
        "http://[::1]:8080",
        "http://127.3.4.5",
        "",
        "  ",
    ] {
        with(ok).unwrap_or_else(|e| panic!("{ok:?}: {e}"));
    }
    for bad in [
        "https://guard.example.com",
        "http://10.0.0.5:8080",
        "http://localhost.evil.example",
        "not a url",
        "http://0.0.0.0:8080",
    ] {
        let e = with(bad).expect_err(bad);
        assert!(e.to_string().contains("PROMPT_GUARD_URL"), "{bad}: {e}");
    }
}

#[test]
fn the_default_endpoint_is_recognised_by_host_and_port_only() {
    // Low: a different scheme or path on the catalog default host is still the default.
    let c = cfg(None);
    for url in [
        "https://localhost:11434",
        "http://LOCALHOST:11434/v1/",
        "http://localhost:11434/anything",
    ] {
        assert!(
            c.check_boot(resolve, env_with("OLLAMA_BASE_URL", url))
                .is_err(),
            "{url}"
        );
    }
}

#[test]
fn boot_refuses_a_model_that_resolves_to_a_frontier_provider() {
    let c = SovereignConfig::build("ollama", "gpt-4o", None).expect("parse-time valid");
    let e = c
        .check_boot(
            resolve,
            env_with("OLLAMA_BASE_URL", "https://llm.bank.example"),
        )
        .expect_err("frontier target");
    assert!(
        e.to_string().contains("not in `sovereign.providers`"),
        "{e}"
    );
}

#[test]
fn boot_refuses_an_unroutable_model() {
    let c = SovereignConfig::build("ollama", "mystery", None).expect("parse-time valid");
    assert!(
        c.check_boot(
            resolve,
            env_with("OLLAMA_BASE_URL", "https://llm.bank.example")
        )
        .is_err()
    );
}

#[test]
fn boot_checks_every_sovereign_provider_not_only_the_target() {
    let c = SovereignConfig::build("ollama,nvidia", "ollama/x", None).expect("valid");
    // ollama re-pointed, nvidia still on its vendor host.
    assert!(
        c.check_boot(
            resolve,
            env_with("OLLAMA_BASE_URL", "https://llm.bank.example")
        )
        .is_err()
    );
}

// ── Classification ──────────────────────────────────────────────────────────

#[test]
fn classify_names_each_detector_class() {
    for (text, class) in [
        (CARD, "credit_card"),
        (SECRET, "secret"),
        (SSN, "ssn"),
        (EMAIL, "email"),
        (PHONE, "phone"),
        (IP, "ip_address"),
    ] {
        assert!(
            classify(&body(text)).0.contains(class),
            "{class} in {text:?}"
        );
    }
}

#[test]
fn classify_clean_text_finds_nothing() {
    assert_eq!(classify(&body(CLEAN)), Found::default());
}

#[test]
fn classify_a_non_luhn_number_is_not_a_card() {
    assert!(
        !classify(&body("order 4111 1111 1111 1112"))
            .0
            .contains("credit_card")
    );
}

#[test]
fn classify_reads_tool_arguments_and_system_prompt_not_only_the_last_message() {
    let b = json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": CLEAN},
            {"role": "assistant", "content": null, "tool_calls": [{
                "id": "c1", "type": "function",
                "function": {"name": "charge", "arguments": "{\"card\":\"4111111111111111\"}"}
            }]},
            {"role": "user", "content": CLEAN}
        ]
    });
    assert!(classify(&b).0.contains("credit_card"));
}

#[test]
fn classify_reads_multipart_text_parts() {
    let b = json!({"model": "m", "messages": [{"role": "user", "content": [
        {"type": "text", "text": CLEAN},
        {"type": "text", "text": SECRET}
    ]}]});
    assert!(classify(&b).0.contains("secret"));
}

// H1: media the detector cannot read is never Clear. A base64 image, a PDF or audio may
// carry a card number the text detector cannot see, so it classifies as UNSCANNABLE.
// The payloads are real signatures (PNG, %PDF, RIFF/WAV) so the walker believes the type.
const PNG_B64: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
const PDF_B64: &str = "JVBERi0xLjQKJcOkw7zDtsOfCjIgMCBvYmoKPDwvTGVuZ3RoIDMgMCBSPj4Kc3RyZWFtCg==";
const WAV_B64: &str = "UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAIA+AAACABAAZGF0YQAAAAA=";

#[test]
fn classify_image_url_base64_is_unscannable() {
    let b = json!({"model": "m", "messages": [{"role": "user", "content": [
        {"type": "text", "text": CLEAN},
        {"type": "image_url", "image_url": {"url": format!("data:image/png;base64,{PNG_B64}")}}
    ]}]});
    assert!(classify(&b).0.contains(UNSCANNABLE));
}

#[test]
fn classify_file_data_pdf_is_unscannable() {
    let b = json!({"model": "m", "messages": [{"role": "user", "content": [
        {"type": "file", "file": {"filename": "statement.pdf",
            "file_data": format!("data:application/pdf;base64,{PDF_B64}")}}
    ]}]});
    assert!(classify(&b).0.contains(UNSCANNABLE));
}

#[test]
fn classify_input_audio_is_unscannable() {
    let b = json!({"model": "m", "messages": [{"role": "user", "content": [
        {"type": "input_audio", "input_audio": {"format": "wav", "data": WAV_B64}}
    ]}]});
    assert!(classify(&b).0.contains(UNSCANNABLE));
}

fn unscannable(content: Value) -> bool {
    let b = json!({"model": "m", "messages": [{"role": "user", "content": content}]});
    classify(&b).0.contains(UNSCANNABLE)
}

#[test]
fn a_remote_image_url_is_unscannable() {
    // H-A: the frontier model FETCHES a remote image (a presigned cheque or ID photo); the
    // detector only sees the URL string. Content it cannot read is never Clear.
    for url in [
        "https://example.com/cat.png",
        "HTTP://bucket.s3.amazonaws.com/id.jpg?X-Amz-Signature=abc",
        "gs://bucket/cheque.png",
    ] {
        assert!(
            unscannable(json!([{"type": "image_url", "image_url": {"url": url}}])),
            "{url}"
        );
    }
}

#[test]
fn a_non_base64_data_uri_is_unscannable() {
    for url in ["data:image/png,%89PNG%0D%0A", "data:text/plain,hello"] {
        assert!(
            unscannable(json!([{"type": "image_url", "image_url": {"url": url}}])),
            "{url}"
        );
    }
}

#[test]
fn a_remote_file_part_is_unscannable() {
    assert!(unscannable(json!([
        {"type": "file", "file": {"file_data": "https://example.com/statement.pdf"}}
    ])));
    assert!(unscannable(json!([
        {"type": "file", "file": {"file_id": "file-abc123"}}
    ])));
    assert!(unscannable(json!([
        {"type": "input_file", "file_id": "file-abc123"}
    ])));
}

#[test]
fn plain_text_parts_stay_clear() {
    assert!(!unscannable(json!([{"type": "text", "text": CLEAN}])));
    assert!(!unscannable(json!(CLEAN)));
}

#[test]
fn binary_media_confines_even_with_a_narrow_class_list() {
    let c = cfg(Some("secret"));
    let b = json!({"model": "gpt-4o", "messages": [{"role": "user", "content": [
        {"type": "image_url", "image_url": {"url": format!("data:image/png;base64,{PNG_B64}")}}
    ]}]});
    assert!(matches!(
        decide(Some(&c), &classify(&b), "gpt-4o", resolve),
        Decision::Confine {
            class: UNSCANNABLE,
            ..
        }
    ));
}

#[test]
fn classify_collects_every_class_present() {
    let f = classify(&body(&format!("{CARD} {EMAIL}")));
    assert!(f.0.contains("credit_card") && f.0.contains("email"));
}

#[test]
fn classify_request_reads_the_typed_request() {
    let req: tracelane_shared::ChatRequest =
        serde_json::from_value(body(CARD)).expect("chat request");
    assert!(classify_request(&req).0.contains("credit_card"));
}

// ── Decision: named states ──────────────────────────────────────────────────

#[test]
fn no_block_is_off_whatever_the_content() {
    for text in [CARD, SECRET, CLEAN] {
        assert_eq!(
            decide(None, &classify(&body(text)), "gpt-4o", resolve),
            Decision::Off
        );
    }
}

#[test]
fn clean_request_is_clear_and_keeps_its_frontier_model() {
    let c = cfg(None);
    assert_eq!(
        decide(Some(&c), &classify(&body(CLEAN)), "gpt-4o", resolve),
        Decision::Clear
    );
}

#[test]
fn card_on_a_frontier_model_is_rerouted_to_the_sovereign_model() {
    let c = cfg(None);
    assert_eq!(
        decide(Some(&c), &classify(&body(CARD)), "gpt-4o", resolve),
        Decision::Confine {
            class: "credit_card",
            model: "ollama/llama3.3".into(),
            provider: "ollama",
            rerouted: true
        }
    );
}

#[test]
fn card_already_on_a_sovereign_model_keeps_the_callers_model() {
    let c = SovereignConfig::build("ollama", "ollama/llama3.3", None).expect("valid");
    assert_eq!(
        decide(Some(&c), &classify(&body(CARD)), "ollama/qwen3", resolve),
        Decision::Confine {
            class: "credit_card",
            model: "ollama/qwen3".into(),
            provider: "ollama",
            rerouted: false
        }
    );
}

#[test]
fn an_unconfigured_class_is_clear() {
    let c = cfg(Some("secret,credit_card"));
    assert_eq!(
        decide(Some(&c), &classify(&body(EMAIL)), "gpt-4o", resolve),
        Decision::Clear
    );
}

#[test]
fn unscannable_is_confined_even_when_no_class_is_configured_for_it() {
    let c = cfg(Some("secret"));
    let found = Found::of(&[UNSCANNABLE]);
    assert!(matches!(
        decide(Some(&c), &found, "gpt-4o", resolve),
        Decision::Confine {
            class: UNSCANNABLE,
            ..
        }
    ));
}

#[test]
fn the_most_severe_class_is_recorded() {
    let c = cfg(None);
    let found = Found::of(&["email", "credit_card", "secret"]);
    assert!(matches!(
        decide(Some(&c), &found, "gpt-4o", resolve),
        Decision::Confine {
            class: "secret",
            ..
        }
    ));
}

#[test]
fn an_unroutable_sovereign_target_refuses_never_falls_back() {
    let c = SovereignConfig::build("ollama", "mystery", None).expect("valid");
    assert_eq!(
        decide(Some(&c), &classify(&body(CARD)), "gpt-4o", resolve),
        Decision::Refuse {
            class: "credit_card"
        }
    );
}

#[test]
fn a_target_that_resolves_to_a_frontier_provider_refuses() {
    let c = SovereignConfig::build("ollama", "gpt-4o-mini", None).expect("valid");
    assert_eq!(
        decide(
            Some(&c),
            &classify(&body(SECRET)),
            "claude-sonnet-4-6",
            resolve
        ),
        Decision::Refuse { class: "secret" }
    );
}

#[test]
fn an_unroutable_requested_model_with_regulated_data_is_rerouted() {
    let c = cfg(None);
    assert!(matches!(
        decide(
            Some(&c),
            &classify(&body(CARD)),
            "my-virtual-model",
            resolve
        ),
        Decision::Confine {
            rerouted: true,
            provider: "ollama",
            ..
        }
    ));
}

// ── Egress ──────────────────────────────────────────────────────────────────

#[test]
fn egress_any_permits_everything_including_unroutable() {
    let e = Egress::Any;
    assert!(e.permits(Some("openai")) && e.permits(Some("ollama")) && e.permits(None));
    assert!(!e.confined());
}

#[test]
fn egress_confined_permits_only_sovereign_providers() {
    let c = cfg(None);
    let d = decide(Some(&c), &classify(&body(CARD)), "gpt-4o", resolve);
    let e = Egress::for_decision(Some(&c), &d);
    assert!(e.confined());
    assert!(e.permits(Some("ollama")));
    for frontier in ["openai", "anthropic", "groq", "nvidia", "google"] {
        assert!(!e.permits(Some(frontier)), "{frontier}");
    }
    assert!(
        !e.permits(None),
        "an unresolved provider is never permitted"
    );
}

#[test]
fn egress_for_refuse_is_still_confined() {
    let c = cfg(None);
    let e = Egress::for_decision(Some(&c), &Decision::Refuse { class: "secret" });
    assert!(e.confined() && !e.permits(Some("openai")));
}

#[test]
fn an_unclassified_dispatch_is_refused_everywhere_while_the_block_is_on() {
    // H2: a server-side dispatch (eval case, judge, Responses translation) whose text was
    // never classified may go nowhere while the block is installed — not even sovereign.
    let c = cfg(None);
    let e = Egress::unclassified(Some(&c));
    assert!(e.confined());
    for p in [Some("ollama"), Some("openai"), Some("anthropic"), None] {
        assert!(!e.permits(p), "{p:?}");
    }
}

#[test]
fn an_unclassified_dispatch_is_unchanged_without_the_block() {
    let e = Egress::unclassified(None);
    assert!(!e.confined() && e.permits(Some("openai")));
}

#[test]
fn egress_for_clear_and_off_is_any() {
    let c = cfg(None);
    assert!(!Egress::for_decision(Some(&c), &Decision::Clear).confined());
    assert!(!Egress::for_decision(None, &Decision::Off).confined());
}

// ── Span meta ───────────────────────────────────────────────────────────────

#[test]
fn meta_is_absent_when_the_block_is_off() {
    assert_eq!(Meta::of(&Decision::Off), None);
}

#[test]
fn meta_records_clear_as_none_and_not_sovereign() {
    let m = Meta::of(&Decision::Clear).expect("meta");
    let mut a = tracelane_shared::span::SpanAttributes::default();
    m.apply(&mut a);
    assert_eq!(a.extra["tracelane_routing_data_class"], json!("none"));
    assert_eq!(a.extra["tracelane_routing_sovereign"], json!(false));
    assert!(!a.extra.contains_key("tracelane_routing_endpoint"));
}

#[test]
fn meta_records_class_endpoint_and_reroute_for_a_confined_request() {
    let m = Meta::of(&Decision::Confine {
        class: "credit_card",
        model: "ollama/x".into(),
        provider: "ollama",
        rerouted: true,
    })
    .expect("meta");
    let mut a = tracelane_shared::span::SpanAttributes::default();
    m.apply(&mut a);
    assert_eq!(
        a.extra["tracelane_routing_data_class"],
        json!("credit_card")
    );
    assert_eq!(a.extra["tracelane_routing_sovereign"], json!(true));
    assert_eq!(a.extra["tracelane_routing_endpoint"], json!("ollama"));
    assert_eq!(a.extra["tracelane_routing_rerouted"], json!(true));
}

#[test]
fn meta_never_carries_the_detected_value() {
    let c = cfg(None);
    let d = decide(Some(&c), &classify(&body(CARD)), "gpt-4o", resolve);
    let mut a = tracelane_shared::span::SpanAttributes::default();
    Meta::of(&d).expect("meta").apply(&mut a);
    let rendered = serde_json::to_string(&a.extra).expect("json");
    assert!(!rendered.contains("4111"), "{rendered}");
}

// ── Wire gate ───────────────────────────────────────────────────────────────

#[test]
fn every_other_model_egress_wire_is_refused() {
    for p in [
        "/v1/embeddings",
        "/v1/messages",
        "/v1/messages/count_tokens",
        "/v1/responses",
        "/v1/responses/input_tokens",
        "/v1/rerank",
        "/v1/moderations",
        "/v1/realtime",
        "/v1/images/generations",
        "/v1/images/edits",
        "/v1/audio/speech",
        "/v1/audio/transcriptions",
        "/v1/audio/translations",
        "/v1/files",
        "/v1/files/abc",
        "/v1/batches",
        "/v1/batches/b1/cancel",
        "/v1/passthrough/openai/v1/chat/completions",
        "/v1beta/models/gemini-2.5-pro:generateContent",
        "/v1/prompts/support-bot/evals",
        "/v1/embeddings/",
        "/v1/experiments",
        "/v1/experiments/",
        "/v1/experiments/exp-1/run",
        "/v1/responses/resp_123",
        "/v1/responses/resp_123/cancel",
    ] {
        assert!(wire_refused(p), "{p} must be refused");
    }
}

#[test]
fn only_the_allow_list_passes_the_gate() {
    for p in [
        "/v1/chat/completions",
        "/health",
        "/metrics",
        "/v1/openapi.json",
        "/v1/auth/whoami",
        "/v1/traces",
        "/v1/traces/count",
        "/v1/traces/groups",
    ] {
        assert!(!wire_refused(p), "{p} must pass");
    }
    // Everything else — control routes, lookalikes, case and dot-segment tricks — is refused.
    for p in [
        "/v1/prompts",
        "/v1/costs",
        "/v1/routing",
        "/v1/models",
        "/v1/traces/abc/spans",
        "/v1/chat/completions/extra",
        "/V1/chat/completions",
        "/v1/traces/../embeddings",
        "/v1/chat/completions%2f..",
        "",
        "/",
        "/v1/some-wire-added-next-year",
    ] {
        assert!(wire_refused(p), "{p} must be refused");
    }
}

/// A new route is refused by default: walk every `.route("<path>"` literal in the gateway
/// source. Exactly the allow-listed paths pass; every other path (including the seven handler
/// families that never reach `dispatch_to_provider`) is refused.
#[test]
fn every_route_in_the_source_is_refused_unless_allow_listed() {
    let allowed: std::collections::BTreeSet<&str> = [
        "/v1/chat/completions",
        "/health",
        "/metrics",
        "/v1/openapi.json",
        "/v1/auth/whoami",
        "/v1/traces",
        "/v1/traces/count",
        "/v1/traces/groups",
    ]
    .into_iter()
    .collect();
    let re = regex::Regex::new(r#"\.route\(\s*"(/[^"]*)""#).expect("regex");
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![src];
    let mut seen = std::collections::BTreeSet::new();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir).expect("read src").flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("read");
                for c in re.captures_iter(&text) {
                    seen.insert(c[1].to_owned());
                }
            }
        }
    }
    assert!(seen.len() > 100, "only {} routes found", seen.len());
    for model_wire in [
        "/v1/messages",
        "/v1/embeddings",
        "/v1/passthrough/{provider}/{*path}",
        "/v1/realtime",
        "/v1/files",
        "/v1/batches",
        "/v1/images/generations",
    ] {
        assert!(
            seen.contains(model_wire),
            "{model_wire} moved; update the test"
        );
    }
    for path in &seen {
        assert_eq!(
            !wire_refused(path),
            allowed.contains(path.as_str()),
            "{path}: the gate and the allow-list disagree"
        );
    }
}

#[test]
fn every_media_kind_endpoint_is_refused() {
    use crate::media_routes::Kind;
    for k in [
        Kind::ImagesGenerations,
        Kind::ImagesEdits,
        Kind::AudioSpeech,
        Kind::AudioTranscriptions,
        Kind::AudioTranslations,
        Kind::Moderations,
        Kind::Rerank,
    ] {
        assert!(wire_refused(k.endpoint()), "{}", k.endpoint());
    }
}

// ── Invariant sweep ─────────────────────────────────────────────────────────

/// Every combination of: block present/absent × configured class set × request content
/// × requested model × sovereign target × the provider a later step (plan, ZDR prune,
/// failover hop, retry) might try to dispatch to.
#[test]
fn invariant_sweep_regulated_data_never_reaches_a_non_sovereign_provider() {
    let contents: &[(&str, &[&'static str])] = &[
        (CLEAN, &[]),
        (CARD, &["credit_card"]),
        (SECRET, &["secret"]),
        (SSN, &["ssn"]),
        (EMAIL, &["email"]),
        (PHONE, &["phone"]),
        (IP, &["ip_address"]),
    ];
    let class_sets: &[Option<&str>] = &[
        None,
        Some("secret"),
        Some("credit_card,ssn"),
        Some("email,phone,ip_address"),
        Some("secret,credit_card,ssn,email,phone,ip_address"),
    ];
    let targets = ["ollama/llama3.3", "gpt-4o", "mystery"];
    let requested = [
        "gpt-4o",
        "claude-sonnet-4-6",
        "ollama/qwen3",
        "nvidia/x",
        "virtual",
    ];
    let dispatch_to: &[Option<&str>] = &[
        Some("ollama"),
        Some("nvidia"),
        Some("openai"),
        Some("anthropic"),
        Some("groq"),
        None,
    ];
    let mut cases = 0usize;
    for with_block in [false, true] {
        for classes in class_sets {
            for target in targets {
                let c = SovereignConfig::build("ollama", target, *classes).expect("valid");
                let cfg_opt = with_block.then_some(&c);
                for (text, present) in contents {
                    for extra_unscannable in [false, true] {
                        let mut found = classify(&body(text));
                        if extra_unscannable {
                            found.0.insert(UNSCANNABLE);
                        }
                        // The classifier names exactly what the fixture holds.
                        for p in *present {
                            assert!(found.0.contains(p), "{p} in {text:?}");
                        }
                        let regulated = with_block
                            && (extra_unscannable || present.iter().any(|p| c.classes.contains(p)));
                        for req in requested {
                            let d = decide(cfg_opt, &found, req, resolve);
                            let egress = Egress::for_decision(cfg_opt, &d);
                            // I1: regulated ⇔ confined (or refused); no block ⇒ Off.
                            assert_eq!(egress.confined(), regulated, "{d:?}");
                            if !with_block {
                                assert_eq!(d, Decision::Off);
                            }
                            // I2: a confined decision's own target is sovereign.
                            if let Decision::Confine {
                                provider,
                                ref model,
                                ..
                            } = d
                            {
                                assert!(c.is_sovereign(provider));
                                assert_eq!(resolve(model), Some(provider));
                            }
                            // I3: a regulated request is refused only when no sovereign
                            // target resolves — never Clear, never Off.
                            if regulated {
                                assert!(matches!(
                                    d,
                                    Decision::Confine { .. } | Decision::Refuse { .. }
                                ));
                            }
                            // I4: whatever later step picks the provider, the egress check
                            // lets a regulated request out only to a sovereign provider.
                            for pid in dispatch_to {
                                cases += 1;
                                let allowed = egress.permits(*pid);
                                if regulated {
                                    assert_eq!(
                                        allowed,
                                        pid.is_some_and(|p| c.is_sovereign(p)),
                                        "{req} {pid:?} {d:?}"
                                    );
                                } else {
                                    assert!(allowed, "unregulated traffic is unchanged");
                                }
                            }
                            // I5: the span never says sovereign for unconfined traffic and
                            // always does for confined traffic.
                            match Meta::of(&d) {
                                None => assert!(!with_block),
                                Some(m) => assert_eq!(m.sovereign, regulated),
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(cases > 10_000, "sweep covered {cases} cases");
}

// ── Through the REAL chat handler ───────────────────────────────────────────
//
// Two wiremock upstreams: `ollama` stands in for the bank's own endpoint (the sovereign
// provider; keyless), `302ai` for a frontier provider (a catalog row no other handler
// test uses; its key is seeded in the decrypted-key cache). Every assertion reads what
// each upstream RECEIVED and the RECORDED span, never only a status code.
#[cfg(debug_assertions)]
mod handler {
    use std::sync::Arc;

    use axum::extract::{Json, State};
    use axum::http::{HeaderValue, StatusCode};
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{CARD, CLEAN, SECRET};
    use crate::handler_harness::{
        LoopbackBypassGuard, authed_with_trace, body_json, chat_ok_body, dev_tenant, test_state,
    };
    use crate::server::{AppState, chat_completions_handler};
    use crate::sovereign::SovereignConfig;

    const FRONTIER: &str = "302ai/frontier-model";
    const OWN: &str = "ollama/llama3";

    async fn upstream(status: u16) -> MockServer {
        let s = MockServer::start().await;
        let t = if status == 200 {
            ResponseTemplate::new(200).set_body_json(chat_ok_body())
        } else {
            ResponseTemplate::new(status).set_body_string("down")
        };
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(t)
            .mount(&s)
            .await;
        s
    }

    fn leak(cfg: SovereignConfig) -> &'static SovereignConfig {
        Box::leak(Box::new(cfg))
    }

    /// State with `ollama` → `own` and `302ai` → `frontier`, the block given, and a
    /// failover chain whose only hop is the frontier provider.
    fn state(own: &MockServer, frontier: &MockServer, block: Option<SovereignConfig>) -> AppState {
        let mut reg = crate::providers::ProviderRegistry::new().expect("registry");
        reg.set_compat_base_url_for_test("ollama", own.uri())
            .expect("ollama");
        reg.set_compat_base_url_for_test("302ai", frontier.uri())
            .expect("302ai");
        crate::db::provider_keys::cache_decrypted(
            &dev_tenant(),
            "302ai",
            Arc::new(secrecy::SecretString::from(
                "gwy80-test-only-not-a-key".to_owned(),
            )),
        );
        let mut st = test_state(reg);
        st.sovereign = block.map(leak);
        let file: &'static crate::server::config::FileConfig = Box::leak(Box::new(
            crate::server::config::parse("failover:\n  chain: 302ai:302ai/fallback-model\n")
                .expect("failover block"),
        ));
        st.failover = file.failover();
        st
    }

    fn block() -> SovereignConfig {
        SovereignConfig::build("ollama", OWN, Some("secret,credit_card,ssn")).expect("block")
    }

    async fn ask(
        st: AppState,
        model: &str,
        text: &str,
        stream: bool,
        failover: bool,
    ) -> (axum::response::Response, uuid::Uuid) {
        let trace = uuid::Uuid::new_v4();
        let mut h = authed_with_trace(trace);
        if failover {
            h.insert(
                "x-tracelane-failover",
                HeaderValue::from_static("cross-provider"),
            );
        }
        let resp = chat_completions_handler(
            State(st),
            h,
            Json(json!({
                "model": model,
                "stream": stream,
                "messages": [{"role": "user", "content": text}],
            })),
        )
        .await;
        (resp, trace)
    }

    async fn hits(s: &MockServer) -> usize {
        s.received_requests().await.map_or(0, |r| r.len())
    }

    async fn bodies(s: &MockServer) -> String {
        s.received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|r| String::from_utf8_lossy(&r.body).into_owned())
            .collect()
    }

    fn span_attr(trace: uuid::Uuid, k: &str) -> Option<serde_json::Value> {
        crate::otlp_emit::test_sink::for_trace(trace)
            .first()
            .and_then(|s| s.attributes.extra.get(k).cloned())
    }

    /// The demo line: a card number sent for a frontier model is served by the bank's
    /// own model, and the frontier upstream never sees a request.
    #[tokio::test]
    async fn a_card_number_never_reaches_the_frontier_provider() {
        let _b = LoopbackBypassGuard::new();
        let (own, frontier) = (upstream(200).await, upstream(200).await);
        let (resp, trace) = ask(
            state(&own, &frontier, Some(block())),
            FRONTIER,
            CARD,
            false,
            false,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(hits(&frontier).await, 0, "frontier contacted");
        assert_eq!(hits(&own).await, 1);
        assert!(bodies(&own).await.contains("4111 1111 1111 1111"));
        assert_eq!(
            span_attr(trace, "tracelane_routing_sovereign"),
            Some(json!(true))
        );
        assert_eq!(
            span_attr(trace, "tracelane_routing_data_class"),
            Some(json!("credit_card"))
        );
        assert_eq!(
            span_attr(trace, "tracelane_routing_endpoint"),
            Some(json!("ollama"))
        );
        assert_eq!(
            span_attr(trace, "tracelane_routing_rerouted"),
            Some(json!(true))
        );
    }

    #[tokio::test]
    async fn a_secret_in_a_streamed_request_is_confined_too() {
        let _b = LoopbackBypassGuard::new();
        let (own, frontier) = (upstream(200).await, upstream(200).await);
        let (_resp, _trace) = ask(
            state(&own, &frontier, Some(block())),
            FRONTIER,
            SECRET,
            true,
            false,
        )
        .await;
        assert_eq!(hits(&frontier).await, 0, "frontier contacted");
        assert_eq!(hits(&own).await, 1);
    }

    /// The sovereign endpoint fails and the caller asked for cross-provider failover: the
    /// request fails rather than falling back to the frontier provider.
    #[tokio::test]
    async fn a_failing_sovereign_endpoint_never_fails_over_to_a_frontier_provider() {
        let _b = LoopbackBypassGuard::new();
        let (own, frontier) = (upstream(503).await, upstream(200).await);
        let (resp, _t) = ask(
            state(&own, &frontier, Some(block())),
            FRONTIER,
            CARD,
            false,
            true,
        )
        .await;
        assert_ne!(resp.status(), StatusCode::OK);
        assert!(hits(&own).await >= 1, "the sovereign endpoint was tried");
        assert_eq!(
            hits(&frontier).await,
            0,
            "failed over to the frontier provider"
        );
    }

    /// Control: WITHOUT the block, the same failing primary does fail over — so the test
    /// above is red if the confinement is removed, not green by accident.
    #[tokio::test]
    async fn control_without_the_block_the_failing_primary_does_fail_over() {
        let _b = LoopbackBypassGuard::new();
        let (own, frontier) = (upstream(503).await, upstream(200).await);
        let (_resp, _t) = ask(state(&own, &frontier, None), OWN, CARD, false, true).await;
        assert!(hits(&frontier).await >= 1, "the failover chain fired");
    }

    #[tokio::test]
    async fn clean_traffic_is_unchanged_and_recorded_as_not_sovereign() {
        let _b = LoopbackBypassGuard::new();
        let (own, frontier) = (upstream(200).await, upstream(200).await);
        let (resp, trace) = ask(
            state(&own, &frontier, Some(block())),
            FRONTIER,
            CLEAN,
            false,
            false,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(hits(&frontier).await, 1);
        assert_eq!(hits(&own).await, 0);
        assert_eq!(
            span_attr(trace, "tracelane_routing_sovereign"),
            Some(json!(false))
        );
        assert_eq!(
            span_attr(trace, "tracelane_routing_data_class"),
            Some(json!("none"))
        );
    }

    #[tokio::test]
    async fn an_unconfigured_class_is_not_confined() {
        let _b = LoopbackBypassGuard::new();
        let (own, frontier) = (upstream(200).await, upstream(200).await);
        let (_r, _t) = ask(
            state(&own, &frontier, Some(block())),
            FRONTIER,
            "mail jane.doe@example.com please",
            false,
            false,
        )
        .await;
        assert_eq!(hits(&frontier).await, 1);
        assert_eq!(hits(&own).await, 0);
    }

    #[tokio::test]
    async fn without_the_block_spans_carry_no_routing_fields() {
        let _b = LoopbackBypassGuard::new();
        let (own, frontier) = (upstream(200).await, upstream(200).await);
        let (resp, trace) = ask(state(&own, &frontier, None), FRONTIER, CARD, false, false).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(hits(&frontier).await, 1, "no block: no change in routing");
        assert_eq!(span_attr(trace, "tracelane_routing_sovereign"), None);
        assert_eq!(span_attr(trace, "tracelane_routing_data_class"), None);
    }

    #[tokio::test]
    async fn an_unresolvable_sovereign_target_refuses_and_sends_nothing() {
        let _b = LoopbackBypassGuard::new();
        let (own, frontier) = (upstream(200).await, upstream(200).await);
        let bad = SovereignConfig::build("ollama", "no-such-model", None).expect("parse-valid");
        let (resp, _t) = ask(
            state(&own, &frontier, Some(bad)),
            FRONTIER,
            CARD,
            false,
            true,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body_json(resp).await["error"],
            "sovereign_route_unavailable"
        );
        assert_eq!(hits(&own).await + hits(&frontier).await, 0);
    }

    /// H-A through the real handler: an image the provider would FETCH is never Clear.
    #[tokio::test]
    async fn a_remote_image_url_never_reaches_the_frontier_provider() {
        let _b = LoopbackBypassGuard::new();
        let (own, frontier) = (upstream(200).await, upstream(200).await);
        let resp = chat_completions_handler(
            State(state(&own, &frontier, Some(block()))),
            authed_with_trace(uuid::Uuid::new_v4()),
            Json(json!({
                "model": FRONTIER,
                "messages": [{"role": "user", "content": [
                    {"type": "text", "text": CLEAN},
                    {"type": "image_url", "image_url":
                        {"url": "https://bucket.example/cheque.png?X-Amz-Signature=abc"}}
                ]}],
            })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            hits(&frontier).await,
            0,
            "the frontier model would fetch it"
        );
        assert_eq!(hits(&own).await, 1);
    }

    /// Control: without the block the same request goes where it was addressed.
    #[tokio::test]
    async fn a_remote_image_url_is_unchanged_without_the_block() {
        let _b = LoopbackBypassGuard::new();
        let (own, frontier) = (upstream(200).await, upstream(200).await);
        let resp = chat_completions_handler(
            State(state(&own, &frontier, None)),
            authed_with_trace(uuid::Uuid::new_v4()),
            Json(json!({
                "model": FRONTIER,
                "messages": [{"role": "user", "content": [
                    {"type": "image_url", "image_url": {"url": "https://bucket.example/a.png"}}
                ]}],
            })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(hits(&frontier).await, 1);
    }

    #[test]
    fn wire_gate_response_is_a_typed_403() {
        let r = crate::sovereign::wire_refused_response();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }
}

// ── The wire gate, through a real router ────────────────────────────────────
//
// `with_wire_gate` is the function `server::run` mounts. A tiny router whose handlers
// forward to a wiremock upstream proves what the gate does: a refused wire answers 403 and
// the upstream is never contacted; with no block the same request passes.
#[cfg(debug_assertions)]
mod gate {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use tower::ServiceExt as _;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::cfg;

    fn leak(c: crate::sovereign::SovereignConfig) -> &'static crate::sovereign::SovereignConfig {
        Box::leak(Box::new(c))
    }

    async fn upstream() -> MockServer {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&s)
            .await;
        s
    }

    fn router(
        url: String,
        mounted_gate: bool,
        block: Option<&'static crate::sovereign::SovereignConfig>,
    ) -> axum::Router {
        let forward = move || {
            let url = url.clone();
            async move {
                let _ = reqwest::Client::new().post(url).send().await;
                StatusCode::OK
            }
        };
        let mut app = axum::Router::new();
        for path in [
            "/v1/embeddings",
            "/v1/messages",
            "/v1/passthrough/openai/v1/x",
            "/v1/responses/abc",
            "/v1/experiments",
            "/v1/chat/completions",
            "/v1/brand-new-model-wire",
        ] {
            app = app.route(path, post(forward.clone()));
        }
        if mounted_gate {
            crate::sovereign::with_wire_gate(app, block)
        } else {
            app
        }
    }

    async fn post_to(app: axum::Router, path: &str) -> StatusCode {
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response")
        .status()
    }

    const REFUSED: [&str; 5] = [
        "/v1/embeddings",
        "/v1/messages",
        "/v1/passthrough/openai/v1/x",
        "/v1/responses/abc",
        "/v1/experiments",
    ];

    #[tokio::test]
    async fn a_refused_wire_answers_403_and_the_upstream_sees_nothing() {
        let up = upstream().await;
        let block = Some(leak(cfg(None)));
        for path in REFUSED {
            let app = router(up.uri(), true, block);
            assert_eq!(post_to(app, path).await, StatusCode::FORBIDDEN, "{path}");
        }
        assert_eq!(up.received_requests().await.map_or(0, |r| r.len()), 0);
    }

    #[tokio::test]
    async fn without_the_block_the_same_wires_pass() {
        let up = upstream().await;
        for path in REFUSED {
            let app = router(up.uri(), true, None);
            assert_eq!(post_to(app, path).await, StatusCode::OK, "{path}");
        }
        assert_eq!(
            up.received_requests().await.map_or(0, |r| r.len()),
            REFUSED.len()
        );
    }

    /// M1: a model wire added tomorrow is refused with no change to the gate.
    #[tokio::test]
    async fn a_brand_new_model_wire_is_refused_by_default() {
        let up = upstream().await;
        let app = router(up.uri(), true, Some(leak(cfg(None))));
        assert_eq!(
            post_to(app, "/v1/brand-new-model-wire").await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(up.received_requests().await.map_or(0, |r| r.len()), 0);
    }

    #[tokio::test]
    async fn the_one_confined_wire_is_not_blocked_by_the_gate() {
        let up = upstream().await;
        let app = router(up.uri(), true, Some(leak(cfg(None))));
        assert_eq!(post_to(app, "/v1/chat/completions").await, StatusCode::OK);
    }

    /// Mutation witness: with the layer NOT mounted the refused wires reach the upstream.
    /// This is the red the gate tests above turn green from.
    #[tokio::test]
    async fn without_the_layer_a_refused_wire_reaches_the_upstream() {
        let up = upstream().await;
        for path in REFUSED {
            let app = router(up.uri(), false, Some(leak(cfg(None))));
            assert_eq!(post_to(app, path).await, StatusCode::OK, "{path}");
        }
        assert_eq!(
            up.received_requests().await.map_or(0, |r| r.len()),
            REFUSED.len()
        );
    }
}
