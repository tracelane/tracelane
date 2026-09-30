use super::*;
use opentelemetry_proto::tonic::common::v1::any_value::Value as WireValue;
use serde_json::{Value, json};

fn kv(key: &str, value: serde_json::Value) -> KeyValue {
    let value = match value {
        serde_json::Value::String(s) => WireValue::StringValue(s),
        serde_json::Value::Number(n) if n.is_i64() => WireValue::IntValue(n.as_i64().unwrap()),
        serde_json::Value::Number(n) => WireValue::DoubleValue(n.as_f64().unwrap()),
        _ => panic!("scalar fixture"),
    };
    KeyValue {
        key: key.into(),
        value: Some(AnyValue { value: Some(value) }),
    }
}

#[test]
fn openinference_aliases_land_and_canonical_values_win_both_orders() {
    for (alias, canonical, stored, value, preferred) in [
        (
            "llm.model_name",
            "gen_ai.request.model",
            "gen_ai_request_model",
            json!("alias"),
            json!("canonical"),
        ),
        (
            "llm.request.model_name",
            "gen_ai.request.model",
            "gen_ai_request_model",
            json!("alias"),
            json!("canonical"),
        ),
        (
            "llm.response.model_name",
            "gen_ai.response.model",
            "gen_ai_response_model",
            json!("alias"),
            json!("canonical"),
        ),
        (
            "llm.provider",
            "gen_ai.provider.name",
            "gen_ai_provider_name",
            json!("openai"),
            json!("anthropic"),
        ),
        (
            "llm.system",
            "gen_ai.system",
            "gen_ai_system",
            json!("openai"),
            json!("anthropic"),
        ),
        (
            "llm.token_count.prompt",
            "gen_ai.usage.input_tokens",
            "gen_ai_usage_input_tokens",
            json!(13),
            json!(21),
        ),
        (
            "llm.token_count.completion",
            "gen_ai.usage.output_tokens",
            "gen_ai_usage_output_tokens",
            json!(7),
            json!(19),
        ),
        (
            "llm.token_count.prompt_details.cache_read",
            "gen_ai.usage.cache_read.input_tokens",
            "gen_ai_usage_cache_read_input_tokens",
            json!(3),
            json!(4),
        ),
        (
            "llm.token_count.prompt_details.cache_write",
            "gen_ai.usage.cache_creation.input_tokens",
            "gen_ai_usage_cache_creation_input_tokens",
            json!(2),
            json!(6),
        ),
        (
            "llm.token_count.completion_details.reasoning",
            "gen_ai.usage.reasoning.output_tokens",
            "gen_ai_usage_reasoning_output_tokens",
            json!(2),
            json!(5),
        ),
        (
            "llm.cost.total",
            "gen_ai.usage.cost",
            "gen_ai_usage_cost",
            json!(0.5),
            json!(0.75),
        ),
    ] {
        let a = kv(alias, value.clone());
        let c = kv(canonical, preferred.clone());
        assert_eq!(
            serde_json::to_value(build_attributes(std::slice::from_ref(&a))).unwrap()[stored],
            value,
            "{alias}"
        );
        for attrs in [vec![a.clone(), c.clone()], vec![c, a]] {
            let result = serde_json::to_value(build_attributes(&attrs)).unwrap();
            assert_eq!(result[stored], preferred, "{alias} precedence");
            assert_eq!(result[alias], value, "retain scalar {alias}");
        }
    }
}

#[test]
fn openinference_messages_tools_and_retrieval_are_ordered_and_typed() {
    let attrs = build_attributes(&[
        kv("openinference.span.kind", json!("LLM")),
        kv("input.value", json!("private input")),
        kv("output.value", json!("private output")),
        kv("input.mime_type", json!("text/plain")),
        kv("output.mime_type", json!("text/plain")),
        kv("llm.input_messages.9.message.content", json!("later")),
        kv("llm.input_messages.2.message.content", json!("earlier")),
        kv("llm.input_messages.2.message.role", json!("user")),
        kv("llm.output_messages.0.message.role", json!("assistant")),
        kv(
            "llm.output_messages.0.message.tool_calls.0.tool_call.function.name",
            json!("lookup"),
        ),
        kv(
            "llm.output_messages.0.message.tool_calls.0.tool_call.function.arguments",
            json!("private arguments"),
        ),
        kv("tool.name", json!("lookup")),
        kv("tool.description", json!("find a record")),
        kv("tool.id", json!("call-1")),
        kv("tool.parameters", json!("private tool parameters")),
        kv(
            "llm.tools.0.tool.json_schema",
            json!(
                r#"{"type":"function","function":{"name":"lookup","parameters":{"secret":"schema"}}}"#
            ),
        ),
        kv("retrieval.documents.2.document.id", json!("doc-2")),
        kv("retrieval.documents.2.document.score", json!(0.8)),
        kv(
            "retrieval.documents.2.document.content",
            json!("private document"),
        ),
        kv(
            "retrieval.documents.2.document.metadata",
            json!("never keep"),
        ),
        kv(
            "llm.invocation_parameters",
            json!(r#"{"temperature":0.25,"top_p":0.5,"max_tokens":42,"seed":9}"#),
        ),
    ]);
    let a = serde_json::to_value(&attrs).unwrap();
    assert_eq!(a["openinference_span_kind"], "llm");
    assert_eq!(a["input_value"], "private input");
    assert_eq!(a["output_value"], "private output");
    assert_eq!(a["input.mime_type"], "text/plain");
    assert_eq!(a["output.mime_type"], "text/plain");
    assert_eq!(a["gen_ai_input_messages"][0]["content"], "earlier");
    assert_eq!(a["gen_ai_input_messages"][1]["content"], "later");
    assert_eq!(
        a["gen_ai_output_messages"][0]["tool_calls"][0]["function"]["arguments"],
        "private arguments"
    );
    assert_eq!(a["tracelane_response_tool_names"], json!(["lookup"]));
    assert_eq!(a["gen_ai.tool.name"], "lookup");
    assert_eq!(a["gen_ai.tool.description"], "find a record");
    assert_eq!(a["gen_ai_tool_call_id"], "call-1");
    assert_eq!(a["gen_ai_tool_call_arguments"], "private tool parameters");
    assert_eq!(a["tracelane_request_tool_count"], 1);
    assert_eq!(a["tracelane_request_tool_names"], json!(["lookup"]));
    assert_eq!(
        a["tracelane_retrieval_documents"],
        json!([{ "id":"doc-2", "score":0.8, "content":"private document" }])
    );
    for (key, value) in [
        ("gen_ai_request_temperature", json!(0.25)),
        ("gen_ai_request_top_p", json!(0.5)),
        ("gen_ai_request_max_tokens", json!(42)),
        ("gen_ai_request_seed", json!(9)),
    ] {
        assert_eq!(a[key], value);
    }
    assert!(!a.to_string().contains("never keep"));
    assert!(!a.to_string().contains("schema"));
    let mut span = crate::TracelaneSpan {
        span_id: Uuid::nil(),
        trace_id: Uuid::nil(),
        parent_span_id: None,
        tenant_id: TenantId::from_jwt_claim(Uuid::from_u128(1)),
        name: "proof".into(),
        start_time: Utc::now(),
        end_time: None,
        attributes: attrs,
        status: SpanStatus {
            code: SpanStatusCode::Ok,
            message: None,
        },
    };
    crate::otlp::content::apply_capture(&mut span, &crate::otlp::content::CaptureHalves::closed());
    let closed = serde_json::to_value(span.attributes).unwrap();
    assert!(!closed.to_string().contains("private"));
    assert_eq!(
        closed["tracelane_retrieval_documents"],
        json!([{ "id":"doc-2", "score":0.8 }])
    );
    assert_eq!(
        closed["tracelane_content_withheld"],
        json!(["input", "output"])
    );
}

#[test]
fn openinference_caps_and_canonical_content_and_config_are_respected() {
    let mut policy = OtlpCapturePolicy::embedded();
    policy.max_retrieval_documents = 1;
    let mut attrs = vec![
        kv("retrieval.documents.9.document.id", json!("later")),
        kv("retrieval.documents.0.document.id", json!("first")),
        kv(
            "llm.invocation_parameters",
            json!(r#"{"temperature":0.25}"#),
        ),
        kv("gen_ai.request.temperature", json!(0.5)),
        kv("llm.input_messages.0.message.content", json!("alias")),
        kv(
            "gen_ai.input.messages",
            json!(r#"[{"content":"canonical"}]"#),
        ),
    ];
    for _ in 0..2 {
        let a = serde_json::to_value(build_attributes_with_policy(&attrs, &policy)).unwrap();
        assert_eq!(a["gen_ai_request_temperature"], 0.5);
        assert_eq!(a["gen_ai_input_messages"][0]["content"], "canonical");
        assert_eq!(a["tracelane_retrieval_documents"], json!([{"id":"first"}]));
        assert_eq!(a["tracelane_attrs_dropped"]["reasons"]["cap"], 1);
        attrs.reverse();
    }
    assert!(
        build_attributes(&[kv("openinference.span.kind", json!("bogus"))])
            .openinference_span_kind
            .is_none()
    );
}

#[test]
fn current_semconv_and_mcp_metadata_rows_land() {
    for key in [
        "gen_ai.tool.type",
        "gen_ai.tool.description",
        "gen_ai.data_source.id",
        "gen_ai.prompt.name",
        "gen_ai.prompt.version",
        "gen_ai.agent.description",
        "gen_ai.workflow.name",
        "gen_ai.output.type",
        "mcp.method.name",
        "mcp.session.id",
        "mcp.protocol.version",
        "mcp.resource.uri",
    ] {
        assert_eq!(
            serde_json::to_value(build_attributes(&[kv(key, json!("value"))])).unwrap()[key],
            "value",
            "{key}"
        );
    }
    assert_eq!(
        serde_json::to_value(build_attributes(&[kv("error.type", json!("Failure"))])).unwrap()["error_type"],
        "Failure"
    );
    for key in [
        "gen_ai.retrieval.top_k",
        "gen_ai.request.top_k",
        "gen_ai.request.frequency_penalty",
        "gen_ai.request.presence_penalty",
        "gen_ai.request.choice.count",
        "mcp.content_count",
        "mcp.argument_count",
    ] {
        assert_eq!(
            serde_json::to_value(build_attributes(&[kv(key, json!(3))])).unwrap()[key],
            3,
            "{key}"
        );
    }
    for key in ["mcp.is_error", "gen_ai.conversation.compacted"] {
        let attr = KeyValue {
            key: key.into(),
            value: Some(AnyValue {
                value: Some(WireValue::BoolValue(true)),
            }),
        };
        assert_eq!(
            serde_json::to_value(build_attributes(&[attr])).unwrap()[key],
            true
        );
    }
}

#[test]
fn current_semconv_aliases_and_canonical_tools_win_both_orders() {
    for (alias, canonical, stored, alias_value, canonical_value) in [
        (
            "gen_ai.usage.cache_write.input_tokens",
            "gen_ai.usage.cache_creation.input_tokens",
            "gen_ai_usage_cache_creation_input_tokens",
            json!(3),
            json!(5),
        ),
        (
            "mcp.tool_name",
            "gen_ai.tool.name",
            "gen_ai.tool.name",
            json!("alias"),
            json!("canonical"),
        ),
        (
            "tool.id",
            "gen_ai.tool.call.id",
            "gen_ai_tool_call_id",
            json!("alias"),
            json!("canonical"),
        ),
        (
            "tool.parameters",
            "gen_ai.tool.call.arguments",
            "gen_ai_tool_call_arguments",
            json!("alias"),
            json!("canonical"),
        ),
    ] {
        let a = kv(alias, alias_value.clone());
        let c = kv(canonical, canonical_value.clone());
        assert_eq!(
            serde_json::to_value(build_attributes(std::slice::from_ref(&a))).unwrap()[stored],
            alias_value
        );
        for attrs in [vec![a.clone(), c.clone()], vec![c, a]] {
            assert_eq!(
                serde_json::to_value(build_attributes(&attrs)).unwrap()[stored],
                canonical_value
            );
        }
    }
}

fn structured(value: serde_json::Value) -> AnyValue {
    use opentelemetry_proto::tonic::common::v1::{ArrayValue, KeyValueList};
    AnyValue {
        value: Some(match value {
            Value::Object(map) => WireValue::KvlistValue(KeyValueList {
                values: map
                    .into_iter()
                    .map(|(key, value)| KeyValue {
                        key,
                        value: Some(structured(value)),
                    })
                    .collect(),
            }),
            Value::Array(values) => WireValue::ArrayValue(ArrayValue {
                values: values.into_iter().map(structured).collect(),
            }),
            Value::String(s) => WireValue::StringValue(s),
            Value::Number(n) if n.is_i64() => WireValue::IntValue(n.as_i64().unwrap()),
            Value::Number(n) => WireValue::DoubleValue(n.as_f64().unwrap()),
            Value::Bool(b) => WireValue::BoolValue(b),
            _ => panic!("unsupported fixture"),
        }),
    }
}

#[test]
fn current_semconv_structured_content_is_gated_by_the_right_half() {
    let attrs = build_attributes(&[
        KeyValue {
            key: "gen_ai.tool.call.result".into(),
            value: Some(structured(json!({"secret":"result"}))),
        },
        KeyValue {
            key: "gen_ai.tool.call.arguments".into(),
            value: Some(structured(json!({"secret":"argument"}))),
        },
        KeyValue {
            key: "gen_ai.tool.definitions".into(),
            value: Some(structured(
                json!([{"name":"lookup","parameters":{"secret":"schema"}}]),
            )),
        },
        KeyValue {
            key: "gen_ai.retrieval.documents".into(),
            value: Some(structured(
                json!([{"id":"d","score":0.5,"content":"private document","metadata":"discard"}]),
            )),
        },
        kv("gen_ai.retrieval.query.text", json!("private query")),
    ]);
    let json = serde_json::to_value(&attrs).unwrap();
    assert_eq!(json["gen_ai_tool_call_result"], r#"{"secret":"result"}"#);
    assert_eq!(json["tracelane_request_tool_names"], json!(["lookup"]));
    assert!(!json.to_string().contains("schema"));
    assert!(!json.to_string().contains("discard"));
    let mut span = crate::TracelaneSpan {
        span_id: Uuid::nil(),
        trace_id: Uuid::nil(),
        parent_span_id: None,
        tenant_id: TenantId::from_jwt_claim(Uuid::from_u128(1)),
        name: "proof".into(),
        start_time: Utc::now(),
        end_time: None,
        attributes: attrs,
        status: SpanStatus {
            code: SpanStatusCode::Ok,
            message: None,
        },
    };
    crate::otlp::content::apply_capture(
        &mut span,
        &crate::otlp::content::CaptureHalves {
            input: false,
            output: true,
            max_field_bytes: 100,
        },
    );
    let kept = serde_json::to_value(span.attributes).unwrap();
    assert!(kept.get("gen_ai_tool_call_result").is_none());
    assert!(kept.get("tracelane_retrieval_query").is_none());
    assert_eq!(
        kept["tracelane_retrieval_documents"],
        json!([{"id":"d","score":0.5}])
    );
    assert_eq!(
        kept["gen_ai_tool_call_arguments"],
        r#"{"secret":"argument"}"#
    );
}
