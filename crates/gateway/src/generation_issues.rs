//! Read-time generation signals. Stored observations are never rewritten.
#![allow(dead_code)] // Read-route consumers land in the following capture-program slices.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Display policy loaded on the existing rate-card refresh cadence. An invalid
/// embedded table disables this read instead of inventing a window or TTL.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub struct SummaryPolicy {
    pub dashboard_window_days: u32,
    pub inline_chip_limit: usize,
    pub summary_cache_ttl_seconds: u64,
}

impl SummaryPolicy {
    pub(crate) fn embedded() -> Self {
        static POLICY: std::sync::LazyLock<SummaryPolicy> = std::sync::LazyLock::new(|| {
            let seed: Value =
                serde_json::from_str(include_str!("../../../apps/web/db/plans.v3.json"))
                    .unwrap_or(Value::Null);
            serde_json::from_value(seed["policy"]["generation_issues"].clone()).unwrap_or_default()
        });
        *POLICY
    }

    pub(crate) fn valid(&self) -> bool {
        self.dashboard_window_days > 0
            && self.summary_cache_ttl_seconds > 0
            && self.inline_chip_limit > 0
    }

    pub(crate) fn window_days(self, effective_days: i32) -> u32 {
        self.dashboard_window_days
            .min(u32::try_from(effective_days).unwrap_or_default())
    }
}

#[derive(Debug, Clone, Deserialize, clickhouse::Row)]
pub(crate) struct SummaryRow {
    pub total_traces: u64,
    pub llm_calls: u64,
    pub no_served_model_calls: u64,
    pub no_finish_reason_calls: u64,
    pub gateway_signal_calls: u64,
    pub issue_counts: Vec<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IssueTraceCount {
    pub kind: Issue,
    pub trace_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct IssueSummary {
    pub total_traces: u64,
    pub llm_calls: u64,
    pub no_served_model_calls: u64,
    pub no_finish_reason_calls: u64,
    /// Positive gateway signals, not a complete origin census. Absence cannot
    /// establish that every span was OTLP (older and blocked calls lack timing).
    pub gateway_signal_calls: u64,
    pub counts: Vec<IssueTraceCount>,
    pub window_days: u32,
    pub since: String,
    pub until: String,
    pub as_of: String,
    /// Current INPUT capture setting; historical trim counts are preserved.
    pub content_capture: bool,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct SummaryCacheKey {
    pub tenant: tracelane_shared::TenantId,
    pub window_days: u32,
    pub ttl_seconds: u64,
    pub content_capture: bool,
}

pub(crate) struct SummaryExpiry;
impl moka::Expiry<SummaryCacheKey, std::sync::Arc<IssueSummary>> for SummaryExpiry {
    fn expire_after_create(
        &self,
        key: &SummaryCacheKey,
        _: &std::sync::Arc<IssueSummary>,
        _: std::time::Instant,
    ) -> Option<std::time::Duration> {
        Some(std::time::Duration::from_secs(key.ttl_seconds))
    }
}

pub(crate) fn summary_sql() -> String {
    let counts = ISSUES
        .into_iter()
        .map(|kind| {
            format!(
                "toUInt64(uniqExactIf(trace_id, {}))",
                issue_predicate_sql(kind)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let chat = "JSONExtractString(attributes, 'gen_ai_operation_name') IN ('chat', 'messages')";
    // Known gateway-writer fields. Counting their presence is deliberately
    // weaker than claiming an exact or authenticated gateway population.
    let gateway = "JSONHas(attributes, 'tracelane_gateway_overhead_us') OR JSONHas(attributes, 'tracelane_model_substitution') OR JSONHas(attributes, 'tracelane.stream.cancelled') OR JSONHas(attributes, 'tracelane_usage_estimated') OR JSONHas(attributes, 'tracelane_semantic_cache_hit') OR JSONHas(attributes, 'tracelane_input_messages_omitted')";
    format!(
        "SELECT toUInt64(uniqExact(trace_id)) AS total_traces, \
toUInt64(countIf({chat})) AS llm_calls, \
toUInt64(countIf({chat} AND empty(trimBoth(JSONExtractString(attributes, 'gen_ai_response_model'))))) AS no_served_model_calls, \
toUInt64(countIf({chat} AND empty(JSONExtractArrayRaw(attributes, 'gen_ai_response_finish_reasons')))) AS no_finish_reason_calls, \
toUInt64(countIf({chat} AND ({gateway}))) AS gateway_signal_calls, \
[{counts}] AS issue_counts FROM spans FINAL \
WHERE tenant_id = ? AND start_time >= fromUnixTimestamp64Micro(?) AND start_time <= fromUnixTimestamp64Micro(?)"
    )
}

pub(crate) const MODEL_DATE_SUFFIX: &str = "-([0-9]{8}|[0-9]{4}-[0-9]{2}-[0-9]{2})$";

#[cfg(test)]
mod summary_tests {
    use super::*;

    #[test]
    fn issue_summary_policy_comes_from_seed_and_clamps_to_the_effective_window() {
        let policy = SummaryPolicy::embedded();
        assert_eq!(policy.dashboard_window_days, 7);
        assert_eq!(policy.summary_cache_ttl_seconds, 60);
        assert_eq!(policy.inline_chip_limit, 3);
        assert!(policy.valid());
        assert_eq!(policy.window_days(3), 3);
        assert_eq!(policy.window_days(90), 7);
        assert_eq!(policy.window_days(1), 1);
        assert_eq!(policy.window_days(0), 0);
        assert_eq!(policy.window_days(-1), 0);
        assert!(!SummaryPolicy::default().valid());
    }

    #[test]
    fn issue_summary_sql_is_tenant_first_window_bounded_and_counts_distinct_traces() {
        let sql = summary_sql();
        assert!(sql.contains("FROM spans FINAL WHERE tenant_id = ? AND start_time >= fromUnixTimestamp64Micro(?) AND start_time <= fromUnixTimestamp64Micro(?)"), "{sql}");
        assert_eq!(sql.matches('?').count(), 3);
        assert!(sql.contains("uniqExact(trace_id)"));
        for issue in ISSUES {
            assert!(
                sql.contains(&format!(
                    "uniqExactIf(trace_id, {})",
                    issue_predicate_sql(issue)
                )),
                "{issue:?}"
            );
        }
        assert!(sql.contains("AS no_served_model_calls"));
        assert!(sql.contains("AS no_finish_reason_calls"));
        assert!(sql.contains("AS gateway_signal_calls"));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Issue {
    ModelSwapped,
    Alias,
    Fallback,
    Truncated,
    Filtered,
    Empty,
    Cancelled,
    Estimated,
    CaptureTrimmed,
}

/// Recorded signals, never an assessment of unrecorded output content.
#[derive(Debug, Clone, Serialize)]
pub struct IssueChip {
    pub kind: Issue,
    pub severity: &'static str,
    pub detail: &'static str,
    pub affected_spans: u64,
}

impl Issue {
    pub(crate) fn chip(self, affected_spans: u64) -> IssueChip {
        let (severity, detail) = match self {
            Self::ModelSwapped => (
                "warn",
                "Different requested and reported model families. Sources: gen_ai_request_model, gen_ai_response_model, tracelane_model_substitution. When no routing verdict is recorded, this is derived from the two model attributes; Tracelane did not observe the routing.",
            ),
            Self::Alias => (
                "neutral",
                "A configured alias selected the model. Source: tracelane_model_substitution.",
            ),
            Self::Fallback => (
                "info",
                "The configured fallback chain selected the model. Source: tracelane_model_substitution.",
            ),
            Self::Truncated => (
                "warn",
                "The provider reported a token limit. Source: gen_ai_response_finish_reasons.",
            ),
            Self::Filtered => (
                "warn",
                "The provider reported filtering, not a Tracelane guardrail block. Source: gen_ai_response_finish_reasons.",
            ),
            Self::Empty => (
                "warn",
                "The provider reported zero output tokens; no response tools, cache hit or cancelled stream was recorded. Sources: gen_ai_usage_output_tokens, tracelane_response_tool_names, tracelane_semantic_cache_hit, tracelane.stream.cancelled, tracelane_usage_estimated.",
            ),
            Self::Cancelled => (
                "info",
                "The client disconnected before the stream finished. Source: tracelane.stream.cancelled.",
            ),
            Self::Estimated => (
                "info",
                "Token counts are a length estimate, not a measurement. Source: tracelane_usage_estimated.",
            ),
            Self::CaptureTrimmed => (
                "info",
                "The stored conversation omitted older messages to fit the recording size cap. The model received the full request. Source: tracelane_input_messages_omitted.",
            ),
        };
        IssueChip {
            kind: self,
            severity,
            detail,
            affected_spans,
        }
    }
}

pub(crate) const ISSUES: [Issue; 9] = [
    Issue::ModelSwapped,
    Issue::Alias,
    Issue::Fallback,
    Issue::Truncated,
    Issue::Filtered,
    Issue::Empty,
    Issue::Cancelled,
    Issue::Estimated,
    Issue::CaptureTrimmed,
];

pub(crate) struct SpanAttrsView<'a> {
    pub attributes: &'a Value,
    pub status_code: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignalsRecorded {
    pub attributes_readable: bool,
    pub chat_operation: bool,
    pub present: Vec<&'static str>,
    pub missing: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GenerationDetails {
    pub issues: Vec<IssueChip>,
    pub signals_recorded: SignalsRecorded,
}

/// Describe evidence separately from issues. Missing text never means an empty
/// answer; the only output observation here is a provider-reported token count.
pub(crate) fn details(span: &SpanAttrsView<'_>) -> GenerationDetails {
    let a = span.attributes;
    let text = |key: &str| a[key].as_str().is_some_and(|v| !v.trim().is_empty());
    let chat_operation = matches!(
        a["gen_ai_operation_name"].as_str(),
        Some("chat" | "messages")
    );
    let mut recorded = SignalsRecorded {
        attributes_readable: a.is_object(),
        chat_operation,
        present: Vec::new(),
        missing: Vec::new(),
    };
    let mut signal = |key, present| {
        if present {
            recorded.present.push(key);
        } else {
            recorded.missing.push(key);
        }
    };
    signal("gen_ai_operation_name", text("gen_ai_operation_name"));
    if chat_operation {
        signal("gen_ai_request_model", text("gen_ai_request_model"));
        signal("gen_ai_response_model", text("gen_ai_response_model"));
        signal(
            "gen_ai_response_finish_reasons",
            a["gen_ai_response_finish_reasons"]
                .as_array()
                .is_some_and(|values| {
                    values
                        .iter()
                        .any(|v| v.as_str().is_some_and(|s| !s.trim().is_empty()))
                }),
        );
        signal(
            "gen_ai_usage_output_tokens",
            a["gen_ai_usage_output_tokens"].as_u64().is_some(),
        );
    }
    GenerationDetails {
        issues: classify(span)
            .into_iter()
            .map(|issue| issue.chip(1))
            .collect(),
        signals_recorded: recorded,
    }
}

#[derive(Deserialize)]
struct Vocabulary {
    length: Vec<String>,
    filtered: Vec<String>,
}
fn vocabulary() -> &'static Vocabulary {
    static VOCABULARY: std::sync::LazyLock<Vocabulary> = std::sync::LazyLock::new(|| {
        serde_json::from_str(include_str!("generation_issues.v1.json")).unwrap_or_else(|_| {
            Vocabulary {
                length: Vec::new(),
                filtered: Vec::new(),
            }
        })
    });
    &VOCABULARY
}

pub(crate) fn classify(span: &SpanAttrsView<'_>) -> Vec<Issue> {
    let a = span.attributes;
    let text = |key: &str| a[key].as_str().unwrap_or("");
    let flag = |key: &str| a[key].as_bool() == Some(true);
    let chat = matches!(text("gen_ai_operation_name"), "chat" | "messages");
    let requested = text("gen_ai_request_model");
    let served = text("gen_ai_response_model");
    let verdict = text("tracelane_model_substitution");
    let reasons = |values: &[String]| {
        a["gen_ai_response_finish_reasons"]
            .as_array()
            .is_some_and(|reasons| {
                reasons
                    .iter()
                    .any(|r| r.as_str().is_some_and(|r| values.iter().any(|v| v == r)))
            })
    };
    ISSUES
        .into_iter()
        .filter(|issue| match issue {
            Issue::ModelSwapped => {
                chat && matches!(verdict, "" | "provider")
                    && !requested.trim().is_empty()
                    && !served.trim().is_empty()
                    && model_family(requested) != model_family(served)
            }
            Issue::Alias => chat && verdict == "alias",
            Issue::Fallback => chat && matches!(verdict, "failover" | "alias+failover"),
            Issue::Truncated => chat && reasons(&vocabulary().length),
            Issue::Filtered => chat && reasons(&vocabulary().filtered),
            Issue::Empty => {
                chat && span.status_code != 2
                    && a["gen_ai_usage_output_tokens"].as_u64() == Some(0)
                    && !flag("tracelane_usage_estimated")
                    && !flag("tracelane_semantic_cache_hit")
                    && !flag("tracelane.stream.cancelled")
                    && a["tracelane_response_tool_names"]
                        .as_array()
                        .is_none_or(Vec::is_empty)
            }
            Issue::Cancelled => chat && flag("tracelane.stream.cancelled"),
            Issue::Estimated => flag("tracelane_usage_estimated"),
            Issue::CaptureTrimmed => a["tracelane_input_messages_omitted"]
                .as_u64()
                .is_some_and(|n| n > 0),
        })
        .collect()
}

pub(crate) fn model_family(model: &str) -> String {
    static DATE: std::sync::LazyLock<Result<regex::Regex, regex::Error>> =
        std::sync::LazyLock::new(|| regex::Regex::new(MODEL_DATE_SUFFIX));
    let model = model.trim().to_lowercase();
    let mut model = model.as_str();
    while let Some((prefix, rest)) = model.split_once('/') {
        if prefix.is_empty() {
            break;
        }
        model = rest;
    }
    DATE.as_ref().map_or_else(
        |_| model.to_owned(),
        |re| re.replace(model, "").into_owned(),
    )
}

pub(crate) fn model_family_sql(expression: &str) -> String {
    format!(
        "replaceRegexpOne(replaceRegexpOne(lowerUTF8(trimBoth({expression})), '^([^/]+/)+', ''), '{MODEL_DATE_SUFFIX}', '')"
    )
}

pub(crate) fn issue_predicate_sql(issue: Issue) -> String {
    let chat = "JSONExtractString(attributes, 'gen_ai_operation_name') IN ('chat', 'messages')";
    let verdict = "JSONExtractString(attributes, 'tracelane_model_substitution')";
    let flag = |key| format!("JSONExtractBool(attributes, '{key}')");
    let reasons = |values: &[String]| {
        // Vocabulary is reviewed build-time data, never request input.
        let values = values
            .iter()
            .map(|s| format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'")))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "hasAny(JSONExtract(attributes, 'gen_ai_response_finish_reasons', 'Array(String)'), [{values}])"
        )
    };
    let predicate = match issue {
        Issue::ModelSwapped => {
            let req = "JSONExtractString(attributes, 'gen_ai_request_model')";
            let served = "JSONExtractString(attributes, 'gen_ai_response_model')";
            format!(
                "{verdict} IN ('', 'provider') AND trimBoth({req}) != '' AND trimBoth({served}) != '' AND {} != {}",
                model_family_sql(req),
                model_family_sql(served)
            )
        }
        Issue::Alias => format!("{verdict} = 'alias'"),
        Issue::Fallback => format!("{verdict} IN ('failover', 'alias+failover')"),
        Issue::Truncated => reasons(&vocabulary().length),
        Issue::Filtered => reasons(&vocabulary().filtered),
        Issue::Empty => format!(
            "status_code != 2 AND JSONHas(attributes, 'gen_ai_usage_output_tokens') AND JSONType(attributes, 'gen_ai_usage_output_tokens') IN ('Int64', 'UInt64') AND JSONExtractInt(attributes, 'gen_ai_usage_output_tokens') = 0 AND NOT {} AND NOT {} AND NOT {} AND empty(JSONExtract(attributes, 'tracelane_response_tool_names', 'Array(String)'))",
            flag("tracelane_usage_estimated"),
            flag("tracelane_semantic_cache_hit"),
            flag("tracelane.stream.cancelled")
        ),
        Issue::Cancelled => flag("tracelane.stream.cancelled"),
        Issue::Estimated => return flag("tracelane_usage_estimated"),
        Issue::CaptureTrimmed => {
            return "JSONExtractInt(attributes, 'tracelane_input_messages_omitted') > 0".into();
        }
    };
    format!("({chat} AND ({predicate}))")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn generation_issues_model_evidence_and_snapshot_families() {
        for (requested, served, verdict, expected) in [
            ("gpt-4o", "gpt-4o-2024-08-06", "provider", None),
            (
                "claude-haiku-4-5",
                "anthropic/claude-haiku-4-5-20251001",
                "provider",
                None,
            ),
            (
                "gpt-4o",
                "claude-sonnet-4-6",
                "provider",
                Some(Issue::ModelSwapped),
            ),
            ("fast", "claude-sonnet-4-6", "alias", Some(Issue::Alias)),
            (
                "gpt-4o",
                "claude-sonnet-4-6",
                "failover",
                Some(Issue::Fallback),
            ),
            (
                "fast",
                "claude-sonnet-4-6",
                "alias+failover",
                Some(Issue::Fallback),
            ),
            ("gpt-4o", "", "", None),
            ("gpt-4o", "claude-sonnet-4-6", "", Some(Issue::ModelSwapped)),
            ("", "claude-sonnet-4-6", "", None),
        ] {
            let attrs = json!({"gen_ai_operation_name":"chat", "gen_ai_request_model":requested, "gen_ai_response_model":served, "tracelane_model_substitution":verdict});
            assert_eq!(
                classify(&SpanAttrsView {
                    attributes: &attrs,
                    status_code: 0
                }),
                expected.into_iter().collect::<Vec<_>>(),
                "{requested} → {served} ({verdict})"
            );
        }
        assert_eq!(model_family(" Vendor/OpenAI/GPT-4o-2024-08-06 "), "gpt-4o");
        assert_eq!(model_family("claude-haiku-4-5"), "claude-haiku-4-5");
    }

    #[test]
    fn generation_issues_empty_needs_measured_usage_and_excludes_tools_cache_cancel_errors() {
        let base = json!({"gen_ai_operation_name":"chat", "gen_ai_usage_output_tokens":0});
        assert_eq!(
            classify(&SpanAttrsView {
                attributes: &base,
                status_code: 0
            }),
            vec![Issue::Empty]
        );
        for (key, value) in [
            ("tracelane_usage_estimated", json!(true)),
            ("tracelane_response_tool_names", json!(["search"])),
            ("tracelane_semantic_cache_hit", json!(true)),
            ("tracelane.stream.cancelled", json!(true)),
            ("gen_ai_operation_name", json!("embeddings")),
            ("gen_ai_usage_output_tokens", Value::Null),
        ] {
            let mut attrs = base.clone();
            attrs[key] = value;
            assert!(
                !classify(&SpanAttrsView {
                    attributes: &attrs,
                    status_code: 0
                })
                .contains(&Issue::Empty),
                "{key}"
            );
        }
        assert!(
            !classify(&SpanAttrsView {
                attributes: &base,
                status_code: 2
            })
            .contains(&Issue::Empty)
        );
    }

    #[test]
    fn generation_issues_finish_reasons_and_dotted_cancel_are_independent() {
        for reason in ["length", "max_tokens"] {
            let attrs = json!({"gen_ai_operation_name":"messages", "gen_ai_response_finish_reasons":[reason]});
            assert_eq!(
                classify(&SpanAttrsView {
                    attributes: &attrs,
                    status_code: 0
                }),
                vec![Issue::Truncated]
            );
        }
        for reason in ["content_filter", "refusal"] {
            let attrs =
                json!({"gen_ai_operation_name":"chat", "gen_ai_response_finish_reasons":[reason]});
            assert_eq!(
                classify(&SpanAttrsView {
                    attributes: &attrs,
                    status_code: 0
                }),
                vec![Issue::Filtered]
            );
        }
        let attrs = json!({"gen_ai_operation_name":"chat", "tracelane.stream.cancelled":true,"tracelane_usage_estimated":true,"tracelane_input_messages_omitted":2});
        assert_eq!(
            classify(&SpanAttrsView {
                attributes: &attrs,
                status_code: 0
            }),
            vec![Issue::Cancelled, Issue::Estimated, Issue::CaptureTrimmed]
        );
        let attrs = json!({"gen_ai_operation_name":"embeddings", "gen_ai_response_finish_reasons":["length"],"tracelane_stream_cancelled":true});
        assert!(
            classify(&SpanAttrsView {
                attributes: &attrs,
                status_code: 0
            })
            .is_empty()
        );
        assert!(issue_predicate_sql(Issue::Cancelled).contains("'tracelane.stream.cancelled'"));
        assert!(
            issue_predicate_sql(Issue::Empty)
                .contains("JSONHas(attributes, 'gen_ai_usage_output_tokens')")
        );
        assert!(model_family_sql("model").contains(MODEL_DATE_SUFFIX));
    }
}

// The existing integration runner discovers this module by `clickhouse_roundtrip`.
// It reads only synthetic bound values; it never writes rows or applies schema.
#[cfg(test)]
mod clickhouse_roundtrip {
    use super::*;
    use serde_json::json;

    fn fixtures() -> Vec<(Value, u8)> {
        let mut rows = Vec::new();
        for (request, response, verdict) in [
            ("gpt-4o", "gpt-4o-2024-08-06", "provider"),
            ("gpt-4o", "gpt-4.1-mini", "provider"),
            ("fast", "gpt-4o", "alias"),
            ("gpt-4o", "claude-sonnet", "failover"),
            ("fast", "claude-sonnet", "alias+failover"),
            ("gpt-4o", "", ""),
            ("gpt-4o", "claude-sonnet", ""),
            ("", "gpt-4o", ""),
            (
                "ANTHROPIC/claude-haiku-4-5",
                "claude-haiku-4-5-20251001",
                "provider",
            ),
        ] {
            rows.push((json!({"gen_ai_operation_name":"chat", "gen_ai_request_model":request, "gen_ai_response_model":response, "tracelane_model_substitution":verdict}), 0));
        }
        for (key, value) in [
            ("gen_ai_usage_output_tokens", json!(0)),
            ("tracelane_usage_estimated", json!(true)),
            ("tracelane_response_tool_names", json!(["search"])),
            ("tracelane_semantic_cache_hit", json!(true)),
            ("tracelane.stream.cancelled", json!(true)),
            ("gen_ai_operation_name", json!("embeddings")),
            ("gen_ai_usage_output_tokens", Value::Null),
            ("gen_ai_usage_output_tokens", json!("0")),
        ] {
            let mut a = json!({"gen_ai_operation_name":"chat", "gen_ai_usage_output_tokens":0});
            a[key] = value;
            rows.push((a, 0));
        }
        rows.push((
            json!({"gen_ai_operation_name":"chat", "gen_ai_usage_output_tokens":0}),
            2,
        ));
        for reason in [
            "length",
            "max_tokens",
            "content_filter",
            "refusal",
            "stop",
            "tool_calls",
        ] {
            rows.push((json!({"gen_ai_operation_name":"messages", "gen_ai_response_finish_reasons":[reason]}), 0));
        }
        for op in ["chat", "embeddings", "execute_tool"] {
            rows.push((json!({"gen_ai_operation_name":op, "tracelane.stream.cancelled":true, "tracelane_usage_estimated":true}), 0));
            rows.push((
                json!({"gen_ai_operation_name":op, "tracelane_input_messages_omitted":2}),
                0,
            ));
        }
        rows
    }

    #[test]
    fn generation_issue_parity_matrix_has_thirty_spans_and_all_kinds() {
        let rows = fixtures();
        assert_eq!(rows.len(), 30);
        for issue in ISSUES {
            assert!(
                rows.iter().any(|(a, status)| classify(&SpanAttrsView {
                    attributes: a,
                    status_code: *status
                })
                .contains(&issue)),
                "missing positive fixture for {issue:?}"
            );
            assert!(
                rows.iter().any(|(a, status)| !classify(&SpanAttrsView {
                    attributes: a,
                    status_code: *status
                })
                .contains(&issue)),
                "missing negative fixture for {issue:?}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires an explicitly supplied CLICKHOUSE_TEST_URL; SELECT-only synthetic fixtures"]
    async fn generation_issue_classifier_equals_sql_for_thirty_spans() {
        let url = std::env::var("CLICKHOUSE_TEST_URL").expect("CLICKHOUSE_TEST_URL required");
        let client = clickhouse::Client::default().with_url(url);
        #[derive(Deserialize, clickhouse::Row)]
        struct Flags {
            flags: Vec<u8>,
        }
        let expressions = ISSUES
            .into_iter()
            .map(|issue| format!("toUInt8({})", issue_predicate_sql(issue)))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT [{expressions}] AS flags FROM (SELECT ? AS attributes, toUInt8(?) AS status_code)"
        );
        for (attrs, status) in fixtures() {
            let row = client
                .query(&sql)
                .bind(attrs.to_string())
                .bind(status)
                .fetch_one::<Flags>()
                .await
                .expect("evaluate synthetic span predicates");
            let rust = classify(&SpanAttrsView {
                attributes: &attrs,
                status_code: status,
            });
            let expected = ISSUES
                .into_iter()
                .map(|issue| u8::from(rust.contains(&issue)))
                .collect::<Vec<_>>();
            assert_eq!(row.flags, expected, "attributes={attrs}, status={status}");
        }
    }
}
