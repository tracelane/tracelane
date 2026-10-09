//! Fixed vendor mappings over the shared bounded hook transport.
//! Contracts: Lakera Guard v2 and Azure Analyze Text 2024-09-01.
//! Invalid destinations, inputs and verdicts fail CLOSED, regardless of failure mode.
use super::hooks::{Hook, Phase, Reply};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Adapter {
    Lakera {},
    AzureContentSafety { thresholds: Thresholds },
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    #[serde(rename = "Hate")]
    pub hate: u8,
    #[serde(rename = "SelfHarm")]
    pub self_harm: u8,
    #[serde(rename = "Sexual")]
    pub sexual: u8,
    #[serde(rename = "Violence")]
    pub violence: u8,
}
impl Thresholds {
    fn values(&self) -> [u8; 4] {
        [self.hate, self.self_harm, self.sexual, self.violence]
    }
}
impl Adapter {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Lakera {} => "lakera",
            Self::AzureContentSafety { .. } => "azure_content_safety",
        }
    }
    pub fn valid(&self, endpoint: &str) -> bool {
        let Ok(url) = reqwest::Url::parse(endpoint) else {
            return false;
        };
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.port().is_some()
        {
            return false;
        }
        match self {
            Self::Lakera {} => url.as_str() == "https://api.lakera.ai/v2/guard",
            Self::AzureContentSafety { thresholds } => {
                url.path() == "/"
                    && url
                        .host_str()
                        .and_then(|h| h.strip_suffix(".cognitiveservices.azure.com"))
                        .is_some_and(|resource| !resource.is_empty() && !resource.contains('.'))
                    && thresholds.values().iter().all(|n| *n <= 7)
            }
        }
    }
}
/// No Debug: this owns authentication headers and customer text.
pub struct Outbound {
    pub url: String,
    pub body: Vec<u8>,
    pub headers: reqwest::header::HeaderMap,
}
impl Outbound {
    /// Expose the key only at the HTTP client's authentication boundary.
    pub fn into_request(self, client: &reqwest::Client, hook: &Hook) -> reqwest::RequestBuilder {
        let request = client
            .post(self.url)
            .header("content-type", "application/json")
            .headers(self.headers)
            .body(self.body);
        if matches!(hook.config.adapter, Some(Adapter::Lakera {})) {
            request.bearer_auth(hook.secret.expose_secret())
        } else {
            request
        }
    }
}
/// Fail-CLOSED before transport. The caller supplies the deadline, DNS pin and body cap.
pub fn request(hook: &Hook, phase: Phase, text: &str) -> Option<Outbound> {
    use reqwest::header::{HeaderMap, HeaderValue};
    let adapter = hook.config.adapter.as_ref()?;
    if !hook.config.valid() || !hook.config.credential_valid(&hook.secret) {
        return None;
    }
    let mut url = reqwest::Url::parse(&hook.config.endpoint).ok()?;
    let mut headers = HeaderMap::new();
    let body = match adapter {
        Adapter::Lakera {} => {
            serde_json::json!({"messages":[{"role":match phase {Phase::Pre=>"user",Phase::Post=>"assistant"},"content":text}]})
        }
        Adapter::AzureContentSafety { .. } => {
            // Azure's documented wire limit is Unicode code points, not UTF-8 bytes.
            if text.chars().count() > 10_000 {
                return None;
            }
            url.set_path("/contentsafety/text:analyze");
            url.set_query(Some("api-version=2024-09-01"));
            let mut auth = HeaderValue::from_str(hook.secret.expose_secret()).ok()?;
            auth.set_sensitive(true);
            headers.insert("ocp-apim-subscription-key", auth);
            serde_json::json!({"text":text,"categories":["Hate","SelfHarm","Sexual","Violence"],"outputType":"EightSeverityLevels"})
        }
    };
    Some(Outbound {
        url: url.into(),
        body: serde_json::to_vec(&body).ok()?,
        headers,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum LakeraAction {
    Enforce,
    Detect,
}
type Diagnostic = serde_json::Map<String, serde_json::Value>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LakeraReply {
    flagged: bool,
    action: LakeraAction,
    #[serde(rename = "payload")]
    _payload: Option<Vec<Diagnostic>>,
    #[serde(rename = "breakdown")]
    _breakdown: Option<Vec<Diagnostic>>,
    #[serde(rename = "tools")]
    _tools: Option<Diagnostic>,
    #[serde(rename = "dev_info")]
    _dev_info: Option<Diagnostic>,
    #[serde(rename = "metadata")]
    _metadata: Option<Diagnostic>,
}
#[derive(Deserialize, Clone, Copy)]
enum Category {
    Hate,
    SelfHarm,
    Sexual,
    Violence,
}
impl Category {
    fn index(self) -> usize {
        match self {
            Self::Hate => 0,
            Self::SelfHarm => 1,
            Self::Sexual => 2,
            Self::Violence => 3,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CategoryResult {
    category: Category,
    severity: u8,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlocklistMatch {
    #[serde(rename = "blocklistName")]
    _name: String,
    #[serde(rename = "blocklistItemId")]
    _id: String,
    #[serde(rename = "blocklistItemText")]
    _text: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AzureReply {
    // No blocklists are requested by this adapter. The optional absent list means
    // no match; four complete category verdicts are still mandatory.
    #[serde(default)]
    blocklists_match: Vec<BlocklistMatch>,
    categories_analysis: Vec<CategoryResult>,
}
/// Only a complete, unambiguous decision can allow. Ignored diagnostics never decide.
pub fn parse_reply(adapter: &Adapter, bytes: &[u8]) -> Option<Reply> {
    if bytes.len() > super::hooks::limits()?.response_bytes {
        return None;
    }
    let deny = match adapter {
        Adapter::Lakera {} => {
            let reply: LakeraReply = serde_json::from_slice(bytes).ok()?;
            // Detect mode forces flagged=false even when threats were found.
            if !matches!(reply.action, LakeraAction::Enforce) {
                return None;
            }
            reply.flagged
        }
        Adapter::AzureContentSafety { thresholds } => {
            let reply: AzureReply = serde_json::from_slice(bytes).ok()?;
            let limits = thresholds.values();
            if limits.iter().any(|n| *n > 7) || reply.categories_analysis.len() != 4 {
                return None;
            }
            let mut seen = [false; 4];
            let mut deny = !reply.blocklists_match.is_empty();
            for category in reply.categories_analysis {
                let i = category.category.index();
                if seen[i] || category.severity > 7 {
                    return None;
                }
                seen[i] = true;
                deny |= category.severity >= limits[i];
            }
            deny
        }
    };
    Some(if deny {
        Reply::Deny {}
    } else {
        Reply::Allow {}
    })
}
