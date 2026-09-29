//! Optional display identity. Never an authentication or tenancy signal.
//! Only a catalog id survives User-Agent classification; the input is borrowed.

use regex::Regex;
use serde::Deserialize;
use std::sync::LazyLock;

const CATALOG: &str = include_str!("../../../apps/web/db/kya_catalog.v1.json");

#[derive(Deserialize)]
struct Catalog {
    clients: Vec<ClientEntry>,
    limits: Limits,
}

#[derive(Deserialize)]
struct ClientEntry {
    id: String,
    ua_pattern: String,
}

#[derive(Deserialize)]
pub(crate) struct Limits {
    pub identities: usize,
    pub cross_list: usize,
    pub recent_traces: usize,
    pub agent_name_chars: usize,
}

struct CompiledCatalog {
    clients: Vec<(String, Regex)>,
    limits: Limits,
}

static COMPILED: LazyLock<Result<CompiledCatalog, String>> = LazyLock::new(|| {
    let data: Catalog = serde_json::from_str(CATALOG).map_err(|e| e.to_string())?;
    let clients = data
        .clients
        .into_iter()
        .map(|c| {
            Regex::new(&c.ua_pattern)
                .map(|pattern| (c.id, pattern))
                .map_err(|e| e.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CompiledCatalog {
        clients,
        limits: data.limits,
    })
});

/// Compile once before accepting requests. A broken embedded catalog refuses boot.
/// # Errors
/// Fails CLOSED on invalid catalog JSON or patterns, before traffic is accepted.
pub(crate) fn initialize() -> anyhow::Result<()> {
    COMPILED
        .as_ref()
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("identity catalog: {e}"))
}

pub(crate) fn limits() -> Option<&'static Limits> {
    COMPILED.as_ref().ok().map(|c| &c.limits)
}

/// Unknown or unreadable display metadata fails OPEN with no identity.
pub(crate) fn classify_client(user_agent: &str) -> Option<String> {
    COMPILED
        .as_ref()
        .ok()?
        .clients
        .iter()
        .find(|(_, pattern)| pattern.is_match(user_agent))
        .map(|(id, _)| id.clone())
}

/// Display names truncate; ids used for correlation retain their existing rules.
pub(crate) fn bounded_agent_name(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.chars().any(char::is_control) {
        return None;
    }
    Some(
        raw.to_lowercase()
            .chars()
            .take(limits()?.agent_name_chars)
            .collect(),
    )
}
