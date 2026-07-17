//! MCP hash watcher — detects tool-list changes between sessions (rug-pull).
//!
//! On every `mcp.tool_list` span, computes SHA256(sorted tool names).
//! If the hash differs from the last recorded hash for this tenant + server,
//! emits `Decision::Warn { aft_id: "AFT-MCP-RUGPULL-001" }`.
//! If any new tool name matches a known-bad pattern, emits `Decision::Block`.
//!
//! State is stored in a `DashMap<(TenantId, ServerName), ToolsHash>`.
//! TTL expiry clears entries after 24h of inactivity — agents restart with
//! a fresh baseline rather than never-expiring state.
//!

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::instrument;

use tracelane_shared::TenantId;

use super::{Decision, PredictiveContext, Predictor};

const ENTRY_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Known-bad tool name patterns (case-insensitive prefix/substring match).
/// If any new tool matches these, severity escalates to Block.
const SUSPICIOUS_PATTERNS: &[&str] = &[
    "exfiltrate",
    "steal",
    "extract_credentials",
    "send_to_attacker",
    "upload_to",
    "submit_payment",
    "wire_transfer",
    "delete_all",
    "drop_table",
];

#[derive(Debug, Clone)]
struct ToolsEntry {
    hash: String,
    tool_names: Vec<String>,
    recorded_at: Instant,
}

/// MCP rug-pull detection predictor.
///
/// Implements AFT-MCP-RUGPULL-001: fires if the SHA256 hash of an MCP
/// server's tool list changes between requests for the same tenant.
pub struct McpHashWatcher {
    state: Arc<Mutex<HashMap<String, ToolsEntry>>>,
}

impl McpHashWatcher {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Compute a stable hash of the sorted tool names list.
    pub fn hash_tools(tool_names: &[&str]) -> String {
        use std::collections::BTreeSet;
        let sorted: BTreeSet<&str> = tool_names.iter().copied().collect();
        let joined = sorted.into_iter().collect::<Vec<_>>().join(",");

        use ring::digest;
        let digest = digest::digest(&digest::SHA256, joined.as_bytes());
        hex::encode(digest.as_ref())
    }

    fn state_key(tenant_id: &TenantId, server_name: &str) -> String {
        format!("{}:{}", tenant_id, server_name)
    }

    fn evict_stale(&self, state: &mut HashMap<String, ToolsEntry>) {
        state.retain(|_, v| v.recorded_at.elapsed() < ENTRY_TTL);
    }
}

impl Default for McpHashWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Predictor for McpHashWatcher {
    fn name(&self) -> &'static str {
        "mcp-hash-watcher"
    }

    #[instrument(skip(self, ctx), fields(tenant_id = %ctx.tenant_id))]
    fn evaluate(&self, ctx: &PredictiveContext<'_>) -> Decision {
        let req = ctx.request_json;

        // Only evaluate requests that include an mcp.tool_list result
        let mcp_server = match req.get("mcp_server_name").and_then(|v| v.as_str()) {
            Some(s) => s.to_owned(),
            None => return Decision::Allow,
        };

        let tools_arr = match req.get("mcp_tools").and_then(|v| v.as_array()) {
            Some(arr) => arr,
            None => return Decision::Allow,
        };

        let tool_names: Vec<String> = tools_arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();

        let tool_refs: Vec<&str> = tool_names.iter().map(String::as_str).collect();
        let current_hash = Self::hash_tools(&tool_refs);
        let key = Self::state_key(ctx.tenant_id, &mcp_server);

        let mut state = self.state.lock().expect("state lock poisoned");
        self.evict_stale(&mut state);

        if let Some(entry) = state.get(&key) {
            if entry.hash != current_hash {
                // Detect new tools that weren't in the previous list
                let prev_set: std::collections::HashSet<&str> =
                    entry.tool_names.iter().map(String::as_str).collect();
                let new_tools: Vec<&str> = tool_refs
                    .iter()
                    .filter(|&&t| !prev_set.contains(t))
                    .copied()
                    .collect();

                tracing::warn!(
                    server = %mcp_server,
                    prev_hash = %entry.hash,
                    curr_hash = %current_hash,
                    new_tools = ?new_tools,
                    "MCP tool list changed — potential rug-pull"
                );

                // Check new tools against known-bad patterns
                let is_suspicious = new_tools.iter().any(|t| {
                    let lower = t.to_lowercase();
                    SUSPICIOUS_PATTERNS.iter().any(|p| lower.contains(p))
                });

                // Update state with new hash
                state.insert(
                    key,
                    ToolsEntry {
                        hash: current_hash,
                        tool_names,
                        recorded_at: Instant::now(),
                    },
                );

                return if is_suspicious {
                    Decision::Block {
                        aft_id: "AFT-MCP-RUGPULL-001",
                    }
                } else {
                    Decision::Warn {
                        aft_id: "AFT-MCP-RUGPULL-001",
                    }
                };
            }
        } else {
            // First time seeing this server — record baseline
            state.insert(
                key,
                ToolsEntry {
                    hash: current_hash,
                    tool_names,
                    recorded_at: Instant::now(),
                },
            );
        }

        Decision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tracelane_shared::TenantId;
    use uuid::Uuid;

    fn tenant() -> TenantId {
        TenantId::from_jwt_claim(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap())
    }

    #[test]
    fn same_tools_returns_allow() {
        let watcher = McpHashWatcher::new();
        let ctx_json = json!({
            "mcp_server_name": "filesystem",
            "mcp_tools": ["read_file", "write_file"]
        });
        let ctx = PredictiveContext {
            tenant_id: &tenant(),
            request_json: &ctx_json,
        };

        assert_eq!(watcher.evaluate(&ctx), Decision::Allow);
        assert_eq!(watcher.evaluate(&ctx), Decision::Allow); // second call same tools
    }

    #[test]
    fn changed_tools_returns_warn() {
        let watcher = McpHashWatcher::new();
        let t = tenant();
        let ctx1 = json!({ "mcp_server_name": "filesystem", "mcp_tools": ["read_file"] });
        let ctx2 =
            json!({ "mcp_server_name": "filesystem", "mcp_tools": ["read_file", "new_tool"] });

        let ctx = PredictiveContext {
            tenant_id: &t,
            request_json: &ctx1,
        };
        assert_eq!(watcher.evaluate(&ctx), Decision::Allow);

        let ctx = PredictiveContext {
            tenant_id: &t,
            request_json: &ctx2,
        };
        assert_eq!(
            watcher.evaluate(&ctx),
            Decision::Warn {
                aft_id: "AFT-MCP-RUGPULL-001"
            }
        );
    }

    #[test]
    fn suspicious_tool_escalates_to_block() {
        let watcher = McpHashWatcher::new();
        let t = tenant();
        let ctx1 = json!({ "mcp_server_name": "payments", "mcp_tools": ["get_balance"] });
        let ctx2 = json!({ "mcp_server_name": "payments", "mcp_tools": ["get_balance", "wire_transfer_all"] });

        let ctx = PredictiveContext {
            tenant_id: &t,
            request_json: &ctx1,
        };
        watcher.evaluate(&ctx);

        let ctx = PredictiveContext {
            tenant_id: &t,
            request_json: &ctx2,
        };
        assert_eq!(
            watcher.evaluate(&ctx),
            Decision::Block {
                aft_id: "AFT-MCP-RUGPULL-001"
            }
        );
    }

    #[test]
    fn hash_is_order_independent() {
        let h1 = McpHashWatcher::hash_tools(&["b", "a", "c"]);
        let h2 = McpHashWatcher::hash_tools(&["a", "b", "c"]);
        assert_eq!(h1, h2);
    }
}
