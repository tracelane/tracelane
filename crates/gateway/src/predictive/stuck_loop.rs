//! Browser stuck-loop detector (AFT-A2UI-STUCKLOOP-001).
//!
//! Detects when an agent repeats the same action without observable
//! progress — a common A2UI failure mode (clicking a button that keeps
//! being intercepted). Two signals, in priority order:
//!
//! 1. **Explicit client hint** — `tracelane_repeat_count` in the request:
//!    `>= 3` warns, `>= 5` blocks. Backward-compatible.
//! 2. **Server-side history** — the detector tracks the last few action
//!    hashes per `(tenant_id, session)` in an in-process `DashMap` and fires
//!    when the trailing run of *identical* actions reaches the warn/block
//!    threshold. This needs no client cooperation: a real loop is caught
//!    even when the agent does not self-report a repeat count.
//!
//! An "action" is hashed from the tool name plus its input fields, so the
//! same tool with different arguments does not count as a repeat. Session is
//! keyed off `tracelane_trace_id` / `tracelane_session_id` /
//! `tracelane_conversation_id` when present, else the tenant-global bucket.
//!
//! State is bounded per session (`HISTORY_CAP` entries) but the map grows
//! with distinct sessions; a TTL sweep is future work (it mirrors the
//! `auto_rollback` per-key state model).
//!
//! AFT reference: AFT-A2UI-STUCKLOOP-001

use std::collections::VecDeque;
use std::hash::{Hash, Hasher};

use dashmap::DashMap;

use tracelane_shared::TenantId;

use super::{Decision, PredictiveContext, Predictor};

const HISTORY_CAP: usize = 8;
const WARN_REPEATS: usize = 3;
const BLOCK_REPEATS: usize = 5;
const AFT: &str = "AFT-A2UI-STUCKLOOP-001";

pub struct StuckLoopDetector {
    /// `(tenant_id, session_key)` -> recent action hashes, most-recent last.
    history: DashMap<(TenantId, String), VecDeque<u64>>,
}

impl StuckLoopDetector {
    pub fn new() -> Self {
        Self {
            history: DashMap::new(),
        }
    }

    /// Hash an action from the tool name plus any of its input fields, so
    /// "same tool, different args" is not counted as a repeat.
    fn action_hash(tool_name: &str, req: &serde_json::Value) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        tool_name.hash(&mut h);
        for k in ["tool_input", "arguments", "tool_args", "tool_url", "input"] {
            if let Some(v) = req.get(k) {
                v.to_string().hash(&mut h);
            }
        }
        h.finish()
    }

    /// Stable per-conversation key, or the tenant-global bucket if the
    /// request carries no correlation id.
    fn session_key(req: &serde_json::Value) -> String {
        for k in [
            "tracelane_trace_id",
            "tracelane_session_id",
            "tracelane_conversation_id",
        ] {
            if let Some(s) = req.get(k).and_then(|v| v.as_str()) {
                return s.to_string();
            }
        }
        String::new()
    }

    /// Length of the trailing run of identical hashes (the current repeat
    /// streak), e.g. `[a,b,b,b]` -> 3.
    fn trailing_run(hist: &VecDeque<u64>) -> usize {
        let Some(&last) = hist.back() else {
            return 0;
        };
        hist.iter().rev().take_while(|&&x| x == last).count()
    }

    fn decision_for_run(run: usize) -> Decision {
        if run >= BLOCK_REPEATS {
            Decision::Block { aft_id: AFT }
        } else if run >= WARN_REPEATS {
            Decision::Warn { aft_id: AFT }
        } else {
            Decision::Allow
        }
    }
}

impl Default for StuckLoopDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Predictor for StuckLoopDetector {
    fn name(&self) -> &'static str {
        "stuck-loop"
    }

    fn evaluate(&self, ctx: &PredictiveContext<'_>) -> Decision {
        let req = ctx.request_json;

        // Only active for tool-call requests.
        let tool_name = match req.get("tool_name").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => return Decision::Allow,
        };

        // 1. Explicit client hint (backward-compatible fast path).
        let repeat_count = req
            .get("tracelane_repeat_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let hint = Self::decision_for_run(repeat_count);
        if !matches!(hint, Decision::Allow) {
            tracing::warn!(tool = %tool_name, repeat_count, "stuck-loop: client-reported repeat");
            return hint;
        }

        // 2. Server-side history — fire on a tight repeat run with no client
        //    cooperation required.
        let key = (ctx.tenant_id.clone(), Self::session_key(req));
        let hash = Self::action_hash(tool_name, req);
        let run = {
            let mut entry = self.history.entry(key).or_default();
            entry.push_back(hash);
            while entry.len() > HISTORY_CAP {
                entry.pop_front();
            }
            Self::trailing_run(&entry)
        };

        let decision = Self::decision_for_run(run);
        if !matches!(decision, Decision::Allow) {
            tracing::warn!(tool = %tool_name, run, "stuck-loop: repeated identical action");
        }
        decision
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

    fn eval(detector: &StuckLoopDetector, req: &serde_json::Value) -> Decision {
        detector.evaluate(&PredictiveContext {
            tenant_id: &tenant(),
            request_json: req,
        })
    }

    #[test]
    fn repeat_3_triggers_warn() {
        let detector = StuckLoopDetector::new();
        let req = json!({ "tool_name": "click", "tracelane_repeat_count": 3 });
        assert_eq!(eval(&detector, &req), Decision::Warn { aft_id: AFT });
    }

    #[test]
    fn repeat_2_is_ok() {
        let detector = StuckLoopDetector::new();
        let req = json!({ "tool_name": "click", "tracelane_repeat_count": 2 });
        assert_eq!(eval(&detector, &req), Decision::Allow);
    }

    #[test]
    fn server_side_detects_loop_without_client_hint() {
        let detector = StuckLoopDetector::new();
        // Identical click in the same session, no repeat-count hint.
        let req = json!({
            "tool_name": "click",
            "tool_input": { "selector": "#submit" },
            "tracelane_session_id": "sess-1"
        });
        assert_eq!(eval(&detector, &req), Decision::Allow); // run 1
        assert_eq!(eval(&detector, &req), Decision::Allow); // run 2
        assert_eq!(eval(&detector, &req), Decision::Warn { aft_id: AFT }); // run 3
        assert_eq!(eval(&detector, &req), Decision::Warn { aft_id: AFT }); // run 4 (>= warn, < block)
        assert_eq!(eval(&detector, &req), Decision::Block { aft_id: AFT }); // run 5
    }

    #[test]
    fn different_input_breaks_the_run() {
        let detector = StuckLoopDetector::new();
        let a = json!({ "tool_name": "click", "tool_input": {"selector": "#a"}, "tracelane_session_id": "s" });
        let b = json!({ "tool_name": "click", "tool_input": {"selector": "#b"}, "tracelane_session_id": "s" });
        assert_eq!(eval(&detector, &a), Decision::Allow);
        assert_eq!(eval(&detector, &a), Decision::Allow);
        // Different selector resets the trailing run.
        assert_eq!(eval(&detector, &b), Decision::Allow);
        assert_eq!(eval(&detector, &a), Decision::Allow);
        // Only one trailing `a`, so still Allow — no false positive.
        assert_eq!(eval(&detector, &b), Decision::Allow);
    }

    #[test]
    fn distinct_sessions_are_isolated() {
        let detector = StuckLoopDetector::new();
        let s1 =
            json!({ "tool_name": "click", "tool_input": {"x":1}, "tracelane_session_id": "s1" });
        let s2 =
            json!({ "tool_name": "click", "tool_input": {"x":1}, "tracelane_session_id": "s2" });
        // Two repeats in s1 then one in s2 — neither reaches the warn run of 3.
        assert_eq!(eval(&detector, &s1), Decision::Allow);
        assert_eq!(eval(&detector, &s1), Decision::Allow);
        assert_eq!(eval(&detector, &s2), Decision::Allow);
        assert_eq!(eval(&detector, &s2), Decision::Allow);
    }

    #[test]
    fn non_tool_request_is_ignored() {
        let detector = StuckLoopDetector::new();
        let req = json!({ "messages": [] });
        assert_eq!(eval(&detector, &req), Decision::Allow);
    }
}
