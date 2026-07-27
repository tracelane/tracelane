//! The 8 V1 guardrail rails (the guardrail spec §3). Each rail implements
//! [`crate::guardrail::rail::Rail`] over the Phase-0 substrate and is registered
//! in the engine. Built in spec order: R4 first (the flagship differentiator),
//! then R1, R3, R2, R5, R6, R7, R8.

pub mod r1_cost;
pub mod r2_secrets_pii;
pub mod r3_tool_safety;
pub mod r4_trifecta;
pub mod r5_format;
pub mod r6_sysprompt_leak;
pub mod r7_topic_competitor;
pub mod r8_injection;

pub use r1_cost::R1Cost;
pub use r2_secrets_pii::R2SecretsPii;
pub use r3_tool_safety::{R3Pinning, R3Schema};
pub use r4_trifecta::R4Trifecta;
pub use r5_format::R5Format;
pub use r6_sysprompt_leak::R6SysPromptLeak;
pub use r7_topic_competitor::{R7Config, R7TopicCompetitor};
pub use r8_injection::R8Injection;
