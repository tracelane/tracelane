//! Key capture overrides. A key can narrow workspace capture, never widen it.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "serde_json::Map<String, serde_json::Value>")]
pub struct KeyCapture {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<bool>,
}

pub fn capture_from_row(row: &tokio_postgres::Row) -> anyhow::Result<Option<KeyCapture>> {
    row.get::<_, Option<serde_json::Value>>("capture")
        .map(serde_json::from_value)
        .transpose()
        .map_err(Into::into)
}

#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
pub struct Policy {
    pub retention_days_min: i32,
    pub retention_days_max: i32,
    pub audit_addon_min_days: i32,
    pub estimate_row_cap: u64,
}
impl Policy {
    pub fn valid(&self) -> bool {
        self.retention_days_min > 0
            && self.retention_days_max >= self.audit_addon_min_days
            && self.audit_addon_min_days >= self.retention_days_min
            && self.estimate_row_cap > 0
    }
    pub fn embedded() -> Option<Self> {
        let seed: serde_json::Value =
            serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json")).ok()?;
        serde_json::from_value::<Self>(seed["policy"]["data_controls"].clone())
            .ok()
            .filter(Self::valid)
    }
}

impl TryFrom<serde_json::Map<String, serde_json::Value>> for KeyCapture {
    type Error = &'static str;
    fn try_from(value: serde_json::Map<String, serde_json::Value>) -> Result<Self, Self::Error> {
        if value.keys().any(|k| k != "input" && k != "output") {
            return Err("unknown capture field");
        }
        let flag = |key: &str| {
            value
                .get(key)
                .map(|v| v.as_bool().ok_or("capture flag must be boolean"))
                .transpose()
        };
        Ok(Self {
            input: flag("input")?,
            output: flag("output")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn og38_capture_accepts_independent_booleans() {
        for value in [
            serde_json::json!({}),
            serde_json::json!({"input":false}),
            serde_json::json!({"output":false}),
            serde_json::json!({"input":true,"output":false}),
        ] {
            assert!(serde_json::from_value::<KeyCapture>(value).is_ok());
        }
    }
    #[test]
    fn og38_capture_rejects_unknown_or_nonboolean_fields() {
        for value in [
            serde_json::json!({"tenant_id":"foreign"}),
            serde_json::json!({"input":null}),
            serde_json::json!({"output":1}),
            serde_json::json!({"input":"false"}),
            serde_json::json!([]),
        ] {
            assert!(serde_json::from_value::<KeyCapture>(value).is_err());
        }
    }
}
