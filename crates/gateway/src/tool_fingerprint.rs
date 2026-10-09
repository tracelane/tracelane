//! Workspace-keyed tool argument equality; no argument text is retained here.
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use tracelane_shared::TenantId;

// Keep non-private keys and their raw JSON values searchable, including nested attributes.
pub(crate) const SEARCHABLE_ATTRIBUTES_SQL: &str = "concat('{', arrayStringConcat(arrayMap(kv -> concat(toJSONString(kv.1), ':', kv.2), arrayFilter(kv -> kv.1 NOT IN ('gen_ai_tool_call_arg_fp', 'tracelane_response_tool_arg_fps'), JSONExtractKeysAndValuesRaw(attributes))), ','), '}')";

static PURPOSE_KEY: std::sync::OnceLock<SecretBox<[u8; 32]>> = std::sync::OnceLock::new();
const CONTEXT: &str = "tracelane 2026-09-29 tool-argument fingerprint v1";

/// Called only after the existing API-key loader accepts the SAME startup value.
/// No environment read, generated secret, debug key, or unkeyed fallback here.
/// # Errors
/// Fail CLOSED on malformed or conflicting key material at startup.
pub(crate) fn init_from_existing_pepper(raw: &str) -> anyhow::Result<()> {
    use base64::Engine as _;
    let mut secret = SecretBox::new(Box::new([0; 32]));
    let raw = raw.trim();
    if raw.len() == 64 {
        hex::decode_to_slice(raw, secret.expose_secret_mut())
            .map_err(|_| anyhow::anyhow!("invalid fingerprint key encoding"))?;
    } else {
        let n = base64::engine::general_purpose::STANDARD
            .decode_slice(raw, secret.expose_secret_mut())
            .map_err(|_| anyhow::anyhow!("invalid fingerprint key encoding"))?;
        anyhow::ensure!(n == 32, "invalid fingerprint pepper length");
    }
    let purpose = SecretBox::new(Box::new(blake3::derive_key(
        CONTEXT,
        secret.expose_secret(),
    )));
    drop(secret); // raw decoded pepper is zeroized before installing the purpose key.
    if let Err(secret) = PURPOSE_KEY.set(purpose) {
        anyhow::ensure!(
            PURPOSE_KEY
                .get()
                .is_some_and(|p| p.expose_secret() == secret.expose_secret()),
            "conflicting fingerprint pepper"
        );
    }
    Ok(())
}

fn derive(purpose: &SecretBox<[u8; 32]>, tenant: &TenantId) -> SecretBox<[u8; 32]> {
    SecretBox::new(Box::new(
        *blake3::keyed_hash(purpose.expose_secret(), tenant.as_uuid().as_bytes()).as_bytes(),
    ))
}

pub(crate) fn workspace_key(tenant: &TenantId) -> Option<SecretBox<[u8; 32]>> {
    PURPOSE_KEY.get().map(|p| derive(p, tenant))
}

pub(crate) fn with_key(key: &SecretBox<[u8; 32]>, raw: &str) -> String {
    let canonical = serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .map(|mut v| {
            v.sort_all_objects();
            v.to_string()
        });
    let hash = blake3::keyed_hash(
        key.expose_secret(),
        canonical.as_deref().unwrap_or(raw).as_bytes(),
    );
    hex::encode(&hash.as_bytes()[..8])
}

/// Serialize public attributes with server-only equality evidence removed.
/// # Errors
/// Fails CLOSED to an empty map on malformed attributes; only serializer errors propagate.
pub(crate) fn public_attributes<S: serde::Serializer>(
    raw: &str,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut attrs =
        serde_json::from_str::<serde_json::Value>(raw).unwrap_or(serde_json::Value::Null);
    let Some(map) = attrs.as_object_mut() else {
        return serializer.serialize_str("{}");
    };
    map.remove("gen_ai_tool_call_arg_fp");
    map.remove("tracelane_response_tool_arg_fps");
    serializer.serialize_str(&attrs.to_string())
}

#[cfg(test)]
fn fingerprint(pepper: &SecretBox<[u8; 32]>, tenant: &TenantId, raw: &str) -> String {
    let purpose = SecretBox::new(Box::new(blake3::derive_key(
        CONTEXT,
        pepper.expose_secret(),
    )));
    with_key(&derive(&purpose, tenant), raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cf_low_decode_errors_never_include_pepper_characters() {
        for raw in ["g".repeat(64), "@secret-marker!".into()] {
            let error = init_from_existing_pepper(&raw).unwrap_err().to_string();
            assert_eq!(error, "invalid fingerprint key encoding");
        }
    }
    #[test]
    fn cf_low_startup_retains_only_domain_separated_key() {
        init_from_existing_pepper(&"07".repeat(32)).unwrap();
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::from_u128(1));
        let purpose = blake3::derive_key(CONTEXT, &[7; 32]);
        let expected = blake3::keyed_hash(&purpose, tenant.as_uuid().as_bytes());
        assert_eq!(
            workspace_key(&tenant).unwrap().expose_secret(),
            expected.as_bytes()
        );
    }

    #[test]
    fn cf_m1_serialized_span_reads_strip_fingerprints() {
        let attrs = serde_json::json!({"gen_ai_tool_call_arg_fp":"private-otlp", "tracelane_response_tool_arg_fps":["private-gateway"], "gen_ai.tool.name":"search"}).to_string();
        let row = crate::trace_reads::SpanRow {
            span_id: "span".into(),
            parent_span_id: None,
            name: "tool".into(),
            start_time: String::new(),
            end_time: String::new(),
            start_time_us: 0,
            duration_us: 0,
            status_code: 1,
            status_message: String::new(),
            attributes: attrs,
            aft_ids: vec![],
            intervention: 0,
        };
        let encoded = serde_json::to_string(&row).unwrap();
        assert!(
            !encoded.contains("private-"),
            "server-only fingerprints must never serialize to clients"
        );
        assert!(encoded.contains("search"));
    }

    #[test]
    fn existing_pepper_encodings_agree_and_conflicts_refuse() {
        use base64::Engine as _;
        init_from_existing_pepper(&"07".repeat(32)).unwrap();
        init_from_existing_pepper(&base64::engine::general_purpose::STANDARD.encode([7; 32]))
            .unwrap();
        assert!(init_from_existing_pepper("invalid").is_err());
        assert!(init_from_existing_pepper(&"08".repeat(32)).is_err());
    }
    #[test]
    fn fingerprints_are_canonical_and_workspace_keyed() {
        let pepper = SecretBox::new(Box::new([7; 32]));
        let a = TenantId::from_jwt_claim(uuid::Uuid::from_u128(1));
        let b = TenantId::from_jwt_claim(uuid::Uuid::from_u128(2));
        let fp = fingerprint(&pepper, &a, r#"{"b":[{"z":1,"a":2}],"a":"Paris"}"#);
        assert_eq!(
            fp,
            fingerprint(&pepper, &a, r#"{ "a":"Paris", "b":[{"a":2,"z":1}] }"#)
        );
        assert_ne!(
            fp,
            fingerprint(&pepper, &b, r#"{"b":[{"z":1,"a":2}],"a":"Paris"}"#),
            "workspaces must not share fingerprints"
        );
        assert_ne!(fp, fingerprint(&pepper, &a, r#"{"a":"London"}"#));
        assert_ne!(
            fp,
            fingerprint(
                &SecretBox::new(Box::new([8; 32])),
                &a,
                r#"{"b":[{"z":1,"a":2}],"a":"Paris"}"#
            )
        );
        assert_eq!(fp.len(), 16);
        assert_ne!(
            fingerprint(&pepper, &a, "bad json"),
            fingerprint(&pepper, &a, "bad json ")
        );
    }
}
