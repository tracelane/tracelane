//! Customer-controlled wrapping of tenant provider-key data keys.
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use secrecy::{ExposeSecret as _, SecretString, zeroize::Zeroizing};
use tracelane_shared::TenantId;
use uuid::Uuid;

pub mod api;
pub mod backend;
pub mod vault;
pub use vault::{KeyVault, VaultError};

#[derive(serde::Deserialize)]
pub struct Limits {
    pub dek_cache_ttl_secs: u64,
    pub dek_cache_max_entries: usize,
    pub call_timeout_ms: u64,
    pub failure_backoff_secs: u64,
    /// How long a caller waits for its OWN tenant's KMS fence or in-flight unwrap
    /// before failing closed (H1).
    pub lock_wait_ms: u64,
    /// Most customer-KMS calls one tenant may have in flight (H1 round 2).
    pub max_calls_per_tenant: usize,
    pub response_bytes: usize,
}
pub fn limits() -> Option<&'static Limits> {
    static LIMITS: std::sync::OnceLock<Option<Limits>> = std::sync::OnceLock::new();
    LIMITS
        .get_or_init(|| {
            let value: serde_json::Value =
                serde_json::from_str(include_str!("../../translation_policy.v1.json")).ok()?;
            let limits: Limits = serde_json::from_value(value.get("kms")?.clone()).ok()?;
            (limits.dek_cache_ttl_secs > 0
                && limits.dek_cache_max_entries > 0
                && limits.call_timeout_ms > 0
                && limits.failure_backoff_secs > 0
                && limits.lock_wait_ms > 0
                && limits.max_calls_per_tenant > 0
                && limits.response_bytes > 0)
                .then_some(limits)
        })
        .as_ref()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KmsError {
    #[error("kms_unavailable")]
    Unavailable,
    #[error("kms_access_denied")]
    Denied,
}

// Version, UUID, nonce and tag lengths are wire-format invariants.
fn seal(
    tenant: &TenantId,
    provider: &str,
    id: Uuid,
    dek: &[u8; 32],
    secret: &SecretString,
) -> Result<String, KmsError> {
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, dek).map_err(|_| KmsError::Denied)?);
    let mut nonce = [0; 12];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| KmsError::Unavailable)?;
    let mut body = Zeroizing::new(secret.expose_secret().as_bytes().to_vec());
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(crate::byok::provider_key_aad(tenant, provider)),
        &mut *body,
    )
    .map_err(|_| KmsError::Denied)?;
    let mut out = vec![4];
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(B64.encode(out))
}
fn open(
    tenant: &TenantId,
    provider: &str,
    id: Uuid,
    dek: &[u8; 32],
    blob: &str,
) -> Result<SecretString, KmsError> {
    let mut raw = Zeroizing::new(B64.decode(blob).map_err(|_| KmsError::Denied)?);
    if raw.len() < 1 + 16 + 12 + 16 || raw[0] != 4 || &raw[1..17] != id.as_bytes() {
        return Err(KmsError::Denied);
    }
    let nonce = Nonce::try_assume_unique_for_key(&raw[17..29]).map_err(|_| KmsError::Denied)?;
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, dek).map_err(|_| KmsError::Denied)?);
    let plain = key
        .open_in_place(
            nonce,
            Aad::from(crate::byok::provider_key_aad(tenant, provider)),
            &mut raw[29..],
        )
        .map_err(|_| KmsError::Denied)?;
    Ok(SecretString::from(
        std::str::from_utf8(plain)
            .map_err(|_| KmsError::Denied)?
            .to_owned(),
    ))
}
fn context(tenant: &TenantId, id: Uuid) -> Vec<u8> {
    let mut out = b"tracelane-dek".to_vec();
    out.extend_from_slice(tenant.as_uuid().as_bytes());
    out.extend_from_slice(id.as_bytes());
    out
}
fn bound_dek(tenant: &TenantId, id: Uuid, dek: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(dek.to_vec());
    out.extend_from_slice(
        ring::digest::digest(&ring::digest::SHA256, &context(tenant, id)).as_ref(),
    );
    out
}
fn unbind_dek(
    tenant: &TenantId,
    id: Uuid,
    payload: &[u8],
) -> Result<Zeroizing<[u8; 32]>, KmsError> {
    // The digest is public context, not a secret-dependent comparison. The KMS
    // authenticates the whole payload; even backends without native AAD bind rows.
    if payload.len() != 64
        || &payload[32..]
            != ring::digest::digest(&ring::digest::SHA256, &context(tenant, id)).as_ref()
    {
        return Err(KmsError::Denied);
    }
    let mut dek = Zeroizing::new([0; 32]);
    dek.copy_from_slice(&payload[..32]);
    Ok(dek)
}

pub fn retry_after(mut response: axum::response::Response, code: &str) -> axum::response::Response {
    if code == "kms_unavailable"
        && let Some(l) = limits()
        && let Ok(h) = l.failure_backoff_secs.to_string().parse()
    {
        response
            .headers_mut()
            .insert(axum::http::header::RETRY_AFTER, h);
    }
    response
}
pub fn failure_response(error: VaultError) -> axum::response::Response {
    use axum::http::StatusCode;
    let (status, code) = match error {
        VaultError::Kms(KmsError::Denied) => (StatusCode::FORBIDDEN, "kms_access_denied"),
        VaultError::Kms(KmsError::Unavailable) => {
            (StatusCode::SERVICE_UNAVAILABLE, "kms_unavailable")
        }
        VaultError::Lookup => (StatusCode::SERVICE_UNAVAILABLE, "provider_key_unavailable"),
        VaultError::Invalid => (StatusCode::BAD_GATEWAY, "provider_key_unusable"),
    };
    crate::openai_responses::coded(status, code, code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip_and_row_binding() {
        let a = TenantId::from_jwt_claim(Uuid::new_v4());
        let b = TenantId::from_jwt_claim(Uuid::new_v4());
        let id = Uuid::new_v4();
        let key = Zeroizing::new([42; 32]);
        let secret = SecretString::from("unit-test-provider-key-do-not-use");
        let blob =
            seal(&a, "openai", id, &key, &secret).expect("a tenant DEK must seal a provider key");
        assert_eq!(B64.decode(&blob).unwrap()[0], 4);
        assert_eq!(
            open(&a, "openai", id, &key, &blob).unwrap().expose_secret(),
            secret.expose_secret()
        );
        assert!(open(&b, "openai", id, &key, &blob).is_err());
        assert!(open(&a, "anthropic", id, &key, &blob).is_err());
        assert!(open(&a, "openai", Uuid::new_v4(), &key, &blob).is_err());
        let master =
            crate::byok::ByokMasterKey::from_values(Some(&B64.encode([7; 32])), None, None)
                .unwrap()
                .unwrap();
        assert!(
            master
                .decrypt_with_context(&blob, &crate::byok::provider_key_aad(&a, "openai"))
                .is_err()
        );
        let old = master
            .encrypt_with_context(&secret, &crate::byok::provider_key_aad(&a, "openai"))
            .unwrap();
        assert!(open(&a, "openai", id, &key, &old).is_err());
    }

    #[test]
    fn wrapped_payload_binds_tenant_and_dek_for_every_backend() {
        let a = TenantId::from_jwt_claim(Uuid::new_v4());
        let b = TenantId::from_jwt_claim(Uuid::new_v4());
        let id = Uuid::new_v4();
        let payload = bound_dek(&a, id, &[17; 32]);
        assert_eq!(
            payload.len(),
            64,
            "wrapped payload must carry a DEK and its context hash"
        );
        assert_eq!(*unbind_dek(&a, id, &payload).unwrap(), [17; 32]);
        assert!(unbind_dek(&b, id, &payload).is_err());
        assert!(unbind_dek(&a, Uuid::new_v4(), &payload).is_err());
        assert!(unbind_dek(&a, id, &payload[..32]).is_err());
    }
}

#[cfg(test)]
pub(crate) mod wire_tests;
