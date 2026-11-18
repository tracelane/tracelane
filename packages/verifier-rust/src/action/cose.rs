//! `checkpoint.cose`: a COSE_Sign1 (RFC 9052 §4.2) over the exact bytes of `checkpoint.json`,
//! with the Signed Statement headers of draft-ietf-scitt-architecture-22 §6 (alg, content
//! type, kid, and CWT Claims with iss and sub). Aligned to that draft; no Receipt and no
//! Transparency Service are involved, so this is not a Transparent Statement.
//!
//! The message has ONE valid encoding per checkpoint (deterministic CBOR, RFC 8949 §4.2.1,
//! and Ed25519 is deterministic). The verifier rebuilds it from `checkpoint.json` and
//! compares bytes, so there is no CBOR parser here; `tests/cose_interop.rs` proves the
//! bytes with an independent COSE implementation.
use anyhow::{Result, ensure};

const SIGNATURE_LEN: usize = 64;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Not the expected COSE_Sign1 encoding for this checkpoint.
    Format(String),
    /// Expected encoding, but the signature does not verify under the external pin.
    Signature,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Format(detail) => write!(f, "checkpoint.cose: {detail}"),
            Self::Signature => f.write_str("checkpoint.cose does not verify under external pin"),
        }
    }
}
impl std::error::Error for Error {}

#[derive(serde::Deserialize)]
struct Subject {
    domain: String,
    tenant_id: uuid::Uuid,
    key_id: String,
}

/// CBOR head: major type plus the shortest argument encoding (RFC 8949 §3, §4.2.1).
fn head(out: &mut Vec<u8>, major: u8, n: usize) {
    let n = n as u64;
    let major = major << 5;
    match n {
        0..=23 => out.push(major | n as u8),
        24..=0xff => out.extend([major | 24, n as u8]),
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend((n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major | 26);
            out.extend((n as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend(n.to_be_bytes());
        }
    }
}
fn bstr(out: &mut Vec<u8>, bytes: &[u8]) {
    head(out, 2, bytes.len());
    out.extend(bytes);
}
fn tstr(out: &mut Vec<u8>, text: &str) {
    head(out, 3, text.len());
    out.extend(text.as_bytes());
}
/// `{1: -8, 3: "application/json", 4: kid, 15: {1: iss, 2: sub}}`, keys in bytewise order.
fn protected_header(key_id: &str, tenant: &uuid::Uuid, domain: &str) -> Vec<u8> {
    let mut out = vec![0xa4, 0x01, 0x27, 0x03]; // map(4), alg: EdDSA (-8), content type:
    tstr(&mut out, "application/json");
    out.push(0x04);
    bstr(&mut out, key_id.as_bytes());
    out.extend([0x0f, 0xa2, 0x01]); // CWT Claims: map(2), iss:
    tstr(&mut out, &format!("urn:uuid:{tenant}"));
    out.push(0x02); // sub:
    tstr(&mut out, domain);
    out
}
fn protected_for(statement: &[u8]) -> Result<Vec<u8>> {
    let subject: Subject = serde_json::from_slice(statement)?;
    ensure!(
        !subject.key_id.is_empty() && !subject.domain.is_empty(),
        "checkpoint key_id/domain empty"
    );
    Ok(protected_header(
        &subject.key_id,
        &subject.tenant_id,
        &subject.domain,
    ))
}
/// `18([protected, {}, payload,` — everything before the signature.
fn envelope(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0xd2, 0x84];
    bstr(&mut out, protected);
    out.push(0xa0);
    bstr(&mut out, payload);
    out
}
/// RFC 9052 §4.4 `Sig_structure` for COSE_Sign1 with empty external_aad.
fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x84];
    tstr(&mut out, "Signature1");
    bstr(&mut out, protected);
    out.push(0x40);
    bstr(&mut out, payload);
    out
}

/// Build `checkpoint.cose` for a `checkpoint.json` statement. `sign` is the tenant Ed25519
/// signer. Errors fail CLOSED: a statement without the head fields, or a signer that does
/// not return 64 bytes, yields no member.
pub fn sign1(statement: &[u8], sign: impl FnOnce(&[u8]) -> Vec<u8>) -> Result<Vec<u8>> {
    let protected = protected_for(statement)?;
    let signature = sign(&sig_structure(&protected, statement));
    ensure!(
        signature.len() == SIGNATURE_LEN,
        "Ed25519 signature must be 64 bytes"
    );
    let mut out = envelope(&protected, statement);
    bstr(&mut out, &signature);
    Ok(out)
}

/// Verify `checkpoint.cose` against the bundle's `checkpoint.json` bytes and the externally
/// pinned tenant key. The embedded payload, kid, issuer and subject must be exactly the ones
/// the checkpoint implies. Errors fail CLOSED.
pub fn verify(cose: &[u8], statement: &[u8], pin: &[u8; 32]) -> std::result::Result<(), Error> {
    let protected = protected_for(statement).map_err(|e| Error::Format(e.to_string()))?;
    let mut expected = envelope(&protected, statement);
    head(&mut expected, 2, SIGNATURE_LEN);
    let signature = cose
        .strip_prefix(expected.as_slice())
        .filter(|signature| signature.len() == SIGNATURE_LEN)
        .ok_or_else(|| {
            Error::Format("not the expected COSE_Sign1 encoding of checkpoint.json".into())
        })?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pin)
        .verify(&sig_structure(&protected, statement), signature)
        .map_err(|_| Error::Signature)
}

#[cfg(test)]
mod tests;
