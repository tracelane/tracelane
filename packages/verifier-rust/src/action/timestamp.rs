//! Offline RFC 3161 / RFC 5816 validation against explicit TSA leaf pins.
//! CMS/DER parsing does not fetch certificates, CRLs, OCSP or any other resource.
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, NaiveDateTime, Utc};
use cms::{
    content_info::ContentInfo,
    signed_data::{SignedData, SignerIdentifier},
};
use der::{
    Any, Decode, DecodePem, Encode, Sequence, Tag, Tagged,
    asn1::{ObjectIdentifier, OctetString, Uint},
};
use x509_cert::{Certificate, spki::AlgorithmIdentifierOwned};
const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const TST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const SIGNED: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const CERT_BINDING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
#[derive(Sequence)]
struct Imprint {
    algorithm: AlgorithmIdentifierOwned,
    digest: OctetString,
}
#[derive(Sequence)]
struct Response {
    status: Any,
    token: Option<ContentInfo>,
}
#[derive(Sequence)]
struct Status {
    status: u8,
    text: Option<Vec<String>>,
    failure: Option<der::asn1::BitString>,
}
#[derive(Sequence)]
struct Accuracy {
    seconds: Option<u32>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    millis: Option<u16>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    micros: Option<u16>,
}
#[derive(Sequence)]
struct Info {
    version: u8,
    policy: ObjectIdentifier,
    imprint: Imprint,
    serial: Uint,
    time: Any,
    accuracy: Option<Accuracy>,
    #[asn1(default = "Default::default")]
    ordering: bool,
    nonce: Option<Uint>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    tsa: Option<Any>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    extensions: Option<x509_cert::ext::Extensions>,
}
#[derive(Sequence)]
struct CertId {
    algorithm: Option<AlgorithmIdentifierOwned>,
    hash: OctetString,
    issuer_serial: Option<Any>,
}
#[derive(Sequence)]
struct CertBinding {
    certs: Vec<CertId>,
    policies: Option<Any>,
}
#[derive(Sequence)]
struct Request {
    version: u8,
    imprint: Imprint,
    cert_req: bool,
}
fn attribute(attrs: &x509_cert::attr::Attributes, oid: ObjectIdentifier) -> Result<&Any> {
    let mut matches = attrs.iter().filter(|a| a.oid == oid);
    let attr = matches
        .next()
        .context("missing timestamp signed attribute")?;
    ensure!(
        matches.next().is_none() && attr.values.len() == 1,
        "duplicate timestamp signed attribute"
    );
    attr.values
        .get(0)
        .context("missing timestamp signed attribute value")
}
fn null_parameters(algorithm: &AlgorithmIdentifierOwned) -> bool {
    algorithm
        .parameters
        .as_ref()
        .is_none_or(|p| p.tag() == Tag::Null && p.value().is_empty())
}
/// Parse one TSA pin (PEM or DER) so callers can reject bad trust input at load time,
/// before any token is checked (review M-A, 2026-11-13). Errors fail CLOSED for the caller.
pub fn validate_pin(raw: &[u8]) -> Result<()> {
    pin_certificate(raw).map(|_| ())
}
fn pin_certificate(raw: &[u8]) -> Result<Certificate> {
    if raw.starts_with(b"-----BEGIN") {
        Ok(Certificate::from_pem(raw)?)
    } else {
        Ok(Certificate::from_der(raw)?)
    }
}
/// Malformed proofs and matching-pin validation failures fail CLOSED.
/// Missing tokens or signers without an external pin return None; callers distinguish absence.
/// Certificate validity is evaluated at gen_time.
pub fn verify_optional(
    token: Option<&[u8]>,
    checkpoint: &[u8],
    pins: &[Vec<u8>],
) -> Result<Option<DateTime<Utc>>> {
    let Some(token) = token else { return Ok(None) };
    let response = Response::from_der(token).context("timestamp DER response")?;
    let status = response
        .status
        .decode_as::<Status>()
        .context("timestamp DER status")?;
    ensure!(
        status.status <= 1 && status.failure.is_none(),
        "timestamp authority did not grant request"
    );
    let content = response.token.context("missing timestamp token")?;
    ensure!(
        content.content_type == SIGNED,
        "timestamp content is not SignedData"
    );
    let signed = content
        .content
        .decode_as::<SignedData>()
        .context("timestamp DER SignedData")?;
    ensure!(
        signed.version == cms::content_info::CmsVersion::V3,
        "timestamp SignedData version"
    );
    ensure!(
        signed.signer_infos.0.len() == 1,
        "timestamp requires one signer"
    );
    ensure!(
        signed.encap_content_info.econtent_type == TST,
        "timestamp content type"
    );
    let info_bytes = signed
        .encap_content_info
        .econtent
        .context("timestamp missing content")?
        .decode_as::<OctetString>()?;
    let info = Info::from_der(info_bytes.as_bytes()).context("timestamp DER TSTInfo")?;
    ensure!(
        info.version == 1
            && info.imprint.algorithm.oid == SHA256
            && info.imprint.digest.as_bytes() == crate::sha256(checkpoint),
        "timestamp imprint mismatch"
    );
    ensure!(
        info.time.tag() == Tag::GeneralizedTime,
        "timestamp generation time type"
    );
    let time_text = std::str::from_utf8(info.time.value())?;
    let gen_time = NaiveDateTime::parse_from_str(time_text, "%Y%m%d%H%M%S%.fZ")
        .context("timestamp generation time")?
        .and_utc();
    let signer = signed
        .signer_infos
        .0
        .get(0)
        .context("timestamp missing signer")?;
    ensure!(
        signer.digest_alg.oid == SHA256
            && signed.digest_algorithms.len() == 1
            && signed
                .digest_algorithms
                .get(0)
                .is_some_and(|a| a.oid == SHA256),
        "unsupported timestamp digest"
    );
    ensure!(
        signer.version == cms::content_info::CmsVersion::V1,
        "timestamp SignerInfo version"
    );
    for algorithm in [&info.imprint.algorithm, &signer.digest_alg]
        .into_iter()
        .chain(signed.digest_algorithms.iter())
    {
        ensure!(null_parameters(algorithm), "timestamp digest parameters");
    }
    ensure!(
        info.extensions
            .as_ref()
            .is_none_or(|extensions| extensions.iter().all(|e| !e.critical)),
        "unsupported critical timestamp extension"
    );
    let attrs = signer
        .signed_attrs
        .as_ref()
        .context("missing timestamp signed attributes")?;
    ensure!(
        attribute(attrs, CONTENT_TYPE)?.decode_as::<ObjectIdentifier>()? == TST,
        "timestamp signed content type"
    );
    ensure!(
        attribute(attrs, MESSAGE_DIGEST)?
            .decode_as::<OctetString>()?
            .as_bytes()
            == crate::sha256(info_bytes.as_bytes()),
        "timestamp signed content digest"
    );
    let binding = attribute(attrs, CERT_BINDING)?.decode_as::<CertBinding>()?;
    let cert_id = binding
        .certs
        .first()
        .context("missing timestamp certificate binding")?;
    ensure!(
        cert_id
            .algorithm
            .as_ref()
            .is_none_or(|a| a.oid == SHA256 && null_parameters(a)),
        "unsupported timestamp certificate binding hash"
    );
    let mut certificate = None;
    for raw in pins {
        // Callers validate pins at load (`validate_pin`); an unparsable pin here is simply not a
        // trust root, never a reason to fail a bundle whose token is otherwise well formed.
        let Ok(cert) = pin_certificate(raw) else {
            continue;
        };
        let identity = match &signer.sid {
            SignerIdentifier::IssuerAndSerialNumber(id) => {
                id.issuer == cert.tbs_certificate.issuer
                    && id.serial_number == cert.tbs_certificate.serial_number
            }
            SignerIdentifier::SubjectKeyIdentifier(_) => false,
        };
        // A pin counts only when it IS the bound signing certificate (issuer+serial AND the
        // ESSCertIDv2 hash). A same-name pin with different bytes (re-issued cert, or a
        // corrupted binding) is not a trust root for this token: report unpinned, never fail.
        // Stripping the token gives the same result, since the manifest is unsigned.
        if identity && cert_id.hash.as_bytes() == crate::sha256(&cert.to_der()?) {
            certificate = Some(cert);
            break;
        }
    }
    let Some(cert) = certificate else {
        return Ok(None);
    };
    let validity = &cert.tbs_certificate.validity;
    let before =
        DateTime::<Utc>::from(std::time::UNIX_EPOCH + validity.not_before.to_unix_duration());
    let after =
        DateTime::<Utc>::from(std::time::UNIX_EPOCH + validity.not_after.to_unix_duration());
    ensure!(
        gen_time >= before && gen_time <= after,
        "timestamp certificate validity at generation"
    );
    let extensions = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .context("timestamp certificate EKU missing")?;
    let eku_oid = ObjectIdentifier::new_unwrap("2.5.29.37");
    let ekus: Vec<_> = extensions.iter().filter(|e| e.extn_id == eku_oid).collect();
    ensure!(
        ekus.len() == 1 && ekus[0].critical,
        "timestamp certificate EKU must be sole critical timestamping purpose"
    );
    let purposes = Vec::<ObjectIdentifier>::from_der(ekus[0].extn_value.as_bytes())?;
    ensure!(
        purposes == [ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8")],
        "timestamp certificate EKU purpose"
    );
    let mut seen = std::collections::BTreeSet::new();
    for extension in extensions {
        ensure!(
            seen.insert(extension.extn_id),
            "duplicate timestamp certificate extension"
        );
        match extension.extn_id.to_string().as_str() {
            "2.5.29.37" => {}
            "2.5.29.15" => {
                let usage =
                    x509_cert::ext::pkix::KeyUsage::from_der(extension.extn_value.as_bytes())?;
                ensure!(
                    usage.digital_signature() || usage.non_repudiation(),
                    "timestamp certificate key usage"
                );
            }
            "2.5.29.19" => {
                let constraints = x509_cert::ext::pkix::BasicConstraints::from_der(
                    extension.extn_value.as_bytes(),
                )?;
                ensure!(
                    !constraints.ca && constraints.path_len_constraint.is_none(),
                    "timestamp requires leaf certificate"
                );
            }
            _ => ensure!(
                !extension.critical,
                "unsupported timestamp certificate critical extension"
            ),
        }
    }
    let signature_oid = signer.signature_algorithm.oid.to_string();
    ensure!(
        if signature_oid == "1.2.840.10045.4.3.2" {
            signer.signature_algorithm.parameters.is_none()
        } else {
            null_parameters(&signer.signature_algorithm)
        },
        "timestamp signature parameters"
    );
    let public = &cert.tbs_certificate.subject_public_key_info;
    if public.algorithm.oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1") {
        ensure!(
            null_parameters(&public.algorithm),
            "timestamp RSA public key parameters"
        );
    }
    let algorithm: &dyn ring::signature::VerificationAlgorithm =
        match signer.signature_algorithm.oid.to_string().as_str() {
            "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.11"
                if public.algorithm.oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1") =>
            {
                &ring::signature::RSA_PKCS1_2048_8192_SHA256
            }
            "1.2.840.10045.4.3.2"
                if public.algorithm.oid == ObjectIdentifier::new_unwrap("1.2.840.10045.2.1")
                    && public
                        .algorithm
                        .parameters
                        .as_ref()
                        .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
                        == Some(ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7")) =>
            {
                &ring::signature::ECDSA_P256_SHA256_ASN1
            }
            _ => anyhow::bail!("unsupported timestamp signature algorithm"),
        };
    ring::signature::UnparsedPublicKey::new(
        algorithm,
        public
            .subject_public_key
            .as_bytes()
            .context("timestamp public key bits")?,
    )
    .verify(&attrs.to_der()?, signer.signature.as_bytes())
    .map_err(|_| anyhow::anyhow!("timestamp signature invalid"))?;
    Ok(Some(gen_time))
}
/// Encode a SHA256 imprint request; only digest bytes are sent to the TSA.
/// Errors fail CLOSED on encoding failure. No network is performed here.
pub fn request(checkpoint: &[u8]) -> Result<Vec<u8>> {
    Ok(Request {
        version: 1,
        imprint: Imprint {
            algorithm: AlgorithmIdentifierOwned {
                oid: SHA256,
                parameters: None,
            },
            digest: OctetString::new(crate::sha256(checkpoint))?,
        },
        cert_req: true,
    }
    .to_der()?)
}
#[cfg(test)]
mod tests;
