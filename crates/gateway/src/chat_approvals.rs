//! ACT-23: verify a Slack interaction request (`specs/ACT-23-approve-from-slack-and-teams.md`
//! §2 steps 1-4 and 6). Pure functions: no I/O, no clock, no route. Nothing calls this until
//! PR 4 wires the handler.
//!
//! # Provenance of the Slack rules (read this before trusting them)
//!
//! The rules below were NOT read from Slack's page. On 2026-11-21 a web search returned excerpts of
//! <https://docs.slack.dev/authentication/verifying-requests-from-slack>, and the same rules
//! were cross-read in Slack's own Python SDK reference,
//! <https://docs.slack.dev/tools/python-slack-sdk/reference/signature/index.html>
//! (`slack_sdk.signature`). The doc page itself was never fetched in full. What they say:
//! - the signature is `v0=` followed by the hex HMAC-SHA256 digest of the basestring, keyed
//!   with the app's signing secret, and arrives in `X-Slack-Signature`;
//! - the basestring is `v0:{X-Slack-Request-Timestamp}:{raw body}`, so the timestamp is inside
//!   the signed bytes, and the check runs over the RAW body before anything is parsed;
//! - a request whose timestamp is more than 5 minutes from local time is a replay. The window is
//!   read from the reference table (`chat.replay_window_secs` in `mcp_policy.v1.json`).
//!
//! Re-read the page itself before relying on any detail not listed above.
//!
//! # Errors
//! Every check here guards a security path and fails CLOSED. A [`Reject`] carries no request
//! content, so a caller can log its [`Reject::reason`] without echoing attacker bytes.
use ring::hmac;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::Deserialize;
use uuid::Uuid;

/// Reference-table values (`chat` in `mcp_policy.v1.json`); never literals in this file.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub replay_window_secs: i64,
    pub max_body_bytes: usize,
}
impl Limits {
    pub fn from_settings(s: &crate::mcp_policy::Settings) -> Self {
        Self {
            replay_window_secs: s.chat.replay_window_secs,
            max_body_bytes: s.chat.max_interaction_bytes,
        }
    }
}

/// Why a request was refused. Fixed vocabulary, safe to count and log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    NoSigningSecret,
    BodyTooLarge,
    MissingTimestamp,
    DuplicateTimestamp,
    MissingSignature,
    DuplicateSignature,
    BadTimestamp,
    StaleTimestamp,
    BadSignatureFormat,
    SignatureMismatch,
    NotFormEncoded,
    BadPayload,
    NotBlockActions,
    BadActionCount,
    UnknownAction,
    BadButtonValue,
    ButtonMacMismatch,
    InstallationMismatch,
}
impl Reject {
    pub fn reason(self) -> &'static str {
        match self {
            Self::NoSigningSecret => "no_signing_secret",
            Self::BodyTooLarge => "body_too_large",
            Self::MissingTimestamp => "missing_timestamp",
            Self::DuplicateTimestamp => "duplicate_timestamp",
            Self::MissingSignature => "missing_signature",
            Self::DuplicateSignature => "duplicate_signature",
            Self::BadTimestamp => "bad_timestamp",
            Self::StaleTimestamp => "stale",
            Self::BadSignatureFormat => "bad_signature_format",
            Self::SignatureMismatch => "bad_signature",
            Self::NotFormEncoded => "not_form_encoded",
            Self::BadPayload => "bad_payload",
            Self::NotBlockActions => "not_block_actions",
            Self::BadActionCount => "bad_action_count",
            Self::UnknownAction => "unknown_action",
            Self::BadButtonValue => "bad_button_value",
            Self::ButtonMacMismatch => "button_mac_mismatch",
            Self::InstallationMismatch => "installation_mismatch",
        }
    }
    /// HTTP status for the request-level checks: 413 for size, 401 for the rest. Payload and
    /// button failures answer 200 with an ephemeral message (spec §6), decided by the handler.
    pub fn status(self) -> u16 {
        match self {
            Self::BodyTooLarge => 413,
            _ => 401,
        }
    }
}

/// `None` when the signing secret is unset or blank: the route is then not mounted (404).
pub fn configured_secret(raw: Option<&str>) -> Option<SecretString> {
    raw.filter(|s| !s.trim().is_empty())
        .map(|s| SecretString::from(s.to_owned()))
}

fn single<'a>(values: &[&'a str], missing: Reject, duplicate: Reject) -> Result<&'a str, Reject> {
    match values {
        [] => Err(missing),
        [one] => Ok(one),
        _ => Err(duplicate),
    }
}

/// Seconds since the epoch from a header value: ASCII digits only, so no sign, space, point or
/// exponent; an overflow is a refusal.
fn parse_timestamp(raw: &str) -> Result<i64, Reject> {
    if raw.is_empty() || raw.len() > 12 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Reject::BadTimestamp);
    }
    raw.parse().map_err(|_| Reject::BadTimestamp)
}

/// `v0=` plus exactly 64 lowercase hex characters, decoded to 32 bytes.
fn parse_signature(raw: &str) -> Result<[u8; 32], Reject> {
    let hex_part = raw.strip_prefix("v0=").ok_or(Reject::BadSignatureFormat)?;
    if hex_part.len() != 64
        || !hex_part
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(Reject::BadSignatureFormat);
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_part, &mut out).map_err(|_| Reject::BadSignatureFormat)?;
    Ok(out)
}

/// A request body whose Slack signature, timestamp window and size were checked by
/// [`verify_request`]. There is no other constructor, so a handler cannot parse unverified bytes:
/// [`parse_interaction`] takes this, not a slice.
///
/// Single use is NOT enforced here. A valid signed request can be replayed inside the window; the
/// caller must record [`Interaction::dedup_key`] in `webhook_events` inside the decision
/// transaction (spec D4, PR 4) and treat a conflict as a duplicate.
#[derive(Debug)]
pub struct VerifiedInteraction {
    body: Vec<u8>,
}
impl VerifiedInteraction {
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Verify a Slack request in the order of spec §2: body cap, headers, timestamp, signature.
///
/// `timestamps` and `signatures` are EVERY value received for `X-Slack-Request-Timestamp` and
/// `X-Slack-Signature`; more than one of either is refused. `now` is the gateway clock in Unix
/// seconds. The HMAC is computed over the raw `body` bytes, constant-time.
///
/// # Errors
/// Any [`Reject`]; fail-CLOSED, and no HMAC is computed for an oversize body. A blank or
/// whitespace-only secret refuses. `Ok` proves authenticity and freshness only, not single use.
#[rustfmt::skip]
pub fn verify_request(
    secret: &SecretString,
    limits: &Limits,
    now: i64,
    timestamps: &[&str],
    signatures: &[&str],
    body: &[u8],
) -> Result<VerifiedInteraction, Reject> {
    if body.len() > limits.max_body_bytes {
        return Err(Reject::BodyTooLarge);
    }
    let ts_raw = single(timestamps, Reject::MissingTimestamp, Reject::DuplicateTimestamp)?;
    let sig_raw = single(signatures, Reject::MissingSignature, Reject::DuplicateSignature)?;
    let ts = parse_timestamp(ts_raw)?;
    if (now - ts).abs() > limits.replay_window_secs {
        return Err(Reject::StaleTimestamp);
    }
    let sig = parse_signature(sig_raw)?;
    if secret.expose_secret().trim().is_empty() {
        return Err(Reject::NoSigningSecret);
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.expose_secret().as_bytes());
    // The signed bytes are `v0:` + the timestamp header exactly as received + `:` + the raw body.
    let mut basestring = Vec::with_capacity(body.len() + ts_raw.len() + 4);
    basestring.extend_from_slice(b"v0:");
    basestring.extend_from_slice(ts_raw.as_bytes());
    basestring.push(b':');
    basestring.extend_from_slice(body);
    hmac::verify(&key, &basestring, &sig).map_err(|_| Reject::SignatureMismatch)?;
    Ok(VerifiedInteraction {
        body: body.to_vec(),
    })
}

/// What a button does. `Open` is a link button and never decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Approve,
    Deny,
    Open,
}
impl Action {
    pub fn decides(self) -> bool {
        !matches!(self, Self::Open)
    }
}

/// The fields of a `block_actions` payload the decision path may use. Nothing else is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interaction {
    pub team_id: String,
    pub user_id: String,
    pub trigger_id: String,
    pub action: Action,
    pub value: String,
    /// Keeps the struct constructible only through [`parse_interaction`].
    _sealed: (),
}
impl Interaction {
    /// The replay key (spec D4): `hex(sha256(team_id ":" trigger_id))`. The caller inserts it into
    /// `webhook_events(source = "slack-interaction")` in the decision transaction.
    pub fn dedup_key(&self) -> String {
        let text = format!("{}:{}", self.team_id, self.trigger_id);
        hex::encode(ring::digest::digest(&ring::digest::SHA256, text.as_bytes()))
    }
}

#[derive(Deserialize)]
struct RawPayload {
    #[serde(rename = "type")]
    kind: String,
    team: RawId,
    user: RawId,
    trigger_id: String,
    actions: Vec<RawAction>,
}
#[derive(Deserialize)]
struct RawId {
    id: String,
}
#[derive(Deserialize)]
struct RawAction {
    action_id: String,
    #[serde(default)]
    value: String,
}

fn slack_id(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn percent_decode(raw: &str) -> Option<Vec<u8>> {
    let b = raw.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let pair = b.get(i + 1..i + 3)?;
                let mut byte = [0u8; 1];
                hex::decode_to_slice(pair, &mut byte).ok()?;
                out.push(byte[0]);
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    Some(out)
}

/// The single `payload` field of a form-encoded body.
fn form_payload(body: &[u8]) -> Result<String, Reject> {
    let text = std::str::from_utf8(body).map_err(|_| Reject::NotFormEncoded)?;
    let mut found = None;
    for pair in text.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == "payload" {
            if found.is_some() {
                return Err(Reject::NotFormEncoded);
            }
            found = Some(value);
        }
    }
    let bytes =
        percent_decode(found.ok_or(Reject::NotFormEncoded)?).ok_or(Reject::NotFormEncoded)?;
    String::from_utf8(bytes).map_err(|_| Reject::NotFormEncoded)
}

/// Parse a verified body into an [`Interaction`].
///
/// # Errors
/// Not form-encoded, bad JSON, `type` other than `block_actions`, an action count other than
/// one, an `action_id` outside `tl_approve | tl_deny | tl_open`, or a malformed id.
pub fn parse_interaction(verified: &VerifiedInteraction) -> Result<Interaction, Reject> {
    let json = form_payload(verified.body())?;
    let raw: RawPayload = serde_json::from_str(&json).map_err(|_| Reject::BadPayload)?;
    if raw.kind != "block_actions" {
        return Err(Reject::NotBlockActions);
    }
    let [action] = <[RawAction; 1]>::try_from(raw.actions).map_err(|_| Reject::BadActionCount)?;
    let action_kind = match action.action_id.as_str() {
        "tl_approve" => Action::Approve,
        "tl_deny" => Action::Deny,
        "tl_open" => Action::Open,
        _ => return Err(Reject::UnknownAction),
    };
    if ![&raw.team.id, &raw.user.id, &raw.trigger_id]
        .into_iter()
        .all(|s| slack_id(s))
    {
        return Err(Reject::BadPayload);
    }
    Ok(Interaction {
        team_id: raw.team.id,
        user_id: raw.user.id,
        trigger_id: raw.trigger_id,
        action: action_kind,
        value: action.value,
        _sealed: (),
    })
}

/// Domain separation for the button MAC.
const BUTTON_PURPOSE: &[u8] = b"act23-button-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Approve,
    Deny,
}

/// The parts of a button value `v1.<approval>.<a|d>.<installation>.<descriptor_digest>.<mac>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Button {
    pub approval_id: Uuid,
    pub decision: Decision,
    pub installation_id: Uuid,
    pub descriptor_digest: String,
    mac: [u8; 32],
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn mac_input(tenant: Uuid, b: &Button) -> Vec<u8> {
    let mut m = BUTTON_PURPOSE.to_vec();
    let decision: &[u8] = match b.decision {
        Decision::Approve => b"a",
        Decision::Deny => b"d",
    };
    for part in [
        tenant.as_bytes().as_slice(),
        b.approval_id.as_bytes(),
        b.installation_id.as_bytes(),
        decision,
        b.descriptor_digest.as_bytes(),
    ] {
        m.push(0);
        m.extend_from_slice(part);
    }
    m
}

/// Mint the value of an Approve or Deny button. `key` is the tenant's workspace key.
pub fn mint_button(
    key: &SecretBox<[u8; 32]>,
    tenant: Uuid,
    approval_id: Uuid,
    decision: Decision,
    installation_id: Uuid,
    descriptor_digest: &str,
) -> String {
    let mut b = Button {
        approval_id,
        decision,
        installation_id,
        descriptor_digest: descriptor_digest.to_owned(),
        mac: [0; 32],
    };
    let k = hmac::Key::new(hmac::HMAC_SHA256, key.expose_secret());
    let tag = hmac::sign(&k, &mac_input(tenant, &b));
    b.mac.copy_from_slice(tag.as_ref());
    format!(
        "v1.{}.{}.{}.{}.{}",
        b.approval_id,
        if decision == Decision::Approve {
            "a"
        } else {
            "d"
        },
        b.installation_id,
        b.descriptor_digest,
        hex::encode(b.mac)
    )
}

/// Parse a button value. The MAC is not checked here: [`verify_button`] does that once the
/// tenant is known from the installation.
///
/// # Errors
/// [`Reject::BadButtonValue`] for any shape other than the one above.
pub fn parse_button(value: &str) -> Result<Button, Reject> {
    let bad = Reject::BadButtonValue;
    let parts: Vec<&str> = value.split('.').collect();
    let [version, approval, decision, installation, digest, mac] = parts.as_slice() else {
        return Err(bad);
    };
    if *version != "v1" || !is_hex64(digest) || !is_hex64(mac) {
        return Err(bad);
    }
    let decision = match *decision {
        "a" => Decision::Approve,
        "d" => Decision::Deny,
        _ => return Err(bad),
    };
    let mut mac_bytes = [0u8; 32];
    hex::decode_to_slice(mac, &mut mac_bytes).map_err(|_| bad)?;
    Ok(Button {
        approval_id: approval.parse().map_err(|_| bad)?,
        decision,
        installation_id: installation.parse().map_err(|_| bad)?,
        descriptor_digest: (*digest).to_owned(),
        mac: mac_bytes,
    })
}

/// Check the button's MAC under the tenant and installation found from the signed `team.id`,
/// never from the button. `installation_id` must be the live (not revoked) installation that
/// lookup returned: a button minted for a different or since-replaced installation is refused even
/// when its MAC is valid. Constant-time MAC compare. A value minted for another tenant, approval,
/// installation, decision or descriptor fails.
///
/// # Errors
/// [`Reject::InstallationMismatch`], [`Reject::ButtonMacMismatch`].
pub fn verify_button(
    key: &SecretBox<[u8; 32]>,
    tenant: Uuid,
    installation_id: Uuid,
    button: &Button,
) -> Result<(), Reject> {
    if button.installation_id != installation_id {
        return Err(Reject::InstallationMismatch);
    }
    let k = hmac::Key::new(hmac::HMAC_SHA256, key.expose_secret());
    hmac::verify(&k, &mac_input(tenant, button), &button.mac).map_err(|_| Reject::ButtonMacMismatch)
}

#[cfg(test)]
#[rustfmt::skip] // dense case tables, one row per input
mod tests;
