//! Bounded REST backends. Provider API keys never enter this module.
use super::{KmsError, context, limits};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL},
};
use secrecy::{ExposeSecret as _, SecretString, zeroize::Zeroizing};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracelane_shared::TenantId;
use uuid::Uuid;

pub trait KmsBackend: Send + Sync {
    fn wrap(
        &self,
        tenant: &TenantId,
        id: Uuid,
        payload: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>, KmsError>> + Send;
    fn unwrap(
        &self,
        tenant: &TenantId,
        id: Uuid,
        ciphertext: &[u8],
    ) -> impl std::future::Future<Output = Result<Zeroizing<Vec<u8>>, KmsError>> + Send;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "backend",
    content = "params",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Config {
    AwsKms(Aws),
    VaultTransit(Vault),
    GcpKms(Gcp),
    AzureKeyVault(Azure),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Aws {
    pub region: String,
    pub role_arn: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vault {
    pub url: String,
    pub mount: String,
    pub role_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gcp {
    pub service_account: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Azure {
    pub directory_id: Uuid,
}

pub struct Backend {
    pub config: Config,
    pub key_ref: String,
    pub secret: Option<SecretString>,
}
fn segment(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}
fn https(raw: &str) -> Option<reqwest::Url> {
    let u = reqwest::Url::parse(raw).ok()?;
    (u.scheme() == "https"
        && u.username().is_empty()
        && u.password().is_none()
        && u.query().is_none()
        && u.fragment().is_none())
    .then_some(u)
}
impl Backend {
    pub fn valid(&self) -> bool {
        if self.key_ref.is_empty() || self.key_ref.len() > limits().map_or(0, |l| l.response_bytes)
        {
            return false;
        }
        match &self.config {
            Config::AwsKms(p) => {
                let role: Vec<_> = p.role_arn.split(':').collect();
                let key: Vec<_> = self.key_ref.split(':').collect();
                segment(&p.region)
                    && role.len() == 6
                    && key.len() == 6
                    && role[..3] == ["arn", "aws", "iam"]
                    && role[3].is_empty()
                    && role[4].len() == 12
                    && role[4].bytes().all(|c| c.is_ascii_digit())
                    && role[5].starts_with("role/")
                    && role[5].split('/').all(segment)
                    && key[..3] == ["arn", "aws", "kms"]
                    && key[3] == p.region
                    && key[4] == role[4]
                    && (key[5].starts_with("key/") || key[5].starts_with("alias/"))
                    && key[5].split('/').all(segment)
                    && self.secret.is_none()
            }
            Config::VaultTransit(p) => {
                https(&p.url).is_some_and(|u| u.path() == "/")
                    && segment(&p.mount)
                    && segment(&self.key_ref)
                    && self
                        .secret
                        .as_ref()
                        .is_some_and(|s| !s.expose_secret().is_empty())
                    && p.role_id.as_ref().is_none_or(|s| !s.is_empty())
            }
            Config::GcpKms(p) => {
                let key: Vec<_> = self.key_ref.split('/').collect();
                p.service_account.ends_with(".iam.gserviceaccount.com")
                    && p.service_account
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"@.-_".contains(&c))
                    && p.service_account.bytes().filter(|c| *c == b'@').count() == 1
                    && key.len() == 8
                    && key[0] == "projects"
                    && key[2] == "locations"
                    && key[4] == "keyRings"
                    && key[6] == "cryptoKeys"
                    && key.iter().all(|s| segment(s))
                    && self.secret.is_none()
            }
            Config::AzureKeyVault(_) => {
                https(&self.key_ref).is_some_and(|u| {
                    u.host_str()
                        .is_some_and(|h| h.ends_with(".vault.azure.net"))
                        && u.port().is_none()
                        && {
                            let p: Vec<_> = u.path().split('/').collect();
                            p.len() == 4 && p[1] == "keys" && segment(p[2]) && segment(p[3])
                        }
                }) && self.secret.is_none()
            }
        }
    }
    pub fn ready(&self) -> bool {
        match &self.config {
            Config::VaultTransit(_) => self.secret.is_some(),
            Config::AwsKms(_) => {
                env_secret("TRACELANE_KMS_AWS_ACCESS_KEY_ID").is_ok()
                    && env_secret("TRACELANE_KMS_AWS_SECRET_ACCESS_KEY").is_ok()
            }
            Config::GcpKms(_) => env_secret("TRACELANE_KMS_GCP_SERVICE_ACCOUNT").is_ok(),
            Config::AzureKeyVault(_) => {
                env_secret("TRACELANE_KMS_AZURE_CLIENT_ID").is_ok()
                    && env_secret("TRACELANE_KMS_AZURE_CLIENT_SECRET").is_ok()
            }
        }
    }
    pub async fn validate_destination(&self) -> Result<(), KmsError> {
        if !self.valid() {
            return Err(KmsError::Denied);
        }
        if let Config::VaultTransit(p) = &self.config {
            crate::ssrf_guard::validate_url_pinned(&p.url)
                .await
                .map_err(|_| KmsError::Denied)?;
        }
        Ok(())
    }
    async fn crypt(
        &self,
        tenant: &TenantId,
        id: Uuid,
        payload: &[u8],
        wrapping: bool,
    ) -> Result<Zeroizing<Vec<u8>>, KmsError> {
        if !self.valid() {
            return Err(KmsError::Denied);
        }
        let deadline = std::time::Duration::from_millis(
            limits().ok_or(KmsError::Unavailable)?.call_timeout_ms,
        );
        let result = tokio::time::timeout(deadline, async {
            match &self.config {
                Config::VaultTransit(p) => self.vault(p, payload, wrapping).await,
                Config::AwsKms(p) => self.aws(p, tenant, id, payload, wrapping).await,
                Config::GcpKms(p) => self.gcp(p, tenant, id, payload, wrapping).await,
                Config::AzureKeyVault(p) => self.azure(p, payload, wrapping).await,
            }
        })
        .await
        .map_err(|_| KmsError::Unavailable)?;
        if matches!(result, Err(KmsError::Denied))
            && let Ok(vault) = super::KeyVault::global()
        {
            vault.invalidate(tenant);
        }
        result
    }
    async fn vault(
        &self,
        p: &Vault,
        payload: &[u8],
        wrapping: bool,
    ) -> Result<Zeroizing<Vec<u8>>, KmsError> {
        let secret = self.secret.as_ref().ok_or(KmsError::Denied)?;
        let token = if let Some(role) = &p.role_id {
            let bytes = post(
                &format!("{}/v1/auth/approle/login", p.url.trim_end_matches('/')),
                json!({"role_id":role,"secret_id":secret.expose_secret()}),
                &[],
            )
            .await?;
            json_secret(&bytes, &["auth", "client_token"])?
        } else {
            secret.clone()
        };
        let operation = if wrapping { "encrypt" } else { "decrypt" };
        let body = if wrapping {
            json!({"plaintext":B64.encode(payload)})
        } else {
            json!({"ciphertext":std::str::from_utf8(payload).map_err(|_| KmsError::Denied)?})
        };
        let bytes = post(
            &format!(
                "{}/v1/{}/{operation}/{}",
                p.url.trim_end_matches('/'),
                p.mount,
                self.key_ref
            ),
            body,
            &[("x-vault-token", token.expose_secret())],
        )
        .await?;
        let result = json_secret(
            &bytes,
            &["data", if wrapping { "ciphertext" } else { "plaintext" }],
        )?;
        if wrapping {
            Ok(Zeroizing::new(result.expose_secret().as_bytes().to_vec()))
        } else {
            Ok(Zeroizing::new(
                B64.decode(result.expose_secret())
                    .map_err(|_| KmsError::Denied)?,
            ))
        }
    }
    async fn aws(
        &self,
        p: &Aws,
        tenant: &TenantId,
        id: Uuid,
        payload: &[u8],
        wrapping: bool,
    ) -> Result<Zeroizing<Vec<u8>>, KmsError> {
        let operator = AwsCredentials {
            access: env_secret("TRACELANE_KMS_AWS_ACCESS_KEY_ID")?,
            secret: env_secret("TRACELANE_KMS_AWS_SECRET_ACCESS_KEY")?,
            token: env_secret("TRACELANE_KMS_AWS_SESSION_TOKEN").ok(),
        };
        let host = format!("sts.{}.amazonaws.com", p.region);
        let external = format!("tracelane-{tenant}");
        let form = form_body(&[
            ("Action", "AssumeRole"),
            ("Version", "2011-06-15"),
            ("RoleArn", &p.role_arn),
            ("RoleSessionName", &external),
            ("ExternalId", &external),
        ]);
        let reply = aws_post(
            &host,
            "sts",
            &p.region,
            "application/x-www-form-urlencoded",
            None,
            &form,
            &operator,
        )
        .await?;
        let creds = AwsCredentials {
            access: xml_secret(&reply, "AccessKeyId")?,
            secret: xml_secret(&reply, "SecretAccessKey")?,
            token: Some(xml_secret(&reply, "SessionToken")?),
        };
        let action = if wrapping { "Encrypt" } else { "Decrypt" };
        let mut doc = json!({"KeyId":self.key_ref,"EncryptionContext":{"tenant_id":tenant.to_string(),"dek_id":id.to_string()}});
        doc[if wrapping {
            "Plaintext"
        } else {
            "CiphertextBlob"
        }] = Value::String(B64.encode(payload));
        let body = Zeroizing::new(serde_json::to_vec(&doc).map_err(|_| KmsError::Unavailable)?);
        scrub_json(&mut doc);
        let bytes = aws_post(
            &format!("kms.{}.amazonaws.com", p.region),
            "kms",
            &p.region,
            "application/x-amz-json-1.1",
            Some(&format!("TrentService.{action}")),
            &body,
            &creds,
        )
        .await?;
        let result = json_secret(
            &bytes,
            &[if wrapping {
                "CiphertextBlob"
            } else {
                "Plaintext"
            }],
        )?;
        Ok(Zeroizing::new(
            B64.decode(result.expose_secret())
                .map_err(|_| KmsError::Denied)?,
        ))
    }
    async fn gcp(
        &self,
        p: &Gcp,
        tenant: &TenantId,
        id: Uuid,
        payload: &[u8],
        wrapping: bool,
    ) -> Result<Zeroizing<Vec<u8>>, KmsError> {
        let sa = env_secret("TRACELANE_KMS_GCP_SERVICE_ACCOUNT")?;
        let email = json_secret(sa.expose_secret().as_bytes(), &["client_email"])?;
        let private_key = json_secret(sa.expose_secret().as_bytes(), &["private_key"])?;
        let now = chrono::Utc::now().timestamp();
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key.expose_secret().as_bytes())
            .map_err(|_| KmsError::Denied)?;
        // OAuth JWT assertions have a protocol maximum lifetime of one hour.
        let assertion = SecretString::from(jsonwebtoken::encode(&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256), &json!({"iss":email.expose_secret(),"scope":"https://www.googleapis.com/auth/cloud-platform","aud":"https://oauth2.googleapis.com/token","iat":now,"exp":now+3600}), &key).map_err(|_| KmsError::Denied)?);
        let form = form_body(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.expose_secret()),
        ]);
        let token = json_secret(
            &send(
                "https://oauth2.googleapis.com/token",
                &form,
                "application/x-www-form-urlencoded",
                &[],
            )
            .await?,
            &["access_token"],
        )?;
        let auth = bearer_header(&token);
        let token = json_secret(&post(&format!("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{}:generateAccessToken", p.service_account), json!({"scope":["https://www.googleapis.com/auth/cloud-platform"]}), &[("authorization",auth.as_str())]).await?, &["accessToken"])?;
        let auth = bearer_header(&token);
        let action = if wrapping { "encrypt" } else { "decrypt" };
        let mut doc = json!({"additionalAuthenticatedData":B64.encode(context(tenant,id))});
        doc[if wrapping { "plaintext" } else { "ciphertext" }] = Value::String(B64.encode(payload));
        let reply = post(
            &format!(
                "https://cloudkms.googleapis.com/v1/{}:{action}",
                self.key_ref
            ),
            doc,
            &[("authorization", auth.as_str())],
        )
        .await?;
        let result = json_secret(&reply, &[if wrapping { "ciphertext" } else { "plaintext" }])?;
        Ok(Zeroizing::new(
            B64.decode(result.expose_secret())
                .map_err(|_| KmsError::Denied)?,
        ))
    }
    async fn azure(
        &self,
        p: &Azure,
        payload: &[u8],
        wrapping: bool,
    ) -> Result<Zeroizing<Vec<u8>>, KmsError> {
        let client = env_secret("TRACELANE_KMS_AZURE_CLIENT_ID")?;
        let secret = env_secret("TRACELANE_KMS_AZURE_CLIENT_SECRET")?;
        let form = form_body(&[
            ("client_id", client.expose_secret()),
            ("client_secret", secret.expose_secret()),
            ("grant_type", "client_credentials"),
            ("scope", "https://vault.azure.net/.default"),
        ]);
        let reply = send(
            &format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                p.directory_id
            ),
            &form,
            "application/x-www-form-urlencoded",
            &[],
        )
        .await?;
        let token = json_secret(&reply, &["access_token"])?;
        let auth = bearer_header(&token);
        let action = if wrapping { "wrapkey" } else { "unwrapkey" };
        let reply = post(
            &format!("{}/{action}?api-version=2025-07-01", self.key_ref),
            json!({"alg":"RSA-OAEP-256","value":B64URL.encode(payload)}),
            &[("authorization", auth.as_str())],
        )
        .await?;
        let result = json_secret(&reply, &["value"])?;
        Ok(Zeroizing::new(
            B64URL
                .decode(result.expose_secret())
                .map_err(|_| KmsError::Denied)?,
        ))
    }
}
impl KmsBackend for Backend {
    async fn wrap(&self, tenant: &TenantId, id: Uuid, payload: &[u8]) -> Result<Vec<u8>, KmsError> {
        Ok(self.crypt(tenant, id, payload, true).await?.to_vec())
    }
    async fn unwrap(
        &self,
        tenant: &TenantId,
        id: Uuid,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KmsError> {
        self.crypt(tenant, id, ciphertext, false).await
    }
}
fn env_secret(name: &str) -> Result<SecretString, KmsError> {
    #[cfg(test)]
    if let Ok(value) = scripted::SCRIPT.try_with(|s| s.borrow().env.get(name).cloned()) {
        return value.map(SecretString::from).ok_or(KmsError::Unavailable);
    }
    std::env::var(name)
        .ok()
        .filter(|s| !s.is_empty())
        .map(SecretString::from)
        .ok_or(KmsError::Unavailable)
}
fn bearer_header(token: &SecretString) -> Zeroizing<String> {
    let mut value = Zeroizing::new(String::from("Bearer "));
    value.push_str(token.expose_secret());
    value
}
fn form_body(fields: &[(&str, &str)]) -> Zeroizing<Vec<u8>> {
    // Form encoding, never a credential-bearing URL (including temporary URLs).
    let mut out = Zeroizing::new(Vec::new());
    for (i, (key, value)) in fields.iter().enumerate() {
        if i > 0 {
            out.push(b'&');
        }
        for (j, part) in [key, value].iter().enumerate() {
            if j > 0 {
                out.push(b'=');
            }
            for byte in part.bytes() {
                if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                    out.push(byte);
                } else {
                    out.push(b'%');
                    out.push(b"0123456789ABCDEF"[usize::from(byte >> 4)]);
                    out.push(b"0123456789ABCDEF"[usize::from(byte & 15)]);
                }
            }
        }
    }
    out
}
fn scrub_json(v: &mut Value) {
    use secrecy::zeroize::Zeroize as _;
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(scrub_json),
        Value::Object(o) => o.values_mut().for_each(scrub_json),
        _ => (),
    }
}
fn json_secret(bytes: &[u8], path: &[&str]) -> Result<SecretString, KmsError> {
    let mut value: Value = serde_json::from_slice(bytes).map_err(|_| KmsError::Unavailable)?;
    let mut field = &value;
    for p in path {
        field = field.get(*p).unwrap_or(&Value::Null);
    }
    let out = field
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| SecretString::from(s.to_owned()))
        .ok_or(KmsError::Unavailable);
    scrub_json(&mut value);
    out
}
fn xml_secret(bytes: &[u8], name: &str) -> Result<SecretString, KmsError> {
    let raw = std::str::from_utf8(bytes).map_err(|_| KmsError::Unavailable)?;
    let start = format!("<{name}>");
    let end = format!("</{name}>");
    let (_, rest) = raw.split_once(&start).ok_or(KmsError::Unavailable)?;
    let (value, tail) = rest.split_once(&end).ok_or(KmsError::Unavailable)?;
    if tail.contains(&start)
        || value.is_empty()
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"/+=_-".contains(&c))
    {
        return Err(KmsError::Unavailable);
    }
    Ok(SecretString::from(value.to_owned()))
}
async fn post(
    url: &str,
    mut doc: Value,
    headers: &[(&str, &str)],
) -> Result<Zeroizing<Vec<u8>>, KmsError> {
    let body = serde_json::to_vec(&doc)
        .map(Zeroizing::new)
        .map_err(|_| KmsError::Unavailable);
    scrub_json(&mut doc);
    send(url, &body?, "application/json", headers).await
}
async fn send(
    url: &str,
    body: &[u8],
    content_type: &str,
    headers: &[(&str, &str)],
) -> Result<Zeroizing<Vec<u8>>, KmsError> {
    #[cfg(test)]
    if let Ok(response) = scripted::SCRIPT.try_with(|s| {
        let mut s = s.borrow_mut();
        s.requests.push(scripted::Request {
            url: url.into(),
            body: body.to_vec(),
            content_type: content_type.into(),
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
        });
        s.replies.pop_front().expect("unexpected KMS HTTP call")
    }) {
        return response.map(Zeroizing::new);
    }
    let cap = limits().ok_or(KmsError::Unavailable)?;
    let pinned = crate::ssrf_guard::validate_url_pinned(url)
        .await
        .map_err(|e| {
            if e.downcast_ref::<std::io::Error>().is_some() {
                KmsError::Unavailable
            } else {
                KmsError::Denied
            }
        })?;
    let client = pinned
        .pin(crate::ssrf_guard::safe_client_builder())
        .no_proxy()
        .timeout(std::time::Duration::from_millis(cap.call_timeout_ms))
        .build()
        .map_err(|_| KmsError::Unavailable)?;
    let mut request = client
        .post(url)
        .header("content-type", content_type)
        .body(body.to_vec());
    for (name, value) in headers {
        if *name == "content-type" {
            continue;
        }
        let mut h = reqwest::header::HeaderValue::from_str(value).map_err(|_| KmsError::Denied)?;
        h.set_sensitive(true);
        request = request.header(*name, h);
    }
    let mut response = request.send().await.map_err(|e| {
        let _ = e.without_url();
        KmsError::Unavailable
    })?;
    let status = response.status();
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(|e| {
        let _ = e.without_url();
        KmsError::Unavailable
    })? {
        if chunk.len() > cap.response_bytes.saturating_sub(bytes.len()) {
            return Err(KmsError::Unavailable);
        }
        bytes.extend_from_slice(&chunk);
    }
    if status.is_success() {
        return Ok(bytes);
    }
    Err(classify_failure(status, &bytes))
}
fn classify_failure(status: reqwest::StatusCode, bytes: &[u8]) -> KmsError {
    // AWS throttles can use HTTP 400. Inspect only the error classification;
    // never retain or return a backend body, which may echo secrets.
    let throttled = serde_json::from_slice::<Value>(bytes)
        .ok()
        .is_some_and(|mut v| {
            let throttled = v
                .get("__type")
                .and_then(Value::as_str)
                .is_some_and(|s| s.ends_with("ThrottlingException"));
            scrub_json(&mut v);
            throttled
        })
        || std::str::from_utf8(bytes).is_ok_and(|s| s.contains("<Code>Throttling</Code>"));
    if status.is_server_error() || matches!(status.as_u16(), 408 | 429) || throttled {
        KmsError::Unavailable
    } else {
        KmsError::Denied
    }
}
struct AwsCredentials {
    access: SecretString,
    secret: SecretString,
    token: Option<SecretString>,
}
fn hmac(key: &[u8], bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key), bytes)
            .as_ref()
            .to_vec(),
    )
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, bytes))
}
async fn aws_post(
    host: &str,
    service: &str,
    region: &str,
    content_type: &str,
    target: Option<&str>,
    body: &[u8],
    creds: &AwsCredentials,
) -> Result<Zeroizing<Vec<u8>>, KmsError> {
    let now = chrono::Utc::now();
    let date = now.format("%Y%m%d").to_string();
    let time = now.format("%Y%m%dT%H%M%SZ").to_string();
    let mut headers = vec![
        ("content-type", content_type),
        ("host", host),
        ("x-amz-date", time.as_str()),
    ];
    if let Some(token) = &creds.token {
        headers.push(("x-amz-security-token", token.expose_secret()));
    }
    if let Some(target) = target {
        headers.push(("x-amz-target", target));
    }
    headers.sort_by_key(|p| p.0);
    let canonical = Zeroizing::new(
        headers
            .iter()
            .map(|(k, v)| format!("{k}:{}\n", v.trim()))
            .collect::<String>(),
    );
    let names = headers.iter().map(|p| p.0).collect::<Vec<_>>().join(";");
    let request = Zeroizing::new(format!(
        "POST\n/\n\n{}\n{names}\n{}",
        *canonical,
        hash(body)
    ));
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{time}\n{scope}\n{}",
        hash(request.as_bytes())
    );
    let mut secret = Zeroizing::new(String::from("AWS4"));
    secret.push_str(creds.secret.expose_secret());
    let signing = hmac(
        &hmac(
            &hmac(&hmac(secret.as_bytes(), date.as_bytes()), region.as_bytes()),
            service.as_bytes(),
        ),
        b"aws4_request",
    );
    use std::fmt::Write as _;
    let mut auth = Zeroizing::new(String::new());
    write!(
        &mut *auth,
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={names}, Signature={}",
        creds.access.expose_secret(),
        hex::encode(hmac(&signing, to_sign.as_bytes()).as_slice())
    )
    .map_err(|_| KmsError::Unavailable)?;
    headers.push(("authorization", auth.as_str()));
    send(&format!("https://{host}/"), body, content_type, &headers).await
}

#[cfg(test)]
mod tests {
    use super::*;
    fn vault(url: &str) -> Backend {
        Backend {
            config: Config::VaultTransit(Vault {
                url: url.into(),
                mount: "transit".into(),
                role_id: None,
            }),
            key_ref: "provider-keys".into(),
            secret: Some(SecretString::from("unit-test-vault-token")),
        }
    }
    #[test]
    fn vault_rejects_credential_urls_and_path_injection() {
        assert!(vault("https://vault.example.com").valid());
        for url in [
            "http://vault.example.com",
            "https://u:p@vault.example.com",
            "https://vault.example.com/?token=x",
            "https://vault.example.com/#fragment",
            "https://vault.example.com/untrusted",
        ] {
            assert!(!vault(url).valid(), "{url}");
        }
        let mut v = vault("https://vault.example.com");
        v.key_ref = "../auth/token".into();
        assert!(!v.valid());
    }
    #[tokio::test]
    async fn vault_refuses_metadata_and_loopback_before_any_call() {
        for url in [
            "https://169.254.169.254",
            "https://127.0.0.1",
            "https://[::1]",
            "https://168.63.129.16",
        ] {
            assert!(vault(url).validate_destination().await.is_err(), "{url}");
        }
    }
    #[test]
    fn all_backend_parameters_are_closed_and_key_refs_are_bounded_destinations() {
        assert!(serde_json::from_value::<Config>(json!({"backend":"aws_kms","params":{"region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/kms","endpoint":"https://evil.example"}})).is_err());
        let mut a = Backend {
            config: Config::AwsKms(Aws {
                region: "us-east-1".into(),
                role_arn: "arn:aws:iam::123456789012:role/kms".into(),
            }),
            key_ref: "arn:aws:kms:us-east-1:123456789012:key/test-key".into(),
            secret: None,
        };
        assert!(a.valid());
        a.key_ref = "arn:aws:kms:us-east-1:987654321098:key/another-account".into();
        assert!(!a.valid());
        let g = Backend {
            config: Config::GcpKms(Gcp {
                service_account: "kms@test-project.iam.gserviceaccount.com".into(),
            }),
            key_ref: "projects/test-project/locations/global/keyRings/custom/cryptoKeys/providers"
                .into(),
            secret: None,
        };
        assert!(g.valid());
        let mut a = Backend {
            config: Config::AzureKeyVault(Azure {
                directory_id: Uuid::new_v4(),
            }),
            key_ref: "https://customer.vault.azure.net/keys/customer/123abc".into(),
            secret: None,
        };
        assert!(a.valid());
        a.key_ref = "https://customer.vault.azure.net.evil.example/keys/customer/123abc".into();
        assert!(!a.valid());
    }
    #[test]
    fn protocol_decoders_never_echo_secrets_or_accept_ambiguous_xml() {
        assert_eq!(
            xml_secret(
                b"<Credentials><AccessKeyId>TESTONLY123</AccessKeyId></Credentials>",
                "AccessKeyId"
            )
            .unwrap()
            .expose_secret(),
            "TESTONLY123"
        );
        assert!(
            xml_secret(
                b"<AccessKeyId>one</AccessKeyId><AccessKeyId>two</AccessKeyId>",
                "AccessKeyId"
            )
            .is_err()
        );
        assert!(xml_secret(b"<AccessKeyId>&entity;</AccessKeyId>", "AccessKeyId").is_err());
        assert_eq!(
            &*form_body(&[("secret", "unit test+/=")]),
            b"secret=unit%20test%2B%2F%3D"
        );
        assert!(json_secret(br#"{"access_token":null}"#, &["access_token"]).is_err());
    }
}

#[cfg(test)]
mod scripted {
    use super::*;
    pub struct Request {
        pub url: String,
        pub body: Vec<u8>,
        pub content_type: String,
        pub headers: Vec<(String, String)>,
    }
    #[derive(Default)]
    pub struct Script {
        pub env: std::collections::HashMap<String, String>,
        pub replies: std::collections::VecDeque<Result<Vec<u8>, KmsError>>,
        pub requests: Vec<Request>,
    }
    tokio::task_local! { pub static SCRIPT: std::cell::RefCell<Script>; }
}

#[cfg(test)]
mod protocol_tests {
    use super::scripted::{SCRIPT, Script};
    use super::*;
    use std::cell::RefCell;

    fn reply(v: Value) -> Result<Vec<u8>, KmsError> {
        Ok(serde_json::to_vec(&v).unwrap())
    }
    fn header<'a>(r: &'a scripted::Request, name: &str) -> &'a str {
        r.headers
            .iter()
            .find(|(k, _)| k == name)
            .unwrap()
            .1
            .as_str()
    }
    fn fixture_pem() -> String {
        use aws_lc_rs::encoding::AsDer as _;
        let key = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let der = key.as_der().unwrap();
        let b64 = B64.encode(der.as_ref());
        let body = b64
            .as_bytes()
            .chunks(64)
            .map(|s| format!("{}\n", std::str::from_utf8(s).unwrap()))
            .collect::<String>();
        format!("-----BEGIN PRIVATE KEY-----\n{body}-----END PRIVATE KEY-----\n")
    }
    #[tokio::test]
    async fn four_backends_wrap_unwrap_and_bind_the_authenticated_requests() {
        let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
        let id = Uuid::new_v4();
        let payload = super::super::bound_dek(&tenant, id, &[7; 32]);
        let configs = [
            Backend {
                config: Config::AwsKms(Aws {
                    region: "us-east-1".into(),
                    role_arn: "arn:aws:iam::123456789012:role/kms".into(),
                }),
                key_ref: "arn:aws:kms:us-east-1:123456789012:key/test".into(),
                secret: None,
            },
            Backend {
                config: Config::VaultTransit(Vault {
                    url: "https://vault.example.com".into(),
                    mount: "transit".into(),
                    role_id: Some("unit-role".into()),
                }),
                key_ref: "provider-keys".into(),
                secret: Some(SecretString::from("unit-secret-id")),
            },
            Backend {
                config: Config::GcpKms(Gcp {
                    service_account: "customer@fixture.iam.gserviceaccount.com".into(),
                }),
                key_ref: "projects/fixture/locations/global/keyRings/ring/cryptoKeys/key".into(),
                secret: None,
            },
            Backend {
                config: Config::AzureKeyVault(Azure {
                    directory_id: Uuid::new_v4(),
                }),
                key_ref: "https://customer.vault.azure.net/keys/key/version".into(),
                secret: None,
            },
        ];
        for backend in configs {
            let mut script = Script::default();
            script.env.insert(
                "TRACELANE_KMS_AWS_ACCESS_KEY_ID".into(),
                "UNITOPERATOR".into(),
            );
            script.env.insert(
                "TRACELANE_KMS_AWS_SECRET_ACCESS_KEY".into(),
                "unit-signing-secret".into(),
            );
            script.env.insert("TRACELANE_KMS_GCP_SERVICE_ACCOUNT".into(),json!({"client_email":"operator@fixture.iam.gserviceaccount.com","private_key":fixture_pem()}).to_string());
            script
                .env
                .insert("TRACELANE_KMS_AZURE_CLIENT_ID".into(), "unit-client".into());
            script.env.insert(
                "TRACELANE_KMS_AZURE_CLIENT_SECRET".into(),
                "unit-client-secret".into(),
            );
            for wrapping in [true, false] {
                let value = if wrapping {
                    b"ciphertext".as_slice()
                } else {
                    payload.as_slice()
                };
                match &backend.config {
                    Config::AwsKms(_) => {
                        script.replies.push_back(Ok(b"<Credentials><AccessKeyId>UNITASSUMED</AccessKeyId><SecretAccessKey>unit-assumed-secret</SecretAccessKey><SessionToken>unit-session</SessionToken></Credentials>".to_vec()));
                        script.replies.push_back(reply(if wrapping {
                            json!({"CiphertextBlob":B64.encode(value)})
                        } else {
                            json!({"Plaintext":B64.encode(value)})
                        }));
                    }
                    Config::VaultTransit(_) => {
                        script
                            .replies
                            .push_back(reply(json!({"auth":{"client_token":"unit-vault-token"}})));
                        script.replies.push_back(reply(if wrapping {
                            json!({"data":{"ciphertext":"vault:v1:fixture"}})
                        } else {
                            json!({"data":{"plaintext":B64.encode(value)}})
                        }));
                    }
                    Config::GcpKms(_) => {
                        script
                            .replies
                            .push_back(reply(json!({"access_token":"unit-operator-token"})));
                        script
                            .replies
                            .push_back(reply(json!({"accessToken":"unit-impersonated-token"})));
                        script.replies.push_back(reply(if wrapping {
                            json!({"ciphertext":B64.encode(value)})
                        } else {
                            json!({"plaintext":B64.encode(value)})
                        }));
                    }
                    Config::AzureKeyVault(_) => {
                        script
                            .replies
                            .push_back(reply(json!({"access_token":"unit-azure-token"})));
                        script
                            .replies
                            .push_back(reply(json!({"value":B64URL.encode(value)})));
                    }
                }
            }
            SCRIPT
                .scope(RefCell::new(script), async {
                    let wrapped = backend.wrap(&tenant, id, &payload).await.unwrap();
                    let opened = backend.unwrap(&tenant, id, &wrapped).await.unwrap();
                    assert_eq!(*opened, *payload);
                    SCRIPT.with(|s| {
                        let s = s.borrow();
                        assert!(s.replies.is_empty());
                        let r = &s.requests;
                        match &backend.config {
                            Config::AwsKms(_) => {
                                assert!(r[0].url.starts_with("https://sts.us-east-1."));
                                let form = String::from_utf8(r[0].body.clone()).unwrap();
                                assert!(form.contains(&format!("ExternalId=tracelane-{tenant}")));
                                assert!(
                                    header(&r[1], "authorization")
                                        .contains("Credential=UNITASSUMED/")
                                );
                                assert_eq!(header(&r[1], "x-amz-security-token"), "unit-session");
                                let doc: Value = serde_json::from_slice(&r[1].body).unwrap();
                                assert_eq!(
                                    doc["EncryptionContext"],
                                    json!({"tenant_id":tenant.to_string(),"dek_id":id.to_string()})
                                );
                                assert_eq!(header(&r[1], "x-amz-target"), "TrentService.Encrypt");
                                assert_eq!(header(&r[3], "x-amz-target"), "TrentService.Decrypt");
                                assert_eq!(r[1].content_type, "application/x-amz-json-1.1");
                            }
                            Config::VaultTransit(_) => {
                                assert_eq!(
                                    r[0].url,
                                    "https://vault.example.com/v1/auth/approle/login"
                                );
                                assert_eq!(
                                    r[1].url,
                                    "https://vault.example.com/v1/transit/encrypt/provider-keys"
                                );
                                assert_eq!(
                                    r[3].url,
                                    "https://vault.example.com/v1/transit/decrypt/provider-keys"
                                );
                                assert_eq!(header(&r[1], "x-vault-token"), "unit-vault-token");
                                assert!(!r.iter().any(|r| r.url.contains("unit-secret")));
                            }
                            Config::GcpKms(_) => {
                                assert_eq!(r[0].url, "https://oauth2.googleapis.com/token");
                                assert!(r[1].url.contains(
                                    "customer@fixture.iam.gserviceaccount.com:generateAccessToken"
                                ));
                                assert_eq!(
                                    header(&r[1], "authorization"),
                                    "Bearer unit-operator-token"
                                );
                                assert_eq!(
                                    header(&r[2], "authorization"),
                                    "Bearer unit-impersonated-token"
                                );
                                let doc: Value = serde_json::from_slice(&r[2].body).unwrap();
                                assert_eq!(
                                    doc["additionalAuthenticatedData"],
                                    B64.encode(context(&tenant, id))
                                );
                                assert!(r[5].url.ends_with(":decrypt"));
                            }
                            Config::AzureKeyVault(_) => {
                                assert!(r[0].url.ends_with("/oauth2/v2.0/token"));
                                assert!(r[1].url.ends_with("/wrapkey?api-version=2025-07-01"));
                                assert!(r[3].url.ends_with("/unwrapkey?api-version=2025-07-01"));
                                assert_eq!(
                                    header(&r[1], "authorization"),
                                    "Bearer unit-azure-token"
                                );
                                let doc: Value = serde_json::from_slice(&r[1].body).unwrap();
                                assert_eq!(doc["alg"], "RSA-OAEP-256");
                                assert_eq!(
                                    B64URL.decode(doc["value"].as_str().unwrap()).unwrap(),
                                    *payload
                                );
                            }
                        }
                    });
                })
                .await;
        }
    }
    #[test]
    fn backend_statuses_are_closed_and_do_not_echo_error_bodies() {
        for (status, body, expected) in [
            (403, b"SECRET".as_slice(), KmsError::Denied),
            (404, b"SECRET", KmsError::Denied),
            (500, b"SECRET", KmsError::Unavailable),
            (429, b"SECRET", KmsError::Unavailable),
            (
                400,
                br#"{"__type":"ThrottlingException","message":"SECRET"}"#,
                KmsError::Unavailable,
            ),
            (
                400,
                br#"{"__type":"DisabledException","message":"SECRET"}"#,
                KmsError::Denied,
            ),
        ] {
            let e = classify_failure(reqwest::StatusCode::from_u16(status).unwrap(), body);
            assert_eq!(e, expected);
            assert!(!e.to_string().contains("SECRET"));
        }
    }
}

#[cfg(all(test, debug_assertions))]
mod transport_tests {
    use super::*;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::path};
    #[tokio::test]
    async fn real_http_transport_bounds_replies_refuses_redirects_and_classifies_failures() {
        let _bypass = crate::handler_harness::LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        let destination = MockServer::start().await;
        Mock::given(path("/ok"))
            .respond_with(ResponseTemplate::new(200).set_body_string("fixture"))
            .mount(&server)
            .await;
        Mock::given(path("/denied"))
            .respond_with(ResponseTemplate::new(403).set_body_string("DO-NOT-ECHO"))
            .mount(&server)
            .await;
        Mock::given(path("/down"))
            .respond_with(ResponseTemplate::new(503).set_body_string("DO-NOT-ECHO"))
            .mount(&server)
            .await;
        Mock::given(path("/large"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![
                b'x';
                limits().unwrap().response_bytes
                    + 1
            ]))
            .mount(&server)
            .await;
        Mock::given(path("/redirect"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", destination.uri()))
            .mount(&server)
            .await;
        Mock::given(path("/slow"))
            .respond_with(
                ResponseTemplate::new(200).set_delay(std::time::Duration::from_millis(
                    limits().unwrap().call_timeout_ms + 100,
                )),
            )
            .mount(&server)
            .await;
        for (route, expected) in [
            ("denied", KmsError::Denied),
            ("down", KmsError::Unavailable),
            ("large", KmsError::Unavailable),
            ("redirect", KmsError::Denied),
            ("slow", KmsError::Unavailable),
        ] {
            let result = send(
                &format!("{}/{route}", server.uri()),
                b"{}",
                "application/json",
                &[],
            )
            .await;
            let err = result.unwrap_err();
            assert_eq!(err, expected);
            assert!(!err.to_string().contains("DO-NOT-ECHO"));
        }
        let ok = send(
            &format!("{}/ok", server.uri()),
            b"{}",
            "application/json",
            &[],
        )
        .await
        .unwrap();
        assert_eq!(&*ok, b"fixture");
        assert!(destination.received_requests().await.unwrap().is_empty());
    }
}
