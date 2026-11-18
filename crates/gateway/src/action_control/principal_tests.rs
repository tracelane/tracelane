use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use jsonwebtoken::{EncodingKey, Header};
const TEST_EC_PKCS8_DER_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgoQQxRjGx1D6cUiiJJQKdasGYEjTskAb3d4xYidfE7HGhRANCAASFXnV/lOagsDqcuUURHWfsDIENCqa8lx3MNOPxvXqYkFkdER1RM4rJWG94NLIrP1cs591Yq1VigsIBuG4tUNJn";
const TEST_EC_JWK_X: &str = "hV51f5TmoLA6nLlFER1n7AyBDQqmvJcdzDTj8b16mJA";
const TEST_EC_JWK_Y: &str = "WR0RHVEzislYb3g0sis_Vyzn3VirVWKCwgG4bi1Q0mc";
pub(super) fn issuer() -> Issuer {
    Issuer {
        issuer: "https://issuer.example".into(),
        jwks_url: "https://issuer.example/jwks".into(),
        audience: "gateway".into(),
        allowed_algs: vec![Algorithm::ES256],
    }
}
fn claims() -> Value {
    json!({"iss":"https://issuer.example", "aud":"gateway", "sub":"test-user",
        "iat":1000,"exp":1300,"roles":["treasury"]})
}
fn keys() -> Value {
    json!({"keys":[{"kty":"EC","crv":"P-256","use":"sig","kid":"test","alg":"ES256","x":TEST_EC_JWK_X,"y":TEST_EC_JWK_Y}]})
}
fn token(value: &Value) -> String {
    let der = STANDARD.decode(TEST_EC_PKCS8_DER_B64).unwrap();
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("test".into());
    jsonwebtoken::encode(&header, value, &EncodingKey::from_ec_der(&der)).unwrap()
}
fn verify(value: &Value) -> Result<Verified> {
    verify_jwks(
        &token(value),
        &issuer(),
        Uuid::nil(),
        Uuid::nil(),
        &keys(),
        1100,
    )
}
#[test]
fn verified_token_minimizes_subject() {
    let verified = verify(&claims()).unwrap();
    let evidence = verified
        .minimize(&SecretString::from("synthetic-test-key".to_owned()))
        .unwrap();
    assert_eq!(evidence.roles, vec!["treasury"]);
    assert_eq!(evidence.sub_digest.len(), 64);
    assert!(!canonical(&evidence).unwrap().contains("test-user"));
}
#[test]
fn roles_are_canonical() {
    let mut c = claims();
    c["roles"] = json!(["treasury", "audit", "treasury"]);
    let p = verify(&c)
        .unwrap()
        .minimize(&SecretString::from("synthetic".to_owned()))
        .unwrap();
    assert_eq!(p.roles, vec!["audit", "treasury"]);
}
#[test]
fn tenant_key_separates_subjects() {
    let v = verify(&claims()).unwrap();
    assert_ne!(
        v.minimize(&SecretString::from("tenant-a".to_owned()))
            .unwrap()
            .sub_digest,
        v.minimize(&SecretString::from("tenant-b".to_owned()))
            .unwrap()
            .sub_digest
    );
}
#[test]
fn absent_roles_are_allowed() {
    let mut c = claims();
    c.as_object_mut().unwrap().remove("roles");
    assert!(verify(&c).unwrap().roles.is_empty());
}
#[test]
fn expired_principal_denied() {
    let mut c = claims();
    c["exp"] = json!(1100);
    assert!(verify(&c).is_err());
}
#[test]
fn invalid_lifetime_rejected() {
    for (k, v) in [
        ("iat", json!(1200)),
        ("exp", json!(2000)),
        ("nbf", json!(1200)),
    ] {
        let mut c = claims();
        c[k] = v;
        assert!(verify(&c).is_err(), "{k}");
    }
}
#[test]
fn wrong_audience_denied() {
    let mut c = claims();
    c["aud"] = json!("other");
    assert!(verify(&c).is_err());
}
#[test]
fn foreign_issuer_denied() {
    let mut c = claims();
    c["iss"] = json!("https://foreign.example");
    assert!(verify(&c).is_err());
}
#[test]
fn empty_subject_denied() {
    let mut c = claims();
    c["sub"] = json!("");
    assert!(verify(&c).is_err());
}
#[test]
fn missing_claims_denied() {
    for k in ["sub", "iss", "aud", "iat", "exp"] {
        let mut c = claims();
        c.as_object_mut().unwrap().remove(k);
        assert!(verify(&c).is_err(), "{k}");
    }
}
#[test]
fn malformed_roles_denied() {
    for roles in [json!("treasury"), json!([7]), json!(["a@b"]), json!([""])] {
        let mut c = claims();
        c["roles"] = roles;
        assert!(verify(&c).is_err());
    }
}
#[test]
fn excessive_roles_denied() {
    let mut c = claims();
    c["roles"] = json!(vec!["treasury"; limits().unwrap().max_roles + 1]);
    assert!(verify(&c).is_err());
}
#[test]
fn hmac_principal_denied() {
    let mut h = Header::new(Algorithm::HS256);
    h.kid = Some("test".into());
    let t = jsonwebtoken::encode(
        &h,
        &claims(),
        &EncodingKey::from_secret(b"synthetic-test-key"),
    )
    .unwrap();
    assert!(verify_jwks(&t, &issuer(), Uuid::nil(), Uuid::nil(), &keys(), 1100).is_err());
}
#[test]
fn duplicate_kid_denied() {
    let mut k = keys();
    let key = k["keys"][0].clone();
    k["keys"].as_array_mut().unwrap().push(key);
    assert!(
        verify_jwks(
            &token(&claims()),
            &issuer(),
            Uuid::nil(),
            Uuid::nil(),
            &k,
            1100
        )
        .is_err()
    );
}
#[test]
fn encryption_key_denied() {
    let mut k = keys();
    k["keys"][0]["use"] = json!("enc");
    assert!(
        verify_jwks(
            &token(&claims()),
            &issuer(),
            Uuid::nil(),
            Uuid::nil(),
            &k,
            1100
        )
        .is_err()
    );
}
#[test]
fn signature_tampering_denied() {
    let mut t = token(&claims()).into_bytes();
    let i = t.len() - 8;
    t[i] = if t[i] == b'A' { b'B' } else { b'A' };
    assert!(
        verify_jwks(
            std::str::from_utf8(&t).unwrap(),
            &issuer(),
            Uuid::nil(),
            Uuid::nil(),
            &keys(),
            1100
        )
        .is_err()
    );
}

pub(super) fn verified_at(tenant: Uuid, registration: Uuid, sub: &str, now: i64) -> Verified {
    let mut c = claims();
    c["sub"] = json!(sub);
    c["iat"] = json!(now);
    c["exp"] = json!(now + 300);
    verify_jwks(&token(&c), &issuer(), tenant, registration, &keys(), now).unwrap()
}
#[test]
fn audience_array_verified() {
    let mut c = claims();
    c["aud"] = json!(["other", "gateway"]);
    assert!(verify(&c).is_ok());
}
#[test]
fn not_before_elapsed_verified() {
    let mut c = claims();
    c["nbf"] = json!(1000);
    assert!(verify(&c).is_ok());
}
#[test]
fn exact_lifetime_cap_verified() {
    let mut c = claims();
    c["exp"] = json!(1000 + limits().unwrap().max_lifetime_secs);
    assert!(verify(&c).is_ok());
}
#[test]
fn eddsa_registered_key_verified() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::signature::KeyPair;
    let der = ring::signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(der.as_ref()).unwrap();
    let mut i = issuer();
    i.allowed_algs = vec![Algorithm::EdDSA];
    let mut h = Header::new(Algorithm::EdDSA);
    h.kid = Some("ed".into());
    let t = jsonwebtoken::encode(&h, &claims(), &EncodingKey::from_ed_der(der.as_ref())).unwrap();
    let k = json!({"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","kid":"ed","x":URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())}]});
    assert!(verify_jwks(&t, &i, Uuid::nil(), Uuid::nil(), &k, 1100).is_ok());
}
#[test]
fn oversized_token_rejected() {
    assert!(
        verify_jwks(
            &"x".repeat(limits().unwrap().max_token_bytes + 1),
            &issuer(),
            Uuid::nil(),
            Uuid::nil(),
            &keys(),
            1100
        )
        .is_err()
    );
}
#[test]
fn registration_rejects_unsafe_urls() {
    for url in [
        "http://issuer.example/jwks",
        "https://user:pass@issuer.example/jwks",
        "https://issuer.example/jwks?token=value",
        "https://issuer.example/jwks#key",
    ] {
        let mut i = issuer();
        i.jwks_url = url.into();
        assert!(validate_issuer(&i).is_err());
    }
}
#[test]
fn registration_rejects_hmac() {
    let mut i = issuer();
    i.allowed_algs.push(Algorithm::HS256);
    assert!(validate_issuer(&i).is_err());
}
#[test]
fn key_algorithm_and_operations_rejected() {
    for (field, value) in [("alg", json!("RS256")), ("key_ops", json!(["encrypt"]))] {
        let mut k = keys();
        k["keys"][0][field] = value;
        assert!(
            verify_jwks(
                &token(&claims()),
                &issuer(),
                Uuid::nil(),
                Uuid::nil(),
                &k,
                1100
            )
            .is_err()
        );
    }
}
#[tokio::test]
async fn duplicate_principal_header_denied_before_database() {
    let config = tokio_postgres::Config::new();
    let pool = deadpool_postgres::Pool::builder(deadpool_postgres::Manager::new(
        config,
        tokio_postgres::NoTls,
    ))
    .max_size(1)
    .build()
    .unwrap();
    let mut headers = axum::http::HeaderMap::new();
    headers.append("tracelane-principal", "one".parse().unwrap());
    headers.append("tracelane-principal", "two".parse().unwrap());
    assert!(matches!(
        verify_headers(&pool, &TenantId::from_jwt_claim(Uuid::nil()), &headers).await,
        Input::Invalid
    ));
}
#[test]
fn same_issuer_approver_separation() {
    let verified = verify(&claims()).unwrap();
    let secret = SecretString::from("synthetic".to_owned());
    let p = verified.minimize(&secret).unwrap();
    assert!(same_subject(&p, Some("https://issuer.example"), "test-user", &secret).unwrap());
    assert!(!same_subject(&p, Some("https://issuer.example"), "other-user", &secret).unwrap());
    assert!(!same_subject(&p, Some("https://other.example"), "test-user", &secret).unwrap());
    assert!(!same_subject(&p, None, "test-user", &secret).unwrap());
}
#[tokio::test]
async fn jwks_cache_singleflight_and_miss_bound() {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    let count = AtomicUsize::new(0);
    let tenant = Uuid::new_v4();
    let id = Uuid::new_v4();
    let ttl = Duration::from_secs(300);
    let load = || async {
        count.fetch_add(1, Ordering::SeqCst);
        Ok(keys())
    };
    let (a, b) = tokio::join!(
        cached_keys_with(tenant, id, "test", ttl, load),
        cached_keys_with(tenant, id, "test", ttl, load)
    );
    assert!(a.is_ok() && b.is_ok());
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(
        cached_keys_with(tenant, id, "unknown", ttl, load)
            .await
            .is_err()
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let entry = cache().unwrap().entry((tenant, id), ttl).unwrap();
    {
        let mut entry = entry.lock().await;
        entry.loaded = std::time::Instant::now() - ttl;
        entry.last_attempt = None;
    }
    assert!(
        cached_keys_with(tenant, id, "test", ttl, || async {
            anyhow::bail!("offline")
        })
        .await
        .is_err()
    );
    assert!(
        cached_keys_with(tenant, id, "test", ttl, load)
            .await
            .is_err(),
        "failed refresh renewed stale keys"
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn jwks_response_limits_and_redirects() {
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::path};
    let server = MockServer::start().await;
    Mock::given(path("/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(keys()))
        .mount(&server)
        .await;
    Mock::given(path("/large"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![
            b'x';
            limits().unwrap().max_jwks_bytes
                + 1
        ]))
        .mount(&server)
        .await;
    Mock::given(path("/redirect"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", format!("{}/keys", server.uri())),
        )
        .mount(&server)
        .await;
    // Production fetch_keys validates HTTPS and pins DNS before invoking this bounded reader.
    let client = crate::ssrf_guard::safe_client_builder()
        .no_proxy()
        .build()
        .unwrap();
    assert_eq!(
        request_keys(&client, &format!("{}/keys", server.uri()))
            .await
            .unwrap(),
        keys()
    );
    assert!(
        request_keys(&client, &format!("{}/large", server.uri()))
            .await
            .is_err()
    );
    assert!(
        request_keys(&client, &format!("{}/redirect", server.uri()))
            .await
            .is_err()
    );
}
#[test]
fn key_curve_relabel_rejected() {
    for curve in ["P-384", "Ed25519"] {
        let mut k = keys();
        k["keys"][0]["crv"] = json!(curve);
        assert!(
            verify_jwks(
                &token(&claims()),
                &issuer(),
                Uuid::nil(),
                Uuid::nil(),
                &k,
                1100
            )
            .is_err(),
            "curve {curve} accepted"
        );
    }
}
#[test]
fn untrusted_jku_ignored() {
    let der = STANDARD.decode(TEST_EC_PKCS8_DER_B64).unwrap();
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("test".into());
    header.jku = Some("http://169.254.169.254/keys".into());
    header.x5u = Some("http://127.0.0.1/keys".into());
    let token = jsonwebtoken::encode(&header, &claims(), &EncodingKey::from_ec_der(&der)).unwrap();
    assert!(verify_jwks(&token, &issuer(), Uuid::nil(), Uuid::nil(), &keys(), 1100).is_ok());
    assert!(
        verify_jwks(
            &token,
            &issuer(),
            Uuid::nil(),
            Uuid::nil(),
            &json!({"keys":[]}),
            1100
        )
        .is_err()
    );
}
#[tokio::test]
async fn private_jwks_addresses_denied() {
    // Non-loopback ranges remain denied even while other local fixtures use loopback bypass.
    for url in [
        "https://169.254.169.254/keys",
        "https://10.1.2.3/keys",
        "https://[fd00::1]/keys",
    ] {
        let mut i = issuer();
        i.jwks_url = url.into();
        assert!(fetch_keys(&i).await.is_err());
    }
}
#[tokio::test]
async fn unknown_kid_refresh_after_ttl() {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    let count = AtomicUsize::new(0);
    let tenant = Uuid::new_v4();
    let id = Uuid::new_v4();
    let ttl = Duration::from_secs(300);
    cached_keys_with(tenant, id, "test", ttl, || async {
        count.fetch_add(1, Ordering::SeqCst);
        Ok(keys())
    })
    .await
    .unwrap();
    let entry = cache().unwrap().entry((tenant, id), ttl).unwrap();
    {
        let mut entry = entry.lock().await;
        entry.last_attempt = Some(std::time::Instant::now() - ttl);
    }
    let rotated = || async {
        count.fetch_add(1, Ordering::SeqCst);
        let mut k = keys();
        k["keys"][0]["kid"] = json!("rotated");
        Ok(k)
    };
    assert_eq!(
        cached_keys_with(tenant, id, "rotated", ttl, rotated)
            .await
            .unwrap()["keys"][0]["kid"],
        "rotated"
    );
    assert!(
        cached_keys_with(tenant, id, "unknown", ttl, rotated)
            .await
            .is_err()
    );
    assert_eq!(count.load(Ordering::SeqCst), 2);
}
#[tokio::test]
async fn cache_capacity_keeps_recent_attempts() {
    use std::time::{Duration, Instant};
    let cache = Cache {
        entries: std::sync::Mutex::new(BTreeMap::new()),
        capacity: 1,
    };
    let ttl = Duration::from_secs(300);
    let first = (Uuid::new_v4(), Uuid::new_v4());
    let second = (first.0, Uuid::new_v4());
    let entry = cache.entry(first, ttl).unwrap();
    entry.lock().await.last_attempt = Some(Instant::now());
    assert!(cache.entry(second, ttl).is_err());
    {
        let mut entry = entry.lock().await;
        entry.loaded = Instant::now() - ttl;
        entry.last_attempt = Some(Instant::now() - ttl);
    }
    drop(entry);
    assert!(cache.entry(second, ttl).is_ok());
}

#[tokio::test]
async fn cache_idle_tenant_cannot_exclude_another_tenant() {
    use std::time::{Duration, Instant};
    let cache = Cache {
        entries: std::sync::Mutex::new(BTreeMap::new()),
        capacity: 2,
    };
    let ttl = Duration::from_secs(300);
    let tenant = Uuid::new_v4();
    for _ in 0..cache.capacity {
        let entry = cache.entry((tenant, Uuid::new_v4()), ttl).unwrap();
        entry.lock().await.last_attempt = Some(Instant::now());
    }
    let other = cache.entry((Uuid::new_v4(), Uuid::new_v4()), ttl);
    assert!(
        other.is_ok(),
        "idle tenant entries must yield cache capacity"
    );
    assert_eq!(cache.entries.lock().unwrap().len(), cache.capacity);
}

#[tokio::test]
async fn cache_pressure_evicts_oldest_idle_entry() {
    use std::time::{Duration, Instant};
    let cache = Cache {
        entries: std::sync::Mutex::new(BTreeMap::new()),
        capacity: 2,
    };
    let ttl = Duration::from_secs(300);
    let old = (Uuid::new_v4(), Uuid::new_v4());
    let recent = (Uuid::new_v4(), Uuid::new_v4());
    for (id, age) in [(old, 20), (recent, 10)] {
        let entry = cache.entry(id, ttl).unwrap();
        let mut keys = entry.lock().await;
        keys.loaded = Instant::now() - Duration::from_secs(age);
        keys.last_attempt = Some(keys.loaded);
    }
    let incoming = (Uuid::new_v4(), Uuid::new_v4());
    assert!(cache.entry(incoming, ttl).is_ok());
    let entries = cache.entries.lock().unwrap();
    assert!(!entries.contains_key(&old));
    assert!(entries.contains_key(&recent));
    assert!(entries.contains_key(&incoming));
}

#[test]
fn principal_one_second_ahead_is_within_clock_skew() {
    let mut value = claims();
    value["iat"] = json!(1101);
    value["nbf"] = json!(1101);
    assert!(verify(&value).is_ok());
}

#[test]
fn principal_clock_skew_boundaries_keep_expiry_strict() {
    let skew = limits().unwrap().clock_skew_secs;
    for field in ["iat", "nbf"] {
        for offset in [skew - 1, skew, skew + 1] {
            let mut value = claims();
            value[field] = json!(1100 + offset);
            value["exp"] = json!(1100 + skew + 100);
            assert_eq!(verify(&value).is_ok(), offset <= skew, "{field} {offset}");
        }
    }
    for expiry in [1099, 1100] {
        let mut expired = claims();
        expired["exp"] = json!(expiry);
        assert!(verify(&expired).is_err());
    }
}
