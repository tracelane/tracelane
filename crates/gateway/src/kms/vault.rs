//! Tenant DEK cache and the single provider-key encryption boundary.
use super::{
    KmsError,
    backend::{Backend, Config, KmsBackend},
    bound_dek, limits, unbind_dek,
};
use secrecy::{SecretString, zeroize::Zeroizing};
use std::{
    collections::HashMap,
    hash::Hash,
    sync::{Arc, OnceLock, Weak},
    time::{Duration, Instant},
};
use tracelane_shared::TenantId;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("provider_key_lookup_failed")]
    Lookup,
    #[error("provider_key_unusable")]
    Invalid,
    #[error(transparent)]
    Kms(#[from] KmsError),
}
pub struct Configuration {
    pub backend: Backend,
    pub id: Uuid,
    pub wrapped: Vec<u8>,
}
pub struct Opened {
    pub secret: Arc<SecretString>,
    pub expires_at: Option<Instant>,
}
struct Entry {
    result: Result<Arc<Zeroizing<[u8; 32]>>, KmsError>,
    expires: Instant,
    last_success: Option<chrono::DateTime<chrono::Utc>>,
}
/// Async mutexes keyed by `K`, created on demand and held weakly: a key nobody holds
/// costs one dead map slot until the next sweep. H1 (security review, 2026-10-05): this
/// replaced 64 STRIPED locks (`tenant % 64`) that every tenant's cold key lookup took and
/// that a KMS write held across customer-Vault calls, so one tenant with a slow Vault
/// stalled ~1/64 of all tenants. A key here is one tenant (or narrower), never a stripe.
///
/// Each key holds `permits` slots (1 = a mutex; more = a per-key concurrency cap).
pub(crate) struct KeyedLocks<K> {
    /// The weak locks, and the size at which dead entries are next swept.
    map: parking_lot::Mutex<(WeakLocks<K>, usize)>,
    permits: usize,
}
type WeakLocks<K> = HashMap<K, Weak<tokio::sync::Semaphore>>;
/// A held slot of a [`KeyedLocks`] key; released on drop.
pub(crate) type KeyedPermit = tokio::sync::OwnedSemaphorePermit;
impl<K> Default for KeyedLocks<K> {
    fn default() -> Self {
        Self::with_permits(1)
    }
}
impl<K> KeyedLocks<K> {
    pub(crate) fn with_permits(permits: usize) -> Self {
        Self {
            map: parking_lot::Mutex::new((HashMap::new(), 64)),
            permits: permits.max(1),
        }
    }
}
impl<K: Eq + Hash> KeyedLocks<K> {
    /// A slot for `key`, waiting at most `wait`. `None` = the wait elapsed: the caller
    /// fails CLOSED for that key only (§10) — nobody else shares it.
    pub(crate) async fn acquire(&self, key: K, wait: Duration) -> Option<KeyedPermit> {
        let lock = {
            let mut guard = self.map.lock();
            let (map, sweep_at) = &mut *guard;
            if let Some(lock) = map.get(&key).and_then(Weak::upgrade) {
                lock
            } else {
                if map.len() >= *sweep_at {
                    map.retain(|_, w| w.strong_count() > 0);
                    *sweep_at = (map.len() * 2).max(64);
                }
                let lock = Arc::new(tokio::sync::Semaphore::new(self.permits));
                map.insert(key, Arc::downgrade(&lock));
                lock
            }
        };
        tokio::time::timeout(wait, lock.acquire_owned())
            .await
            .ok()?
            .ok()
    }
    #[cfg(test)]
    fn live(&self) -> usize {
        self.map
            .lock()
            .0
            .values()
            .filter(|w| w.strong_count() > 0)
            .count()
    }
}

/// A tenant's KMS write fence: held while a KMS configuration or provider-key write
/// commits, never across a customer KMS call.
pub type TenantLock = KeyedPermit;

pub struct KeyVault {
    cache: parking_lot::Mutex<HashMap<(Uuid, Uuid), Entry>>,
    /// Per-tenant write fence ([`Self::lock`]). Writes do their customer-KMS I/O BEFORE
    /// taking it and re-check (CAS) the configuration they used once inside it.
    locks: KeyedLocks<Uuid>,
    /// Single flight per `(tenant, DEK id)` for an unwrap: only that tenant's own callers
    /// ever wait on its KMS, and only for `lock_wait_ms`.
    flights: KeyedLocks<(Uuid, Uuid)>,
    /// H1 round 2: at most `kms.max_calls_per_tenant` customer-KMS calls of one tenant in
    /// flight ([`Self::kms_call`]) — a hanging Vault cannot accumulate waiters.
    calls: KeyedLocks<Uuid>,
    /// MED round 2: invalidation generations, striped by tenant. `dek` reads its
    /// tenant's stripe before the unwrap and caches only if no invalidation landed in
    /// between. A collision only skips caching (one more unwrap) — it never serves a
    /// stale DEK — and no lock is involved.
    generations: Box<[std::sync::atomic::AtomicU64]>,
}

/// Generation stripes (a power of two). A wire-format-free bound, not a tunable.
const GENERATION_STRIPES: usize = 4096;
impl KeyVault {
    fn new() -> Self {
        Self {
            cache: Default::default(),
            locks: KeyedLocks::default(),
            flights: KeyedLocks::default(),
            calls: KeyedLocks::with_permits(limits().map_or(1, |l| l.max_calls_per_tenant)),
            generations: (0..GENERATION_STRIPES)
                .map(|_| std::sync::atomic::AtomicU64::new(0))
                .collect(),
        }
    }
    fn generation(&self, tenant: &TenantId) -> &std::sync::atomic::AtomicU64 {
        let n = tenant.as_uuid().as_u128() as usize & (GENERATION_STRIPES - 1);
        &self.generations[n]
    }
    /// Run one customer-KMS call for `tenant` inside its per-tenant cap (H1 round 2).
    ///
    /// # Errors
    /// `KmsError::Unavailable` when no slot frees within `lock_wait_ms` — fail CLOSED for
    /// that tenant only; otherwise whatever the call returns.
    pub(crate) async fn kms_call<T>(
        &self,
        tenant: &TenantId,
        call: impl std::future::Future<Output = Result<T, KmsError>>,
    ) -> Result<T, KmsError> {
        let wait = Duration::from_millis(limits().ok_or(KmsError::Unavailable)?.lock_wait_ms);
        let _slot = self
            .calls
            .acquire(*tenant.as_uuid(), wait)
            .await
            .ok_or(KmsError::Unavailable)?;
        call.await
    }
    pub fn global() -> Result<&'static Self, VaultError> {
        static VAULT: OnceLock<KeyVault> = OnceLock::new();
        limits().ok_or(KmsError::Unavailable)?;
        Ok(VAULT.get_or_init(Self::new))
    }
    /// The tenant's KMS write fence, waited for at most `kms.lock_wait_ms`.
    ///
    /// # Errors
    /// `KmsError::Unavailable` when the wait elapses — fail CLOSED for THIS tenant only.
    pub async fn lock(&self, tenant: &TenantId) -> Result<TenantLock, KmsError> {
        let wait = Duration::from_millis(limits().ok_or(KmsError::Unavailable)?.lock_wait_ms);
        self.locks
            .acquire(*tenant.as_uuid(), wait)
            .await
            .ok_or(KmsError::Unavailable)
    }
    pub fn invalidate(&self, tenant: &TenantId) {
        self.generation(tenant)
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.cache.lock().retain(|(t, _), _| t != tenant.as_uuid());
        crate::db::provider_keys::invalidate_tenant(tenant);
    }
    pub fn status(
        &self,
        tenant: &TenantId,
        id: Uuid,
    ) -> (Option<chrono::DateTime<chrono::Utc>>, Option<&'static str>) {
        let map = self.cache.lock();
        match map.get(&(*tenant.as_uuid(), id)) {
            Some(e) => match e.result {
                Ok(_) => (e.last_success, None),
                Err(KmsError::Denied) => (e.last_success, Some("kms_access_denied")),
                Err(KmsError::Unavailable) => (e.last_success, Some("kms_unavailable")),
            },
            None => (None, None),
        }
    }
    /// The tenant's DEK, unwrapped by its customer KMS at most once per `(tenant, id)` at
    /// a time (single flight; no tenant-wide or shared lock is taken). The DEK expiry is
    /// inherited by the plaintext it opens, never restarted on each provider.
    ///
    /// # Errors
    /// Fail CLOSED: `Unavailable` when another unwrap of this tenant's DEK is still in
    /// flight after `lock_wait_ms`, or the KMS fails; `Denied` when it refuses.
    pub async fn dek(
        &self,
        backend: &impl KmsBackend,
        tenant: &TenantId,
        id: Uuid,
        wrapped: &[u8],
    ) -> Result<(Arc<Zeroizing<[u8; 32]>>, Instant), KmsError> {
        let l = limits().ok_or(KmsError::Unavailable)?;
        let now = Instant::now();
        if let Some(e) = self.cache.lock().get(&(*tenant.as_uuid(), id))
            && now < e.expires
        {
            return e.result.clone().map(|d| (d, e.expires));
        }
        let _flight = self
            .flights
            .acquire(
                (*tenant.as_uuid(), id),
                Duration::from_millis(l.lock_wait_ms),
            )
            .await
            .ok_or(KmsError::Unavailable)?;
        // The flight we waited for may have filled it.
        let now = Instant::now();
        if let Some(e) = self.cache.lock().get(&(*tenant.as_uuid(), id))
            && now < e.expires
        {
            return e.result.clone().map(|d| (d, e.expires));
        }
        let last_success = self
            .cache
            .lock()
            .get(&(*tenant.as_uuid(), id))
            .and_then(|e| e.last_success);
        let generation = self
            .generation(tenant)
            .load(std::sync::atomic::Ordering::Acquire);
        // Boxed: a backend call is a large future, and this one sits inside every cold
        // key lookup's future on the request path.
        let result = self
            .kms_call(tenant, Box::pin(backend.unwrap(tenant, id, wrapped)))
            .await
            .and_then(|bytes| unbind_dek(tenant, id, &bytes))
            .map(Arc::new);
        if matches!(result, Err(KmsError::Denied)) {
            self.invalidate(tenant);
        }
        let expires = now
            + Duration::from_secs(if result.is_ok() {
                l.dek_cache_ttl_secs
            } else {
                l.failure_backoff_secs
            });
        let mut map = self.cache.lock();
        // An invalidation (delete/rotate/denial) landed during the unwrap: a DEK it
        // produced answers THIS request only and is never cached. A failure is still
        // cached (a negative entry is fail-closed, and a denial invalidates by itself).
        if result.is_ok()
            && self
                .generation(tenant)
                .load(std::sync::atomic::Ordering::Acquire)
                != generation
        {
            return result.map(|d| (d, expires));
        }
        map.retain(|_, e| e.expires > now);
        if map.len() >= l.dek_cache_max_entries
            && let Some(oldest) = map.iter().min_by_key(|(_, e)| e.expires).map(|(k, _)| *k)
        {
            map.remove(&oldest);
        }
        map.insert(
            (*tenant.as_uuid(), id),
            Entry {
                result: result.clone(),
                expires,
                last_success: if result.is_ok() {
                    Some(chrono::Utc::now())
                } else {
                    last_success
                },
            },
        );
        result.map(|d| (d, expires))
    }
    pub async fn open(
        &self,
        config: Option<&Configuration>,
        tenant: &TenantId,
        provider: &str,
        blob: &str,
        master: &crate::byok::ByokMasterKey,
    ) -> Result<Opened, VaultError> {
        match config {
            Some(c) => {
                // A customer-managed tenant never accepts a platform envelope.
                if crate::byok::ByokMasterKey::kek_id_of(blob).is_some() {
                    return Err(VaultError::Invalid);
                }
                let (dek, expires) = self.dek(&c.backend, tenant, c.id, &c.wrapped).await?;
                let secret = super::open(tenant, provider, c.id, &dek, blob)
                    .map_err(|_| VaultError::Invalid)?;
                Ok(Opened {
                    secret: Arc::new(secret),
                    expires_at: Some(expires),
                })
            }
            None => Ok(Opened {
                secret: Arc::new(
                    master
                        .decrypt_with_context(
                            blob,
                            &crate::byok::provider_key_aad(tenant, provider),
                        )
                        .map_err(|_| VaultError::Invalid)?,
                ),
                expires_at: None,
            }),
        }
    }
    pub async fn seal(
        &self,
        config: Option<&Configuration>,
        tenant: &TenantId,
        provider: &str,
        secret: &SecretString,
        master: &crate::byok::ByokMasterKey,
    ) -> Result<String, VaultError> {
        match config {
            Some(c) => {
                let (dek, _) = self.dek(&c.backend, tenant, c.id, &c.wrapped).await?;
                super::seal(tenant, provider, c.id, &dek, secret).map_err(Into::into)
            }
            None => master
                .encrypt_with_context(secret, &crate::byok::provider_key_aad(tenant, provider))
                .map_err(|_| VaultError::Invalid),
        }
    }
}
/// Fail CLOSED on query, configuration, or credential decode errors; a database
/// outage must not look like a tenant that has no KMS configured.
pub async fn load(
    client: &impl tokio_postgres::GenericClient,
    tenant: &TenantId,
    master: &crate::byok::ByokMasterKey,
) -> Result<Option<Configuration>, VaultError> {
    let row = client.query_opt("SELECT c.backend, c.key_ref, c.params, c.secret_enc, d.id, d.wrapped_dek, d.key_ref FROM tenant_kms_configs c LEFT JOIN tenant_data_keys d ON d.tenant_id = c.tenant_id AND d.retired_at IS NULL WHERE c.tenant_id = $1", &[tenant.as_uuid()]).await.map_err(|_| VaultError::Lookup)?;
    let Some(row) = row else { return Ok(None) };
    let backend: String = row.get(0);
    let key_ref: String = row.get(1);
    let params: serde_json::Value = row.get(2);
    let config: Config =
        serde_json::from_value(serde_json::json!({"backend":backend,"params":params}))
            .map_err(|_| VaultError::Invalid)?;
    let secret: Option<String> = row.get(3);
    let secret = secret
        .map(|s| {
            master
                .decrypt_with_context(&s, &crate::byok::kms_config_aad(tenant.as_uuid()))
                .map_err(|_| VaultError::Invalid)
        })
        .transpose()?;
    let id: Uuid = row.get::<_, Option<Uuid>>(4).ok_or(VaultError::Invalid)?;
    let wrapped: Vec<u8> = row
        .get::<_, Option<Vec<u8>>>(5)
        .ok_or(VaultError::Invalid)?;
    if row.get::<_, Option<String>>(6).as_deref() != Some(key_ref.as_str()) {
        return Err(VaultError::Invalid);
    }
    Ok(Some(Configuration {
        backend: Backend {
            config,
            key_ref,
            secret,
        },
        id,
        wrapped,
    }))
}
pub fn fresh_dek() -> Result<Zeroizing<[u8; 32]>, KmsError> {
    use ring::rand::SecureRandom as _;
    let mut key = Zeroizing::new([0; 32]);
    ring::rand::SystemRandom::new()
        .fill(key.as_mut())
        .map_err(|_| KmsError::Unavailable)?;
    Ok(key)
}
pub async fn wrap_probe(
    backend: &impl KmsBackend,
    tenant: &TenantId,
    id: Uuid,
    dek: &[u8; 32],
) -> Result<Vec<u8>, KmsError> {
    let vault = KeyVault::global().map_err(|_| KmsError::Unavailable)?;
    let wrapped = vault
        .kms_call(
            tenant,
            backend.wrap(tenant, id, &bound_dek(tenant, id, dek)),
        )
        .await?;
    let opened = unbind_dek(
        tenant,
        id,
        &vault
            .kms_call(tenant, backend.unwrap(tenant, id, &wrapped))
            .await?,
    )?;
    if &*opened != dek {
        return Err(KmsError::Denied);
    };
    Ok(wrapped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    struct Fake {
        calls: AtomicUsize,
        deny: AtomicBool,
    }
    impl KmsBackend for Fake {
        async fn wrap(&self, _: &TenantId, _: Uuid, bytes: &[u8]) -> Result<Vec<u8>, KmsError> {
            Ok(bytes.to_vec())
        }
        async fn unwrap(
            &self,
            _: &TenantId,
            _: Uuid,
            bytes: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, KmsError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.deny.load(Ordering::SeqCst) {
                Err(KmsError::Denied)
            } else {
                Ok(Zeroizing::new(bytes.to_vec()))
            }
        }
    }
    fn fake() -> Fake {
        Fake {
            calls: AtomicUsize::new(0),
            deny: AtomicBool::new(false),
        }
    }
    fn vault() -> KeyVault {
        KeyVault::new()
    }
    #[tokio::test]
    async fn concurrent_cold_requests_single_flight_and_revocation_no_stale() {
        let v = vault();
        let f = fake();
        let t = TenantId::from_jwt_claim(Uuid::new_v4());
        let id = Uuid::new_v4();
        let wrapped = bound_dek(&t, id, &[31; 32]);
        futures::future::join_all((0..100).map(|_| async {
            assert_eq!(**v.dek(&f, &t, id, &wrapped).await.unwrap().0, [31; 32]);
        }))
        .await;
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
        f.deny.store(true, Ordering::SeqCst);
        assert!(
            v.dek(&f, &t, id, &wrapped).await.is_ok(),
            "existing DEK is valid within the stated bound"
        );
        v.cache.lock().get_mut(&(*t.as_uuid(), id)).unwrap().expires = Instant::now();
        crate::db::provider_keys::cache_decrypted(
            &t,
            "openai",
            Arc::new(SecretString::from("unit-test-secret")),
        );
        assert!(matches!(
            v.dek(&f, &t, id, &wrapped).await,
            Err(KmsError::Denied)
        ));
        assert!(matches!(
            crate::db::provider_keys::lookup_swr(&t, "openai"),
            crate::db::provider_keys::CachedLookup::Miss
        ));
        f.deny.store(false, Ordering::SeqCst);
        assert!(
            matches!(v.dek(&f, &t, id, &wrapped).await, Err(KmsError::Denied)),
            "negative cache must suppress repeated KMS calls"
        );
        assert_eq!(f.calls.load(Ordering::SeqCst), 2);
        v.cache.lock().get_mut(&(*t.as_uuid(), id)).unwrap().expires = Instant::now();
        assert!(v.dek(&f, &t, id, &wrapped).await.is_ok());
    }
    #[tokio::test]
    async fn cache_bound_and_dek_zeroization_type() {
        fn zeroizes<T: secrecy::zeroize::ZeroizeOnDrop>() {}
        zeroizes::<Zeroizing<[u8; 32]>>();
        let v = vault();
        let f = fake();
        let t = TenantId::from_jwt_claim(Uuid::new_v4());
        let id = Uuid::new_v4();
        {
            let mut map = v.cache.lock();
            for _ in 0..limits().unwrap().dek_cache_max_entries {
                map.insert(
                    (Uuid::new_v4(), Uuid::new_v4()),
                    Entry {
                        result: Ok(Arc::new(Zeroizing::new([1; 32]))),
                        expires: Instant::now() + Duration::from_secs(60),
                        last_success: Some(chrono::Utc::now()),
                    },
                );
            }
        }
        v.dek(&f, &t, id, &bound_dek(&t, id, &[2; 32]))
            .await
            .unwrap();
        assert_eq!(
            v.cache.lock().len(),
            limits().unwrap().dek_cache_max_entries
        );
        assert!(v.cache.lock().contains_key(&(*t.as_uuid(), id)));
    }
    #[tokio::test]
    async fn cross_tenant_wrapped_dek_swap_is_denied_even_without_native_aad() {
        let v = vault();
        let f = fake();
        let a = TenantId::from_jwt_claim(Uuid::new_v4());
        let b = TenantId::from_jwt_claim(Uuid::new_v4());
        let id = Uuid::new_v4();
        assert!(matches!(
            v.dek(&f, &b, id, &bound_dek(&a, id, &[1; 32])).await,
            Err(KmsError::Denied)
        ));
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    }
    /// A customer KMS that never answers.
    struct Hang;
    impl KmsBackend for Hang {
        async fn wrap(&self, _: &TenantId, _: Uuid, _: &[u8]) -> Result<Vec<u8>, KmsError> {
            std::future::pending().await
        }
        async fn unwrap(
            &self,
            _: &TenantId,
            _: Uuid,
            _: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, KmsError> {
            std::future::pending().await
        }
    }

    /// H1 (security review, 2026-10-05): a tenant whose customer KMS never answers must
    /// not delay ANOTHER tenant's first key lookup — the two tenants below collided on
    /// the old 64-stripe lock (`tenant % 64`).
    #[tokio::test]
    async fn h1_a_hung_kms_tenant_never_delays_another_tenants_first_lookup() {
        let v = Arc::new(vault());
        // The old lock count: these two tenants shared stripe `tenant % 64`.
        let stripes = 64u128;
        let a = TenantId::from_jwt_claim(Uuid::from_u128(0x4b4d_5301));
        let b = TenantId::from_jwt_claim(Uuid::from_u128(0x4b4d_5301 + stripes));
        let (va, ta) = (Arc::clone(&v), a.clone());
        let hung = tokio::spawn(async move {
            // Tenant A: a KMS write holds A's fence, and A's unwrap never returns.
            let _lock = va.lock(&ta).await.unwrap();
            let id = Uuid::new_v4();
            let _ = va.dek(&Hang, &ta, id, &bound_dek(&ta, id, &[1; 32])).await;
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let f = fake();
        let id = Uuid::new_v4();
        let other = tokio::time::timeout(Duration::from_millis(250), async {
            // Tenant B's first key lookup (the cold dispatch path takes no fence).
            v.dek(&f, &b, id, &bound_dek(&b, id, &[2; 32])).await
        })
        .await;
        // And B's own KMS write fence is B's alone.
        let fence = tokio::time::timeout(Duration::from_millis(250), v.lock(&b)).await;
        hung.abort();
        assert!(
            other.is_ok(),
            "tenant B's first key lookup waited on tenant A's hung KMS"
        );
        assert!(other.unwrap().is_ok());
        assert!(fence.is_ok_and(|l| l.is_ok()), "B's fence is not A's");
    }

    /// H1: the hung tenant's OWN callers wait at most `lock_wait_ms`, then fail closed
    /// (`kms_unavailable`) — for that tenant only.
    #[tokio::test(start_paused = true)]
    async fn h1_waits_on_a_hung_tenant_are_bounded_and_fail_closed_for_that_tenant() {
        let v = Arc::new(vault());
        let a = TenantId::from_jwt_claim(Uuid::new_v4());
        let id = Uuid::new_v4();
        let wrapped = bound_dek(&a, id, &[3; 32]);
        let (va, ta, w) = (Arc::clone(&v), a.clone(), wrapped.clone());
        let first = tokio::spawn(async move { va.dek(&Hang, &ta, id, &w).await });
        tokio::task::yield_now().await;
        let started = tokio::time::Instant::now();
        assert!(matches!(
            v.dek(&fake(), &a, id, &wrapped).await,
            Err(KmsError::Unavailable)
        ));
        let waited = started.elapsed();
        let bound = Duration::from_millis(limits().unwrap().lock_wait_ms);
        assert!(waited >= bound && waited < bound + Duration::from_millis(50));
        let _held = v.lock(&a).await.unwrap();
        assert!(matches!(v.lock(&a).await, Err(KmsError::Unavailable)));
        first.abort();
    }

    /// A customer KMS that never answers, counting the calls that reached it.
    struct CountingHang(AtomicUsize);
    impl KmsBackend for CountingHang {
        async fn wrap(&self, _: &TenantId, _: Uuid, _: &[u8]) -> Result<Vec<u8>, KmsError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            std::future::pending().await
        }
        async fn unwrap(
            &self,
            _: &TenantId,
            _: Uuid,
            _: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, KmsError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            std::future::pending().await
        }
    }

    /// H1 round 2 (security re-review, 2026-10-05): a KMS tenant with a hanging Vault
    /// and many concurrent cold lookups (many labels / DEKs) must not put unbounded calls
    /// in flight — each one used to pin a shared resource (a pooled Postgres connection)
    /// for its whole wait. At most `kms.max_calls_per_tenant` reach that tenant's KMS;
    /// the rest fail closed after `lock_wait_ms`; another tenant is unaffected.
    #[tokio::test(start_paused = true)]
    async fn h1r2_kms_calls_are_capped_per_tenant() {
        let v = Arc::new(vault());
        let hang = Arc::new(CountingHang(AtomicUsize::new(0)));
        let a = TenantId::from_jwt_claim(Uuid::new_v4());
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let (v, hang, a) = (Arc::clone(&v), Arc::clone(&hang), a.clone());
            tasks.push(tokio::spawn(async move {
                let id = Uuid::new_v4();
                v.dek(&*hang, &a, id, &bound_dek(&a, id, &[4; 32])).await
            }));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        let cap = limits().unwrap().max_calls_per_tenant;
        assert!(
            hang.0.load(Ordering::SeqCst) <= cap,
            "{} KMS calls in flight for one tenant",
            hang.0.load(Ordering::SeqCst)
        );
        let b = TenantId::from_jwt_claim(Uuid::new_v4());
        let id = Uuid::new_v4();
        assert!(
            v.dek(&fake(), &b, id, &bound_dek(&b, id, &[5; 32]))
                .await
                .is_ok()
        );
        for t in tasks {
            t.abort();
        }
    }

    /// A KMS whose unwrap waits until released.
    struct Gated(tokio::sync::Notify, AtomicUsize);
    impl KmsBackend for Gated {
        async fn wrap(&self, _: &TenantId, _: Uuid, b: &[u8]) -> Result<Vec<u8>, KmsError> {
            Ok(b.to_vec())
        }
        async fn unwrap(
            &self,
            _: &TenantId,
            _: Uuid,
            b: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, KmsError> {
            self.1.fetch_add(1, Ordering::SeqCst);
            self.0.notified().await;
            Ok(Zeroizing::new(b.to_vec()))
        }
    }

    /// MED round 2: an unwrap in flight when the tenant's KMS state is invalidated (a
    /// delete/rotate committed) must not re-cache the old DEK afterwards.
    #[tokio::test]
    async fn r2_an_unwrap_racing_an_invalidation_does_not_recache_the_old_dek() {
        let v = Arc::new(vault());
        let gate = Arc::new(Gated(tokio::sync::Notify::new(), AtomicUsize::new(0)));
        let t = TenantId::from_jwt_claim(Uuid::new_v4());
        let id = Uuid::new_v4();
        let wrapped = bound_dek(&t, id, &[6; 32]);
        let (v2, g2, t2, w2) = (
            Arc::clone(&v),
            Arc::clone(&gate),
            t.clone(),
            wrapped.clone(),
        );
        let flight = tokio::spawn(async move { v2.dek(&*g2, &t2, id, &w2).await });
        while gate.1.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        v.invalidate(&t);
        gate.0.notify_one();
        let _ = flight.await.unwrap();
        assert!(
            !v.cache.lock().contains_key(&(*t.as_uuid(), id)),
            "the DEK unwrapped under the invalidated state was cached"
        );
    }

    /// H1: locks are per key and released ones do not accumulate.
    #[tokio::test]
    async fn h1_keyed_locks_are_independent_and_released() {
        let locks: KeyedLocks<u32> = KeyedLocks::default();
        let wait = Duration::from_millis(10);
        let one = locks.acquire(1, wait).await.unwrap();
        assert!(
            locks.acquire(2, wait).await.is_some(),
            "another key is free"
        );
        assert!(locks.acquire(1, wait).await.is_none(), "the same key waits");
        drop(one);
        assert!(locks.acquire(1, wait).await.is_some());
        for k in 0..1_000 {
            drop(locks.acquire(k, wait).await);
        }
        assert_eq!(locks.live(), 0);
        assert!(locks.map.lock().0.len() < 1_000, "dead entries are swept");
    }

    #[test]
    fn provider_plaintext_never_outlives_its_dek() {
        let t = TenantId::from_jwt_claim(Uuid::new_v4());
        let secret = Arc::new(SecretString::from("unit-test-secret"));
        crate::db::provider_keys::cache_decrypted_until(
            &t,
            "openai",
            crate::db::provider_keys::DEFAULT_LABEL,
            Arc::clone(&secret),
            Some(Instant::now()),
        );
        assert!(matches!(
            crate::db::provider_keys::lookup_swr(&t, "openai"),
            crate::db::provider_keys::CachedLookup::Miss
        ));
        crate::db::provider_keys::cache_decrypted_until(
            &t,
            "openai",
            crate::db::provider_keys::DEFAULT_LABEL,
            secret,
            Some(Instant::now() + Duration::from_secs(60)),
        );
        assert!(matches!(
            crate::db::provider_keys::lookup_swr(&t, "openai"),
            crate::db::provider_keys::CachedLookup::Fresh(_)
        ));
        crate::db::provider_keys::invalidate_tenant(&t);
    }
}
