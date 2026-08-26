//! `tracelane.yaml` — the operator config file (GWY-39).
//!
//! Two customer-facing pages (`apps/docs/providers.mdx`,
//! `apps/docs/prompt-promotion.mdx`) told operators to configure a file the
//! gateway never opened. This module is the reader that makes the first of
//! those claims true: **model aliases** — mapping an arbitrary model name to a
//! `(provider, upstream model)` pair, so a name the built-in prefix table
//! cannot route (`providers/mod.rs::provider_id_for_model`, which fail-closes
//! with `400 unroutable_model`) becomes routable.
//!
//! It also reads the **failover** block: the cross-provider fallback chain and
//! the same-provider retry policy, which were compiled-in constants before
//! (`providers/failover.rs`).
//!
//! ## The file
//!
//! ```yaml
//! models:
//!   my-fast-model:
//!     provider: groq
//!     model: llama-3.3-70b-versatile
//!
//! failover:
//!   chain: anthropic, openai, google
//!   retries: 1
//!   backoff_ms: 100
//! ```
//!
//! Read from `$TRACELANE_CONFIG`, or `./tracelane.yaml` when that is unset.
//! Either block may be omitted, and either may come first.
//!
//! ## The `failover:` block, and why it refuses so much
//!
//! A chain entry is `provider` or `provider:model`. Bare providers take their
//! model from `failover::DEFAULT_CHAIN`, which covers three of the 169 routable
//! providers; every other provider must name its model.
//!
//! Every hop is proved dispatchable **at parse time**: the provider id must be
//! one an adapter serves, and the model must resolve back to that same provider
//! through `ProviderRegistry::provider_id_for_model` — the resolver the chat
//! handler itself calls to pick the adapter and the BYOK key. A hop that fails
//! either check would be skipped at dispatch without a word, which is a
//! failover the operator believes is configured and that never fires. So it is
//! a parse error naming the line instead.
//!
//! ## Fail directions
//!
//! - **No file at the default path ⇒ fail OPEN.** Zero aliases, zero behaviour
//!   change. Every existing deployment is byte-identical without the file.
//! - **`$TRACELANE_CONFIG` set but unreadable ⇒ fail CLOSED at startup.** The
//!   operator explicitly named a file; silently ignoring it would route traffic
//!   under a config they believe is live.
//! - **A file that parses only partially ⇒ fail CLOSED at startup.** A
//!   half-applied routing table is how a request reaches the wrong provider
//!   with the wrong tenant's credential (the class). There is no
//!   "skip the bad line" path.
//!
//! ## Why this parser and not `serde_yaml`
//!
//! The gateway has no YAML dependency, and this change could not add one. The
//! reader below is therefore a **strict subset**: block mappings, scalar
//! leaves, `#` comments, spaces-only indentation. Anything outside that subset
//! is a hard error naming the line — it never degrades to a guess. Replacing
//! it with a real YAML parser is a drop-in swap behind [`parse`]; the tests in
//! this file are the contract that swap must keep.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context as _, bail};

/// Env var naming an explicit config-file path. Unset ⇒ [`DEFAULT_PATH`].
pub const PATH_ENV: &str = "TRACELANE_CONFIG";

/// Config-file path used when [`PATH_ENV`] is unset. Absent ⇒ no aliases.
pub const DEFAULT_PATH: &str = "tracelane.yaml";

/// One `models:` entry — an operator-defined name and where it actually goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelAlias {
    /// Canonical provider id (the same token `provider_id_for_model` returns
    /// and `dispatch_to_provider` matches on). Validated at parse time.
    pub provider_id: String,
    /// The model string sent upstream. The caller's alias is what lands on the
    /// span and in the ledger; this is what the provider is asked for.
    pub upstream_model: String,
}

/// One hop of the `failover:` chain: which provider to try, and the model to
/// ask it for. Both validated at parse time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailoverHop {
    /// Canonical provider id, checked against the catalog.
    pub provider_id: String,
    /// The model to send upstream. Resolves back to `provider_id` through
    /// `ProviderRegistry::provider_id_for_model`.
    pub model: String,
}

/// The parsed `semantic_cache:` block (GWY-24). Absent ⇒ the cache is OFF, and
/// off is the only safe default: a cache that turns itself on serves a
/// remembered answer to somebody who never asked for one.
///
/// **Operator-level for now, deliberately.** The founder's brief asks for a
/// per-KEY toggle, and that needs a Neon migration plus a `PATCH /v1/keys/{id}`
/// that does not exist yet (`key_routes.rs` mounts only `POST /v1/keys`, and the
/// whole web api-keys tree has zero `PATCH`/`PUT` — there is no update path for a
/// minted key at all). Shipping the operator switch first gets the feature and
/// its measured latency into production without stranding either behind a
/// migration; per-key granularity is a refinement of WHO may enable it, not of
/// what it does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticCacheConfig {
    embedding_models: Vec<String>,
    embedding_dimensions: u32,
    /// Threshold in THOUSANDTHS (950 = 0.95). Integer on purpose: `FileConfig`
    /// derives `Eq`, and a float in a config struct invites equality
    /// comparisons that are wrong for reasons unrelated to the config.
    default_threshold_milli: u16,
    ttl_hours: u32,
    max_scan_entries: u32,
}

impl SemanticCacheConfig {
    /// Embedding models to try, in order. The first one the tenant holds a
    /// usable BYOK credential for wins — because half of today's BYOK tenants
    /// hold ONLY a native-adapter key (Anthropic has no embeddings API at all),
    /// so a single hardcoded model would silently exclude them.
    #[must_use]
    pub fn embedding_models(&self) -> &[String] {
        &self.embedding_models
    }

    /// Requested embedding width. Smaller is materially faster: measured on the
    /// live prod ClickHouse, a brute-force cosine scan over 10,000 rows costs
    /// 16 ms at 1536 dims and 8 ms at 512.
    #[must_use]
    pub fn embedding_dimensions(&self) -> u32 {
        self.embedding_dimensions
    }

    /// Cosine similarity a candidate must reach. Conservative by default: a
    /// wrong hit is worse than a miss, because a miss costs money and a wrong
    /// hit costs trust.
    #[must_use]
    pub fn default_threshold(&self) -> f32 {
        f32::from(self.default_threshold_milli) / 1000.0
    }

    #[must_use]
    pub fn ttl_hours(&self) -> u32 {
        self.ttl_hours
    }

    /// Rows one lookup may scan. The scan is LINEAR, so this cap IS the latency
    /// ceiling — it is not a memory guard.
    #[must_use]
    pub fn max_scan_entries(&self) -> u32 {
        self.max_scan_entries
    }
}

/// The parsed `failover:` block. Absent from the file ⇒ the built-ins in
/// [`crate::providers::failover`] apply and behaviour is unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailoverConfig {
    chain: Vec<FailoverHop>,
    retries: u32,
    backoff_ms: u64,
}

impl FailoverConfig {
    /// The ordered hops, primary-first. Never empty — an empty `chain:` is a
    /// parse error, not a config that disables failover.
    #[must_use]
    pub fn chain(&self) -> &[FailoverHop] {
        &self.chain
    }

    /// Same-provider attempts after the first. `0` disables the retry.
    #[must_use]
    pub fn retries(&self) -> u32 {
        self.retries
    }

    /// Pause between same-provider attempts, in milliseconds.
    #[must_use]
    pub fn backoff_ms(&self) -> u64 {
        self.backoff_ms
    }
}

/// The parsed `trace_content:` block (GWY-45). Absent ⇒ content capture is OFF
/// for every tenant, which is the pre-GWY-45 behaviour and the fail-CLOSED
/// default required by `.claude/rules/tenancy.md`.
///
/// **Tenants are stored as raw `Uuid`, never as `TenantId`, and that is
/// deliberate.** `TenantId`'s three constructors all attest to a SOURCE — a
/// validated JWT claim or a verified SPIFFE SVID (`crates/shared/src/tenant.rs`).
/// An operator config file is neither. Minting a `TenantId` here would put a
/// config-authored value into the type whose whole purpose is to prove the value
/// came from an authenticated caller, weakening CLAUDE.md §4 structurally for a
/// convenience. Compare against `TenantId::as_uuid()` instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContentConfig {
    tenants: std::collections::BTreeSet<uuid::Uuid>,
    max_field_bytes: usize,
}

impl TraceContentConfig {
    /// Whether this tenant's gateway-proxied spans capture message content.
    ///
    /// Takes `&TenantId` so the caller must already hold an attested id; the
    /// comparison is against its inner uuid.
    #[must_use]
    pub fn captures(&self, tenant_id: &tracelane_shared::TenantId) -> bool {
        self.tenants.contains(tenant_id.as_uuid())
    }

    /// Per-field byte ceiling. A 1 MB prompt must not become a 1 MB span:
    /// `otlp_emit::publish_span` has no payload check of its own, so an
    /// oversized span is dropped WHOLE by NATS — losing the trace, not just the
    /// text.
    #[must_use]
    pub const fn max_field_bytes(&self) -> usize {
        self.max_field_bytes
    }

    /// The allowlist, for the guard and for tests.
    #[must_use]
    pub fn tenants(&self) -> &std::collections::BTreeSet<uuid::Uuid> {
        &self.tenants
    }
}

/// The parsed contents of `tracelane.yaml`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FileConfig {
    models: BTreeMap<String, ModelAlias>,
    failover: Option<FailoverConfig>,
    semantic_cache: Option<SemanticCacheConfig>,
    trace_content: Option<TraceContentConfig>,
}

impl FileConfig {
    /// Look up an alias by the exact model string the caller sent.
    #[must_use]
    pub fn alias(&self, model: &str) -> Option<&ModelAlias> {
        self.models.get(model)
    }

    /// The `semantic_cache:` block, or `None` when the key is absent — which
    /// means the cache is OFF.
    #[must_use]
    pub fn semantic_cache(&self) -> Option<&SemanticCacheConfig> {
        self.semantic_cache.as_ref()
    }

    /// The `trace_content:` block, or `None` when absent — which means content
    /// capture is OFF for everyone.
    #[must_use]
    pub fn trace_content(&self) -> Option<&TraceContentConfig> {
        self.trace_content.as_ref()
    }

    /// Number of aliases defined.
    #[must_use]
    pub fn len(&self) -> usize {
        self.models.len()
    }

    /// True when the file defined no aliases at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
    }

    /// Every alias name, in sorted order. Used for the startup log line, which
    /// is the only external evidence the file was actually read.
    pub fn alias_names(&self) -> impl Iterator<Item = &str> {
        self.models.keys().map(String::as_str)
    }

    /// The `failover:` block, if the file carried one.
    #[must_use]
    pub fn failover(&self) -> Option<&FailoverConfig> {
        self.failover.as_ref()
    }
}

/// Process-global config. Written once, at startup, before the router is built.
static CONFIG: OnceLock<FileConfig> = OnceLock::new();

/// Resolve an alias from the installed config.
///
/// Returns `None` — the cost of one relaxed atomic load — when no config file
/// was installed, which is every deployment that does not ship a
/// `tracelane.yaml`. Called from the routing seam, so it is on the hot path.
#[must_use]
pub fn alias(model: &str) -> Option<&'static ModelAlias> {
    CONFIG.get()?.alias(model)
}

/// The installed `failover:` block, or `None` — which is both "no config file"
/// and "a config file with no `failover:` block", because the two mean the same
/// thing: the built-in chain and retry policy apply.
///
/// Reached from the cross-provider failover decision (opt-in per request, and
/// only after the primary provider errored) and from
/// The installed `semantic_cache:` block, or `None` when absent.
#[must_use]
pub fn semantic_cache() -> Option<&'static SemanticCacheConfig> {
    CONFIG.get().and_then(|c| c.semantic_cache.as_ref())
}

/// The installed `trace_content:` block, or `None` when absent — which means no
/// tenant captures message content. Fail-CLOSED by construction.
#[must_use]
pub fn trace_content() -> Option<&'static TraceContentConfig> {
    CONFIG.get().and_then(|c| c.trace_content.as_ref())
}
/// `failover::retry_policy`. One relaxed atomic load when it is reached.
#[must_use]
pub fn failover() -> Option<&'static FailoverConfig> {
    CONFIG.get()?.failover.as_ref()
}

/// Path the reader will use: `$TRACELANE_CONFIG` if set and non-empty,
/// otherwise `./tracelane.yaml`.
#[must_use]
pub fn resolved_path() -> PathBuf {
    match std::env::var(PATH_ENV) {
        Ok(p) if !p.trim().is_empty() => PathBuf::from(p),
        _ => PathBuf::from(DEFAULT_PATH),
    }
}

/// Read + install `tracelane.yaml`. Call once, at startup, before the router
/// is built — aliases must be live before the first request routes.
///
/// Returns the path that was read, or `None` when no config file exists.
///
/// # Errors
///
/// **Fails CLOSED** — the caller is expected to abort startup:
/// - `$TRACELANE_CONFIG` names a file that cannot be read. The operator asked
///   for that file by name; ignoring it would serve traffic under a routing
///   table they believe is live.
/// - The file exists but does not parse. A partially-applied model→provider
///   table can send a request to a provider the caller never named, with
///   another provider's credential.
///
/// It does **not** fail when the default `./tracelane.yaml` is simply absent —
/// that is the no-config deployment, and it fails OPEN to zero aliases.
pub fn install_from_env() -> anyhow::Result<Option<PathBuf>> {
    let explicit = matches!(std::env::var(PATH_ENV), Ok(ref p) if !p.trim().is_empty());
    let path = resolved_path();
    let Some(cfg) = read_at(&path, explicit)? else {
        return Ok(None);
    };
    install(cfg, &path);
    Ok(Some(path))
}

/// Read and parse the config at `path`.
///
/// `explicit` is true when the operator named the path themselves (via
/// [`PATH_ENV`]), which is what turns "file not found" from a normal
/// no-config deployment into a misconfiguration. Split out of
/// [`install_from_env`] so the read + fail-direction can be tested against a
/// real file without mutating process env.
///
/// # Errors
///
/// Fails CLOSED on an unreadable explicit path, on any read error other than
/// not-found, and on a file that does not parse.
fn read_at(path: &Path, explicit: bool) -> anyhow::Result<Option<FileConfig>> {
    let src = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound && !explicit => {
            tracing::debug!(
                path = %path.display(),
                "no tracelane.yaml — model aliases disabled (routing uses the built-in prefix table only)"
            );
            return Ok(None);
        }
        Err(err) => {
            return Err(anyhow::Error::new(err).context(format!(
                "{PATH_ENV} points at {} but it could not be read",
                path.display()
            )));
        }
    };
    parse(&src)
        .with_context(|| format!("{} is not valid", path.display()))
        .map(Some)
}

/// Install an already-parsed config. Separate from [`install_from_env`] so the
/// tests can install without touching the filesystem or process env.
fn install(cfg: FileConfig, path: &Path) {
    let names: Vec<&str> = cfg.alias_names().collect();
    let count = cfg.len();
    let summary = names.join(", ");
    // Rendered before the move into the write-once slot.
    let fo = cfg.failover().map(|f| {
        let hops: Vec<String> = f
            .chain()
            .iter()
            .map(|h| format!("{}:{}", h.provider_id, h.model))
            .collect();
        (hops.join(" -> "), f.retries(), f.backoff_ms())
    });
    if CONFIG.set(cfg).is_err() {
        tracing::warn!(
            path = %path.display(),
            "tracelane.yaml already installed — ignoring the second install"
        );
        return;
    }
    tracing::info!(
        path = %path.display(),
        model_aliases = count,
        aliases = %summary,
        failover_chain = fo.as_ref().map_or("<built-in>", |(c, _, _)| c.as_str()),
        failover_retries = fo.as_ref().map_or(crate::providers::failover::DEFAULT_RETRIES, |(_, r, _)| *r),
        failover_backoff_ms = fo.as_ref().map_or(crate::providers::failover::DEFAULT_BACKOFF_MS, |(_, _, b)| *b),
        "tracelane.yaml loaded"
    );
    // THIS WARN IS GONE, AND ITS REMOVAL IS THE POINT.
    //
    // It used to fire whenever an operator configured anything other than the
    // built-in policy, saying `retries/backoff_ms` were "validated but NOT
    // applied yet". That was true when it was written and FALSE from the moment
    // GWY-44 pointed `server.rs::dispatch_with_retry` at
    // `failover::retry_policy()` — which reads this config. The warning outlived
    // the gap it described.
    //
    // It was caught by checking whether the failover chain was really in force
    // before trusting it, and it would have fired on the first prod deploy that
    // shipped a `tracelane.yaml`: this repo's own config sets `retries: 2,
    // backoff_ms: 50` against a built-in of 1/100, so the condition was true.
    //
    // **A false reassurance and a false alarm fail the same way** — both teach an
    // operator to distrust the log. The honest signal is the `tracelane.yaml
    // loaded` line above, which already reports `failover_retries` and
    // `failover_backoff_ms` as the values actually in force.
}

/// Test-only installer: put a parsed config into the process-global slot
/// without touching the filesystem or process env.
///
/// Returns `false` if a config was already installed (the slot is
/// write-once). Tests that depend on an alias must therefore use alias names
/// no other test uses, and must assert on the return value.
#[cfg(test)]
pub fn install_for_test(cfg: FileConfig) -> bool {
    CONFIG.set(cfg).is_ok()
}

// The prod-config parse test lives in the canonical repo only: its subject,
// infra/prod/tracelane.yaml, is deliberately not published. Removed at export
// time because include_str! resolves at compile time, so leaving it would
// break `cargo test` for everyone who clones this repo.

pub fn parse(src: &str) -> anyhow::Result<FileConfig> {
    let mut models: BTreeMap<String, ModelAlias> = BTreeMap::new();
    let mut section = Section::None;
    let mut seen_models = false;
    let mut seen_failover = false;
    let mut seen_semantic_cache = false;
    let mut seen_trace_content = false;
    // Indent at which alias names sit. Fixed by the first alias line, so an
    // inconsistently-indented sibling is an error rather than a silent skip.
    let mut alias_indent: Option<usize> = None;
    let mut pending: Option<PendingAlias> = None;
    // Indent at which `failover:` keys sit, fixed the same way. Raw values are
    // carried with their line number because the whole block is validated after
    // the file is read — which is what lets `failover:` sit before or after
    // `models:` — and a refusal still has to name the line that caused it.
    let mut failover_indent: Option<usize> = None;
    let mut semantic_cache_indent: Option<usize> = None;
    let mut trace_content_indent: Option<usize> = None;
    let mut tc_tenants: Option<(String, usize)> = None;
    let mut tc_max_bytes: Option<(String, usize)> = None;
    let mut sc_models: Option<(String, usize)> = None;
    let mut sc_dims: Option<(String, usize)> = None;
    let mut sc_threshold: Option<(String, usize)> = None;
    let mut sc_ttl: Option<(String, usize)> = None;
    let mut sc_scan: Option<(String, usize)> = None;
    let mut fo_chain: Option<(String, usize)> = None;
    let mut fo_retries: Option<(String, usize)> = None;
    let mut fo_backoff: Option<(String, usize)> = None;

    for (idx, raw) in src.lines().enumerate() {
        let lineno = idx + 1;
        let line = raw.trim_end();
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indent = leading_indent(line, lineno)?;
        let content = &line[indent..];

        if indent == 0 {
            flush(&mut pending, &mut models)?;
            match content {
                "models:" => {
                    if seen_models {
                        bail!("line {lineno}: duplicate `models:` block");
                    }
                    seen_models = true;
                    section = Section::Models;
                }
                "failover:" => {
                    if seen_failover {
                        bail!("line {lineno}: duplicate `failover:` block");
                    }
                    seen_failover = true;
                    section = Section::Failover;
                }
                "semantic_cache:" => {
                    if seen_semantic_cache {
                        bail!("line {lineno}: duplicate `semantic_cache:` block");
                    }
                    seen_semantic_cache = true;
                    section = Section::SemanticCache;
                }
                "trace_content:" => {
                    if seen_trace_content {
                        bail!("line {lineno}: duplicate `trace_content:` block");
                    }
                    seen_trace_content = true;
                    section = Section::TraceContent;
                }
                other => bail!(
                    "line {lineno}: unsupported top-level key `{other}` — this reader \
                     understands only `models:`, `failover:`, `semantic_cache:` and \
                     `trace_content:`"
                ),
            }
            continue;
        }

        match section {
            Section::None => bail!("line {lineno}: indented line before any top-level key"),
            Section::Failover => {
                let failover_at = *failover_indent.get_or_insert(indent);
                if indent != failover_at {
                    bail!(
                        "line {lineno}: inconsistent indentation — `failover:` keys are \
                         indented {failover_at} spaces, this line is indented {indent}"
                    );
                }
                let (key, value) = content.split_once(':').ok_or_else(|| {
                    anyhow::anyhow!(
                        "line {lineno}: expected `key: value` under `failover:`, found `{content}`"
                    )
                })?;
                let value = scalar(value, lineno)?;
                if value.is_empty() {
                    bail!("line {lineno}: `{}` has an empty value", key.trim());
                }
                match key.trim() {
                    "chain" => set_once(&mut fo_chain, "chain", value, lineno)?,
                    "retries" => set_once(&mut fo_retries, "retries", value, lineno)?,
                    "backoff_ms" => set_once(&mut fo_backoff, "backoff_ms", value, lineno)?,
                    other => bail!(
                        "line {lineno}: unsupported key `{other}` under `failover:` — only \
                         `chain`, `retries` and `backoff_ms` are read"
                    ),
                }
                continue;
            }
            Section::SemanticCache => {
                let sc_at = *semantic_cache_indent.get_or_insert(indent);
                if indent != sc_at {
                    bail!(
                        "line {lineno}: inconsistent indentation — `semantic_cache:` keys \
                         are indented {sc_at} spaces, this line is indented {indent}"
                    );
                }
                let (key, value) = content.split_once(':').ok_or_else(|| {
                    anyhow::anyhow!(
                        "line {lineno}: expected `key: value` under `semantic_cache:`, \
                         found `{content}`"
                    )
                })?;
                let value = scalar(value, lineno)?;
                if value.is_empty() {
                    bail!("line {lineno}: `{}` has an empty value", key.trim());
                }
                match key.trim() {
                    "embedding_models" => {
                        set_once(&mut sc_models, "embedding_models", value, lineno)?;
                    }
                    "embedding_dimensions" => {
                        set_once(&mut sc_dims, "embedding_dimensions", value, lineno)?;
                    }
                    "default_threshold" => {
                        set_once(&mut sc_threshold, "default_threshold", value, lineno)?;
                    }
                    "ttl_hours" => set_once(&mut sc_ttl, "ttl_hours", value, lineno)?,
                    "max_scan_entries" => {
                        set_once(&mut sc_scan, "max_scan_entries", value, lineno)?;
                    }
                    other => bail!(
                        "line {lineno}: unsupported key `{other}` under `semantic_cache:` \
                         — only `embedding_models`, `embedding_dimensions`, \
                         `default_threshold`, `ttl_hours` and `max_scan_entries` are read"
                    ),
                }
                continue;
            }
            Section::TraceContent => {
                let tc_at = *trace_content_indent.get_or_insert(indent);
                if indent != tc_at {
                    bail!(
                        "line {lineno}: inconsistent indentation — `trace_content:` keys \
                         are indented {tc_at} spaces, this line is indented {indent}"
                    );
                }
                let (key, value) = content.split_once(':').ok_or_else(|| {
                    anyhow::anyhow!(
                        "line {lineno}: expected `key: value` under `trace_content:`, \
                         found `{content}`"
                    )
                })?;
                let value = scalar(value, lineno)?;
                if value.is_empty() {
                    bail!("line {lineno}: `{}` has an empty value", key.trim());
                }
                match key.trim() {
                    "tenants" => set_once(&mut tc_tenants, "tenants", value, lineno)?,
                    "max_field_bytes" => {
                        set_once(&mut tc_max_bytes, "max_field_bytes", value, lineno)?;
                    }
                    other => bail!(
                        "line {lineno}: unsupported key `{other}` under `trace_content:` \
                         — only `tenants` and `max_field_bytes` are read"
                    ),
                }
                continue;
            }
            Section::Models => {}
        }

        let alias_at = *alias_indent.get_or_insert(indent);
        if indent == alias_at {
            flush(&mut pending, &mut models)?;
            let name = content.strip_suffix(':').ok_or_else(|| {
                anyhow::anyhow!(
                    "line {lineno}: expected `<model-name>:` under `models:`, found `{content}`"
                )
            })?;
            let name = unquote(name.trim());
            if name.is_empty() {
                bail!("line {lineno}: empty model-alias name");
            }
            if models.contains_key(name) {
                bail!("line {lineno}: duplicate model alias `{name}`");
            }
            pending = Some(PendingAlias {
                name: name.to_owned(),
                lineno,
                provider: None,
                model: None,
            });
            continue;
        }

        if indent < alias_at {
            bail!(
                "line {lineno}: inconsistent indentation — model aliases are indented \
                 {alias_at} spaces, this line is indented {indent}"
            );
        }

        let Some(entry) = pending.as_mut() else {
            bail!("line {lineno}: `{content}` is not inside a model alias");
        };
        let (key, value) = content.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("line {lineno}: expected `key: value`, found `{content}`")
        })?;
        let value = scalar(value, lineno)?;
        if value.is_empty() {
            bail!("line {lineno}: `{}` has an empty value", key.trim());
        }
        match key.trim() {
            "provider" => entry.provider = Some((value.to_owned(), lineno)),
            "model" => entry.model = Some(value.to_owned()),
            other => bail!(
                "line {lineno}: unsupported key `{other}` under model alias \
                 `{}` — only `provider` and `model` are read",
                entry.name
            ),
        }
    }

    flush(&mut pending, &mut models)?;
    let failover = if seen_failover {
        Some(build_failover(fo_chain, fo_retries, fo_backoff)?)
    } else {
        None
    };
    let trace_content = if seen_trace_content {
        Some(build_trace_content(tc_tenants, tc_max_bytes)?)
    } else {
        None
    };
    let semantic_cache = if seen_semantic_cache {
        Some(build_semantic_cache(
            sc_models,
            sc_dims,
            sc_threshold,
            sc_ttl,
            sc_scan,
        )?)
    } else {
        None
    };

    Ok(FileConfig {
        models,
        failover,
        semantic_cache,
        trace_content,
    })
}

/// Which top-level block the reader is currently inside.
#[derive(Clone, Copy)]
enum Section {
    /// Before any top-level key — an indented line here is an error.
    None,
    Models,
    Failover,
    SemanticCache,
    TraceContent,
}

/// Record a `failover:` scalar, refusing a second one.
///
/// # Errors
///
/// Fails CLOSED on a repeated key. Last-write-wins would install a chain the
/// operator could only discover was not theirs by reading the startup log.
fn set_once(
    slot: &mut Option<(String, usize)>,
    key: &str,
    value: &str,
    lineno: usize,
) -> anyhow::Result<()> {
    if slot.is_some() {
        bail!("line {lineno}: duplicate `{key}:` under `failover:`");
    }
    *slot = Some((value.to_owned(), lineno));
    Ok(())
}

/// Turn the raw `failover:` scalars into a validated [`FailoverConfig`].
///
/// Runs after the whole file is read, so the block may sit before or after
/// `models:`. Each argument carries the line it came from: a refusal that does
/// not name a line makes the operator re-read the file to find it.
///
/// Omitted keys take the built-ins from [`crate::providers::failover`], so a
/// block that sets only `retries:` keeps the built-in chain.
///
/// # Errors
///
/// **Fails CLOSED**, naming the line, on: a non-numeric or negative `retries:`
/// / `backoff_ms:`; a `retries:` above `failover::MAX_RETRIES`; a `backoff_ms:`
/// at or beyond the `failover::FAILOVER_BUDGET_MS` total budget; a
/// retries×backoff plan that spends the whole budget sleeping; and every
/// chain defect [`parse_chain`] refuses.
fn build_failover(
    chain: Option<(String, usize)>,
    retries: Option<(String, usize)>,
    backoff: Option<(String, usize)>,
) -> anyhow::Result<FailoverConfig> {
    use crate::providers::failover;

    let retries_line = retries.as_ref().map(|(_, line)| *line);
    let backoff_line = backoff.as_ref().map(|(_, line)| *line);

    let retries = match retries {
        Some((raw, lineno)) => {
            // A negative count fails HERE: `u32::from_str` rejects the sign, so
            // `retries: -1` is a parse error rather than a silent wrap.
            let n: u32 = raw.parse().map_err(|_| {
                anyhow::anyhow!(
                    "line {lineno}: `retries: {raw}` is not a whole number 0..={}",
                    failover::MAX_RETRIES
                )
            })?;
            if n > failover::MAX_RETRIES {
                bail!(
                    "line {lineno}: `retries: {n}` exceeds the maximum of {} — every attempt is \
                     a real upstream round trip inside the same {}ms budget",
                    failover::MAX_RETRIES,
                    failover::FAILOVER_BUDGET_MS
                );
            }
            n
        }
        None => failover::DEFAULT_RETRIES,
    };

    let backoff_ms = match backoff {
        Some((raw, lineno)) => {
            let ms: u64 = raw.parse().map_err(|_| {
                anyhow::anyhow!(
                    "line {lineno}: `backoff_ms: {raw}` is not a whole number of milliseconds"
                )
            })?;
            if ms >= failover::FAILOVER_BUDGET_MS {
                bail!(
                    "line {lineno}: `backoff_ms: {ms}` is not less than the {}ms total failover \
                     budget — the retry could never fire",
                    failover::FAILOVER_BUDGET_MS
                );
            }
            ms
        }
        None => failover::DEFAULT_BACKOFF_MS,
    };

    // Only checked when the operator wrote at least one of the two keys: the
    // built-in pair is proved to fit by a `const _: () = assert!(…)` in
    // `providers/failover.rs`, so with neither key present there is nothing to
    // check and no line to blame.
    if let Some(lineno) = backoff_line.or(retries_line) {
        let policy = failover::RetryPolicy {
            retries,
            backoff_ms,
        };
        if policy.planned_backoff_ms() >= failover::FAILOVER_BUDGET_MS {
            bail!(
                "line {lineno}: `retries: {retries}` x `backoff_ms: {backoff_ms}` spends {}ms of \
                 the {}ms failover budget sleeping alone — the later attempts could never run",
                policy.planned_backoff_ms(),
                failover::FAILOVER_BUDGET_MS
            );
        }
    }

    let chain = match chain {
        Some((raw, lineno)) => parse_chain(&raw, lineno)?,
        None => failover::DEFAULT_CHAIN
            .iter()
            .map(|(provider_id, model)| FailoverHop {
                provider_id: (*provider_id).to_owned(),
                model: (*model).to_owned(),
            })
            .collect(),
    };

    Ok(FailoverConfig {
        chain,
        retries,
        backoff_ms,
    })
}

/// Build [`SemanticCacheConfig`] from the parsed scalars, applying defaults.
///
/// # Errors
///
/// **Fails CLOSED**, naming the line, on every out-of-range value. A cache is a
/// performance feature, but a MIS-configured one serves wrong answers, so a
/// nonsense threshold is a boot refusal rather than a clamp — clamping would
/// leave the operator believing a number that is not in force.
/// Build the `trace_content:` block, refusing anything ambiguous.
///
/// **Every failure here is a BOOT REFUSAL**, which is the correct direction for a
/// setting that decides whether customer prompt text is persisted. A typo'd uuid
/// that silently dropped a tenant from the allowlist would fail OPEN in the
/// dangerous direction on the day someone *removed* a tenant expecting it to take
/// effect — and a typo that silently ADDED one is worse still.
fn build_trace_content(
    tenants: Option<(String, usize)>,
    max_field_bytes: Option<(String, usize)>,
) -> anyhow::Result<TraceContentConfig> {
    // `tenants` has NO default. An empty allowlist and an absent block mean the
    // same thing (capture off), so a `trace_content:` block with no `tenants:`
    // key is far more likely to be a mistake than an intent — refuse it and make
    // the operator say which they meant.
    let (raw, lineno) = tenants.ok_or_else(|| {
        anyhow::anyhow!(
            "`trace_content:` is present but has no `tenants:` key — omit the whole \
             block to disable content capture, or name the tenant uuid(s) explicitly"
        )
    })?;

    let mut set = std::collections::BTreeSet::new();
    for part in raw.split(',') {
        let t = part.trim();
        if t.is_empty() {
            bail!(
                "line {lineno}: `tenants` has an empty entry — check for a trailing or \
                 doubled comma"
            );
        }
        let id = uuid::Uuid::parse_str(t)
            .with_context(|| format!("line {lineno}: `tenants` entry `{t}` is not a valid uuid"))?;
        if !set.insert(id) {
            bail!("line {lineno}: `tenants` lists `{t}` more than once");
        }
    }

    let max_field_bytes = match max_field_bytes {
        None => 65_536,
        Some((v, ln)) => {
            let n: usize = v.parse().with_context(|| {
                format!("line {ln}: `max_field_bytes` must be a positive integer, got `{v}`")
            })?;
            // Lower bound: below ~1 KiB every realistic prompt is truncated to
            // nothing and the feature silently produces unusable eval cases.
            // Upper bound: `otlp_emit::publish_span` has no payload check, so an
            // oversized span is dropped WHOLE by NATS — losing the trace, not
            // just the text. 1 MiB is well under the default NATS max_payload.
            if !(1_024..=1_048_576).contains(&n) {
                bail!(
                    "line {ln}: `max_field_bytes` must be between 1024 and 1048576, got {n} \
                     — below 1 KiB truncates every prompt to nothing; above 1 MiB risks the \
                     span exceeding the NATS payload limit and being dropped whole"
                );
            }
            n
        }
    };

    Ok(TraceContentConfig {
        tenants: set,
        max_field_bytes,
    })
}

fn build_semantic_cache(
    models: Option<(String, usize)>,
    dims: Option<(String, usize)>,
    threshold: Option<(String, usize)>,
    ttl: Option<(String, usize)>,
    scan: Option<(String, usize)>,
) -> anyhow::Result<SemanticCacheConfig> {
    let embedding_models: Vec<String> = match models {
        Some((raw, lineno)) => {
            let list: Vec<String> = raw
                .split(',')
                .map(|m| m.trim().to_owned())
                .filter(|m| !m.is_empty())
                .collect();
            if list.is_empty() {
                bail!(
                    "line {lineno}: `embedding_models` is empty — omit the key to leave the cache off, do not configure it with nothing to embed with"
                );
            }
            // A model that routes nowhere would fail at dispatch on the first
            // miss, which is a runtime surprise on the hot path. Catch it here.
            for m in &list {
                if crate::providers::ProviderRegistry::provider_id_for_model(m).is_none() {
                    bail!(
                        "line {lineno}: `embedding_models` names `{m}`, which no provider serves"
                    );
                }
            }
            list
        }
        None => bail!(
            "`semantic_cache:` needs `embedding_models` — there is no sane default, because which model you embed with depends on which provider credential your tenants hold"
        ),
    };

    let embedding_dimensions = match dims {
        Some((raw, lineno)) => {
            let v: u32 = raw.parse().map_err(|_| {
                anyhow::anyhow!("line {lineno}: `embedding_dimensions` must be a positive integer, found `{raw}`")
            })?;
            if !(64..=4096).contains(&v) {
                bail!("line {lineno}: `embedding_dimensions` must be 64-4096, found {v}");
            }
            v
        }
        // 512 rather than the model default: measured on the live prod
        // ClickHouse, a 10,000-row cosine scan costs 8 ms at 512 dims and 16 ms
        // at 1536, and the recall difference over a 0.95 threshold does not pay
        // for the other 8 ms.
        None => 512,
    };

    let default_threshold_milli: u16 = match threshold {
        Some((raw, lineno)) => {
            let v: f64 = raw.parse().map_err(|_| {
                anyhow::anyhow!(
                    "line {lineno}: `default_threshold` must be a number, found `{raw}`"
                )
            })?;
            if !(0.80..=1.0).contains(&v) {
                bail!(
                    "line {lineno}: `default_threshold` must be 0.80-1.00, found {v} — below 0.80 a cache serves answers to questions nobody asked"
                );
            }
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let milli = (v * 1000.0).round() as u16;
            milli
        }
        None => 950,
    };

    let ttl_hours = match ttl {
        Some((raw, lineno)) => {
            let v: u32 = raw.parse().map_err(|_| {
                anyhow::anyhow!(
                    "line {lineno}: `ttl_hours` must be a positive integer, found `{raw}`"
                )
            })?;
            if !(1..=24 * 90).contains(&v) {
                bail!("line {lineno}: `ttl_hours` must be 1-2160, found {v}");
            }
            v
        }
        None => 168,
    };

    let max_scan_entries = match scan {
        Some((raw, lineno)) => {
            let v: u32 = raw.parse().map_err(|_| {
                anyhow::anyhow!(
                    "line {lineno}: `max_scan_entries` must be a positive integer, found `{raw}`"
                )
            })?;
            if !(100..=200_000).contains(&v) {
                bail!("line {lineno}: `max_scan_entries` must be 100-200000, found {v}");
            }
            v
        }
        None => 10_000,
    };

    Ok(SemanticCacheConfig {
        embedding_models,
        embedding_dimensions,
        default_threshold_milli,
        ttl_hours,
        max_scan_entries,
    })
}

/// Split and validate a `chain:` value into ordered hops.
///
/// Entries are comma-separated `provider` or `provider:model`. A bare provider
/// takes its model from `failover::failover_model_for`, which knows three of
/// them; every other provider must spell its model out.
///
/// # Errors
///
/// **Fails CLOSED**, naming the line, on: more entries than the provider
/// catalog holds; an empty entry; a provider id no adapter serves; a repeated
/// provider; a bare provider with no built-in model; a model that resolves to a
/// *different* provider; and a model no prefix can route. Nothing here is a
/// warning and nothing is skipped — a chain that drops one entry is a failover
/// the operator believes is configured and that never fires.
fn parse_chain(raw: &str, lineno: usize) -> anyhow::Result<Vec<FailoverHop>> {
    use crate::providers::failover;

    let entries: Vec<&str> = raw.split(',').map(str::trim).collect();
    // A bound, not an exact provider count: the six native adapters are not
    // catalog rows. A chain longer than the whole catalog is a paste accident,
    // and the per-entry duplicate check below is what actually pins the length.
    let catalog_len = crate::providers::catalog::providers().len();
    if entries.len() > catalog_len {
        bail!(
            "line {lineno}: failover chain has {} entries — more than the {catalog_len} providers \
             in the catalog, so it cannot be a routing plan",
            entries.len()
        );
    }

    let mut hops: Vec<FailoverHop> = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.is_empty() {
            bail!(
                "line {lineno}: empty entry in the failover chain — check for a doubled or \
                 trailing comma"
            );
        }
        // Only the FIRST colon splits, so a model may contain one
        // (`bedrock:bedrock/anthropic.claude-3-5-sonnet-20240620-v1:0`).
        let (provider_id, model) = match entry.split_once(':') {
            Some((provider_id, model)) => (provider_id.trim(), model.trim()),
            None => (entry, ""),
        };
        if provider_id.is_empty() {
            bail!("line {lineno}: failover chain entry `{entry}` has no provider id");
        }
        if !is_known_provider_id(provider_id) {
            bail!(
                "line {lineno}: failover chain names provider `{provider_id}`, which no adapter \
                 serves"
            );
        }
        if hops.iter().any(|hop| hop.provider_id == provider_id) {
            bail!("line {lineno}: failover chain lists provider `{provider_id}` twice");
        }
        let model = if model.is_empty() {
            failover::failover_model_for(provider_id).ok_or_else(|| {
                anyhow::anyhow!(
                    "line {lineno}: failover chain names provider `{provider_id}`, which has no \
                     built-in failover model — write the hop as `{provider_id}:<model>`"
                )
            })?
        } else {
            model
        };
        // A hop is dispatchable only if its model routes BACK to its own
        // provider: the chat handler re-resolves the model to choose the adapter
        // AND the BYOK key, so a mismatch would send this tenant's credential for
        // one provider to another (the shape), and an unroutable
        // model would be skipped without a word.
        match crate::providers::ProviderRegistry::provider_id_for_model(model) {
            Some(actual) if actual == provider_id => {}
            Some(actual) => bail!(
                "line {lineno}: failover model `{model}` routes to `{actual}`, not \
                 `{provider_id}` — that hop would dispatch to the wrong provider"
            ),
            None => bail!(
                "line {lineno}: failover model `{model}` is unroutable — no provider prefix \
                 matches it, so the hop would be skipped in silence"
            ),
        }
        hops.push(FailoverHop {
            provider_id: provider_id.to_owned(),
            model: model.to_owned(),
        });
    }
    Ok(hops)
}

/// An alias being accumulated across its indented lines.
struct PendingAlias {
    name: String,
    /// Line the alias name appeared on — the one to blame for a missing field.
    lineno: usize,
    /// `(provider id, line)` — the line is needed to blame an unknown provider.
    provider: Option<(String, usize)>,
    model: Option<String>,
}

/// Validate and commit the alias under construction.
///
/// # Errors
///
/// Fails CLOSED when the alias is missing `provider` or `model`, or names a
/// provider no adapter serves.
fn flush(
    pending: &mut Option<PendingAlias>,
    models: &mut BTreeMap<String, ModelAlias>,
) -> anyhow::Result<()> {
    let Some(entry) = pending.take() else {
        return Ok(());
    };
    let (provider_id, provider_line) = entry.provider.ok_or_else(|| {
        anyhow::anyhow!(
            "line {}: model alias `{}` has no `provider:`",
            entry.lineno,
            entry.name
        )
    })?;
    let upstream_model = entry.model.ok_or_else(|| {
        anyhow::anyhow!(
            "line {}: model alias `{}` has no `model:`",
            entry.lineno,
            entry.name
        )
    })?;
    if !is_known_provider_id(&provider_id) {
        bail!(
            "line {provider_line}: model alias `{}` names provider `{provider_id}`, \
             which no adapter serves",
            entry.name
        );
    }
    models.insert(
        entry.name,
        ModelAlias {
            provider_id,
            upstream_model,
        },
    );
    Ok(())
}

/// Is this a provider id the gateway can actually dispatch to?
///
/// Derived from [`crate::providers::ProviderRegistry::env_var_for_provider_id`]
/// rather than a fresh list, so adding a provider does not create a fifth
/// hand-maintained table to drift (`crates/gateway/CLAUDE.md`: routing,
/// env-var, dispatch and BYOK-upload lists already move in lockstep). That
/// function returns `""` for both "unknown" and "needs no credential", and
/// Ollama is the only member of the second class.
fn is_known_provider_id(id: &str) -> bool {
    id == "ollama" || !crate::providers::ProviderRegistry::env_var_for_provider_id(id).is_empty()
}

/// Leading-space count.
///
/// # Errors
///
/// Fails CLOSED on a tab in the indentation. YAML forbids tabs for indentation,
/// and a reader that guessed a tab width would apply a routing table the
/// operator did not write.
fn leading_indent(line: &str, lineno: usize) -> anyhow::Result<usize> {
    let indent = line.len() - line.trim_start_matches(' ').len();
    if line[..indent].contains('\t') || line[indent..].starts_with('\t') {
        bail!("line {lineno}: tabs are not valid YAML indentation — use spaces");
    }
    Ok(indent)
}

/// Read one scalar value: an optionally-quoted string, plus an optional
/// trailing `# comment`.
///
/// # Errors
///
/// Fails CLOSED on an unterminated quote, or on text after the closing quote
/// that is not a comment. Both mean the operator wrote something this reader
/// does not understand, and guessing at it would apply a routing rule they did
/// not write.
fn scalar(value: &str, lineno: usize) -> anyhow::Result<&str> {
    let v = value.trim();
    if let Some(quote) = v.chars().next().filter(|c| *c == '"' || *c == '\'') {
        let end = v[1..]
            .find(quote)
            .map(|i| i + 1)
            .ok_or_else(|| anyhow::anyhow!("line {lineno}: unterminated quoted value `{v}`"))?;
        let rest = v[end + 1..].trim();
        if !rest.is_empty() && !rest.starts_with('#') {
            bail!("line {lineno}: unexpected text after a quoted value: `{rest}`");
        }
        return Ok(&v[1..end]);
    }
    Ok(strip_inline_comment(v))
}

/// Strip a trailing ` # comment` from an UNQUOTED scalar, and only when the `#`
/// is preceded by whitespace — `model: a#b` is the literal `a#b`, exactly as
/// YAML reads it.
fn strip_inline_comment(value: &str) -> &str {
    match value.find(" #") {
        Some(i) => value[..i].trim_end(),
        None => value,
    }
}

/// Remove one matching pair of surrounding quotes.
fn unquote(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        if (first == b'"' || first == b'\'') && bytes[bytes.len() - 1] == first {
            return &value[1..value.len() - 1];
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact block `apps/docs/providers.mdx` tells operators to write.
    const DOCUMENTED: &str = "\
# Tracelane gateway config.
models:
  my-fast-model:
    provider: groq
    model: llama-3.3-70b-versatile

  my-embedder:
    provider: openai
    model: text-embedding-3-small
";

    #[test]
    fn parses_the_documented_shape() {
        let cfg = parse(DOCUMENTED).expect("documented shape must parse");
        assert_eq!(cfg.len(), 2);
        assert_eq!(
            cfg.alias("my-fast-model"),
            Some(&ModelAlias {
                provider_id: "groq".into(),
                upstream_model: "llama-3.3-70b-versatile".into(),
            })
        );
        assert_eq!(
            cfg.alias("my-embedder"),
            Some(&ModelAlias {
                provider_id: "openai".into(),
                upstream_model: "text-embedding-3-small".into(),
            })
        );
        assert_eq!(cfg.alias("not-defined"), None);
    }

    #[test]
    fn quoted_and_commented_scalars_read_as_written() {
        let cfg = parse(
            "models:\n  a:\n    provider: \"openrouter\"  # host\n    model: 'meta/llama#3'\n",
        )
        .expect("quoted scalars parse");
        let a = cfg.alias("a").expect("alias a");
        assert_eq!(a.provider_id, "openrouter");
        // A `#` with no leading space is part of the value, not a comment.
        assert_eq!(a.upstream_model, "meta/llama#3");
    }

    // ── Negative cases. Every one of these must REFUSE, not half-apply. ──

    #[test]
    fn rejects_an_unterminated_quote() {
        let err = parse("models:\n  a:\n    provider: \"openai\n    model: gpt-5\n")
            .expect_err("an unterminated quote must be refused");
        assert!(
            err.to_string().contains("unterminated quoted value"),
            "{err}"
        );
    }

    #[test]
    fn rejects_junk_after_a_quoted_value() {
        let err = parse("models:\n  a:\n    provider: \"openai\" groq\n    model: gpt-5\n")
            .expect_err("trailing text after a quoted value must be refused");
        assert!(
            err.to_string()
                .contains("unexpected text after a quoted value"),
            "{err}"
        );
    }

    #[test]
    fn rejects_unknown_provider() {
        let err = parse("models:\n  a:\n    provider: notaprovider\n    model: x\n")
            .expect_err("unknown provider must be refused");
        let msg = err.to_string();
        assert!(msg.contains("notaprovider"), "{msg}");
        assert!(msg.contains("no adapter serves"), "{msg}");
    }

    #[test]
    fn rejects_alias_missing_model() {
        let err = parse("models:\n  a:\n    provider: openai\n")
            .expect_err("alias without `model:` must be refused");
        assert!(err.to_string().contains("has no `model:`"), "{err}");
    }

    #[test]
    fn rejects_alias_missing_provider() {
        let err = parse("models:\n  a:\n    model: gpt-5\n")
            .expect_err("alias without `provider:` must be refused");
        assert!(err.to_string().contains("has no `provider:`"), "{err}");
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        let err = parse("prompts:\n  a:\n    suite: evals/\n")
            .expect_err("an unread top-level key must be refused, not ignored");
        assert!(
            err.to_string().contains("unsupported top-level key"),
            "{err}"
        );
    }

    #[test]
    fn rejects_unknown_key_under_alias() {
        let err = parse("models:\n  a:\n    provider: openai\n    model: gpt-5\n    weight: 3\n")
            .expect_err("an unread alias key must be refused");
        assert!(
            err.to_string().contains("unsupported key `weight`"),
            "{err}"
        );
    }

    #[test]
    fn rejects_tab_indentation() {
        let err = parse("models:\n\ta:\n\t\tprovider: openai\n\t\tmodel: gpt-5\n")
            .expect_err("tabs must be refused");
        assert!(err.to_string().contains("tabs are not valid"), "{err}");
    }

    #[test]
    fn rejects_duplicate_alias() {
        let err = parse(
            "models:\n  a:\n    provider: openai\n    model: gpt-5\n  a:\n    provider: groq\n    model: llama-3.3\n",
        )
        .expect_err("a duplicate alias must be refused — last-write-wins silently reroutes");
        assert!(err.to_string().contains("duplicate model alias"), "{err}");
    }

    #[test]
    fn rejects_empty_value() {
        let err = parse("models:\n  a:\n    provider:\n    model: gpt-5\n")
            .expect_err("an empty provider must be refused");
        assert!(err.to_string().contains("empty value"), "{err}");
    }

    #[test]
    fn rejects_orphan_key_outside_an_alias() {
        let err = parse("models:\n  provider: openai\n  a:\n    model: gpt-5\n")
            .expect_err("a key at alias indent that is not `<name>:` must be refused");
        assert!(
            err.to_string().contains("expected `<model-name>:`"),
            "{err}"
        );
    }

    #[test]
    fn empty_file_is_an_empty_config_not_an_error() {
        // An operator may ship the file with everything commented out. That is
        // "no aliases", not a misconfiguration.
        let cfg = parse("# nothing here yet\n").expect("comment-only file parses");
        assert!(cfg.is_empty());
    }

    #[test]
    fn ollama_is_a_known_provider_despite_needing_no_key() {
        // Regression guard for the `env_var_for_provider_id` derivation: Ollama
        // maps to `""` because it is local, NOT because it is unknown.
        assert!(is_known_provider_id("ollama"));
        assert!(is_known_provider_id("openai"));
        assert!(!is_known_provider_id(""));
        assert!(!is_known_provider_id("definitely-not-a-provider"));
    }

    // ── The `failover:` block ────────────────────────────────────────────

    /// The exact block the module doc shows.
    const DOCUMENTED_FAILOVER: &str = "\
failover:
  chain: anthropic, openai, google
  retries: 1
  backoff_ms: 100
";

    #[test]
    fn parses_the_documented_failover_block() {
        let cfg = parse(DOCUMENTED_FAILOVER).expect("documented failover block must parse");
        let fo = cfg.failover().expect("the block must be present");
        assert_eq!(
            fo.chain(),
            &[
                FailoverHop {
                    provider_id: "anthropic".into(),
                    model: "claude-3-5-sonnet-latest".into()
                },
                FailoverHop {
                    provider_id: "openai".into(),
                    model: "gpt-4o".into()
                },
                FailoverHop {
                    provider_id: "google".into(),
                    model: "gemini-1.5-pro".into()
                },
            ]
        );
        assert_eq!(fo.retries(), 1);
        assert_eq!(fo.backoff_ms(), 100);
    }

    #[test]
    fn an_absent_failover_block_is_none_so_the_builtins_apply() {
        // Every deployment today. `failover()` returning None is what makes
        // `cross_provider_candidates` fall back to DEFAULT_CHAIN unchanged.
        let cfg = parse(DOCUMENTED).expect("models-only file parses");
        assert!(cfg.failover().is_none());
    }

    #[test]
    fn a_partial_failover_block_keeps_the_other_defaults() {
        let cfg = parse("failover:\n  retries: 0\n").expect("a retries-only block parses");
        let fo = cfg.failover().expect("block present");
        assert_eq!(fo.retries(), 0, "0 is a valid opt-out of the retry");
        assert_eq!(
            fo.backoff_ms(),
            crate::providers::failover::DEFAULT_BACKOFF_MS
        );
        assert_eq!(
            fo.chain().len(),
            crate::providers::failover::DEFAULT_CHAIN.len(),
            "omitting `chain:` must leave the built-in chain, not empty it"
        );
    }

    #[test]
    fn a_hop_may_name_its_own_model_which_is_how_the_other_166_providers_are_reachable() {
        let cfg = parse("failover:\n  chain: groq:llama-3.3-70b-versatile, openai:gpt-4o\n")
            .expect("explicit per-hop models must parse");
        let fo = cfg.failover().expect("block present");
        assert_eq!(fo.chain()[0].provider_id, "groq");
        assert_eq!(fo.chain()[0].model, "llama-3.3-70b-versatile");
        assert_eq!(fo.chain()[1].provider_id, "openai");
    }

    #[test]
    fn only_the_first_colon_splits_a_hop_so_a_model_may_contain_one() {
        let cfg = parse(
            "failover:\n  chain: bedrock:bedrock/anthropic.claude-3-5-sonnet-20240620-v1:0\n",
        )
        .expect("a model containing a colon must parse");
        let hop = &cfg.failover().expect("block present").chain()[0];
        assert_eq!(hop.provider_id, "bedrock");
        assert_eq!(
            hop.model,
            "bedrock/anthropic.claude-3-5-sonnet-20240620-v1:0"
        );
    }

    #[test]
    fn models_and_failover_parse_in_either_order() {
        let first = parse(&format!("{DOCUMENTED}\n{DOCUMENTED_FAILOVER}"))
            .expect("models then failover parses");
        let second = parse(&format!("{DOCUMENTED_FAILOVER}\n{DOCUMENTED}"))
            .expect("failover then models parses");
        assert_eq!(first, second, "block order must not change the result");
        assert_eq!(first.len(), 2);
        assert!(first.failover().is_some());
    }

    // ── Negative cases. Every one of these must REFUSE, not half-apply. ──

    #[test]
    fn rejects_an_unknown_provider_in_the_failover_chain() {
        let err = parse("failover:\n  chain: anthropic, notaprovider\n")
            .expect_err("an unknown provider in the chain must be refused, never dropped");
        let msg = err.to_string();
        assert!(msg.contains("notaprovider"), "{msg}");
        assert!(msg.contains("no adapter serves"), "{msg}");
        assert!(
            msg.contains("line 2"),
            "the refusal must name the line: {msg}"
        );
    }

    #[test]
    fn rejects_a_bare_provider_with_no_builtin_failover_model() {
        // `groq` is routable and storable — it just has no built-in model, so
        // the hop would have been silently filtered out of the chain before.
        let err = parse("failover:\n  chain: groq\n")
            .expect_err("a bare provider with no built-in model must be refused");
        let msg = err.to_string();
        assert!(msg.contains("built-in failover model"), "{msg}");
        assert!(
            msg.contains("groq:<model>"),
            "the message must show the fix: {msg}"
        );
    }

    #[test]
    fn rejects_a_failover_model_that_routes_to_a_different_provider() {
        // The shape: this hop would dispatch to Anthropic while the BYOK
        // key was fetched for OpenAI.
        let err = parse("failover:\n  chain: openai:claude-3-5-sonnet-latest\n")
            .expect_err("a model that routes elsewhere must be refused");
        let msg = err.to_string();
        assert!(msg.contains("routes to `anthropic`"), "{msg}");
        assert!(msg.contains("wrong provider"), "{msg}");
    }

    #[test]
    fn rejects_a_failover_model_no_prefix_can_route() {
        let err = parse("failover:\n  chain: openai:totally-made-up-model\n")
            .expect_err("an unroutable failover model must be refused");
        assert!(err.to_string().contains("is unroutable"), "{err}");
    }

    #[test]
    fn rejects_a_provider_listed_twice_in_the_chain() {
        let err = parse("failover:\n  chain: openai, anthropic, openai\n")
            .expect_err("a repeated provider must be refused");
        assert!(err.to_string().contains("twice"), "{err}");
    }

    #[test]
    fn rejects_a_chain_longer_than_the_provider_catalog() {
        let huge = "openai, ".repeat(crate::providers::catalog::providers().len() + 1);
        let err = parse(&format!("failover:\n  chain: {huge}openai\n"))
            .expect_err("a chain longer than the catalog must be refused");
        assert!(
            err.to_string().contains("cannot be a routing plan"),
            "{err}"
        );
    }

    #[test]
    fn rejects_an_empty_chain_entry() {
        let err = parse("failover:\n  chain: anthropic,\n")
            .expect_err("a trailing comma must be refused, not read as a 1-hop chain");
        assert!(err.to_string().contains("empty entry"), "{err}");
    }

    #[test]
    fn rejects_an_empty_chain_value() {
        let err = parse("failover:\n  chain:\n").expect_err("an empty `chain:` must be refused");
        assert!(err.to_string().contains("empty value"), "{err}");
    }

    #[test]
    fn rejects_a_negative_retry_count() {
        let err = parse("failover:\n  retries: -1\n")
            .expect_err("a negative retry count must be refused");
        let msg = err.to_string();
        assert!(msg.contains("not a whole number"), "{msg}");
        assert!(msg.contains("line 2"), "{msg}");
    }

    #[test]
    fn rejects_a_retry_count_above_the_maximum() {
        let err = parse(&format!(
            "failover:\n  retries: {}\n",
            crate::providers::failover::MAX_RETRIES + 1
        ))
        .expect_err("more retries than the budget can hold must be refused");
        assert!(err.to_string().contains("exceeds the maximum"), "{err}");
    }

    #[test]
    fn rejects_a_backoff_that_reaches_the_failover_budget() {
        let err = parse(&format!(
            "failover:\n  backoff_ms: {}\n",
            crate::providers::failover::FAILOVER_BUDGET_MS
        ))
        .expect_err("a backoff at the budget leaves no room for the retry itself");
        assert!(err.to_string().contains("could never fire"), "{err}");
    }

    #[test]
    fn rejects_a_retry_plan_that_spends_the_whole_budget_sleeping() {
        // Each value is individually legal; the PLAN is not. Without this check
        // the config would read as three retries and deliver one.
        let err = parse("failover:\n  retries: 3\n  backoff_ms: 80\n")
            .expect_err("retries x backoff over the budget must be refused");
        let msg = err.to_string();
        assert!(msg.contains("240ms"), "{msg}");
        assert!(msg.contains("could never run"), "{msg}");
    }

    #[test]
    fn rejects_a_non_numeric_backoff() {
        let err = parse("failover:\n  backoff_ms: soon\n")
            .expect_err("a non-numeric backoff must be refused");
        assert!(
            err.to_string().contains("whole number of milliseconds"),
            "{err}"
        );
    }

    #[test]
    fn rejects_an_unknown_key_under_failover() {
        let err = parse("failover:\n  chain: openai\n  jitter_ms: 20\n")
            .expect_err("an unread failover key must be refused, not ignored");
        assert!(
            err.to_string().contains("unsupported key `jitter_ms`"),
            "{err}"
        );
    }

    #[test]
    fn rejects_a_duplicate_failover_key() {
        let err = parse("failover:\n  retries: 1\n  retries: 2\n")
            .expect_err("a duplicate key must be refused — last-write-wins is invisible");
        assert!(err.to_string().contains("duplicate `retries:`"), "{err}");
    }

    #[test]
    fn rejects_a_duplicate_failover_block() {
        let err = parse("failover:\n  retries: 1\nfailover:\n  retries: 0\n")
            .expect_err("a second `failover:` block must be refused");
        assert!(
            err.to_string().contains("duplicate `failover:` block"),
            "{err}"
        );
    }

    #[test]
    fn rejects_inconsistent_indentation_under_failover() {
        let err = parse("failover:\n  chain: openai\n    retries: 1\n")
            .expect_err("a differently-indented sibling must be refused");
        assert!(
            err.to_string().contains("inconsistent indentation"),
            "{err}"
        );
    }

    #[test]
    fn the_unknown_top_level_key_message_names_every_block_the_reader_understands() {
        let err = parse("failovers:\n  retries: 1\n").expect_err("a typo'd block must be refused");
        let msg = err.to_string();
        assert!(msg.contains("unsupported top-level key"), "{msg}");
        // RENAMED 2026-08-20 (was `…_names_both_blocks`): there are three now.
        // The point of the assertion is that the refusal ENUMERATES what the
        // reader accepts — a config parser that fails closed without saying what
        // it would have taken sends the operator to guess, and `tracelane.yaml`
        // parse failures are BOOT REFUSALS. So the test asserts every name, and
        // adding a fourth block must update it.
        assert!(msg.contains("`models:`"), "{msg}");
        assert!(msg.contains("`failover:`"), "{msg}");
        assert!(msg.contains("`semantic_cache:`"), "{msg}");
    }

    /// A unique scratch path under the OS temp dir. No env mutation, so this
    /// is safe against the parallel suite.
    fn scratch(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "tracelane-cfg-test-{}-{name}.yaml",
            std::process::id()
        ));
        p
    }

    #[test]
    fn reads_a_real_file_from_disk() {
        let path = scratch("read");
        std::fs::write(&path, DOCUMENTED).expect("write scratch config");
        let cfg = read_at(&path, true)
            .expect("a valid file must read")
            .expect("a present file must produce a config");
        assert_eq!(cfg.len(), 2);
        assert_eq!(
            cfg.alias("my-fast-model").map(|a| a.provider_id.as_str()),
            Some("groq")
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_absent_default_file_fails_open_to_no_aliases() {
        // The no-config deployment: every gateway running today. Zero aliases,
        // zero behaviour change, and startup must NOT refuse.
        let path = scratch("absent-default");
        let _ = std::fs::remove_file(&path);
        assert!(
            read_at(&path, false)
                .expect("absent default must not error")
                .is_none(),
            "an absent ./tracelane.yaml is the no-config case, not a misconfiguration"
        );
    }

    #[test]
    fn an_absent_explicit_file_fails_closed() {
        // The operator named this file. Ignoring it would serve traffic under a
        // routing table they believe is live.
        let path = scratch("absent-explicit");
        let _ = std::fs::remove_file(&path);
        let err = read_at(&path, true)
            .expect_err("an explicitly-named missing config must refuse to boot");
        assert!(err.to_string().contains(PATH_ENV), "{err}");
    }

    #[test]
    fn a_file_that_does_not_parse_fails_closed_naming_the_path() {
        let path = scratch("invalid");
        std::fs::write(&path, "models:\n  a:\n    provider: nope\n    model: x\n")
            .expect("write scratch config");
        let err = read_at(&path, false).expect_err("an invalid config must refuse to boot");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("is not valid"), "{rendered}");
        assert!(rendered.contains("no adapter serves"), "{rendered}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resolved_path_defaults_to_tracelane_yaml() {
        // Read-only: does not mutate process env (parallel tests).
        if std::env::var(PATH_ENV).is_err() {
            assert_eq!(resolved_path(), PathBuf::from(DEFAULT_PATH));
        }
    }
}
