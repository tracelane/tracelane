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
//! ## The file
//!
//! ```yaml
//! models:
//!   my-fast-model:
//!     provider: groq
//!     model: llama-3.3-70b-versatile
//! ```
//!
//! Read from `$TRACELANE_CONFIG`, or `./tracelane.yaml` when that is unset.
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

/// The parsed contents of `tracelane.yaml`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FileConfig {
    models: BTreeMap<String, ModelAlias>,
}

impl FileConfig {
    /// Look up an alias by the exact model string the caller sent.
    #[must_use]
    pub fn alias(&self, model: &str) -> Option<&ModelAlias> {
        self.models.get(model)
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
        "tracelane.yaml loaded"
    );
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

/// Parse the strict `tracelane.yaml` subset.
///
/// Accepts exactly the documented shape:
///
/// ```yaml
/// models:
///   <alias>:
///     provider: <provider-id>
///     model: <upstream-model>
/// ```
///
/// # Errors
///
/// **Fails CLOSED on anything it does not fully understand**, naming the line
/// number: tabs in the indentation, an unknown top-level key, an unknown key
/// under an alias, a missing `provider` or `model`, a duplicate alias, a
/// provider id no adapter serves. Refusing is deliberate — a routing file the
/// reader silently half-applies is worse than no routing file.
pub fn parse(src: &str) -> anyhow::Result<FileConfig> {
    let mut models: BTreeMap<String, ModelAlias> = BTreeMap::new();
    let mut in_models = false;
    // Indent at which alias names sit. Fixed by the first alias line, so an
    // inconsistently-indented sibling is an error rather than a silent skip.
    let mut alias_indent: Option<usize> = None;
    let mut pending: Option<PendingAlias> = None;

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
            if content == "models:" {
                if in_models {
                    bail!("line {lineno}: duplicate `models:` block");
                }
                in_models = true;
                continue;
            }
            bail!(
                "line {lineno}: unsupported top-level key `{content}` — this reader \
                 understands only `models:`"
            );
        }

        if !in_models {
            bail!("line {lineno}: indented line before any top-level key");
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
    Ok(FileConfig { models })
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
