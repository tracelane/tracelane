#!/usr/bin/env python3
"""Guard: exactly ONE model→provider map, fail-closed, from ONE data file.

The bug (cross-provider BYOK misroute + "unknown" span provider) was caused by
FOUR hand-maintained model→provider `match model { m.starts_with(..) => .. }`
tables that drifted: a model dispatched to Groq while its key was resolved under
"anthropic" (B-126). The fix collapsed the model-prefix logic into ONE canonical
function, `ProviderRegistry::provider_id_for_model`; every other consumer
DELEGATES to it and keys its own decision on the returned `provider_id` — a
fixed enumeration that cannot drift on model names.

GWY-42 then moved the OpenAI-compatible half of that map out of Rust and into
`crates/gateway/providers.tsv`, resolved by `providers/catalog.rs`. So the map is
now TWO layers — six native `match` arms, then the catalog — and the ways it can
rot changed with it. **This guard was rewritten for that shape.** What it used to
assert ("`provider_id_for_model` still LOOKS like the prefix table", measured as a
threshold on `.starts_with(` occurrences) no longer discriminates: the natives
alone clear any threshold that the whole 163-row table used to clear, and — much
worse — the old B-127 fail-closed scan read RUST ONLY, so a default planted in
`providers.tsv`, a data file no guard read, was invisible.

Three properties, re-established against the new shape:

  **1. ONE table.** `ProviderRegistry::provider_id_for_model` is the single
  model→provider map: its six native arms, then `catalog::provider_id_for_model`
  for everything else. `api_key_env_var`, `provider_name_from_model` and
  `dispatch_to_provider` DELEGATE to it; `env_var_for_provider_id` and
  `openai_compatible` are keyed on the provider_id it returns. NO other function
  in the three sources may match a model on a literal prefix.

  **2. FAIL-CLOSED (B-127) — in the SOURCE *and* in the DATA.** Both resolvers
  return `Option`. No catch-all arm and no `unwrap_or` may yield a provider id or
  a key env var anywhere in the three sources — checked against the ids and key
  envs *parsed out of providers.tsv*, so it cannot rot as the catalog grows.
  And `providers.tsv` itself carries no default: exact column header (a `default`
  column would be a default provider), no default-ish row id, and no row whose
  prefix list holds an empty string or a `*` / `/` wildcard. An empty prefix is
  invisible at runtime — `parse()` does `.filter(|p| !p.is_empty())` — so this
  guard is the only thing that can see one.

  **3. The catalog is the only OTHER source.** `catalog.rs` carries exactly one
  `include_str!` and it is `../../providers.tsv`; no second provider `.tsv`/`.json`
  has appeared under `crates/gateway/`.

Tests are stripped before scanning: a test may legitimately mention a provider id
in a match arm, and the routing path is production code. The strip is size-checked
so a stripper that ate the file fails loud instead of finding nothing.

Wired into scripts/verify-all.sh + .github/workflows/ci.yml.
`--selftest` plants each violation in synthetic sources and asserts the guard
blocks, and asserts a clean input passes so the check is not vacuous.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MOD_RS = REPO / "crates/gateway/src/providers/mod.rs"
SERVER_RS = REPO / "crates/gateway/src/server.rs"
CATALOG_RS = REPO / "crates/gateway/src/providers/catalog.rs"
PROVIDERS_TSV = REPO / "crates/gateway/providers.tsv"
GATEWAY_DIR = REPO / "crates/gateway"

CANONICAL = "provider_id_for_model"

# The six native adapters. They are matched INSIDE the canonical fn, ahead of the
# catalog, because their wire format is not OpenAI's. Set equality is asserted:
# losing one silently sends its traffic to the catalog (or nowhere), and gaining
# one that the catalog also claims is the shape.
NATIVE_IDS = frozenset({"anthropic", "google", "vertex", "bedrock", "azure", "cohere"})
NATIVE_KEY_ENVS = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "GOOGLE_VERTEX_SERVICE_ACCOUNT_JSON",
        "AWS_ACCESS_KEY_ID",
        "AZURE_OPENAI_API_KEY",
        "COHERE_API_KEY",
    }
)

# Delegates that take a MODEL: each must consult the canonical resolver.
MODEL_DELEGATES = {
    "api_key_env_var": "mod",
    "provider_name_from_model": "server",
    "dispatch_to_provider": "server",
}
# Delegates keyed on a provider_id the canonical resolver already returned. They
# must never see a model, and must consult the catalog rather than re-listing it.
ID_DELEGATES = {
    "env_var_for_provider_id": ("mod", "catalog::api_key_env"),
    "openai_compatible": ("mod", "self.compat"),
}

# A literal prefix match on a model, outside the two resolvers, is a second table.
# Exemptions are BY NAME and each carries its reason in writing.
PREFIX_MATCH_EXEMPT = {
    "is_bench_mock_model": (
        "returns bool for the reserved `__bench_mock` sentinel; it resolves to "
        "BENCH_MOCK_PROVIDER_ID, which is deliberately not a real provider id"
    ),
}

# A catch-all/fallback arm may yield these and only these. `""` is "keyless or
# unknown" from `catalog::api_key_env`, `"unknown"` is a span LABEL in
# `provider_name_from_model` (never a key lookup).
ALLOWED_FALLBACK_LITERALS = frozenset({"", "unknown"})

# `providers.tsv` column contract, exactly. An extra column is how a `default`
# would arrive.
TSV_HEADER = ("id", "label", "base_url", "base_url_env", "api_key_env", "prefixes")
TSV_FIELDS = len(TSV_HEADER)
MIN_TSV_ROWS = 100  # mirrors the catalog.rs test; below this, parsing has rotted

DEFAULTISH_IDS = frozenset(
    {"default", "fallback", "catchall", "catch-all", "*", "_", ""}
)
WILDCARD_PREFIXES = frozenset({"", "*", "/", "**", "?", ".", ".*"})

# Data files under crates/gateway that are allowed to exist, and why. Anything
# else matching *.tsv/*.json is a second provider list until proven otherwise.
KNOWN_DATA_FILES = {
    "crates/gateway/providers.tsv": "the ONE provider catalog (this guard reads it)",
    "crates/gateway/model_prices.tsv": "per-model pricing, read by pricing.rs; not a routing list",
}

# Parser floors. A guard that silently parses nothing and reports OK is the defect
# class this repo calls a broken parser, so every scan asserts a minimum first.
# Floors sit at roughly 60% of what the sources measure today (mod 7.7KB/16 fns,
# server 175KB/116 fns, catalog 3.5KB/8 fns AFTER tests and comments are stripped),
# so ordinary editing never trips them but a stripper or regex that ate the file does.
MIN_PROD_FNS = {"mod": 10, "server": 60, "catalog": 5}
MIN_PROD_BYTES = {"mod": 5_000, "server": 100_000, "catalog": 2_000}


# ── source parsing ────────────────────────────────────────────────────────────


def strip_test_modules(src: str) -> str:
    """Remove every `#[cfg(test)]`-gated block (balanced braces)."""
    cuts: list[tuple[int, int]] = []
    for m in re.finditer(r"#\[cfg\(test\)\]", src):
        if cuts and m.start() < cuts[-1][1]:
            continue
        b = src.find("{", m.end())
        if b < 0:
            continue
        depth = 0
        for j in range(b, len(src)):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    cuts.append((m.start(), j + 1))
                    break
    for s, e in reversed(cuts):
        src = src[:s] + src[e:]
    return src


def strip_line_comments(s: str) -> str:
    """Drop `//` comments (keeping `://` in URLs) so documenting a banned
    pattern is not itself a violation."""
    return re.sub(r"(?<!:)//[^\n]*", "", s)


def fn_spans(src: str) -> list[tuple[str, int, int]]:
    """Every `fn <name> { ... }` as (name, body_open, body_close)."""
    out: list[tuple[str, int, int]] = []
    for m in re.finditer(r"\bfn\s+([A-Za-z0-9_]+)\b", src):
        i = src.find("{", m.end())
        if i < 0:
            continue
        depth = 0
        for j in range(i, len(src)):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    out.append((m.group(1), i, j))
                    break
    return out


def innermost_fn(spans: list[tuple[str, int, int]], pos: int) -> str:
    """Name of the smallest fn span containing `pos` (`<file scope>` if none)."""
    hits = [(j - i, n) for n, i, j in spans if i <= pos <= j]
    return min(hits)[1] if hits else "<file scope>"


def extract_fn_body(src: str, name: str) -> str | None:
    m = re.search(rf"\bfn\s+{re.escape(name)}\b", src)
    if not m:
        return None
    i = src.find("{", m.end())
    if i < 0:
        return None
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i : j + 1]
    return None


def fn_return_type(src: str, name: str) -> str | None:
    m = re.search(rf"\bfn\s+{re.escape(name)}\s*\(", src)
    if not m:
        return None
    # Walk the parameter list with a paren counter — a param may contain parens.
    depth = 0
    k = m.end() - 1
    for j in range(k, len(src)):
        if src[j] == "(":
            depth += 1
        elif src[j] == ")":
            depth -= 1
            if depth == 0:
                k = j + 1
                break
    tail = src[k : k + 200]
    r = re.match(r"\s*->\s*([^\{;]+)", tail)
    return r.group(1).strip() if r else ""


# A model-ish receiver prefix-matched against a STRING LITERAL. Both halves are
# required: `prefix.starts_with(p)` (no literal) is data-driven and fine, and
# `host.starts_with("127.")` is not a model at all.
MODEL_PREFIX_MATCH = re.compile(
    r'\b(?:model|m|model_id|model_name|req\.model|request\.model)\s*\.starts_with\(\s*"'
)

# A fallback arm: `_ =>`, a bare binder `other =>`, or `None =>` — the three
# shapes a default-to-a-provider actually takes.
FALLBACK_ARM = re.compile(
    r"(?:^|[\n{,(])\s*(_|None|[a-z][a-z0-9_]*)\s*=>\s*([^\n]*)", re.MULTILINE
)
# A fallback that BAILS is the goal, not a violation.
FAILS_CLOSED = re.compile(
    r"\b(?:bail!|panic!|unreachable!|todo!|anyhow!|Err\(|return\s+Err|"
    r"ok_or|StatusCode::|unroutable)"
)
UNWRAP_OR_LITERAL = re.compile(r'unwrap_or(?:_default)?\(\s*"([^"]*)"')
DISPATCH_DEFAULT = re.compile(r"(?:_|[a-z][a-z0-9_]*)\s*=>\s*registry\.\w+\.chat")


# ── the checks ────────────────────────────────────────────────────────────────


def parse_tsv(text: str) -> tuple[list[list[str]], list[str], list[str]]:
    """(data rows, header fields, structural errors) from providers.tsv."""
    errors: list[str] = []
    header: list[str] = []
    rows: list[list[str]] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip("\r")
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if not header:
            header = fields
            if tuple(header) != TSV_HEADER:
                errors.append(
                    f"providers.tsv line {n}: column header is {header}, expected "
                    f"{list(TSV_HEADER)}. An extra or renamed column is how a "
                    f"default provider arrives in the DATA (B-127)."
                )
            continue
        if len(fields) != TSV_FIELDS:
            errors.append(
                f"providers.tsv line {n}: {len(fields)} tab-separated fields, "
                f"expected {TSV_FIELDS} — the Rust parser panics on a short row"
            )
            continue
        rows.append(fields)
    if not header:
        errors.append(
            "providers.tsv: no column header found — the guard cannot parse it"
        )
    return rows, header, errors


def check_tsv_fail_closed(rows: list[list[str]], errors: list[str]) -> None:
    """B-127 in the DATA: no row in providers.tsv may act as a default."""
    for pid, _label, _base, _base_env, _key_env, prefixes in rows:
        if pid.strip().lower() in DEFAULTISH_IDS:
            errors.append(
                f"providers.tsv: row id `{pid}` is a default/catch-all sentinel. "
                f"There is no default provider (B-127) — an unmatched model must "
                f"fail closed, never route to somebody else's key."
            )
        for p in prefixes.split(","):
            if p in WILDCARD_PREFIXES:
                errors.append(
                    f"providers.tsv: `{pid}` carries the wildcard/empty prefix "
                    f"`{p}` in its prefix list. An empty prefix matches EVERY "
                    f"model, which is a default provider written as data. "
                    f"(`parse()` filters empties out, so this is invisible at "
                    f"runtime — this guard is the only thing that sees it.)"
                )
            elif "*" in p or "?" in p:
                errors.append(
                    f"providers.tsv: `{pid}` prefix `{p}` contains a glob "
                    f"character. Prefixes are matched with `starts_with`, not "
                    f"globbed; a glob here is either dead or a default."
                )


def run(
    mod_src: str,
    server_src: str,
    catalog_src: str,
    tsv_text: str,
    data_files: list[str],
    mod_label: str = "crates/gateway/src/providers/mod.rs",
    server_label: str = "crates/gateway/src/server.rs",
    catalog_label: str = "crates/gateway/src/providers/catalog.rs",
) -> list[str]:
    """Return every violation found. Sources are ARGUMENTS, not reads, so the
    selftest plants each violation in synthetic input instead of editing the
    real gateway."""
    errors: list[str] = []

    prod = {
        "mod": strip_line_comments(strip_test_modules(mod_src)),
        "server": strip_line_comments(strip_test_modules(server_src)),
        "catalog": strip_line_comments(strip_test_modules(catalog_src)),
    }
    labels = {"mod": mod_label, "server": server_label, "catalog": catalog_label}
    spans = {k: fn_spans(v) for k, v in prod.items()}

    # ── 0. PARSER SANITY. Assert we parsed something before judging anything.
    for key, src in prod.items():
        if len(src) < MIN_PROD_BYTES[key]:
            errors.append(
                f"PARSER ROT: {labels[key]} is {len(src)}B of production source "
                f"after stripping tests, below the {MIN_PROD_BYTES[key]}B floor. "
                f"The guard refuses to report OK on input it may not have read."
            )
        if len(spans[key]) < MIN_PROD_FNS[key]:
            errors.append(
                f"PARSER ROT: found {len(spans[key])} production fns in "
                f"{labels[key]}, below the {MIN_PROD_FNS[key]} floor — the fn "
                f"parser has stopped matching. A guard that finds nothing and "
                f"reports OK is the defect it exists to prevent."
            )
    rows, _header, tsv_errors = parse_tsv(tsv_text)
    errors += tsv_errors
    if len(rows) < MIN_TSV_ROWS:
        errors.append(
            f"PARSER ROT: providers.tsv parsed to {len(rows)} rows, below the "
            f"{MIN_TSV_ROWS} floor. Either the catalog collapsed or the TSV "
            f"parser did; both are blocking."
        )
    if errors:
        # Nothing below can be trusted on input the guard could not parse.
        return errors

    catalog_ids = {r[0] for r in rows}
    catalog_key_envs = {r[4] for r in rows if r[4]}
    provider_ids = catalog_ids | NATIVE_IDS
    key_envs = catalog_key_envs | NATIVE_KEY_ENVS

    # ── 1. ONE TABLE.
    canon = extract_fn_body(prod["mod"], CANONICAL)
    if canon is None:
        errors.append(f"MISSING canonical `{CANONICAL}` in {mod_label}")
    else:
        # 1a. Its native arms are EXACTLY the six. Replaces the old
        #     `.starts_with(` threshold, which stopped discriminating the moment
        #     the catalog absorbed the other 157 rows.
        found = set(re.findall(r'=>\s*Some\(\s*"([a-z0-9_-]+)"\s*\)', canon))
        if found != NATIVE_IDS:
            errors.append(
                f"`{CANONICAL}` native arms are {sorted(found)}, expected "
                f"{sorted(NATIVE_IDS)}. Losing a native arm hands its models to "
                f"the catalog (or to nothing); adding one the catalog also "
                f"claims is the B-126 misroute."
            )
        # 1b. Everything else must fall through to the ONE catalog resolver.
        if f"catalog::{CANONICAL}(" not in canon:
            errors.append(
                f"`{CANONICAL}` no longer falls through to "
                f"`catalog::{CANONICAL}(`. The natives are only half the map; "
                f"without the catalog it is a second, shorter table."
            )

    # 1c. The catalog resolver exists and is DATA-driven, not a literal table.
    cat_body = extract_fn_body(prod["catalog"], CANONICAL)
    if cat_body is None:
        errors.append(f"MISSING `catalog::{CANONICAL}` in {catalog_label}")
    elif MODEL_PREFIX_MATCH.search(cat_body):
        errors.append(
            f"`catalog::{CANONICAL}` prefix-matches a STRING LITERAL. It must "
            f"resolve from the parsed providers.tsv only; a literal here is a "
            f"routing rule that lives in code instead of the one data file."
        )

    # 1d. Model delegates must consult the canonical resolver, and never
    #     prefix-match a model themselves.
    for name, which in MODEL_DELEGATES.items():
        body = extract_fn_body(prod[which], name)
        if body is None:
            errors.append(f"MISSING delegate `{name}` in {labels[which]}")
            continue
        if f"{CANONICAL}(" not in body:
            errors.append(
                f"`{name}` must DELEGATE to `{CANONICAL}(` (one source of "
                f"truth) — it does not reference it"
            )
        if MODEL_PREFIX_MATCH.search(body):
            errors.append(
                f"`{name}` reintroduced model-prefix matching. Route on the "
                f"provider_id from `{CANONICAL}` instead — a second "
                f"model-prefix table is the exact B-126 drift surface."
            )

    # 1e. Provider-id delegates must stay keyed on the id and consult the catalog.
    for name, (which, must_call) in ID_DELEGATES.items():
        body = extract_fn_body(prod[which], name)
        if body is None:
            errors.append(f"MISSING delegate `{name}` in {labels[which]}")
            continue
        if must_call not in body:
            errors.append(
                f"`{name}` must resolve through `{must_call}` — otherwise it is "
                f"a hand-maintained second list of providers"
            )
        if MODEL_PREFIX_MATCH.search(body):
            errors.append(
                f"`{name}` prefix-matches a MODEL. It is keyed on the "
                f"provider_id `{CANONICAL}` already returned; touching the model "
                f"string here reopens the drift."
            )

    # 1f. GLOBAL: nobody else may match a model on a literal prefix.
    allowed_here = {CANONICAL} | set(PREFIX_MATCH_EXEMPT)
    for key, src in prod.items():
        for m in MODEL_PREFIX_MATCH.finditer(src):
            owner = innermost_fn(spans[key], m.start())
            if owner in allowed_here:
                continue
            line = src[: m.start()].count("\n") + 1
            errors.append(
                f"`{owner}` in {labels[key]} (~line {line}) matches a model on a "
                f"literal prefix. There must be exactly ONE model→provider map "
                f"(`{CANONICAL}`, then the catalog); delegate to it instead."
            )

    # ── 2. FAIL-CLOSED, in the SOURCE.
    for key, fname, label in (
        ("mod", CANONICAL, mod_label),
        ("catalog", CANONICAL, catalog_label),
    ):
        ret = fn_return_type(prod[key], fname)
        if ret is None:
            continue  # already reported as MISSING above
        if "Option" not in ret:
            errors.append(
                f"`{fname}` in {label} returns `{ret or '<nothing>'}` — it must "
                f"return `Option<&'static str>` so an unmatched model fails "
                f"closed (B-127), not a bare `&str` that forces a default."
            )

    for key, src in prod.items():
        for m in FALLBACK_ARM.finditer(src):
            rhs = m.group(2)
            if FAILS_CLOSED.search(rhs):
                continue  # a fallback that bails is the goal
            for lit in re.findall(r'"([^"]*)"', rhs):
                if lit in ALLOWED_FALLBACK_LITERALS:
                    continue
                if lit in provider_ids or lit in key_envs:
                    owner = innermost_fn(spans[key], m.start())
                    errors.append(
                        f"fail-closed VIOLATED in {labels[key]}: `{owner}` has a "
                        f'catch-all arm `{m.group(1)} => …"{lit}"`. An '
                        f"unmatched model or provider_id must fail closed with a "
                        f"typed unroutable error — never route to a default "
                        f"provider's key (B-127)."
                    )
        for m in UNWRAP_OR_LITERAL.finditer(src):
            lit = m.group(1)
            if lit in ALLOWED_FALLBACK_LITERALS:
                continue
            if lit in provider_ids or lit in key_envs:
                owner = innermost_fn(spans[key], m.start())
                errors.append(
                    f"fail-closed VIOLATED in {labels[key]}: `{owner}` has "
                    f'`unwrap_or("{lit}")` — a defaulted provider/key. Propagate '
                    f"the `None` and fail closed (B-127)."
                )
        for m in DISPATCH_DEFAULT.finditer(src):
            owner = innermost_fn(spans[key], m.start())
            errors.append(
                f"fail-closed VIOLATED in {labels[key]}: `{owner}` has a "
                f"`_ => registry.<provider>.chat` dispatch default. A "
                f"provider_id the dispatch does not know is a catalog bug, not "
                f"'probably Anthropic' — bail (B-127)."
            )

    # ── 2b. FAIL-CLOSED in the DATA. The half the old guard could not see.
    check_tsv_fail_closed(rows, errors)

    # ── 3. THE CATALOG IS THE ONLY OTHER SOURCE.
    includes = re.findall(r'include_str!\(\s*"([^"]+)"', prod["catalog"])
    if includes != ["../../providers.tsv"]:
        errors.append(
            f"{catalog_label} embeds {includes or 'nothing'}; it must embed "
            f"exactly one file, `../../providers.tsv`. A second embedded list is "
            f"a second source of routing truth."
        )
    for key in ("mod", "server"):
        for inc in re.findall(r'include_str!\(\s*"([^"]+)"', prod[key]):
            if inc.endswith((".tsv", ".json", ".csv")):
                errors.append(
                    f"{labels[key]} embeds the data file `{inc}`. Only "
                    f"{catalog_label} may embed a provider list, and only "
                    f"providers.tsv."
                )
    for f in sorted(data_files):
        if f not in KNOWN_DATA_FILES:
            errors.append(
                f"unexpected data file `{f}` under crates/gateway/. If it is a "
                f"second provider list, it is a second source of truth "
                f"(the exact shape of B-126); if it is not, add it to "
                f"KNOWN_DATA_FILES in this guard with the reason."
            )

    return errors


def find_data_files() -> list[str]:
    """Every *.tsv/*.json/*.csv under crates/gateway, repo-relative."""
    out: list[str] = []
    for p in GATEWAY_DIR.rglob("*"):
        if not p.is_file() or p.suffix not in (".tsv", ".json", ".csv"):
            continue
        rel = p.relative_to(REPO).as_posix()
        if "/target/" in f"/{rel}" or "/node_modules/" in f"/{rel}":
            continue
        out.append(rel)
    return out


# ── selftest fixtures ─────────────────────────────────────────────────────────
# Synthetic sources with the same shapes the guard parses, big enough to clear the
# parser floors (which are scaled down for fixtures via _floors).

_NATIVE_ARMS = "\n".join(
    f'            m if m.starts_with("{pid}/") => Some("{pid}"),'
    for pid in sorted(NATIVE_IDS)
)
_FILLER = "\n".join(f"fn filler_{i}() -> u32 {{ {i} }}" for i in range(70))

CLEAN_MOD = f"""//! fixture providers/mod.rs
impl ProviderRegistry {{
    pub fn provider_id_for_model(model: &str) -> Option<&'static str> {{
        let native = match model {{
{_NATIVE_ARMS}
            _ => None,
        }};
        if native.is_some() {{
            return native;
        }}
        catalog::provider_id_for_model(model)
    }}

    pub fn api_key_env_var(model: &str) -> Option<&'static str> {{
        Self::provider_id_for_model(model).map(Self::env_var_for_provider_id)
    }}

    pub fn env_var_for_provider_id(provider_id: &str) -> &'static str {{
        match provider_id {{
            "anthropic" => "ANTHROPIC_API_KEY",
            other => catalog::api_key_env(other).unwrap_or(""),
        }}
    }}

    pub fn openai_compatible(&self, provider_id: &str) -> Option<&OpenAiProvider> {{
        self.compat(provider_id)
    }}
}}
{_FILLER}
"""

CLEAN_SERVER = f"""//! fixture server.rs
fn provider_name_from_model(model: &str) -> &'static str {{
    match crate::providers::ProviderRegistry::provider_id_for_model(model) {{
        Some("vertex") => "gcp_vertex_ai",
        Some(other) => other,
        None => "unknown",
    }}
}}

async fn dispatch_to_provider(model: &str, registry: &ProviderRegistry) -> Result<R, E> {{
    let Some(provider_id) = ProviderRegistry::provider_id_for_model(model) else {{
        anyhow::bail!("unroutable model '{{model}}'");
    }};
    match provider_id {{
        "anthropic" => registry.anthropic.chat().await,
        other => match registry.compat(other) {{
            Some(p) => p.chat().await,
            None => anyhow::bail!("unroutable provider_id '{{provider_id}}'"),
        }},
    }}
}}

fn is_bench_mock_model(model: &str) -> bool {{
    model.starts_with("__bench_mock")
}}
{_FILLER}
{_FILLER.replace("filler_", "filler_b_")}
"""

CLEAN_CATALOG = f"""//! fixture catalog.rs
const CATALOG_TSV: &str = include_str!("../../providers.tsv");

pub fn provider_id_for_model(model: &str) -> Option<&'static str> {{
    let c = catalog();
    let b = *model.as_bytes().first()? as usize;
    c.buckets[b]
        .iter()
        .find(|(pre, _)| model.starts_with(*pre))
        .map(|(_, id)| *id)
}}

pub fn api_key_env(provider_id: &str) -> Option<&'static str> {{
    by_id(provider_id).map(|p| p.api_key_env)
}}
{_FILLER}
"""

_TSV_HEAD = "# fixture providers.tsv\n" + "\t".join(TSV_HEADER) + "\n"
# Real provider ids and key envs, deliberately: the fail-closed check derives the
# banned literal set FROM this file, so a fixture of made-up ids would let a
# planted `_ => "openai"` pass for the wrong reason and prove nothing.
CLEAN_TSV = (
    _TSV_HEAD
    + "".join(
        f"{pid}\t{pid.title()}\thttps://api.{pid}.example\t"
        f"{pid.upper()}_BASE_URL\t{pid.upper()}_API_KEY\t{pid}/\n"
        for pid in ("openai", "groq", "mistral", "perplexity", "deepseek")
    )
    + "".join(
        f"p{i}\tP{i}\thttps://api.p{i}.example\tP{i}_BASE_URL\tP{i}_API_KEY\tp{i}/\n"
        for i in range(MIN_TSV_ROWS + 5)
    )
)
CLEAN_FILES = ["crates/gateway/providers.tsv", "crates/gateway/model_prices.tsv"]


def selftest() -> int:
    """Plant every violation this guard exists to catch, and prove a clean input
    passes so none of it is vacuous."""
    ok = True
    # Fixtures are far smaller than the real gateway; scale the byte floors so the
    # floors themselves stay meaningful against the real sources.
    real_bytes = dict(MIN_PROD_BYTES)
    MIN_PROD_BYTES.update({"mod": 500, "server": 500, "catalog": 300})

    def case(
        name: str,
        expect: str | None,
        mod_src: str = CLEAN_MOD,
        server_src: str = CLEAN_SERVER,
        catalog_src: str = CLEAN_CATALOG,
        tsv: str = CLEAN_TSV,
        files: list[str] | None = None,
    ) -> None:
        """expect=None means the input is CLEAN and must produce no errors."""
        nonlocal ok
        errors = run(
            mod_src,
            server_src,
            catalog_src,
            tsv,
            CLEAN_FILES if files is None else files,
            "fixture-mod.rs",
            "fixture-server.rs",
            "fixture-catalog.rs",
        )
        if expect is None:
            if errors:
                print(f"SELFTEST FAIL: {name} — clean input flagged: {errors}")
                ok = False
                return
        elif not any(expect in e for e in errors):
            print(
                f"SELFTEST FAIL: {name} — no error containing {expect!r}; got {errors}"
            )
            ok = False
            return
        print(f"  ✓ {name}")

    # THE NEGATIVE, FIRST. A guard that fails on everything would otherwise look
    # correct for every planted violation below.
    case("clean single-source layout PASSES", None)

    # ── 1. ONE TABLE ─────────────────────────────────────────────────────────
    # THE headline plant: a second prefix-matching function.
    case(
        "a SECOND prefix-matching function -> REFUSED",
        "`shadow_router` in fixture-server.rs",
        server_src=CLEAN_SERVER + "\nfn shadow_router(model: &str) -> Option<&str> {\n"
        '    if model.starts_with("llama") { return Some("groq"); }\n'
        "    None\n}\n",
    )
    # ...even when it is only ONE arm. The old threshold needed six.
    case(
        "a second prefix table with a SINGLE arm -> REFUSED",
        "matches a model on a literal prefix",
        mod_src=CLEAN_MOD + "\nfn sneaky(model: &str) -> Option<&str> {\n"
        '    if model.starts_with("gpt") { return Some("openai"); }\n'
        "    None\n}\n",
    )
    case(
        "a delegate reintroduces model-prefix matching -> REFUSED",
        "`provider_name_from_model` reintroduced model-prefix matching",
        server_src=CLEAN_SERVER.replace(
            "    match crate::providers::ProviderRegistry",
            '    if model.starts_with("llama") { return "groq"; }\n'
            "    match crate::providers::ProviderRegistry",
        ),
    )
    case(
        "a delegate stops delegating -> REFUSED",
        "must DELEGATE to `provider_id_for_model(`",
        server_src=CLEAN_SERVER.replace(
            "crate::providers::ProviderRegistry::provider_id_for_model(model)",
            "lookup_elsewhere(model)",
        ),
    )
    case(
        "env_var_for_provider_id stops consulting the catalog -> REFUSED",
        "must resolve through `catalog::api_key_env`",
        mod_src=CLEAN_MOD.replace('catalog::api_key_env(other).unwrap_or("")', '""'),
    )
    case(
        "canonical map deleted -> REFUSED",
        f"MISSING canonical `{CANONICAL}`",
        mod_src=CLEAN_MOD.replace(
            "pub fn provider_id_for_model", "pub fn gone_for_model"
        ),
    )
    case(
        "a native arm disappears -> REFUSED",
        "native arms are",
        mod_src=CLEAN_MOD.replace(
            '            m if m.starts_with("cohere/") => Some("cohere"),\n', ""
        ),
    )
    case(
        "canonical map stops falling through to the catalog -> REFUSED",
        "no longer falls through to `catalog::provider_id_for_model(`",
        mod_src=CLEAN_MOD.replace(
            "        catalog::provider_id_for_model(model)\n", "        None\n"
        ),
    )
    case(
        "the catalog resolver grows a literal prefix arm -> REFUSED",
        "prefix-matches a STRING LITERAL",
        catalog_src=CLEAN_CATALOG.replace(
            "    let c = catalog();",
            '    if model.starts_with("gpt") { return Some("openai"); }\n    let c = catalog();',
        ),
    )

    # ── 2. FAIL-CLOSED, SOURCE ───────────────────────────────────────
    case(
        "canonical map stops returning Option -> REFUSED",
        "must return `Option<&'static str>`",
        mod_src=CLEAN_MOD.replace(
            "pub fn provider_id_for_model(model: &str) -> Option<&'static str> {",
            "pub fn provider_id_for_model(model: &str) -> &'static str {",
        ),
    )
    # A catch-all default — and NOT spelled "anthropic". The old guard hardcoded
    # anthropic and sailed straight past every other provider id.
    for lit in ("anthropic", "openai", "groq", "OPENAI_API_KEY"):
        case(
            f'catch-all default `_ => "{lit}"` -> REFUSED',
            "fail-closed VIOLATED",
            mod_src=CLEAN_MOD
            + f'\nfn leak(id: &str) -> &str {{\n    match id {{\n        "x" => "y",\n        _ => "{lit}",\n    }}\n}}\n',
        )
    case(
        'defaulted `unwrap_or("groq")` -> REFUSED',
        "fail-closed VIOLATED",
        mod_src=CLEAN_MOD
        + '\nfn leak2(x: Option<&str>) -> &str { x.unwrap_or("groq") }\n',
    )
    case(
        "`_ => registry.<provider>.chat` dispatch default -> REFUSED",
        "dispatch default",
        server_src=CLEAN_SERVER.replace(
            "            None => anyhow::bail!(\"unroutable provider_id '{provider_id}'\"),",
            "            _ => registry.anthropic.chat().await,",
        ),
    )
    case(
        'a `None => "anthropic"` span-label default -> REFUSED',
        "fail-closed VIOLATED",
        server_src=CLEAN_SERVER.replace('None => "unknown",', 'None => "anthropic",'),
    )
    # ...but the same text in a COMMENT must NOT fire, and a legitimate
    # fail-closed bail arm must NOT fire either.
    case(
        "banned default quoted in a COMMENT does not fire",
        None,
        mod_src=CLEAN_MOD + '\n// never write `_ => "anthropic"` here\n',
    )

    # ── 2b. FAIL-CLOSED, DATA ────────────────────────────────────────
    # THE plant the old guard was structurally blind to: it read Rust only.
    for bad_prefix, why in (
        ("*", "star wildcard"),
        ("", "empty prefix"),
        ("/", "bare slash"),
    ):
        case(
            f"providers.tsv row with a {why} -> REFUSED",
            "wildcard/empty prefix",
            tsv=CLEAN_TSV
            + f"wild\tWild\thttps://api.wild.example\tWILD_BASE_URL\tWILD_API_KEY\t{bad_prefix}\n",
        )
    case(
        "providers.tsv prefix containing a glob -> REFUSED",
        "contains a glob character",
        tsv=CLEAN_TSV
        + "glob\tGlob\thttps://api.glob.example\tG_BASE_URL\tG_API_KEY\tgpt-*\n",
    )
    case(
        "providers.tsv row whose id is `default` -> REFUSED",
        "is a default/catch-all sentinel",
        tsv=CLEAN_TSV
        + "default\tDefault\thttps://api.d.example\tD_BASE_URL\tD_API_KEY\tzz/\n",
    )
    case(
        "a `default` COLUMN added to providers.tsv -> REFUSED",
        "column header is",
        tsv=CLEAN_TSV.replace(
            "\t".join(TSV_HEADER), "\t".join(TSV_HEADER) + "\tdefault_provider"
        ),
    )
    case(
        "a short (malformed) providers.tsv row -> REFUSED",
        "tab-separated fields, expected",
        tsv=CLEAN_TSV + "truncated\tRow\thttps://api.t.example\n",
    )

    # ── 3. THE CATALOG IS THE ONLY OTHER SOURCE ──────────────────────────────
    case(
        "a SECOND include_str! in catalog.rs -> REFUSED",
        "it must embed exactly one file",
        catalog_src=CLEAN_CATALOG
        + '\nconst MORE: &str = include_str!("../../providers_extra.tsv");\n',
    )
    case(
        "mod.rs embeds its own provider list -> REFUSED",
        "embeds the data file",
        mod_src=CLEAN_MOD
        + '\nconst X: &str = include_str!("../../providers2.json");\n',
    )
    case(
        "a second provider .tsv appears under crates/gateway -> REFUSED",
        "unexpected data file",
        files=CLEAN_FILES + ["crates/gateway/providers_v2.tsv"],
    )

    # ── 0. PARSER ROT. The guard must refuse to report OK on input it did not
    #      parse — a silent zero-finding pass is the defect class itself.
    case("empty providers.tsv -> REFUSED (parser rot)", "PARSER ROT", tsv=_TSV_HEAD)
    case(
        "truncated mod.rs -> REFUSED (parser rot)", "PARSER ROT", mod_src="// nothing\n"
    )
    case(
        "fn parser matching nothing -> REFUSED (parser rot)",
        "PARSER ROT",
        catalog_src="//" + "x" * 5000,
    )

    MIN_PROD_BYTES.update(real_bytes)
    print("selftest PASSED." if ok else "selftest FAILED.")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Guard: ONE model→provider map (natives + the one catalog), "
            "fail-closed in source AND data, from one providers.tsv."
        )
    )
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="plant each violation in synthetic sources and prove the guard blocks",
    )
    args = ap.parse_args()  # unknown flags -> argparse exits 2 with usage
    if args.selftest:
        return selftest()

    errors = run(
        MOD_RS.read_text(encoding="utf-8"),
        SERVER_RS.read_text(encoding="utf-8"),
        CATALOG_RS.read_text(encoding="utf-8"),
        PROVIDERS_TSV.read_text(encoding="utf-8"),
        find_data_files(),
    )

    if errors:
        print(
            "FAIL: provider-mapping single-source + fail-closed guard\n",
            file=sys.stderr,
        )
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    rows, _, _ = parse_tsv(PROVIDERS_TSV.read_text(encoding="utf-8"))
    print(
        f"OK: ONE model→provider map — {len(NATIVE_IDS)} native arms then "
        f"{len(rows)} catalog rows from the single providers.tsv; "
        f"{', '.join(MODEL_DELEGATES)} delegate; "
        f"{', '.join(ID_DELEGATES)} keyed on provider_id; "
        f"no default provider in source or data (B-127)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
