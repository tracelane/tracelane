#!/usr/bin/env python3
"""Guard: exactly ONE model→provider prefix table.

The bug (cross-provider BYOK misroute + "unknown" span provider) was caused
by FOUR hand-maintained model→provider `match model { m.starts_with(..) => .. }`
tables that drifted: a model dispatched to Groq while its key was resolved under
"anthropic". The fix collapses the model-prefix logic into ONE canonical function,
`ProviderRegistry::provider_id_for_model`; every other consumer DELEGATES to it and
keys its own decision on the returned `provider_id` (a fixed enumeration that cannot
drift on model names).

This guard fails CI if that invariant is broken, i.e. if a *second* model-prefix
provider table is reintroduced. It enforces:

  1. `provider_id_for_model`  — the ONE allowed model-prefix table (must contain the
     prefix matches).
  2. `api_key_env_var`, `provider_name_from_model`, `dispatch_to_provider` — the
     DELEGATES — must call `provider_id_for_model(` and must NOT do their own
     `.starts_with(` model-prefix matching.
  3. No OTHER function in the two files may carry a large model-prefix table
     (> THRESHOLD `.starts_with(` arms).

Wired into scripts/verify-all.sh + .github/workflows/ci.yml.
`--selftest` plants each violation in synthetic Rust and asserts the guard blocks.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MOD_RS = REPO / "crates/gateway/src/providers/mod.rs"
SERVER_RS = REPO / "crates/gateway/src/server.rs"

# A function carrying more than this many `.starts_with(` arms is a model-prefix
# table. Only `provider_id_for_model` is allowed to be one.
TABLE_THRESHOLD = 5

CANONICAL = "provider_id_for_model"
# delegate fn name -> which of the two sources it lives in ("mod" | "server").
# Keyed by source NAME, not by Path, so the selftest can supply fixture text for
# each side without touching the repo.
DELEGATES = {
    "api_key_env_var": "mod",
    "provider_name_from_model": "server",
    "dispatch_to_provider": "server",
}


def extract_fn_body(src: str, name: str) -> str | None:
    """Return the brace-delimited body of `fn <name>(...) ... { ... }`."""
    m = re.search(rf"\bfn\s+{re.escape(name)}\b", src)
    if not m:
        return None
    i = src.find("{", m.end())
    if i < 0:
        return None
    depth = 0
    for j in range(i, len(src)):
        c = src[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[i : j + 1]
    return None


def count_starts_with(body: str) -> int:
    return len(re.findall(r"\.starts_with\(", body))


def run(
    mod_src: str,
    server_src: str,
    mod_label: str = "providers/mod.rs",
    server_label: str = "server.rs",
) -> list[str]:
    """Return every violation found in the two sources.

    Sources are arguments, not reads, so the selftest can plant each violation in
    synthetic Rust instead of editing the real gateway.
    """
    errors: list[str] = []
    sources = {"mod": (mod_label, mod_src), "server": (server_label, server_src)}

    # 1. The canonical table must exist and BE a prefix table.
    canon = extract_fn_body(mod_src, CANONICAL)
    if canon is None:
        errors.append(f"MISSING canonical `{CANONICAL}` in {mod_label}")
    elif count_starts_with(canon) < TABLE_THRESHOLD:
        errors.append(
            f"`{CANONICAL}` no longer looks like the model-prefix table "
            f"({count_starts_with(canon)} `.starts_with(` < {TABLE_THRESHOLD})"
        )

    # 2. Each delegate must call the canonical fn and NOT prefix-match models.
    for name, which in DELEGATES.items():
        src = sources[which][1]
        body = extract_fn_body(src, name)
        if body is None:
            errors.append(f"MISSING delegate `{name}`")
            continue
        if f"{CANONICAL}(" not in body:
            errors.append(
                f"`{name}` must DELEGATE to `{CANONICAL}(` (one source of "
                f"truth) — it does not reference it"
            )
        sw = count_starts_with(body)
        if sw > 0:
            errors.append(
                f"`{name}` reintroduced model-prefix matching "
                f"({sw} `.starts_with(`). Route on the provider_id from "
                f"`{CANONICAL}` instead — a second model-prefix table is the exact "
                f"drift surface."
            )

    # 3. No OTHER function may be a model-prefix table.
    for label, src in sources.values():
        for m in re.finditer(r"\bfn\s+([A-Za-z0-9_]+)\b", src):
            fn = m.group(1)
            if fn == CANONICAL:
                continue
            body = extract_fn_body(src, fn)
            if body and count_starts_with(body) > TABLE_THRESHOLD:
                errors.append(
                    f"`{fn}` in {label} carries a model-prefix table "
                    f"({count_starts_with(body)} `.starts_with(` arms). There must be "
                    f"exactly ONE ({CANONICAL}); delegate to it instead."
                )

    #    and NO default-to-a-provider may survive anywhere in provider/key resolution.
    #    Defaulting to a provider on an unmatched model is credential misrouting.
    canon_sig = re.search(rf"fn\s+{CANONICAL}\s*\([^)]*\)\s*->\s*([^\{{]+)\{{", mod_src)
    if not canon_sig or "Option" not in canon_sig.group(1):
        errors.append(
            f"`{CANONICAL}` must return `Option<&'static str>` (fail closed on "
            f"an unmatched model), not a bare `&str` that forces a default provider."
        )
    FORBIDDEN = [
        (
            r'_\s*=>\s*"anthropic"',
            '`_ => "anthropic"` default in the model→provider map',
        ),
        (
            r'_\s*=>\s*"ANTHROPIC_API_KEY"',
            '`_ => "ANTHROPIC_API_KEY"` default in the key-env map',
        ),
        (
            r"_\s*=>\s*registry\.\w+\.chat",
            "`_ => registry.<provider>.chat` default in the dispatch",
        ),
        (
            r'unwrap_or\(\s*"anthropic"',
            '`unwrap_or("anthropic")` — a defaulted provider',
        ),
        (
            r'unwrap_or\(\s*"ANTHROPIC_API_KEY"',
            '`unwrap_or("ANTHROPIC_API_KEY")` — a defaulted key env',
        ),
    ]

    # strip line comments (but keep `://` in URLs) so a pattern quoted in a
    # comment doesn't false-positive.
    def strip_comments(s: str) -> str:
        return re.sub(r"(?<!:)//[^\n]*", "", s)

    for label, src in (
        (mod_label, strip_comments(mod_src)),
        (server_label, strip_comments(server_src)),
    ):
        for pat, desc in FORBIDDEN:
            if re.search(pat, src):
                errors.append(
                    f"fail-closed VIOLATED in {label}: {desc}. "
                    f"An unmatched model/provider must fail closed (typed unroutable "
                    f"error), never route to a default provider's key."
                )

    return errors


# ── selftest fixtures ─────────────────────────────────────────────────────────
# Synthetic Rust with the same shapes the guard parses. Small enough to read; the
# violations below are each planted by string-substituting ONE of these.

_PREFIX_ARMS = "\n".join(
    f'        if model.starts_with("m{i}-") {{ return Some("p{i}"); }}'
    for i in range(6)
)

CLEAN_MOD = f"""//! fixture providers/mod.rs
impl ProviderRegistry {{
    pub fn provider_id_for_model(model: &str) -> Option<&'static str> {{
{_PREFIX_ARMS}
        None
    }}

    pub fn env_var_for_provider_id(provider_id: &str) -> &'static str {{
        match provider_id {{
            "p0" => "P0_API_KEY",
            _ => "",
        }}
    }}
}}

fn api_key_env_var(model: &str) -> Option<&'static str> {{
    let id = ProviderRegistry::provider_id_for_model(model)?;
    Some(ProviderRegistry::env_var_for_provider_id(id))
}}
"""

CLEAN_SERVER = """//! fixture server.rs
fn provider_name_from_model(model: &str) -> &'static str {
    ProviderRegistry::provider_id_for_model(model).unwrap_or("unknown")
}

fn dispatch_to_provider(model: &str, registry: &ProviderRegistry) -> Result<Resp, Err> {
    let id = ProviderRegistry::provider_id_for_model(model)
        .ok_or(Err::UnroutableModel)?;
    match id {
        "p0" => registry.p0.chat(),
        _ => Err(Err::UnroutableModel),
    }
}
"""


def selftest() -> int:
    """Plant each violation this guard exists to catch and assert it blocks."""
    ok = True

    def case(name: str, mod_src: str, server_src: str, expect: str | None) -> None:
        """expect=None means the input is clean and MUST produce no errors."""
        nonlocal ok
        errors = run(mod_src, server_src, "fixture-mod.rs", "fixture-server.rs")
        if expect is None:
            if errors:
                print(f"SELFTEST FAIL: {name} — clean input flagged: {errors}")
                ok = False
                return
        else:
            if not any(expect in e for e in errors):
                print(
                    f"SELFTEST FAIL: {name} — no error containing {expect!r}; "
                    f"got {errors}"
                )
                ok = False
                return
        print(f"  ✓ {name}")

    # THE NEGATIVE, first. A guard that fails on everything would otherwise look
    # correct for every planted violation below.
    case("clean single-source layout passes", CLEAN_MOD, CLEAN_SERVER, None)

    rogue = CLEAN_SERVER.replace(
        '    ProviderRegistry::provider_id_for_model(model).unwrap_or("unknown")',
        '    if model.starts_with("llama") { return "groq"; }\n'
        '    ProviderRegistry::provider_id_for_model(model).unwrap_or("unknown")',
    )
    case(
        "delegate reintroduces .starts_with model matching -> caught",
        CLEAN_MOD,
        rogue,
        "`provider_name_from_model` reintroduced model-prefix matching",
    )

    # A delegate that stops consulting the canonical map at all.
    orphan = CLEAN_SERVER.replace(
        'ProviderRegistry::provider_id_for_model(model).unwrap_or("unknown")',
        'lookup_elsewhere(model).unwrap_or("unknown")',
    )
    case(
        "delegate stops delegating -> caught",
        CLEAN_MOD,
        orphan,
        "must DELEGATE to `provider_id_for_model(`",
    )

    # A brand-new SECOND prefix table elsewhere in the file (over threshold).
    second_table = "\n".join(
        f'    if model.starts_with("q{i}-") {{ return "p{i}"; }}'
        for i in range(TABLE_THRESHOLD + 1)
    )
    case(
        "a second model-prefix table anywhere -> caught",
        CLEAN_MOD,
        CLEAN_SERVER
        + f"\nfn shadow_router(model: &str) -> &'static str {{\n{second_table}\n"
        '    "p0"\n}\n',
        "`shadow_router` in fixture-server.rs carries a model-prefix table",
    )

    # The canonical map must EXIST and still BE a prefix table.
    case(
        "canonical map deleted -> caught",
        CLEAN_MOD.replace("provider_id_for_model", "gone_id_for_model"),
        CLEAN_SERVER,
        f"MISSING canonical `{CANONICAL}`",
    )
    thin = CLEAN_MOD.replace(
        _PREFIX_ARMS, '        if model.starts_with("m0-") { return Some("p0"); }'
    )
    case(
        "canonical map hollowed out below the table threshold -> caught",
        thin,
        CLEAN_SERVER,
        "no longer looks like the model-prefix table",
    )

    open_sig = CLEAN_MOD.replace(
        "pub fn provider_id_for_model(model: &str) -> Option<&'static str> {",
        "pub fn provider_id_for_model(model: &str) -> &'static str {",
    )
    case(
        "canonical map stops returning Option -> caught",
        open_sig,
        CLEAN_SERVER,
        "must return `Option<&'static str>`",
    )

    for planted, needle, where in (
        ('    _ => "anthropic",\n', '`_ => "anthropic"` default', "mod"),
        (
            '    _ => "ANTHROPIC_API_KEY",\n',
            '`_ => "ANTHROPIC_API_KEY"` default',
            "mod",
        ),
        (
            "    _ => registry.anthropic.chat(),\n",
            "`_ => registry.<provider>.chat`",
            "server",
        ),
        ('    let p = x.unwrap_or("anthropic");\n', '`unwrap_or("anthropic")`', "mod"),
        (
            '    let k = x.unwrap_or("ANTHROPIC_API_KEY");\n',
            '`unwrap_or("ANTHROPIC_API_KEY")`',
            "server",
        ),
    ):
        m = CLEAN_MOD + (f"fn leak() {{\n{planted}}}\n" if where == "mod" else "")
        s = CLEAN_SERVER + (f"fn leak() {{\n{planted}}}\n" if where == "server" else "")
        case(f"fail-closed: {needle} -> caught", m, s, "fail-closed VIOLATED")

    # ...but the same text inside a COMMENT must NOT fire — the strip-comments
    # pass exists precisely so documenting the banned pattern is not a violation.
    case(
        "banned default quoted in a comment does NOT fire",
        CLEAN_MOD + '\n// never write `_ => "anthropic"` here\n',
        CLEAN_SERVER,
        None,
    )

    print("selftest PASSED." if ok else "selftest FAILED.")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Guard: exactly ONE model→provider prefix table, fail-closed."
    )
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="plant each violation in synthetic Rust and prove the guard blocks",
    )
    args = ap.parse_args()  # unknown flags -> argparse exits 2 with usage
    if args.selftest:
        return selftest()

    errors = run(
        MOD_RS.read_text(encoding="utf-8"),
        SERVER_RS.read_text(encoding="utf-8"),
        MOD_RS.relative_to(REPO).as_posix(),
        SERVER_RS.relative_to(REPO).as_posix(),
    )

    if errors:
        print("FAIL: provider-mapping single-source + fail-closed guard\n")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(
        f"OK: single model→provider table ({CANONICAL}, returns Option/fail-closed); "
        f"{', '.join(DELEGATES)} delegate; no default-to-provider (guard)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
