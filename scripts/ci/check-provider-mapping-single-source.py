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
"""

from __future__ import annotations

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
# delegate fn name -> the file it lives in
DELEGATES = {
    "api_key_env_var": MOD_RS,
    "provider_name_from_model": SERVER_RS,
    "dispatch_to_provider": SERVER_RS,
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


def main() -> int:
    errors: list[str] = []
    mod_src = MOD_RS.read_text(encoding="utf-8")
    server_src = SERVER_RS.read_text(encoding="utf-8")

    # 1. The canonical table must exist and BE a prefix table.
    canon = extract_fn_body(mod_src, CANONICAL)
    if canon is None:
        errors.append(f"MISSING canonical `{CANONICAL}` in {MOD_RS.relative_to(REPO)}")
    elif count_starts_with(canon) < TABLE_THRESHOLD:
        errors.append(
            f"`{CANONICAL}` no longer looks like the model-prefix table "
            f"({count_starts_with(canon)} `.starts_with(` < {TABLE_THRESHOLD})"
        )

    # 2. Each delegate must call the canonical fn and NOT prefix-match models.
    for name, path in DELEGATES.items():
        src = mod_src if path == MOD_RS else server_src
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
    for path, src in ((MOD_RS, mod_src), (SERVER_RS, server_src)):
        for m in re.finditer(r"\bfn\s+([A-Za-z0-9_]+)\b", src):
            fn = m.group(1)
            if fn == CANONICAL:
                continue
            body = extract_fn_body(src, fn)
            if body and count_starts_with(body) > TABLE_THRESHOLD:
                errors.append(
                    f"`{fn}` in {path.relative_to(REPO)} carries a model-prefix table "
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

    for path, src in (
        (MOD_RS, strip_comments(mod_src)),
        (SERVER_RS, strip_comments(server_src)),
    ):
        for pat, desc in FORBIDDEN:
            if re.search(pat, src):
                errors.append(
                    f"fail-closed VIOLATED in {path.relative_to(REPO)}: {desc}. "
                    f"An unmatched model/provider must fail closed (typed unroutable "
                    f"error), never route to a default provider's key."
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
