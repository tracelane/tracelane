#!/usr/bin/env python3
"""Assert every routable provider can actually accept a BYOK key (B-145).

Why this exists: the gateway routed more providers than a customer could store a
key for — the BYOK upload allowlist (`is_known_provider`) listed only 31 and the
dashboard dropdown only 30. Groq, Together, Fireworks and OpenRouter routed fine
yet `POST /v1/byok/provider-keys` rejected them with 400 "unknown provider_id",
so a customer could not store a key for them at all — they were reachable only
via the server-side env-var fallback, which is not a customer path in hosted
BYOK. Vertex was allowlisted by the gateway but absent from the dropdown, so it
could not be added from the dashboard either.

**Routed must equal usable must equal offered.** Three lists, each of which
looks complete on its own — which is exactly the shape that rots silently.

## The four sources, after GWY-42

The 163 OpenAI-compatible providers now live in `crates/gateway/providers.tsv`
and resolve through `providers::catalog`. Only the SIX native adapters
(anthropic, google, vertex, bedrock, azure, cohere) are still hand-written arms,
so the lists this guard compares are:

  routable  = native ids in `provider_id_for_model`'s native `match`
              UNION every id in providers.tsv
  storable  = native ids in `is_known_provider`'s `matches!`
              UNION the catalog, but ONLY because the source visibly contains
              `|| catalog::by_id(p).is_some()`. No clause -> the guard FAILS
              rather than assuming coverage
  env       = native ids with an explicit `env_var_for_provider_id` arm
  offerable = the ids behind ProviderKeyManager's `PROVIDERS` dropdown, whether
              that is an inline const or (today) a generated module it imports

**Be honest about what is now covered by construction.** Both `routable` and
`storable` contain the whole catalog, so those halves cancel: no TSV row can be
routable-but-not-storable while that `||` clause stands, and the guard's job
there is to prove the clause EXISTS. The drift that remains genuinely possible
is the NATIVE half — six ids repeated across three files — plus the whole
dropdown, which is a separate artifact that has to be regenerated.

## What "the dropdown" means, and why the guard follows the import

GWY-42 replaced the hand-written TS array with
`provider-catalog.generated.ts`, generated from the same TSV. The guard resolves
`PROVIDERS` the way the compiler does: an inline const if there is one,
otherwise the relative module the component imports it from. If a later change
serves the list from `GET /v1/providers` instead, the leg is dropped WITH A
NOTICE — never silently — and if the ids cannot be traced to any of those, the
guard fails, because it cannot then tell a covered dropdown from an empty one.

A provider with no API key env var in the TSV (Ollama is local) is exempt from
the dropdown requirement only: there is no key to store from the UI, though it
stays storable so a self-host can.

Exit 0 = every routable provider can be stored and offered. Exit 1 = drift, or
the guard's own parsing has rotted. `--selftest` plants every direction in
synthetic sources and proves both that each blocks and that a clean world passes.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[2]
MOD_RS = ROOT / "crates/gateway/src/providers/mod.rs"
BYOK_RS = ROOT / "crates/gateway/src/byok_api/provider_keys_api.rs"
CATALOG_TSV = ROOT / "crates/gateway/providers.tsv"
UI_TSX = ROOT / "apps/web/components/settings/ProviderKeyManager.tsx"

# The generated catalog's column order, asserted against the header row so a
# reordered column is caught instead of silently reading the wrong field.
TSV_COLUMNS = ("id", "label", "base_url", "base_url_env", "api_key_env", "prefixes")

# Floors, not targets. A guard that parses zero things and reports OK is the
# defect class this repo calls a broken parser, so smallness is fatal.
MIN_CATALOG = 100
MIN_NATIVE = 4
MIN_ROUTABLE = 100

ID_RE = r"[a-z0-9][a-z0-9._-]*"


def die(msg: str) -> NoReturn:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


# ── parsers ───────────────────────────────────────────────────────────────────


def catalog_rows(tsv: str) -> list[list[str]]:
    """Rows of providers.tsv, skipped exactly as `catalog::parse` skips them.

    Mirrors the Rust (`catalog.rs`: blank, `#`, and the `id\\t` header line) so
    the guard's idea of the catalog cannot differ from the gateway's.
    """
    rows: list[list[str]] = []
    header_seen = False
    for raw in tsv.splitlines():
        line = raw.rstrip("\r")
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if fields[0] == "id":
            if tuple(fields) != TSV_COLUMNS:
                die(
                    "providers.tsv header changed — the guard reads columns by position "
                    f"like the Rust does. expected {TSV_COLUMNS}, got {tuple(fields)}"
                )
            header_seen = True
            continue
        if len(fields) != len(TSV_COLUMNS):
            die(
                f"providers.tsv malformed row (expected {len(TSV_COLUMNS)} tab-separated "
                f"fields, got {len(fields)}): {line}"
            )
        rows.append(fields)
    if not header_seen:
        die(
            "providers.tsv has no `id\\t…` header row — the guard cannot trust its columns"
        )
    if not rows:
        die(
            "providers.tsv parsed to zero providers — the guard's TSV reader has rotted"
        )
    return rows


def catalog_ids(rows: list[list[str]]) -> set[str]:
    ids = {r[0] for r in rows}
    if len(ids) != len(rows):
        counts = Counter(r[0] for r in rows)
        dupes = sorted(i for i, n in counts.items() if n > 1)
        die(
            f"providers.tsv has duplicate ids (the Rust id map would keep only one): {dupes}"
        )
    bad = sorted(i for i in ids if not re.fullmatch(ID_RE, i))
    if bad:
        die(f"providers.tsv ids do not look like provider ids — column shift? {bad}")
    return ids


def catalog_keyless(rows: list[list[str]]) -> set[str]:
    """Catalog ids with no API-key env var — local providers needing no key."""
    bad = sorted(
        r[4] for r in rows if r[4] and not re.fullmatch(r"[A-Z0-9][A-Z0-9_]*", r[4])
    )
    if bad:
        die(
            f"providers.tsv api_key_env column does not hold env-var names — column shift? {bad}"
        )
    return {r[0] for r in rows if not r[4].strip()}


def native_route_ids(src: str) -> set[str]:
    """Native adapter ids from `provider_id_for_model`'s native `match`."""
    anchor = re.search(r"fn provider_id_for_model\b", src)
    if not anchor:
        die("could not locate `fn provider_id_for_model` in providers/mod.rs")
    block = re.search(r"match model \{(.*?)\n\s+\};", src[anchor.end() :], re.DOTALL)
    if not block:
        die(
            "could not locate the native `match model { … };` block inside "
            "`provider_id_for_model` — the native adapters are no longer parseable"
        )
    ids = set(re.findall(rf'=>\s*Some\("({ID_RE})"\)', block.group(1)))
    if not ids:
        die(
            "the native `match model` block yielded 0 provider ids — the guard's regex has rotted"
        )
    return ids


def native_env_ids(src: str) -> set[str]:
    """Native ids with an explicit `env_var_for_provider_id` arm.

    These arms are matched BEFORE the catalog fall-through, so a native that
    routes without an arm here resolves through `catalog::api_key_env(..)` — and
    the catalog holds no row for a native adapter, so the env var comes back "".
    """
    anchor = re.search(r"fn env_var_for_provider_id\b", src)
    if not anchor:
        die("could not locate `fn env_var_for_provider_id` in providers/mod.rs")
    block = re.search(
        r"match provider_id \{(.*?)\n\s+\}", src[anchor.end() :], re.DOTALL
    )
    if not block:
        die(
            "could not locate the `match provider_id { … }` block in `env_var_for_provider_id`"
        )
    ids = set(re.findall(rf'"({ID_RE})"\s*=>\s*"', block.group(1)))
    if not ids:
        die(
            "`env_var_for_provider_id` yielded 0 native arms — the guard's regex has rotted"
        )
    return ids


def storable_natives(src: str) -> set[str]:
    """Native ids in `is_known_provider`'s `matches!`, proving the catalog clause.

    The catalog clause is NOT assumed. If `|| catalog::by_id(p).is_some()` is not
    visibly in the body the guard fails: without it the BYOK gate rejects every
    catalog provider, which is B-145 restaged at 163× the size.
    """
    fn = re.search(
        r"\nfn is_known_provider\s*\(\s*(\w+)\s*:[^\n]*\{\n(.*?)\n\}\n", src, re.DOTALL
    )
    if not fn:
        die("could not locate `fn is_known_provider` in provider_keys_api.rs")
    param, body = fn.group(1), fn.group(2)

    matches = re.search(r"matches!\(([^()]*)\)", body, re.DOTALL)
    if not matches:
        die("`is_known_provider` no longer contains a `matches!` over the native ids")
    if not re.match(rf"\s*{re.escape(param)}\s*,", matches.group(1)):
        die(f"`is_known_provider`'s `matches!` does not test its parameter `{param}`")

    if not re.search(
        rf"\|\|\s*(?:crate::)?(?:providers::)?catalog::by_id\(\s*{re.escape(param)}\s*\)"
        rf"\s*\.is_some\(\)",
        body,
    ):
        die(
            "`is_known_provider` has no `|| catalog::by_id(p).is_some()` clause — the guard "
            "will NOT assume the catalog is storable. Either the BYOK gate now rejects all "
            "163 catalog providers, or it derives them some other way this guard must be "
            "taught to read"
        )

    ids = set(re.findall(rf'"({ID_RE})"', matches.group(1)))
    if not ids:
        die(
            "`is_known_provider`'s `matches!` yielded 0 native ids — the guard's regex has rotted"
        )
    return ids


def _array_ids(text: str, what: str) -> set[str]:
    ids = set(re.findall(rf'id:\s*"({ID_RE})"', text))
    if not ids:
        die(
            f"{what} parsed to 0 provider ids — the guard's regex has rotted, or the list is empty"
        )
    return ids


def dropdown_ids(tsx_src: str, tsx_path: Path) -> tuple[set[str] | None, str]:
    """The ids behind the BYOK dropdown, resolved the way the compiler resolves them.

    Returns `(ids, where)`, or `(None, where)` once the list is served by
    `GET /v1/providers` — a dropped leg is announced on stderr, never silent.
    """
    inline = re.search(r"const PROVIDERS\b[^=]*=\s*\[(.*?)\n\];", tsx_src, re.DOTALL)
    if inline:
        return _array_ids(
            inline.group(1), "the inline `const PROVIDERS`"
        ), "inline const"

    imported = re.search(
        r'import\s*\{[^}]*\bPROVIDERS\b[^}]*\}\s*from\s*["\']([^"\']+)["\']',
        tsx_src,
        re.DOTALL,
    )
    if imported:
        spec = imported.group(1)
        if not spec.startswith("."):
            die(
                f"`PROVIDERS` is imported from the non-relative module `{spec}`, which this "
                "guard cannot resolve. Teach it the path, do not leave the dropdown unchecked"
            )
        for ext in ("", ".ts", ".tsx"):
            mod_path = (tsx_path.parent / (spec + ext)).resolve()
            if mod_path.is_file():
                break
        else:
            die(
                f"`PROVIDERS` is imported from `{spec}` but no such file exists next to {tsx_path.name}"
            )
        body = re.search(
            r"export const PROVIDERS\b[^=]*=\s*\[(.*?)\n\];",
            mod_path.read_text(encoding="utf-8"),
            re.DOTALL,
        )
        if not body:
            die(
                f"{mod_path.name} does not export a `PROVIDERS = [ … ];` array the guard can read"
            )
        return _array_ids(body.group(1), mod_path.name), mod_path.name

    if "/v1/providers" in tsx_src:
        print(
            "NOTE: ProviderKeyManager.tsx no longer holds or imports a `PROVIDERS` list and "
            "now reads `GET /v1/providers`. The dropdown leg of this guard is DROPPED — the "
            "endpoint serves the gateway's own catalog, so that drift is gone by construction. "
            "Routable-vs-storable is still enforced below.",
            file=sys.stderr,
        )
        return None, "GET /v1/providers"

    die(
        "ProviderKeyManager.tsx neither declares, imports, nor fetches a `PROVIDERS` list — "
        "the dropdown's source of ids cannot be found, so this guard cannot tell a covered "
        "dropdown from an empty one"
    )


def featured_ids(tsx_src: str) -> set[str]:
    """The `POPULAR` above-the-fold ids, which are looked up in `PROVIDERS`.

    The lookup `.map(…).filter(p => p !== undefined)` DROPS an id that is not in
    the catalog, so a stale entry here vanishes from the UI with no error at all.
    An empty set (no such const) is a real answer: nothing to check.
    """
    block = re.search(r"const POPULAR\b[^=]*=\s*\[(.*?)\n\]", tsx_src, re.DOTALL)
    return set(re.findall(rf'"({ID_RE})"', block.group(1))) if block else set()


# ── the property ──────────────────────────────────────────────────────────────


def assert_plausible(catalog: set[str], natives: set[str], routable: set[str]) -> None:
    """Refuse a vacuous pass. A guard judging three things and printing OK is the defect."""
    if len(catalog) < MIN_CATALOG:
        die(
            f"parsed only {len(catalog)} catalog providers (< {MIN_CATALOG}) — providers.tsv shrank or the reader rotted"
        )
    if len(natives) < MIN_NATIVE:
        die(
            f"parsed only {len(natives)} native adapters (< {MIN_NATIVE}) — the native `match` reader rotted"
        )
    if len(routable) < MIN_ROUTABLE:
        die(
            f"parsed only {len(routable)} routable providers (< {MIN_ROUTABLE}) — the guard would be judging nothing"
        )


def compare(
    routable: set[str],
    storable: set[str],
    natives: set[str],
    env: set[str],
    catalog: set[str],
    keyless: set[str],
    ui: set[str] | None,
    featured: set[str],
) -> list[str]:
    """Every coverage gap between the lists, in both directions.

    Split out from the file reads so the selftest can plant each gap directly
    instead of editing the gateway or the dashboard.
    """
    failures = []

    missing_store = sorted(routable - storable)
    if missing_store:
        failures.append(
            "these providers ROUTE but cannot accept a BYOK key "
            f"(add to `is_known_provider`): {', '.join(missing_store)}"
        )

    missing_env = sorted(natives - env)
    if missing_env:
        failures.append(
            "these NATIVE adapters route but have no `env_var_for_provider_id` arm, so their "
            "key lookup falls through to the catalog — which holds no row for a native "
            f"adapter — and resolves to an empty env var: {', '.join(missing_env)}"
        )

    shadowed = sorted(catalog & natives)
    if shadowed:
        failures.append(
            "these ids are BOTH a native adapter and a providers.tsv row — the native arm is "
            "matched first, so the catalog row's api_key_env is dead and a key stored for it "
            f"resolves elsewhere: {', '.join(shadowed)}"
        )

    if ui is not None:
        missing_ui = sorted((routable - keyless) - ui)
        if missing_ui:
            failures.append(
                "these providers accept a key but are NOT offered in the dashboard, so a "
                "customer cannot add one from it (regenerate the provider catalog): "
                f"{', '.join(missing_ui)}"
            )

        unknown_ui = sorted(ui - routable)
        if unknown_ui:
            failures.append(
                "the dashboard offers providers the gateway cannot route "
                f"(upload would 400): {', '.join(unknown_ui)}"
            )

        missing_featured = sorted(featured - ui)
        if missing_featured:
            failures.append(
                "these ids are listed as above-the-fold favourites but are not in the "
                "dropdown's catalog, so the lookup drops them with no error: "
                f"{', '.join(missing_featured)}"
            )

    return failures


# ── selftest fixtures ─────────────────────────────────────────────────────────
# Same shapes the parsers expect, small enough to reason about. The fixtures go
# through the REAL parsers, so a regex that rots against these shapes is caught
# here too — not just the set comparison.


def _fixture_mod(route: list[str], env: dict[str, str]) -> str:
    arms = "\n".join(
        f'            m if m.starts_with("{i}/") => Some("{i}"),' for i in route
    )
    env_arms = "\n".join(f'            "{k}" => "{v}",' for k, v in env.items())
    return (
        "impl ProviderRegistry {\n"
        "    pub fn provider_id_for_model(model: &str) -> Option<&'static str> {\n"
        "        let native = match model {\n"
        f"{arms}\n"
        "            _ => None,\n"
        "        };\n"
        "        if native.is_some() {\n"
        "            return native;\n"
        "        }\n"
        "        catalog::provider_id_for_model(model)\n"
        "    }\n"
        "\n"
        "    pub fn env_var_for_provider_id(provider_id: &str) -> &'static str {\n"
        "        match provider_id {\n"
        f"{env_arms}\n"
        '            other => catalog::api_key_env(other).unwrap_or(""),\n'
        "        }\n"
        "    }\n"
        "}\n"
    )


def _fixture_tsv(rows: list[tuple[str, str]]) -> str:
    """`rows` is (id, api_key_env); an empty env means a keyless provider."""
    out = ["# GENERATED — DO NOT EDIT BY HAND.", "\t".join(TSV_COLUMNS)]
    for pid, key_env in rows:
        out.append(
            f"{pid}\t{pid.title()}\thttps://api.{pid}.test\t{pid.upper()}_BASE_URL\t{key_env}\t{pid}/"
        )
    return "\n".join(out) + "\n"


def _fixture_byok(natives: list[str], *, catalog_clause: bool = True) -> str:
    arms = " | ".join(f'"{i}"' for i in natives)
    tail = (
        "\n        || crate::providers::catalog::by_id(p).is_some()"
        if catalog_clause
        else ""
    )
    return f"\nfn is_known_provider(p: &str) -> bool {{\n    matches!(p, {arms}){tail}\n}}\n"


def _fixture_generated(ids: list[str]) -> str:
    rows = "\n".join(f'\t{{ id: "{i}", label: "{i.title()}" }},' for i in ids)
    return (
        "// GENERATED — DO NOT EDIT BY HAND.\n"
        "export const PROVIDERS: ReadonlyArray<CatalogProvider> = [\n"
        f"{rows}\n"
        "];\n"
    )


def _fixture_tsx_importing(
    featured: list[str], module: str = "./provider-catalog.generated"
) -> str:
    pop = "\n".join(f'\t"{i}",' for i in featured)
    return (
        f'import {{ type CatalogProvider, PROVIDERS, PROVIDER_LABEL }} from "{module}";\n'
        "\nconst POPULAR = [\n"
        f"{pop}\n"
        "] as const;\n"
    )


def _fixture_tsx_inline(ids: list[str]) -> str:
    rows = "\n".join(f'\t{{ id: "{i}", label: "{i.title()}" }},' for i in ids)
    return (
        "const PROVIDERS: ReadonlyArray<{ id: string; label: string }> = [\n"
        f"{rows}\n"
        "];\n"
    )


def _dies(fn, *args) -> tuple[bool, str]:
    """Run `fn`, reporting whether it exited non-zero, plus what it printed."""
    buf = io.StringIO()
    try:
        with contextlib.redirect_stderr(buf):
            fn(*args)
    except SystemExit as e:
        return e.code != 0, buf.getvalue().strip()
    return False, "returned instead of exiting"


def selftest() -> int:
    """Plant each drift direction and assert the guard reports it."""
    ok = True

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok
        if cond:
            print(f"  ✓ {name}")
        else:
            print(f"SELFTEST FAIL: {name}{(' — ' + detail) if detail else ''}")
            ok = False

    # A small but complete world -- provider-count-exempt: 3 native adapters,
    # 4 catalog rows (one keyless), all storable, and a generated dropdown
    # holding all of them except the keyless one. These counts describe the
    # FIXTURE, not the real tree.
    natives = ["anthropic", "vertex", "cohere"]
    env = {i: f"{i.upper()}_API_KEY" for i in natives}
    cat_rows = [
        ("openai", "OPENAI_API_KEY"),
        ("groq", "GROQ_API_KEY"),
        ("ollama", ""),
        ("moonshot", "MOONSHOT_API_KEY"),
    ]
    cat = [r[0] for r in cat_rows]
    featured = ["anthropic", "openai"]
    offered = [*natives, "openai", "groq", "moonshot"]

    mod_src = _fixture_mod(natives, env)
    byok_src = _fixture_byok(natives)

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "provider-catalog.generated.ts").write_text(_fixture_generated(offered))
        tsx = d / "ProviderKeyManager.tsx"
        tsx.write_text(_fixture_tsx_importing(featured))

        # 1. The parsers must actually parse these shapes. A regex that rots and
        #    returns an empty set would make every comparison below vacuously pass.
        rows = catalog_rows(_fixture_tsv(cat_rows))
        cat_ids = catalog_ids(rows)
        keyless = catalog_keyless(rows)
        nat_route = native_route_ids(mod_src)
        nat_env = native_env_ids(mod_src)
        nat_store = storable_natives(byok_src)
        ui, where = dropdown_ids(tsx.read_text(), tsx)
        feat = featured_ids(tsx.read_text())
        check(
            "parsers extract ids from all four sources",
            cat_ids == set(cat)
            and keyless == {"ollama"}
            and nat_route == set(natives)
            and nat_env == set(natives)
            and nat_store == set(natives)
            and ui == set(offered)
            and feat == set(featured),
            f"cat={sorted(cat_ids)} keyless={sorted(keyless)} route={sorted(nat_route)} "
            f"env={sorted(nat_env)} store={sorted(nat_store)} ui={ui and sorted(ui)} "
            f"where={where} featured={sorted(feat)}",
        )

        # 2. The guard must FOLLOW the import, not just find a file. A dropdown
        #    whose ids cannot be traced is unchecked, and must not read as clean.
        for label, src in (
            ("import target missing", _fixture_tsx_importing(featured, "./not-there")),
            (
                "non-relative import",
                _fixture_tsx_importing(featured, "@/lib/providers"),
            ),
        ):
            bad = d / "Bad.tsx"
            bad.write_text(src)
            died, msg = _dies(dropdown_ids, bad.read_text(), bad)
            check(f"{label} -> fatal", died, msg)

        no_export = d / "Empty.tsx"
        no_export.write_text(_fixture_tsx_importing(featured, "./no-export"))
        (d / "no-export.ts").write_text("export const SOMETHING_ELSE = [];\n")
        died, msg = _dies(dropdown_ids, no_export.read_text(), no_export)
        check("imported module without a PROVIDERS export -> fatal", died, msg)

        # 3. The pre-GWY-42 inline const still parses, so reverting the dropdown
        #    to a hand-written array does not silently disable this leg.
        inline = d / "Inline.tsx"
        inline.write_text(_fixture_tsx_inline(offered))
        inline_ui, inline_where = dropdown_ids(inline.read_text(), inline)
        check(
            "inline `const PROVIDERS` still parses",
            inline_ui == set(offered) and inline_where == "inline const",
            f"ui={inline_ui and sorted(inline_ui)} where={inline_where}",
        )

        # 4. The endpoint shape: leg dropped, but ANNOUNCED. A leg nobody is
        #    told about is indistinguishable from a passing one.
        buf = io.StringIO()
        endpoint = d / "Endpoint.tsx"
        endpoint.write_text("await apiFetch(`/v1/providers`);\n")
        with contextlib.redirect_stderr(buf):
            ep_ui, ep_where = dropdown_ids(endpoint.read_text(), endpoint)
        check(
            "dropdown served by `/v1/providers` -> leg dropped WITH a notice",
            ep_ui is None
            and "DROPPED" in buf.getvalue()
            and ep_where == "GET /v1/providers",
            f"ui={ep_ui!r} where={ep_where} stderr={buf.getvalue().strip()!r}",
        )

        # 5. No list at all, from anywhere -> fatal, never a quiet pass.
        nothing = d / "Nothing.tsx"
        nothing.write_text("export function ProviderKeyManager() { return null; }\n")
        died, msg = _dies(dropdown_ids, nothing.read_text(), nothing)
        check("dropdown with no traceable list -> fatal", died, msg)

    routable = nat_route | cat_ids
    storable = nat_store | cat_ids

    def cmp(**over):
        """`compare` over the consistent world, with one list swapped out."""
        return compare(
            **{
                "routable": routable,
                "storable": storable,
                "natives": nat_route,
                "env": nat_env,
                "catalog": cat_ids,
                "keyless": keyless,
                "ui": ui,
                "featured": feat,
            }
            | over
        )

    # 6. THE NEGATIVE: a consistent world must PASS. Without this, a guard that
    #    fails on every input would look correct for every case below.
    check("consistent world passes", cmp() == [], str(cmp()))

    # 7. in the post-GWY-42 shape: a NATIVE adapter routes but is missing
    #    from `is_known_provider`'s matches!, so its upload 400s. (The catalog
    #    half cannot drift while the `||` clause stands — case 8 guards that.)
    thin = (
        storable_natives(_fixture_byok([i for i in natives if i != "vertex"])) | cat_ids
    )
    f = cmp(storable=thin)
    check(
        "native provider missing from the BYOK allowlist -> caught",
        any("cannot accept a BYOK key" in x and "vertex" in x for x in f),
        str(f),
    )

    # 8. The clause the whole catalog leg rests on. If it is gone the guard must
    #    FAIL, never quietly keep crediting the whole catalog as storable.
    died, msg = _dies(storable_natives, _fixture_byok(natives, catalog_clause=False))
    check(
        "missing `catalog::by_id(p).is_some()` clause -> guard fails, not assumes",
        died,
        msg,
    )

    # 9. A native that routes with no `env_var_for_provider_id` arm resolves to
    #    an empty env var through the catalog fall-through — silently keyless.
    f = cmp(env=nat_env - {"cohere"})
    check(
        "native routes but has no env-var arm -> caught",
        any("empty env var" in x and "cohere" in x for x in f),
        str(f),
    )

    # 10. An id that is both a native arm and a catalog row: the native arm wins,
    #     so the row's api_key_env is dead and the stored key resolves elsewhere.
    f = cmp(catalog=cat_ids | {"vertex"})
    check(
        "catalog row colliding with a native id -> caught",
        any("BOTH a native adapter" in x and "vertex" in x for x in f),
        str(f),
    )

    # 11. The `vertex` half of: routable and storable, but absent from the
    #     dropdown, so it cannot be added from the dashboard.
    f = cmp(ui=ui - {"vertex"})
    check(
        "provider missing from the dashboard dropdown -> caught",
        any("NOT offered in the dashboard" in x and "vertex" in x for x in f),
        str(f),
    )

    # 12. The same, for a CATALOG row — the dropdown is generated, and a stale
    #     generated file is exactly how it goes out of step with the TSV.
    f = cmp(ui=ui - {"moonshot"})
    check(
        "catalog provider missing from the dropdown -> caught",
        any("NOT offered in the dashboard" in x and "moonshot" in x for x in f),
        str(f),
    )

    # 13. The ONE exemption is UI-only: a keyless provider may be absent from the
    #     dropdown (nothing to store), but dropping it from the ALLOWLIST must
    #     still fail — a self-host has to be able to store one.
    check(
        "keyless provider is exempt from the dropdown check",
        cmp(ui=ui - {"ollama"}) == [],
    )
    f = cmp(storable=storable - {"ollama"})
    check(
        "keyless provider is NOT exempt from the allowlist check",
        any("cannot accept a BYOK key" in x and "ollama" in x for x in f),
        str(f),
    )

    # 14. The opposite direction: the dropdown offers something the gateway
    #     cannot route, so the upload 400s from the other side.
    f = cmp(ui=ui | {"phantom"})
    check(
        "dashboard offers an unroutable provider -> caught",
        any("cannot route" in x and "phantom" in x for x in f),
        str(f),
    )

    # 15. A favourite that is not in the catalog is DROPPED by
    #     `.filter(p => p !== undefined)` — no error, just a shorter list.
    f = cmp(featured=feat | {"ghost"})
    check(
        "above-the-fold favourite missing from the catalog -> caught",
        any("above-the-fold" in x and "ghost" in x for x in f),
        str(f),
    )

    # 16. Vacuity floors: a shrunken catalog / native list / routable set must be
    #     fatal, because a guard judging three things and printing OK is the defect.
    big = {f"p{i}" for i in range(MIN_CATALOG + 20)}
    six = {"a", "b", "c", "d", "e", "f"}
    check(
        "plausible sizes pass the floors",
        not _dies(assert_plausible, big, six, big | six)[0],
    )
    for label, args in (
        ("catalog too small", ({"a", "b"}, six, big | six)),
        ("natives too small", (big, {"a"}, big | six)),
        ("routable too small", (big, six, {"a", "b"})),
    ):
        died, msg = _dies(assert_plausible, *args)
        check(f"{label} -> fatal", died, msg)

    # 17. Parser rot must be loud, not silent: a source whose anchor is gone must
    #     exit non-zero rather than yield an empty set that passes everything.
    for label, fn, bad in (
        ("native match", native_route_ids, "fn something_else() {}\n"),
        ("env-var match", native_env_ids, "fn something_else() {}\n"),
        ("allowlist", storable_natives, "\nfn other(p: &str) -> bool {\n    true\n}\n"),
        ("catalog tsv", catalog_rows, "# only a comment\n"),
    ):
        died, msg = _dies(fn, bad)
        check(f"{label} parser rot exits non-zero", died, msg)

    # 18. Structural TSV rot: a reordered or short row must not be read
    #     positionally as if nothing had happened.
    for label, bad in (
        (
            "reordered header",
            "label\tid\tbase_url\tbase_url_env\tapi_key_env\tprefixes\nx\ty\tz\tw\tv\tu\n",
        ),
        ("short row", "\t".join(TSV_COLUMNS) + "\nonlyid\tOnly\n"),
        ("no header", "groq\tGroq\thttps://g\tG_BASE\tG_KEY\tg/\n"),
        (
            "duplicate ids",
            "\t".join(TSV_COLUMNS) + "\ngroq\tA\tu\tB\tK\tg/\ngroq\tB\tu\tB\tK\th/\n",
        ),
    ):
        died, msg = _dies(lambda s: catalog_ids(catalog_rows(s)), bad)
        check(f"tsv {label} -> fatal", died, msg)

    print("selftest PASSED." if ok else "selftest FAILED.")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Assert every routable provider can accept a BYOK key (B-145)."
    )
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="plant coverage drift in synthetic sources and prove the guard blocks",
    )
    args = ap.parse_args()  # unknown flags -> argparse exits 2 with usage
    if args.selftest:
        return selftest()

    mod_src = MOD_RS.read_text(encoding="utf-8")
    tsx_src = UI_TSX.read_text(encoding="utf-8")
    rows = catalog_rows(CATALOG_TSV.read_text(encoding="utf-8"))

    catalog = catalog_ids(rows)
    keyless = catalog_keyless(rows)
    natives = native_route_ids(mod_src)
    env = native_env_ids(mod_src)
    storable = storable_natives(BYOK_RS.read_text(encoding="utf-8")) | catalog
    ui, where = dropdown_ids(tsx_src, UI_TSX)
    featured = featured_ids(tsx_src)

    routable = natives | catalog
    assert_plausible(catalog, natives, routable)

    failures = compare(routable, storable, natives, env, catalog, keyless, ui, featured)
    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        return 1

    offerable = where if ui is None else f"{len(ui)} from {where}"
    print(
        f"byok-provider-coverage OK — {len(routable)} routable "
        f"({len(natives)} native + {len(catalog)} catalog), {len(storable)} storable, "
        f"{offerable} offerable ({len(featured)} featured, {len(keyless)} keyless and "
        "exempt from the dropdown); every routable provider can accept a BYOK key"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
