#!/usr/bin/env python3
"""Assert every routable provider can actually accept a BYOK key.

Why this exists: the gateway routed 35+ providers, but the BYOK upload
allowlist (`is_known_provider`) listed only 31 and the dashboard dropdown only
30. Groq, Together, Fireworks and OpenRouter routed fine yet
`POST /v1/byok/provider-keys` rejected them with 400 "unknown provider_id", so a
customer could not store a key for them at all — they were reachable only via the
server-side env-var fallback, which is not a customer path in hosted BYOK. Vertex
was allowlisted by the gateway but absent from the dropdown, so it could not be
added from the dashboard either.

Three hand-maintained lists that must agree is exactly the shape that rots
silently: each one looks complete on its own. So the source of truth is the
registry's `env_var_for_provider_id` match — every provider id the router can dispatch to
and needs a credential for — and both consumer lists are checked against it.

  routable  = provider ids in `ProviderRegistry::env_var_for_provider_id`
  allowlist = ids accepted by `is_known_provider` (BYOK upload gate)
  ui        = ids offered by ProviderKeyManager's PROVIDERS dropdown

`ollama` is exempt from the UI check only: it is local and needs no key
(`"ollama" => ""`), though it stays allowlisted so a self-host can store one.

Exit 0 = every routable provider can be stored and is offerable. Exit 1 = drift.
`--selftest` plants each drift direction in synthetic sources and proves it blocks.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import re
import sys
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[2]
MOD_RS = ROOT / "crates/gateway/src/providers/mod.rs"
BYOK_RS = ROOT / "crates/gateway/src/byok_api/provider_keys_api.rs"
UI_TSX = ROOT / "apps/web/components/settings/ProviderKeyManager.tsx"

# Local provider — no credential to store, so not required in the dropdown.
NO_KEY_NEEDED = {"ollama"}


def die(msg: str) -> NoReturn:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def routable_ids(src: str) -> set[str]:
    """Provider ids from the `env_var_for_provider_id` match — the single source."""
    body = re.search(r"fn env_var_for_provider_id\b(.*?)\n    \}\n", src, re.DOTALL)
    if not body:
        die("could not locate `fn env_var_for_provider_id` in providers/mod.rs")
    return set(re.findall(r'"([a-z0-9_-]+)"\s*=>\s*"', body.group(1)))


def allowlist_ids(src: str) -> set[str]:
    body = re.search(
        r"fn is_known_provider\b.*?matches!\((.*?)\n    \)", src, re.DOTALL
    )
    if not body:
        die("could not locate `fn is_known_provider` in provider_keys_api.rs")
    return set(re.findall(r'"([a-z0-9_-]+)"', body.group(1)))


def ui_ids(src: str) -> set[str]:
    body = re.search(r"const PROVIDERS[^=]*=\s*\[(.*?)\n\];", src, re.DOTALL)
    if not body:
        die("could not locate `const PROVIDERS` in ProviderKeyManager.tsx")
    return set(re.findall(r'id:\s*"([a-z0-9_-]+)"', body.group(1)))


def compare(routable: set[str], allowed: set[str], ui: set[str]) -> list[str]:
    """Return every coverage gap between the three lists, in both directions.

    Set comparison is split out from the file reads so the selftest can plant
    each gap directly instead of editing the gateway or the dashboard.
    """
    failures = []

    missing_allow = sorted(routable - allowed)
    if missing_allow:
        failures.append(
            "these providers ROUTE but cannot accept a BYOK key "
            f"(add to `is_known_provider`): {', '.join(missing_allow)}"
        )

    missing_ui = sorted((routable - NO_KEY_NEEDED) - ui)
    if missing_ui:
        failures.append(
            "these providers accept a key but are NOT offered in the dashboard "
            f"(add to PROVIDERS): {', '.join(missing_ui)}"
        )

    unknown_ui = sorted(ui - routable)
    if unknown_ui:
        failures.append(
            "the dashboard offers providers the gateway cannot route "
            f"(upload would 400): {', '.join(unknown_ui)}"
        )

    return failures


# ── selftest fixtures ─────────────────────────────────────────────────────────
# Same shapes the three parsers expect, small enough to reason about. Note the
# fixtures go through the REAL parsers, so a regex that rots against these shapes
# is caught here too — not just the set comparison.


def _fixture_mod(ids: dict[str, str]) -> str:
    arms = "\n".join(f'            "{k}" => "{v}",' for k, v in ids.items())
    return (
        "impl ProviderRegistry {\n"
        "    pub fn env_var_for_provider_id(provider_id: &str) -> &'static str {\n"
        "        match provider_id {\n"
        f"{arms}\n"
        '            _ => "",\n'
        "        }\n"
        "    }\n"
        "}\n"
    )


def _fixture_byok(ids: list[str]) -> str:
    arms = "\n            | ".join(f'"{i}"' for i in ids)
    return (
        "fn is_known_provider(p: &str) -> bool {\n"
        "    matches!(\n"
        "        p,\n"
        f"        {arms}\n"
        "    )\n"
        "}\n"
    )


def _fixture_ui(ids: list[str]) -> str:
    rows = "\n".join(f'\t{{ id: "{i}", label: "{i.title()}" }},' for i in ids)
    return (
        "const PROVIDERS: ReadonlyArray<{ id: string; label: string }> = [\n"
        f"{rows}\n"
        "];\n"
    )


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

    # The full, consistent world: 4 routable, all allowlisted, all in the UI
    # except the keyless local one.
    world = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "groq": "GROQ_API_KEY",
        "ollama": "",
    }
    all_ids = list(world)
    ui_ok = [i for i in all_ids if i not in NO_KEY_NEEDED]

    # 1. The parsers must actually parse these shapes. A regex that rots and
    #    returns an empty set would make every comparison below vacuously pass.
    routable = routable_ids(_fixture_mod(world))
    allowed = allowlist_ids(_fixture_byok(all_ids))
    ui = ui_ids(_fixture_ui(ui_ok))
    check(
        "parsers extract the ids from all three sources",
        routable == set(all_ids) and allowed == set(all_ids) and ui == set(ui_ok),
        f"routable={sorted(routable)} allowed={sorted(allowed)} ui={sorted(ui)}",
    )

    # 2. THE NEGATIVE: a consistent world must PASS. Without this, a guard that
    #    fails on every input would look correct for every case below.
    check("consistent world passes", compare(routable, allowed, ui) == [])

    #    POST /v1/byok/provider-keys 400s and no customer can store a key.
    no_groq = allowlist_ids(_fixture_byok([i for i in all_ids if i != "groq"]))
    f = compare(routable, no_groq, ui)
    check(
        "routable provider missing from the BYOK allowlist -> caught",
        any("cannot accept a BYOK key" in x and "groq" in x for x in f),
        str(f),
    )

    # 4. The mirror gap: allowlisted + routable, but absent from the dropdown, so
    #    it cannot be added from the dashboard (this was `vertex`).
    no_ui = ui_ids(_fixture_ui([i for i in ui_ok if i != "openai"]))
    f = compare(routable, allowed, no_ui)
    check(
        "routable provider missing from the dashboard dropdown -> caught",
        any("NOT offered in the dashboard" in x and "openai" in x for x in f),
        str(f),
    )

    # 5. The opposite direction: the UI offers something the gateway cannot
    #    route, so the upload 400s from the other side.
    extra_ui = ui_ids(_fixture_ui([*ui_ok, "phantom"]))
    f = compare(routable, allowed, extra_ui)
    check(
        "dashboard offers an unroutable provider -> caught",
        any("cannot route" in x and "phantom" in x for x in f),
        str(f),
    )

    # 6. The ONE exemption is UI-only: `ollama` needs no key so it may be absent
    #    from the dropdown (case 2 proved that), but dropping it from the
    #    ALLOWLIST must still fail — a self-host has to be able to store one.
    no_ollama_allow = allowlist_ids(
        _fixture_byok([i for i in all_ids if i != "ollama"])
    )
    f = compare(routable, no_ollama_allow, ui)
    check(
        "keyless provider is exempt from the UI check ONLY, not the allowlist",
        any("cannot accept a BYOK key" in x and "ollama" in x for x in f),
        str(f),
    )

    # 7. Parser rot must be loud, not silent: a source whose anchor is gone must
    #    exit non-zero rather than yield an empty set that passes everything.
    for label, fn, bad in (
        ("registry", routable_ids, "fn something_else() {}\n"),
        ("allowlist", allowlist_ids, "fn other(p: &str) -> bool { true }\n"),
        ("dropdown", ui_ids, "const OTHER = [];\n"),
    ):
        buf = io.StringIO()
        try:
            with contextlib.redirect_stderr(buf):
                fn(bad)
        except SystemExit as e:
            check(f"{label} parser rot exits non-zero", e.code != 0, f"code={e.code}")
        else:
            check(f"{label} parser rot exits non-zero", False, "returned instead")

    print("selftest PASSED." if ok else "selftest FAILED.")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Assert every routable provider can accept a BYOK key."
    )
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="plant coverage drift in synthetic sources and prove the guard blocks",
    )
    args = ap.parse_args()  # unknown flags -> argparse exits 2 with usage
    if args.selftest:
        return selftest()

    routable = routable_ids(MOD_RS.read_text(encoding="utf-8"))
    allowed = allowlist_ids(BYOK_RS.read_text(encoding="utf-8"))
    ui = ui_ids(UI_TSX.read_text(encoding="utf-8"))

    if not routable:
        die("parsed 0 routable providers — the guard's regex has rotted")

    failures = compare(routable, allowed, ui)
    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        return 1

    print(
        f"byok-provider-coverage OK — {len(routable)} routable providers, "
        f"all storable, all offerable (minus {len(NO_KEY_NEEDED)} keyless)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
