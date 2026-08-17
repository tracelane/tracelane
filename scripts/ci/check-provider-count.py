#!/usr/bin/env python3
"""Assert the provider-count doc-comments match the actual ProviderRegistry.

Why this exists: `providers/mod.rs` and `server.rs` carry human-written counts of
how many providers the gateway routes. Those comments drifted from the registry
("35 total" / "8 wired adapters" against a 34-field struct), and the wrong number
propagated outward into published copy before anyone noticed.

They were corrected by hand once — and drifted again within a day, when a new
adapter landed and nobody re-counted. A hand-maintained count is a claim that
rots silently: nothing fails, the number is just quietly wrong.

So the counts are derived from the source of truth and enforced here:
  routable = number of `pub <name>: <Type>` fields on ProviderRegistry
  native   = number of dedicated adapter modules (each owns its wire translation)
  compat   = routable - native  (instances sharing the OpenAiProvider client)

`openai` is counted as NATIVE: it has its own adapter module (`openai.rs`), even
though the registry field is typed `OpenAiProvider` — that type IS the OpenAI
adapter, reused by compatible providers. Counting by type instead of by module
would misclassify it and reintroduce the off-by-one this guard exists to stop.

Exit 0 = counts agree. Exit 1 = drift (fails CI with the correct numbers).
`--selftest` plants drift in a temp fixture tree and asserts the guard catches it.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROVIDERS_DIR = ROOT / "crates/gateway/src/providers"
MOD_RS = PROVIDERS_DIR / "mod.rs"
SERVER_RS = ROOT / "crates/gateway/src/server.rs"

# Modules under providers/ that are NOT provider adapters.
NON_ADAPTER_MODULES = {
    "mod",
    "failover",
    "smoke_tests",
    "behavioral_tests",
    "wasm_plugin",
}


def registry_field_count(src: str) -> int:
    """Count `pub <name>: <Type>` fields on ProviderRegistry."""
    try:
        block = src.split("pub struct ProviderRegistry {")[1].split("\n}")[0]
    except IndexError:
        sys.exit("FAIL: could not locate `pub struct ProviderRegistry` in mod.rs")
    return len(re.findall(r"^\s+pub \w+:\s*\w+", block, re.MULTILINE))


def native_adapter_count(providers_dir: Path) -> tuple[int, list[str]]:
    """Count dedicated adapter modules (a file per provider that owns translation)."""
    names = sorted(
        p.stem for p in providers_dir.glob("*.rs") if p.stem not in NON_ADAPTER_MODULES
    )
    return len(names), names


def run(
    mod_src: str,
    server_src: str,
    providers_dir: Path,
    mod_label: str,
    server_label: str,
) -> tuple[list[tuple[str, str]], int, int, int, list[str]]:
    """Return (failures, routable, native, compat, native_names).

    Takes sources and the adapter directory as arguments rather than reading the
    repo directly, so the selftest can point it at a fixture tree where drift can
    actually be planted.
    """
    routable = registry_field_count(mod_src)
    native, native_names = native_adapter_count(providers_dir)
    compat = routable - native

    # The three claims, and the exact substring each must contain.
    expected = [
        (
            mod_label,
            mod_src,
            f"{routable} routable — {native} native adapters + {compat} OpenAI-compatible",
        ),
        (
            mod_label,
            mod_src,
            f"({native} native + {compat} OpenAI-compatible instances)",
        ),
        (
            server_label,
            server_src,
            f"{routable} routable: {native} native adapters + {compat} OpenAI-compatible",
        ),
    ]

    failures = [(label, needle) for label, src, needle in expected if needle not in src]
    return failures, routable, native, compat, native_names


# ── selftest fixtures ─────────────────────────────────────────────────────────
# A miniature registry: 5 fields, 3 adapter modules => 5 routable / 3 native /
# 2 OpenAI-compatible. Small enough to reason about, same shape as the real one.
FIXTURE_ADAPTERS = ["anthropic", "openai", "google"]
FIXTURE_NON_ADAPTERS = ["mod", "failover"]


def _fixture_mod_src(routable: int, native: int, compat: int, fields: int) -> str:
    """A synthetic providers/mod.rs: `fields` registry fields, claiming `routable`."""
    body = "\n".join(f"    pub p{i}: SomeProvider," for i in range(fields))
    return (
        "//! Provider adapter layer.\n"
        f"//! Providers registered here ({routable} routable — {native} native "
        f"adapters + {compat} OpenAI-compatible):\n"
        "//!   Dedicated adapters: A, B, C\n"
        f"//! The registry holds ({native} native + {compat} OpenAI-compatible "
        "instances)\n"
        "pub struct ProviderRegistry {\n"
        f"{body}\n"
        "}\n"
    )


def _fixture_server_src(routable: int, native: int, compat: int) -> str:
    return (
        "//! Axum HTTP server.\n"
        f"//!   providers — ProviderRegistry ({routable} routable: {native} native "
        f"adapters + {compat} OpenAI-compatible + failover chain)\n"
    )


def _fixture_dir(td: Path, extra_adapters: tuple[str, ...] = ()) -> Path:
    d = td / "providers"
    d.mkdir(parents=True, exist_ok=True)
    for stem in FIXTURE_NON_ADAPTERS + FIXTURE_ADAPTERS + list(extra_adapters):
        (d / f"{stem}.rs").write_text("// fixture\n")
    return d


def selftest() -> int:
    """Plant count drift and assert the guard reports it; assert clean passes."""
    ok = True

    def case(
        name: str,
        expect_fail: bool,
        mod_src: str,
        server_src: str,
        providers_dir: Path,
        expect_label: str | None = None,
    ) -> None:
        nonlocal ok
        failures, *_ = run(mod_src, server_src, providers_dir, "mod.rs", "server.rs")
        got_fail = bool(failures)
        if got_fail != expect_fail:
            verb = "did NOT flag" if expect_fail else "wrongly flagged"
            print(f"SELFTEST FAIL: {name} — guard {verb} it")
            ok = False
            return
        if expect_label and not any(label == expect_label for label, _ in failures):
            print(f"SELFTEST FAIL: {name} — no finding attributed to {expect_label}")
            ok = False
            return
        print(f"  ✓ {name}")

    with tempfile.TemporaryDirectory() as tmp:
        td = Path(tmp)
        pdir = _fixture_dir(td)

        # 3 adapter modules (mod/failover excluded), 5 registry fields.
        clean_mod = _fixture_mod_src(5, 3, 2, fields=5)
        clean_server = _fixture_server_src(5, 3, 2)

        # THE NEGATIVE, first: honest counts must PASS. Without this a guard that
        # fails on everything would look correct.
        case(
            "clean tree with honest counts passes", False, clean_mod, clean_server, pdir
        )

        case(
            "registry grew a field, doc-comment stale -> caught",
            True,
            _fixture_mod_src(5, 3, 2, fields=6),
            clean_server,
            pdir,
            expect_label="mod.rs",
        )

        # The mirror: server.rs carries its own copy of the claim.
        case(
            "server.rs claim stale -> caught",
            True,
            clean_mod,
            _fixture_server_src(4, 3, 1),
            pdir,
            expect_label="server.rs",
        )

        # Hand-edited mod.rs comment that simply says the wrong number.
        case(
            "mod.rs doc-comment says the wrong routable count -> caught",
            True,
            _fixture_mod_src(34, 3, 31, fields=5),
            clean_server,
            pdir,
            expect_label="mod.rs",
        )

        # A new adapter MODULE shifts native/compat even with the field count
        # unchanged — the drift axis the count guard exists to cover.
        grown = _fixture_dir(td / "grown", extra_adapters=("newprov",))
        case(
            "new adapter module shifts native/compat -> caught",
            True,
            clean_mod,
            clean_server,
            grown,
        )
        # ...and the same tree passes once the comments are corrected (4 native,
        # 1 compat), proving the guard tracks the source of truth, not a constant.
        case(
            "corrected counts for the grown tree pass",
            False,
            _fixture_mod_src(5, 4, 1, fields=5),
            _fixture_server_src(5, 4, 1),
            grown,
        )

    print("selftest PASSED." if ok else "selftest FAILED.")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Assert provider-count doc-comments match the ProviderRegistry."
    )
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="plant count drift in a temp fixture tree and prove the guard blocks",
    )
    args = ap.parse_args()  # unknown flags -> argparse exits 2 with usage
    if args.selftest:
        return selftest()

    failures, routable, native, compat, native_names = run(
        MOD_RS.read_text(),
        SERVER_RS.read_text(),
        PROVIDERS_DIR,
        MOD_RS.relative_to(ROOT).as_posix(),
        SERVER_RS.relative_to(ROOT).as_posix(),
    )

    if failures:
        print("FAIL: provider-count doc-comments do not match the registry.")
        print(
            f"  TRUTH: {routable} routable = {native} native + {compat} OpenAI-compatible"
        )
        print(f"  native adapters ({native}): {', '.join(native_names)}")
        print()
        for label, needle in failures:
            print(f"  {label} must contain: {needle!r}")
        print()
        print("  A wrong count here has shipped to the marketing site before. Fix the")
        print("  comment, not this guard.")
        return 1

    print(
        f"OK: provider counts agree — {routable} routable "
        f"({native} native + {compat} OpenAI-compatible)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
