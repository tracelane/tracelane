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
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MOD_RS = ROOT / "crates/gateway/src/providers/mod.rs"
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
    return len(re.findall(r"^\s+pub \w+:\s*\w+", block, re.M))


def native_adapter_count() -> tuple[int, list[str]]:
    """Count dedicated adapter modules (a file per provider that owns translation)."""
    names = sorted(
        p.stem
        for p in (ROOT / "crates/gateway/src/providers").glob("*.rs")
        if p.stem not in NON_ADAPTER_MODULES
    )
    return len(names), names


def main() -> int:
    mod_src = MOD_RS.read_text()
    server_src = SERVER_RS.read_text()

    routable = registry_field_count(mod_src)
    native, native_names = native_adapter_count()
    compat = routable - native

    # The three claims, and the exact substring each must contain.
    expected = [
        (MOD_RS, mod_src, f"{routable} routable — {native} native adapters + {compat} OpenAI-compatible"),
        (MOD_RS, mod_src, f"({native} native + {compat} OpenAI-compatible instances)"),
        (SERVER_RS, server_src, f"{routable} routable: {native} native adapters + {compat} OpenAI-compatible"),
    ]

    failures = []
    for path, src, needle in expected:
        if needle not in src:
            failures.append((path.relative_to(ROOT), needle))

    if failures:
        print("FAIL: provider-count doc-comments do not match the registry.")
        print(f"  TRUTH: {routable} routable = {native} native + {compat} OpenAI-compatible")
        print(f"  native adapters ({native}): {', '.join(native_names)}")
        print()
        for rel, needle in failures:
            print(f"  {rel} must contain: {needle!r}")
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
