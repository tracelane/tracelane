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
"""

from __future__ import annotations

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
    body = re.search(r"fn env_var_for_provider_id\b(.*?)\n    \}\n", src, re.S)
    if not body:
        die("could not locate `fn env_var_for_provider_id` in providers/mod.rs")
    return set(re.findall(r'"([a-z0-9_-]+)"\s*=>\s*"', body.group(1)))


def allowlist_ids(src: str) -> set[str]:
    body = re.search(r"fn is_known_provider\b.*?matches!\((.*?)\n    \)", src, re.S)
    if not body:
        die("could not locate `fn is_known_provider` in provider_keys_api.rs")
    return set(re.findall(r'"([a-z0-9_-]+)"', body.group(1)))


def ui_ids(src: str) -> set[str]:
    body = re.search(r"const PROVIDERS[^=]*=\s*\[(.*?)\n\];", src, re.S)
    if not body:
        die("could not locate `const PROVIDERS` in ProviderKeyManager.tsx")
    return set(re.findall(r'id:\s*"([a-z0-9_-]+)"', body.group(1)))


def main() -> int:
    routable = routable_ids(MOD_RS.read_text(encoding="utf-8"))
    allowed = allowlist_ids(BYOK_RS.read_text(encoding="utf-8"))
    ui = ui_ids(UI_TSX.read_text(encoding="utf-8"))

    if not routable:
        die("parsed 0 routable providers — the guard's regex has rotted")

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
