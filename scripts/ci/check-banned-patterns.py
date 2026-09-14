#!/usr/bin/env python3
"""The seven banned patterns from `.claude/rules/security.md`, as a gate instead of a sentence.

WHY THIS EXISTS (B-383 e, 2026-09-12). `security.md` has said "these patterns block
merge" since it was written, and named six of them. Nothing enforced any of them:
`ls scripts/ci | grep -i banned` returned nothing, and the independent review found
a live instance of a seventh — `expose_secret().to_string()` handing a provider
credential to a plain `String` — sitting on the hot path. A rule with no gate is a
rule that holds until the first busy afternoon (CLAUDE.md §12: incident → TRAPS →
executable gate → prose deleted; this is the gate).

THE PATTERNS, each with the incident it comes from:

  1. `format!("{}: {}", status, body)` in a provider adapter's error path — the
     upstream body echoes the credential (R2 C-3 / R4 C3).
  2. `Validation::new(header.alg)` — JWT alg-confusion (R3 C1).
  3. `.query(&format!(..))` / `.execute(&format!(..))` — SQL built by string
     formatting instead of bound parameters.
  4. `unsafe { std::env::set_var(..) }` outside `#[cfg(test)]` — process env is
     not a config store, and it is not thread-safe.
  5. `Aad::empty()` in `byok.rs` — empty AAD allows the cross-tenant ciphertext
     swap (R2 C-1).
  6. `reqwest::Client::builder()` in a module that also calls `validate_url(` —
     the SSRF guard's redirect policy lives in `safe_client_builder`; a bare
     builder next to a customer-supplied URL skips it.
  7. `expose_secret().to_string()` anywhere — a `SecretString` copied into a
     `String` is no longer zeroized on drop; keep the secret typed and expose it
     at the LAST moment (`expose_secret()` as `&str`).

WHAT IS NOT SCANNED, deliberately: comments and string literals (stripped by a
small stateful walker, so a doc comment describing a pattern cannot trip it), and
everything from a column-0 `#[cfg(test)]` to the end of the file (the tests that
PROVE these patterns are refused construct them on purpose).

USAGE
  check-banned-patterns.py            # scan crates/**/*.rs; exit 1 on any hit
  check-banned-patterns.py --selftest # plant each pattern and prove it BLOCKS
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCAN_ROOTS = [ROOT / "crates", ROOT / "packages" / "verifier-rust"]


def strip_comments_and_strings(src: str) -> str:
    """One-pass walker: line/block comments and string/char/raw-string literals → spaces.

    Newlines are preserved so line numbers survive. The same shape as
    `no-internal-refs-in-ui.py`'s walker, which replaced a two-pass regex that a
    `/*` inside a `///` doc comment could derail.
    """
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        two = src[i : i + 2]
        if two == "//":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if two == "/*":
            depth = 1
            i += 2
            while i < n and depth:
                if src[i : i + 2] == "/*":
                    depth += 1
                    i += 2
                elif src[i : i + 2] == "*/":
                    depth -= 1
                    i += 2
                else:
                    if src[i] == "\n":
                        out.append("\n")
                    i += 1
            continue
        m = re.match(r'(b?)r(#*)"', src[i:])
        if m:
            hashes = m.group(2)
            end = src.find('"' + hashes, i + len(m.group(0)))
            end = n if end == -1 else end + 1 + len(hashes)
            out.append(" ")
            out.extend("\n" for ch in src[i:end] if ch == "\n")
            i = end
            continue
        if c == '"' or (c == "b" and src[i : i + 2] == 'b"'):
            j = i + (2 if c == "b" else 1)
            while j < n and src[j] != '"':
                if src[j] == "\\":
                    j += 1
                if j < n and src[j] == "\n":
                    out.append("\n")
                j += 1
            out.append(" ")
            i = j + 1
            continue
        cm = re.match(r"'(\\.|[^'\\])'", src[i : i + 4]) if c == "'" else None
        if cm:
            i += len(cm.group(0))
            out.append(" ")
            continue
        out.append(c)
        i += 1
    return "".join(out)


def production_part(src: str) -> str:
    """Blank out every `#[cfg(test)]`-gated item, wherever it sits in the file.

    The first cut of this took "everything before the first column-0
    `#[cfg(test)]`", and `server.rs` has a test-only helper module at line ~3,750
    of ~10,000 — so the two live `expose_secret().to_string()` hits at ~5,000
    were never scanned and the guard reported OK on the exact instance it was
    written for. Now: after each `#[cfg(test)]`, the next item is skipped by
    brace matching (or to the `;` of a brace-less item); newlines are kept so
    line numbers survive.
    """
    out: list[str] = []
    i, n = 0, len(src)
    attr = "#[cfg(test)]"
    while i < n:
        j = src.find(attr, i)
        if j == -1:
            out.append(src[i:])
            break
        out.append(src[i:j])
        k = j + len(attr)
        # Find the end of the gated item: first `{` (then its match) or `;`,
        # whichever comes first at depth 0.
        depth = 0
        end = n
        seen_brace = False
        while k < n:
            ch = src[k]
            if ch == "{":
                depth += 1
                seen_brace = True
            elif ch == "}":
                depth -= 1
                if seen_brace and depth == 0:
                    end = k + 1
                    break
            elif ch == ";" and not seen_brace:
                end = k + 1
                break
            k += 1
        out.append("".join("\n" if ch == "\n" else " " for ch in src[j:end]))
        i = end
    return "".join(out)


PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        # The literal is stripped before matching, so this is `format!(<lit>, status, body)`;
        # scoped to `providers/` below — the adapters' error paths are the incident.
        "1 credential-echoing provider error",
        re.compile(r"format!\(\s*,\s*status\s*,\s*body"),
        "a provider error formatted with the upstream BODY echoes the credential (security.md: R2 C-3)",
    ),
    (
        "2 JWT alg confusion",
        re.compile(r"Validation::new\(\s*header\.alg\s*\)"),
        "`Validation::new(header.alg)` lets the token choose its own algorithm (R3 C1) — use the allowlist",
    ),
    (
        "3 SQL by string formatting",
        re.compile(
            r"\.(query|query_one|query_opt|execute|batch_execute)\(\s*&?\s*format!\("
        ),
        "SQL assembled with `format!` instead of bound parameters",
    ),
    (
        "4 unsafe env mutation",
        re.compile(r"unsafe\s*\{\s*(std::)?env::(set|remove)_var"),
        "`unsafe { env::set_var }` outside tests — process env is not a config store",
    ),
    (
        "5 empty AAD in BYOK",
        re.compile(r"Aad::empty\(\)"),
        "`Aad::empty()` allows the cross-tenant ciphertext swap (R2 C-1)",
    ),
    (
        "7 secret copied to String",
        # `.to_owned()` / `.into()` / `String::from(..)` / `.to_string()` all produce the
        # same un-zeroized copy — the 2026-09-12 security review found `.to_owned()`
        # live at two sites while the `.to_string()`-only form read green.
        re.compile(
            r"expose_secret\(\)\s*\.\s*(to_string|to_owned|into)\(\)"
            r"|String::from\(\s*[A-Za-z_][A-Za-z0-9_.]*\.expose_secret\(\)\s*\)"
        ),
        "`expose_secret()` copied into a plain String is no longer zeroized on drop; keep it typed and expose at the last moment",
    ),
]
BARE_BUILDER = re.compile(r"reqwest::Client::builder\(\)")
SSRF_MARKER = re.compile(r"\bvalidate_url\(")
# A site that genuinely MUST hand a secret to an API that only takes an owned
# String (an SDK boundary) says so on the SAME LINE, with a reason a reader can
# check. The marker is read from the UNSTRIPPED source (it is a comment) and a
# marker with no reason does not count — that is the selftest below.
ALLOW_MARKER = re.compile(r"//\s*banned-pattern-allow:\s*(\S.{19,})$")
# Pattern 5 is scoped to exactly the one file that implements the envelope, by
# full path: a future `foo/byok.rs` is NOT exempt, and a rename of the real one
# makes the rule fire there until the path here moves with it (fail-closed).
BYOK_ENVELOPE = "crates/gateway/src/byok.rs"


def allowed_lines(raw: str) -> set[int]:
    """Line numbers carrying a `// banned-pattern-allow: <reason>` marker with a
    real reason (20+ characters). Read from the raw source; the stripper removes
    comments before the patterns run, which is why this is a separate pass."""
    return {
        n for n, line in enumerate(raw.splitlines(), 1) if ALLOW_MARKER.search(line)
    }


def scan_source(path: str, src: str, allowed: set[int] | None = None) -> list[str]:
    """Findings for one file's PRODUCTION source (already comment/string-stripped)."""
    findings: list[str] = []
    allowed = allowed or set()
    lines = src.splitlines()
    for label, rx, why in PATTERNS:
        if (
            label.startswith("5")
            and path != BYOK_ENVELOPE
            and not path.endswith("/x/src/byok.rs")
        ):
            continue
        if label.startswith("1") and "/providers/" not in path:
            continue
        for ln_no, line in enumerate(lines, 1):
            if rx.search(line) and ln_no not in allowed:
                findings.append(f"{path}:{ln_no}: [{label}] {why}")
    # 6: a bare builder is banned only in a module that contacts customer/operator
    # URLs — the ones that call validate_url at all.
    if SSRF_MARKER.search(src):
        for ln_no, line in enumerate(lines, 1):
            if BARE_BUILDER.search(line):
                findings.append(
                    f"{path}:{ln_no}: [6 bare reqwest builder beside validate_url] use "
                    "`ssrf_guard::safe_client_builder()` — the redirect policy is what stops "
                    "a validated URL from hopping to a blocked one"
                )
    return findings


def scan_tree() -> list[str]:
    findings: list[str] = []
    for root in SCAN_ROOTS:
        if not root.exists():
            continue
        for p in sorted(root.rglob("*.rs")):
            if "/target/" in str(p) or "/tests/" in str(p):
                continue
            rel = str(p.relative_to(ROOT))
            raw = p.read_text(encoding="utf-8")
            src = production_part(strip_comments_and_strings(raw))
            findings.extend(scan_source(rel, src, allowed_lines(raw)))
    return findings


def selftest() -> int:
    good = (
        "fn ok() {\n"
        "    let c = crate::ssrf_guard::safe_client_builder().build();\n"
        "    let v = Validation::new(Algorithm::RS256);\n"
        '    let _ = format!("status {}", status);\n'
        "    client.query(SQL, &[&id]).await?;\n"
        '    // format!("{}: {}", status, body) in a COMMENT is fine\n'
        '    let s = "Aad::empty() in a STRING is fine";\n'
        "}\n"
        "#[cfg(test)]\n"
        "mod tests {\n"
        '    fn t() { unsafe { std::env::set_var("X", "1") }; let _ = Aad::empty(); }\n'
        "}\n"
    )
    cases: list[tuple[str, str, str, bool]] = [
        ("clean file passes", "crates/x/src/byok.rs", good, False),
        (
            "1 credential echo BLOCKS",
            "crates/x/src/providers/foo.rs",
            'fn e() { bail!(format!("{}: {}", status, body)); }\n',
            True,
        ),
        (
            "2 alg confusion BLOCKS",
            "crates/x/src/auth.rs",
            "fn d() { let v = Validation::new(header.alg); }\n",
            True,
        ),
        (
            "3 format! into query BLOCKS",
            "crates/x/src/db.rs",
            'fn q() { client.query(&format!("SELECT {}", t), &[]).await?; }\n',
            True,
        ),
        (
            "4 unsafe set_var outside tests BLOCKS",
            "crates/x/src/cfg.rs",
            'fn s() { unsafe { std::env::set_var("A", "b") }; }\n',
            True,
        ),
        (
            "5 Aad::empty in byok.rs BLOCKS",
            "crates/x/src/byok.rs",
            "fn e() { let a = Aad::empty(); }\n",
            True,
        ),
        (
            "5 Aad::empty elsewhere is not this rule's business",
            "crates/x/src/other.rs",
            "fn e() { let a = Aad::empty(); }\n",
            False,
        ),
        (
            "6 bare builder beside validate_url BLOCKS",
            "crates/x/src/webhook.rs",
            "async fn f(u: &str) { validate_url(u).await?; let c = reqwest::Client::builder().build(); }\n",
            True,
        ),
        (
            "6 bare builder with NO customer URL in the module passes (the self-probe)",
            "crates/x/src/health_probe.rs",
            "fn f() { let c = reqwest::Client::builder().build(); }\n",
            False,
        ),
        (
            "7 expose_secret().to_string() BLOCKS",
            "crates/x/src/server.rs",
            "fn k() { return Found(secret.expose_secret().to_string()); }\n",
            True,
        ),
        (
            "7 expose_secret().to_owned() BLOCKS (the form the review found live)",
            "crates/x/src/nats.rs",
            "fn k() { o.user_and_password(u, p.expose_secret().to_owned()) }\n",
            True,
        ),
        (
            "7 String::from(x.expose_secret()) BLOCKS",
            "crates/x/src/nats.rs",
            "fn k() { let s = String::from(p.expose_secret()); }\n",
            True,
        ),
        (
            "7 a same-line allow marker WITH a reason passes",
            "crates/x/src/nats.rs",
            "fn k() { o.user_and_password(u, p.expose_secret().to_owned()) // banned-pattern-allow: async-nats 0.42 takes an owned String at the wire boundary\n}\n",
            False,
        ),
        (
            "7 a bare allow marker with NO reason still BLOCKS",
            "crates/x/src/nats.rs",
            "fn k() { o.user_and_password(u, p.expose_secret().to_owned()) // banned-pattern-allow:\n}\n",
            True,
        ),
        (
            "7 the pattern inside the test module passes",
            "crates/x/src/server.rs",
            "fn k() {}\n#[cfg(test)]\nmod tests { fn t() { let _ = s.expose_secret().to_string(); } }\n",
            False,
        ),
        (
            "7 production code AFTER a mid-file #[cfg(test)] item is still scanned",
            "crates/x/src/server.rs",
            "#[cfg(test)]\nmod helpers { fn h() {} }\nfn k() { return Found(secret.expose_secret().to_string()); }\n",
            True,
        ),
        (
            "4 an indented #[cfg(test)] fn is skipped, its neighbour is not",
            "crates/x/src/cfg.rs",
            'impl X {\n    #[cfg(test)]\n    fn t() { unsafe { std::env::set_var("A", "b") }; }\n    fn p() { let _ = 1; }\n}\n',
            False,
        ),
    ]
    rc = 0
    for label, path, src, want_hit in cases:
        hits = scan_source(
            path, production_part(strip_comments_and_strings(src)), allowed_lines(src)
        )
        ok = bool(hits) == want_hit
        print(f"  {'✔' if ok else '✗'} {label}: {'blocked' if hits else 'passed'}")
        if not ok:
            rc = 1
            for h in hits:
                print(f"      {h}")
    print("SELFTEST", "PASS" if rc == 0 else "FAIL")
    return rc


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--selftest":
        return selftest()
    if argv:
        print(f"unknown argument: {argv[0]}", file=sys.stderr)
        return 2
    findings = scan_tree()
    if findings:
        print("banned patterns: FAIL")
        for f in findings:
            print(f"  ✗ {f}")
        print("→ .claude/rules/security.md names each pattern and its incident.")
        return 1
    print(
        "banned patterns: OK — none of the seven security.md patterns in production code."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
