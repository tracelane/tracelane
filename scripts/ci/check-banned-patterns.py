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
  8. A credential in a URL query string (`?key={}`, `&api_key={}`, `access_token=`)
     built in production code — ONE GATEWAY D6 (2026-10-01): the Google adapter put
     the tenant's BYOK key in the URL, and `reqwest::Error`'s Display includes the
     URL, so every connect/timeout error carried the key into error strings. Scanned
     on the RAW source (the credential lives inside a string literal).
  9. An outbound provider `.send()` whose error is not converted with
     `.without_url()` in the same statement — the same D6 class: even with no key in
     the URL, the URL of a customer-chosen base is not ours to log. Scoped to the
     provider adapters and the byte-faithful relays.

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


_RAW_STR = re.compile(r'(b?)r(#*)"')
_CHAR_LIT = re.compile(r"'(\\.|[^'\\])'")


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
        # `.match(src, i)`, never `re.match(…, src[i:])`: the slice copied the rest of the
        # file for EVERY character — quadratic, ~60 s of the gate across this guard and
        # check-image-embeds (2026-09-30). Same patterns, same positions, same result.
        m = _RAW_STR.match(src, i) if c in "br" else None
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
        cm = _CHAR_LIT.match(src, i, i + 4) if c == "'" else None
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
            # `format!`/`write!` interpolating an exposed secret is the SAME
            # un-zeroized copy wearing a different hat. Found 2026-09-22 by the
            # security review, live at one site: a WorkOS management key built
            # as `format!("Bearer {}", key.expose_secret())` read green here
            # while `.to_string()` two lines away would have blocked. The repo's
            # shape is `bearer_auth(secret.expose_secret())` — the copy happens
            # inside the client, not in a String we own.
            r"|(format|write|writeln|print|println|eprint|eprintln)!\s*\([^)]*"
            r"[A-Za-z_][A-Za-z0-9_.]*\.expose_secret\(\)"
        ),
        "`expose_secret()` copied into a plain String is no longer zeroized on drop; keep it typed and expose at the last moment",
    ),
]
# 8: checked on RAW lines (the credential sits inside a string literal), production
# lines only. `{` or `{name}` right after `=` is a format placeholder being filled.
CREDENTIAL_IN_URL = re.compile(
    r"[?&](key|api_key|apikey|api-key|access_token|token|secret)=\{", re.IGNORECASE
)
# 9: the provider-call sites. A new relay module joins this list or is not scanned —
# the list is the scope, said here so a reviewer can see it.
SEND_SCOPE = (
    "/providers/",
    "crates/gateway/src/anthropic_messages.rs",
    "crates/gateway/src/openai_responses.rs",
    "crates/gateway/src/gemini_native.rs",
    "crates/gateway/src/passthrough.rs",
    "crates/gateway/src/realtime.rs",
    "crates/gateway/src/server/dispatch.rs",
    # OG-06: the media / files / batch relay. `media_common.rs` owns the one `send`;
    # the two route modules are scanned too so a second send site cannot appear unseen.
    "crates/gateway/src/media_common.rs",
    "crates/gateway/src/media_routes.rs",
    "crates/gateway/src/files_batches.rs",
)
SEND_CALL = re.compile(r"\.send\(\)")
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
    # 9: an outbound `.send()` on a provider path must strip the URL from its error
    # within the same statement (up to its `;`).
    if any(scope in path for scope in SEND_SCOPE):
        for idx, line in enumerate(lines):
            if not SEND_CALL.search(line) or (idx + 1) in allowed:
                continue
            stmt = "\n".join(lines[idx : idx + 10])
            stmt = stmt.split(";", 1)[0]
            if "without_url" not in stmt:
                findings.append(
                    f"{path}:{idx + 1}: [9 provider send without .without_url()] a reqwest "
                    "error renders the request URL; convert it with `.without_url()` before "
                    "it becomes a string or an anyhow chain (ONE GATEWAY D6)"
                )
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


def test_lines(stripped: str) -> set[int]:
    """1-based line numbers inside `#[cfg(test)]` items (the regions
    [`production_part`] blanks), so a RAW-source rule can skip the same code."""
    blanked = production_part(stripped)
    out: set[int] = set()
    for n, (a, b) in enumerate(zip(stripped.splitlines(), blanked.splitlines()), 1):
        if a.strip() and not b.strip():
            out.add(n)
    # a line that is ONLY a string literal strips to blank in both; attribute it to
    # its neighbourhood: inside a test region iff the previous line was.
    lines = stripped.splitlines()
    for n in range(1, len(lines) + 1):
        if not lines[n - 1].strip() and (n - 1) in out:
            out.add(n)
    return out


def scan_raw(
    path: str, raw: str, allowed: set[int] | None = None, tests: set[int] | None = None
) -> list[str]:
    """Rule 8 on the unstripped source, production lines only."""
    allowed = allowed or set()
    tests = tests or set()
    findings: list[str] = []
    for n, line in enumerate(raw.splitlines(), 1):
        if n in allowed or n in tests:
            continue
        if line.lstrip().startswith("//"):
            continue
        if CREDENTIAL_IN_URL.search(line):
            findings.append(
                f"{path}:{n}: [8 credential in a URL] send it in a header — a URL is "
                "rendered into reqwest errors, access logs and proxies (ONE GATEWAY D6)"
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
            stripped = strip_comments_and_strings(raw)
            src = production_part(stripped)
            allowed = allowed_lines(raw)
            findings.extend(scan_source(rel, src, allowed))
            findings.extend(scan_raw(rel, raw, allowed, test_lines(stripped)))
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
            "7 format!(..) interpolating an exposed secret BLOCKS",
            "crates/x/src/webhook.rs",
            'fn k() { let h = format!("Bearer {}", key.expose_secret()); }\n',
            True,
        ),
        (
            "7 bearer_auth(expose_secret()) — the sanctioned shape — PASSES",
            "crates/x/src/webhook.rs",
            "fn k() { let r = c.get(u).bearer_auth(key.expose_secret()); }\n",
            False,
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
        (
            "8 a key in a provider URL query BLOCKS (the D6 shape)",
            "crates/x/src/providers/google.rs",
            'fn u() { let url = format!("{}/v1beta/models/{}:x?alt=sse&key={}", b, m, k); }\n',
            True,
        ),
        (
            "8 a key in a URL inside the test module passes",
            "crates/x/src/providers/google.rs",
            'fn u() {}\n#[cfg(test)]\nmod tests {\n    fn t() {\n        let url = format!("http://x/?key={}", k);\n    }\n}\n',
            False,
        ),
        (
            "8 the key in a header passes",
            "crates/x/src/providers/google.rs",
            'fn u() { let r = c.post(url).header("x-goog-api-key", k); }\n',
            False,
        ),
        (
            "9 a provider send whose error keeps the URL BLOCKS",
            "crates/x/src/providers/foo.rs",
            'async fn s() { let r = c.post(u).send().await.context("send")?; }\n',
            True,
        ),
        (
            "9 a provider send with .without_url() in the statement passes",
            "crates/x/src/providers/foo.rs",
            'async fn s() {\n    let r = c\n        .post(u)\n        .send()\n        .await\n        .map_err(|e| e.without_url())\n        .context("send")?;\n}\n',
            False,
        ),
        (
            "9 OG-06: a send in media_routes.rs that keeps the URL BLOCKS",
            "crates/gateway/src/media_routes.rs",
            'async fn s() { let r = c.post(u).send().await.context("send")?; }\n',
            True,
        ),
        (
            "9 OG-06: a send in files_batches.rs that keeps the URL BLOCKS",
            "crates/gateway/src/files_batches.rs",
            'async fn s() { let r = c.post(u).send().await.context("send")?; }\n',
            True,
        ),
        (
            "9 OG-06: a send in media_common.rs with .without_url() passes",
            "crates/gateway/src/media_common.rs",
            "async fn s() { let r = c.post(u).send().await.map_err(reqwest::Error::without_url)?; }\n",
            False,
        ),
        (
            "9 a send outside the provider scope is not this rule's business",
            "crates/x/src/alerts/mod.rs",
            "async fn s() { let r = c.post(u).send().await?; }\n",
            False,
        ),
    ]
    rc = 0
    for label, path, src, want_hit in cases:
        stripped = strip_comments_and_strings(src)
        hits = scan_source(path, production_part(stripped), allowed_lines(src))
        hits += scan_raw(path, src, allowed_lines(src), test_lines(stripped))
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
    print("banned patterns: OK — none of the nine banned patterns in production code.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
