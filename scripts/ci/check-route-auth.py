#!/usr/bin/env python3
"""Every mounted `/v1` route authenticates AND checks a scope or role — proven per handler.

WHY THIS EXISTS (B-383 d, 2026-09-12). The gateway has no tower auth layer; every
handler runs its own admission cascade (`crates/gateway/CLAUDE.md`: "adding a route
without replicating that sequence ships an unauthenticated endpoint"). The
independent review found four route families — alerts, annotations, notifications,
online-evals — that authenticate and then answer ANY scope: an `ingest`-only SDK
key, the credential that ships inside a customer's container image, could read the
workspace's alert destinations (webhook URLs, bearer-equivalent). `grep allows_scope`
on those files returned nothing, and no guard noticed, because nothing asked.

WHAT IT PROVES. For every `.route("<path>", <method>(<handler>))` in
`crates/gateway/src/**/*.rs` outside `#[cfg(test)]`, the handler — or a function in
the same file that the handler calls — must (a) call `validate_authorization(` and
(b) call one of the authorization predicates: `allows_scope(`, `can_admin(`,
`is_verified_owner(`, `can_mint_keys(`, `can_write_prompts(`, `require_scope(`.
One level of indirection is followed on purpose: most families funnel auth through
a local `authenticate` / `require_claims` helper, and that helper is where the
scope check belongs.

THE ALLOWLIST is the set of routes that are unauthenticated BY DESIGN, each with the
reason beside it. A route that is neither authenticated nor on the list fails.

HONEST LIMIT: this reads names, not types. A handler that calls
`validate_authorization` and then ignores the result would pass; that half is
review. What it cannot miss is the finding's shape — a handler with no scope call at
all — and that is the shape that shipped.

USAGE
  check-route-auth.py            # scan; exit 1 if any route is unproven
  check-route-auth.py --selftest # plant an unscoped handler and prove it BLOCKS
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GATEWAY_SRC = ROOT / "crates" / "gateway" / "src"

# path → why it is unauthenticated (or authenticated by another mechanism).
ALLOWLIST: dict[str, str] = {
    "/health": "liveness probe — must answer under every failure",
    "/metrics": "loopback-only Prometheus listener (B-389), never mounted on :8080",
    "/v1/auth/whoami": "authenticates (it IS the auth probe); no scope — it returns the caller's own identity",
    "/v1/share/{token}": "public share link (OBS-48): the token is the credential, rate-limited per IP",
    "/v1/audit/pubkey": "public verification key (ADR-062): unauthenticated by design, rate-limited",
    "/v1/audit/pubkey/{tenant_id}": "public per-tenant verification key: unauthenticated by design, rate-limited",
    "/v1/webhooks/workos": "HMAC-verified webhook (its own credential; `auth::workos_webhook`)",
    "/v1/traces": "OTLP ingest (`trace_ingest.rs`): authenticates + `ingest` scope inline — mounted from server.rs, so the same-file follow cannot see it; asserted by trace_ingest's own tests",
    "/v1/chat/completions": "the chat handler: auth + scope run by `crate::admission::admit` (B-385 — Step::Auth < Step::Scope is a compile-time fact), proven by `admission::tests` + `handler_harness`",
    "/v1/embeddings": "embeddings: the SAME `admission::admit` pipeline as chat (B-385), proven by the same tests",
    "/v1/messages": "Anthropic-native: the SAME `admission::admit` pipeline as chat (B-385), proven by `anthropic_messages::tests`",
    "/v1/messages/count_tokens": "Anthropic-native: auth + scope inline",
}
# Handlers whose auth is inline in a function the simple call-follow cannot see
# (the chat path calls validate_authorization directly; listed above by path).

AUTH_CALL = re.compile(r"\bvalidate_authorization\(")
SCOPE_CALL = re.compile(
    r"\b(allows_scope|can_admin|is_verified_owner|can_mint_keys|can_write_prompts|require_scope)\("
)
ROUTE_HEAD = re.compile(r'\.route\(\s*"(/[^"]*)"\s*,')
HANDLER_IN_METHOD = re.compile(
    r"\b(?:get|post|put|patch|delete|head|options)\(\s*(?:crate::)?([A-Za-z0-9_:]+)\s*\)"
)
FN_DEF = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)\b", re.MULTILINE
)


def strip_test_items(src: str) -> str:
    """Blank every `#[cfg(test)]`-gated item (newlines kept)."""
    out: list[str] = []
    i, n = 0, len(src)
    attr = "#[cfg(test)]"
    while i < n:
        j = src.find(attr, i)
        if j == -1:
            out.append(src[i:])
            break
        out.append(src[i:j])
        k, depth, seen, end = j + len(attr), 0, False, n
        while k < n:
            ch = src[k]
            if ch == "{":
                depth += 1
                seen = True
            elif ch == "}":
                depth -= 1
                if seen and depth == 0:
                    end = k + 1
                    break
            elif ch == ";" and not seen:
                end = k + 1
                break
            k += 1
        out.append("".join("\n" if ch == "\n" else " " for ch in src[j:end]))
        i = end
    return "".join(out)


def fn_bodies(src: str) -> dict[str, str]:
    """name → body text (brace-matched) for every fn in the (test-stripped) source.

    A name defined more than once (a store-trait method and a handler can share
    `list_datasets`) keeps the TOP-LEVEL definition — handlers are top-level
    `async fn`s, trait impls are indented — and otherwise the first.
    """
    bodies: dict[str, str] = {}
    top_level: set[str] = set()
    for m in FN_DEF.finditer(src):
        name = m.group(1)
        line_start = src.rfind("\n", 0, m.start()) + 1
        indented = src[line_start : m.start() + 1].startswith((" ", "\t")) or bool(
            re.match(r"\s", src[line_start]) if line_start < len(src) else False
        )
        start = src.find("{", m.end())
        if start == -1:
            continue
        depth, k = 0, start
        while k < len(src):
            if src[k] == "{":
                depth += 1
            elif src[k] == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        body = src[start : k + 1]
        if not indented:
            bodies[name] = body
            top_level.add(name)
        elif name not in top_level:
            bodies.setdefault(name, body)
    return bodies


def handler_proven(handler: str, bodies: dict[str, str]) -> tuple[bool, bool]:
    """(authenticates, scoped) for a handler, following same-file calls transitively.

    Bounded by the set of functions in the file (each visited once), so a helper
    that calls a helper that calls `validate_authorization` still counts — the
    dataset / experiment families are three levels deep.
    """
    start = handler.split("::")[-1]
    if start not in bodies:
        return (False, False)
    seen: set[str] = set()
    todo = [start]
    auth = scoped = False
    while todo and not (auth and scoped):
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        body = bodies[name]
        auth = auth or bool(AUTH_CALL.search(body))
        scoped = scoped or bool(SCOPE_CALL.search(body))
        for callee in set(re.findall(r"\b([a-z_][A-Za-z0-9_]*)\s*\(", body)):
            if callee in bodies and callee not in seen:
                todo.append(callee)
    return (auth, scoped)


def route_calls(src: str) -> list[tuple[str, str]]:
    """(path, argument text) for every `.route("/…", …)` — the argument text is
    taken by paren matching, so a chained `get(a)\n.post(b)` spanning lines is
    one route. Paths not starting with `/` (a `{route}` in a format string) are
    not routes."""
    out: list[tuple[str, str]] = []
    for m in ROUTE_HEAD.finditer(src):
        path = m.group(1)
        # Walk from the `.route(` open paren to its match.
        open_paren = src.rfind("(", 0, m.end())
        depth, k = 0, open_paren
        while k < len(src):
            if src[k] == "(":
                depth += 1
            elif src[k] == ")":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        out.append((path, src[m.end() : k]))
    return out


def scan_file(rel: str, src: str) -> list[str]:
    src = strip_test_items(src)
    bodies = fn_bodies(src)
    findings: list[str] = []
    for path, rhs in route_calls(src):
        if path in ALLOWLIST:
            continue
        handlers = HANDLER_IN_METHOD.findall(rhs)
        if not handlers:
            findings.append(
                f"{rel}: route {path!r}: could not identify its handler(s) in `{rhs.strip()[:60]}`"
            )
            continue
        for h in handlers:
            auth, scoped = handler_proven(h, bodies)
            if not auth:
                findings.append(
                    f"{rel}: route {path!r} → `{h}` never calls validate_authorization (directly or via a same-file helper) — UNAUTHENTICATED, or add it to the allowlist with a reason"
                )
            elif not scoped:
                findings.append(
                    f"{rel}: route {path!r} → `{h}` authenticates but checks NO scope or role — an ingest-only key can reach it (B-383 d)"
                )
    return findings


def scan_tree() -> list[str]:
    findings: list[str] = []
    for p in sorted(GATEWAY_SRC.rglob("*.rs")):
        rel = str(p.relative_to(ROOT))
        findings.extend(scan_file(rel, p.read_text(encoding="utf-8")))
    return findings


def selftest() -> int:
    good = (
        "pub fn routes() -> Router<S> {\n"
        '    Router::new().route("/v1/things", get(list_things))\n'
        '        .route("/health", get(health))\n'
        "}\n"
        "async fn require_claims(h: &HeaderMap) -> Result<Claims, R> {\n"
        "    let c = crate::auth::validate_authorization(h).await?;\n"
        "    if !c.allows_scope(Scope::Read) { return Err(forbidden()); }\n"
        "    Ok(c)\n"
        "}\n"
        "async fn list_things(headers: HeaderMap) -> Response { let c = require_claims(&headers).await?; ok() }\n"
        'async fn health() -> &\'static str { "ok" }\n'
    )
    unscoped = good.replace(
        "    if !c.allows_scope(Scope::Read) { return Err(forbidden()); }\n", ""
    )
    unauth = good.replace(
        "    let c = crate::auth::validate_authorization(h).await?;\n",
        "    let c = dev_claims();\n",
    )
    hidden_in_test = (
        good
        + '#[cfg(test)]\nmod tests {\n    fn routes_t() { Router::new().route("/v1/open", get(open)); }\n    async fn open() {}\n}\n'
    )
    cases = [
        ("scoped through a same-file helper passes", good, None),
        ("authenticated but UNSCOPED blocks", unscoped, "checks NO scope or role"),
        ("unauthenticated blocks", unauth, "never calls validate_authorization"),
        ("a route inside #[cfg(test)] is not scanned", hidden_in_test, None),
    ]
    rc = 0
    for label, src, want in cases:
        hits = scan_file("crates/gateway/src/x.rs", src)
        ok = (not hits) if want is None else any(want in h for h in hits)
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
        print("route auth: FAIL")
        for f in findings:
            print(f"  ✗ {f}")
        return 1
    print(
        "route auth: OK — every mounted route authenticates and checks a scope or role, or is allowlisted with a reason."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
