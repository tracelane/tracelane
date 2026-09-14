#!/usr/bin/env python3
"""Fail when a mutating web API route has no reachable caller in the app.

WHY (founder, 2026-09-07). The annotation-queue CREATE path existed end to end
— gateway `POST /v1/annotation-queues` and the web proxy
`apps/web/app/api/annotation-queues/route.ts` — and no UI anywhere called it.
The founder opened `/review`, saw a well-written empty state, and asked the
one question that matters: *"what is its purpose? nothing to add?"* Every
existing gate missed it: the L16 Playwright gate asserts a button DOES
something and cannot see a button never built; the prod proof drove the API
directly with curl, which proves the route works, never that a customer can
reach it. A follow-up sweep (read-only, cited in the commit) found four more
instances of the same shape, including a dashboard rename route whose own
list-card comment claims "rename + delete actions" while only delete shipped.
CLAUDE.md §12: an incident graduates into an executable gate or it is context
debt repeated at the next review.

WHAT IT CHECKS. Every `apps/web/app/api/**/route.ts` that exports POST, PUT,
PATCH or DELETE gets its URL path derived from the file path (Next.js
app-router convention: a directory named `[param]` is a dynamic segment).
For each (method, path) pair, this searches every non-test `.ts`/`.tsx` file
under `apps/web/app/**` and `apps/web/components/**` for a string literal
that names that exact path — a bare literal (`"/api/foo"`) or one with
template-literal segments in place of the dynamic parts
(`` `/api/foo/${id}` ``) — with the target HTTP method quoted somewhere in the
same call (a `method: "X"` object field, a `method="x"` JSX attribute, or a
ternary/conditional between two method strings, all handled the same way:
find every quoted HTTP-verb token between the path and the next `fetch(` /
`apiFetch(` / `<form` in the file). A route with no such caller and no
allowlist entry FAILS, naming the file, the method, the derived path, and the
founder's own question: **can a customer do this in the app?**

ALLOWLIST. A route legitimately has no in-app caller when it is a webhook
receiver, a CLI/SDK-only surface, an MCP tool, or a deliberate documented
stub. Each entry cites `(reason, evidence)` where evidence is a `file:line`
or a doc path that has to exist ON DISK — an entry whose evidence file is
missing is worse than no entry, because it reads as proof of a decision that
was never written down, so this refuses to pass on it.

USAGE
  check-unreachable-write-routes.py              # apps/web/app/api under ROOT
  check-unreachable-write-routes.py --selftest    # prove it blocks AND passes

HONEST LIMIT — read before trusting a pass. This sees the Next.js web-proxy
layer only: a gateway route (`/v1/...`) with no web proxy at all — a CLI-only
or customer-SDK-only endpoint — is invisible to it by construction, because it
never appears as a `route.ts` file under `apps/web/app/api`; those need their
own sweep (CLI source, `apps/docs/**`) and are out of this guard's scope, not
silently passed. It cannot tell a reachable-but-broken button from a working
one — a caller that 404s at runtime still counts as "found". Its window-bound
method search (stop at the next `fetch(`/`apiFetch(`/`<form` in the file, or
600 characters, whichever comes first) can misattribute a method from an
adjacent call if two calls to DIFFERENT paths sit closer together than that —
none do in this tree today, checked by hand for every route this guard would
otherwise flag. And it cannot see a caller built by string concatenation or a
shared helper that never spells out the literal path (`base + "/" + id`) —
every real caller in this tree today uses a literal or a template literal, so
this has not yet cost a false pass, but it is a blind spot, not a guarantee.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
API_DIR = ROOT / "apps" / "web" / "app" / "api"
CALLER_DIRS = [ROOT / "apps" / "web" / "app", ROOT / "apps" / "web" / "components"]

MUTATING_METHODS = ("POST", "PUT", "PATCH", "DELETE")

METHOD_EXPORT_RE = re.compile(
    r"^export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\s*\(",
    re.MULTILINE,
)
# Belt-and-braces for a route handler exported as a const arrow fn — none do
# today, but a guard that only recognises the shape it was written against is
# how this class comes back under a different export style.
METHOD_CONST_RE = re.compile(
    r"^export\s+const\s+(GET|POST|PUT|PATCH|DELETE)\s*[:=]", re.MULTILINE
)

TEST_NAME_RE = re.compile(r"\.test\.|\.spec\.")

METHOD_TOKEN_RE = re.compile(r"""['"](GET|POST|PUT|PATCH|DELETE)['"]""", re.IGNORECASE)
# Where a caller's method-window search stops: the next call site in the file,
# so a route's OWN window never reads into a sibling call's method.
NEXT_CALL_RE = re.compile(r"\b(?:fetch|apiFetch)\s*\(|<form\b")
WINDOW_MAX_CHARS = 600

# reason -> the vocabulary this guard accepts; enforced only by convention
# (a founder/reviewer reads the reason), not by the guard itself.
REASONS = {"cli", "sdk", "webhook", "mcp", "deliberate-stub"}

# (METHOD, url_path) -> (reason, evidence). Evidence is `file:line` or a doc
# path, resolved relative to ROOT, and MUST exist on disk — see
# `evidence_path()` and its use in `check()`.
ALLOWLIST: dict[tuple[str, str], tuple[str, str]] = {
    # Called only by Polar.sh's own webhook dispatcher — documented in the
    # route's own file header, never invoked from our UI by construction.
    ("POST", "/api/webhooks/polar"): (
        "webhook",
        "apps/web/app/api/webhooks/polar/route.ts:1",
    ),
}


# ── Discovery ────────────────────────────────────────────────────────────────
def is_test_path(p: Path) -> bool:
    return (
        bool(TEST_NAME_RE.search(p.name)) or "__tests__" in p.parts or "e2e" in p.parts
    )


def route_files(api_dir: Path) -> list[Path]:
    return sorted(p for p in api_dir.rglob("route.ts") if not is_test_path(p))


def derive_path(route_file: Path, api_dir: Path) -> str:
    rel_dir = route_file.parent.relative_to(api_dir)
    parts = [] if rel_dir == Path(".") else list(rel_dir.parts)
    return "/" + "/".join(["api", *parts])


def exported_methods(text: str) -> list[str]:
    found = {m.group(1) for m in METHOD_EXPORT_RE.finditer(text)}
    found |= {m.group(1) for m in METHOD_CONST_RE.finditer(text)}
    return sorted(found)


# ── Caller search ────────────────────────────────────────────────────────────
def gather_corpus(dirs: list[Path]) -> list[tuple[Path, str]]:
    files: list[Path] = []
    for d in dirs:
        if not d.exists():
            continue
        for pattern in ("*.ts", "*.tsx"):
            files.extend(p for p in d.rglob(pattern) if not is_test_path(p))
    seen: dict[Path, str] = {}
    for p in sorted(set(files)):
        try:
            seen[p] = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return list(seen.items())


def path_pattern(url_path: str) -> re.Pattern[str]:
    segments = url_path.strip("/").split("/")
    parts: list[str] = []
    for seg in segments:
        if seg.startswith("[") and seg.endswith("]"):
            # A dynamic segment: a template expression, or a bare
            # identifier-ish token. Deliberately excludes `[`/`]` so a
            # doc comment or an import path that spells the literal
            # Next.js folder name (`/api/foo/[id]`) never counts as a
            # caller — that is a description of the route, not a call.
            parts.append(r"(?:\$\{[^}]{1,200}\}|[A-Za-z0-9_.-]+)")
        else:
            parts.append(re.escape(seg))
    # Negative lookahead: the match must not be followed by more path-like
    # characters. Without it, "/api/foo" would match inside the LONGER path
    # "/api/foo/${id}" (a different route entirely), and an import path
    # like "@/app/api/foo/[id]/route" would spuriously match "/api/foo".
    return re.compile("/" + "/".join(parts) + r"(?![\w/-])")


def method_window(text: str, start: int) -> str:
    end_limit = min(len(text), start + WINDOW_MAX_CHARS)
    nxt = NEXT_CALL_RE.search(text, start + 1)
    if nxt and nxt.start() < end_limit:
        end_limit = nxt.start()
    return text[start:end_limit]


def find_caller(
    method: str, url_path: str, corpus: list[tuple[Path, str]]
) -> tuple[Path, int] | None:
    pattern = path_pattern(url_path)
    for path, text in corpus:
        for m in pattern.finditer(text):
            window = method_window(text, m.start())
            methods_found = {t.upper() for t in METHOD_TOKEN_RE.findall(window)}
            if method in methods_found:
                lineno = text.count("\n", 0, m.start()) + 1
                return (path, lineno)
    return None


# ── Allowlist evidence ───────────────────────────────────────────────────────
def evidence_path(evidence: str) -> Path:
    if ":" in evidence:
        head, _, tail = evidence.rpartition(":")
        if tail.isdigit():
            return ROOT / head
    return ROOT / evidence


# ── Check ────────────────────────────────────────────────────────────────────
def check(
    api_dir: Path,
    caller_dirs: list[Path],
    allowlist: dict[tuple[str, str], tuple[str, str]],
) -> list[str]:
    corpus = gather_corpus(caller_dirs)
    findings: list[str] = []

    for route_file in route_files(api_dir):
        text = route_file.read_text(encoding="utf-8", errors="replace")
        url_path = derive_path(route_file, api_dir)
        rel = route_file.relative_to(ROOT) if ROOT in route_file.parents else route_file

        for method in exported_methods(text):
            if method not in MUTATING_METHODS:
                continue

            if find_caller(method, url_path, corpus) is not None:
                continue

            key = (method, url_path)
            if key in allowlist:
                reason, evidence = allowlist[key]
                if reason not in REASONS:
                    findings.append(
                        f"{rel}: allowlist entry for {method} {url_path} has an "
                        f"unrecognised reason {reason!r} (expected one of "
                        f"{sorted(REASONS)})"
                    )
                    continue
                ev_path = evidence_path(evidence)
                if not ev_path.exists():
                    findings.append(
                        f"{rel}: allowlist entry for {method} {url_path} "
                        f"({reason}) cites evidence {evidence!r} which does not "
                        "exist on disk — an allowlist entry without provable "
                        "evidence is a lie; fix the citation or remove the entry"
                    )
                continue

            findings.append(
                f"{rel}: {method} {url_path} has no caller anywhere under "
                "apps/web/app/** or apps/web/components/** (tests excluded) "
                "and no allowlist entry. Can a customer do this in the app?"
            )

    return findings


def run(api_dir: Path = API_DIR, caller_dirs: list[Path] = CALLER_DIRS) -> int:
    if not api_dir.exists():
        print(f"FAIL: {api_dir} does not exist")
        return 1
    findings = check(api_dir, caller_dirs, ALLOWLIST)
    if findings:
        for f in findings:
            print(f"FAIL {f}")
        print(
            f"\n{len(findings)} mutating web route(s) failed the reachability check. "
            "A route with no caller and no allowlist entry is reachable only by "
            "curl — see docs/reference/TRAPS.md for the incident this guard closes."
        )
        return 1
    n = len(route_files(api_dir))
    print(f"unreachable write routes: clean ({n} route.ts file(s) checked)")
    return 0


# ── Selftest ─────────────────────────────────────────────────────────────────
def selftest() -> int:
    import tempfile

    def w(root: Path, rel: str, body: str) -> Path:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
        return p

    with tempfile.TemporaryDirectory() as tdname:
        td = Path(tdname)
        api_dir = td / "app" / "api"
        caller_dirs = [td / "app", td / "components"]

        # (a) a mutating route with no caller anywhere — must BLOCK.
        w(
            td,
            "app/api/widgets/route.ts",
            "export async function POST(req: Request) {\n  return Response.json({});\n}\n",
        )
        findings = check(api_dir, caller_dirs, {})
        assert any("POST /api/widgets" in f for f in findings), (
            "selftest (a): a route with no caller must BLOCK"
        )
        print("✓ selftest (a): a mutating route with no caller BLOCKS")

        # (b) the same route, now with a real caller in a component — PASSES.
        w(
            td,
            "components/WidgetForm.tsx",
            "async function create() {\n"
            '  const res = await fetch("/api/widgets", { method: "POST" });\n'
            "}\n",
        )
        findings = check(api_dir, caller_dirs, {})
        assert not any("POST /api/widgets" in f for f in findings), (
            "selftest (b): a route with a real caller must PASS"
        )
        print("✓ selftest (b): the same route with a component caller PASSES")

        # (c) the ONLY caller is a .test.ts file — a test is not a customer,
        # must still BLOCK.
        (td / "components" / "WidgetForm.tsx").unlink()
        w(
            td,
            "components/WidgetForm.test.ts",
            'test("posts", async () => {\n'
            '  await fetch("/api/widgets", { method: "POST" });\n'
            "});\n",
        )
        findings = check(api_dir, caller_dirs, {})
        assert any("POST /api/widgets" in f for f in findings), (
            "selftest (c): a caller that exists only in a .test.ts must BLOCK"
        )
        print("✓ selftest (c): a caller living only in a .test.ts file BLOCKS")

        # (d) allowlisted with valid evidence — PASSES. `evidence_path()`
        # resolves relative to the real ROOT (not this temp tree), so cite a
        # file that genuinely exists under ROOT — this guard's own source is
        # as good a proof-of-existence as any.
        (td / "components" / "WidgetForm.test.ts").unlink()
        real_evidence = "scripts/ci/check-unreachable-write-routes.py"
        allow_ok = {("POST", "/api/widgets"): ("webhook", real_evidence)}
        findings = check(api_dir, caller_dirs, allow_ok)
        assert not any("POST /api/widgets" in f for f in findings), (
            "selftest (d): an allowlist entry with evidence that exists must PASS"
        )
        print("✓ selftest (d): an allowlisted route with valid evidence PASSES")

        # (e) allowlisted but the evidence file does not exist — BLOCKS.
        allow_bad = {
            ("POST", "/api/widgets"): (
                "webhook",
                "docs/this-file-does-not-exist-anywhere.md",
            )
        }
        findings = check(api_dir, caller_dirs, allow_bad)
        assert any("does not exist on disk" in f for f in findings), (
            "selftest (e): an allowlist entry with missing evidence must BLOCK"
        )
        print("✓ selftest (e): an allowlist entry whose evidence is missing BLOCKS")

    print("\nselftest PASSED.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="unreachable mutating web-route guard (the /review empty-state class)"
    )
    ap.add_argument(
        "--selftest", action="store_true", help="prove the guard blocks and passes"
    )
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    return run()


if __name__ == "__main__":
    sys.exit(main())
