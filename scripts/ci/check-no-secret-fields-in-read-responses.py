#!/usr/bin/env python3
"""No read or list response we serve carries a secret-shaped field.

B-430 (2026-09-19): a vendor's LIST endpoint returned each webhook endpoint's signing
secret INLINE and it reached a transcript. The ruling's second half: never BE that
vendor. Redaction belongs at the boundary (the serialized type), never in the caller.

THE RULE. In `crates/gateway/src`, every `#[derive(… Serialize …)]` struct, and every
struct-variant of a `Serialize` enum, is a wire shape. A field whose wire NAME is
secret-shaped — a segment secret / token / password / passwd / apikey / pepper /
authorization / cookie / session / credential(s), or a pair api_key / private_key /
signing_key / access_key / raw_key / plain_key / master_key / encryption_key — and whose
TYPE can carry a secret (String / str / Cow / Vec<u8> / Bytes / serde_json::Value /
*Secret*, bare or wrapped) must be `#[serde(skip)]` / `#[serde(skip_serializing)]`, or
DERIVED (*_id *_hash *_prefix *_masked *_count *_url *_env *_name … / has_* is_*), or
carry `// secret-field-ok: <why this is not a secret>` (>= 20 chars, within 6 lines).
`#[serde(rename = "secret")]` makes the wire name the one that counts. Plural `tokens` /
`sessions` are this product's observability nouns and never match; `secrets` does.

`apps/web/app/api/**/route.ts` is scanned best-effort for `NextResponse.json({…})` /
`Response.json({…})` object LITERALS and their keys; a body built from a variable or a
spread is invisible, and that half is review.

HONEST LIMIT: this reads rustfmt-formatted source line by line (`cargo fmt --check` is a
preflight gate, so the shapes it relies on — one-line derives, fields one per line,
the item's closing brace at its own indent — hold). It proves a wire shape does not
ADVERTISE a secret; it cannot see one behind an innocent name or a hand-written
`impl Serialize`. `--selftest` plants the real shape and proves it BLOCKS.

USAGE
  check-no-secret-fields-in-read-responses.py             # scan the tree
  check-no-secret-fields-in-read-responses.py --selftest  # plant violations, prove they block
  check-no-secret-fields-in-read-responses.py --file F    # scan one .rs or .ts file
"""

from __future__ import annotations

import itertools
import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
ROOTS = ["crates/gateway/src", "apps/web/app/api"]
MARK = "secret-field-ok:"

# THE NAME SHAPE — kept textually identical in scripts/ops/vendor-read.py
SECRET_WORDS = {"secret", "secrets", "token", "password", "passwd", "apikey", "pepper", "authorization", "cookie", "session", "credential", "credentials"}  # fmt: skip
SECRET_PAIRS = {(a, "key") for a in ("api", "private", "signing", "access", "raw", "plain", "plaintext", "full", "master", "encryption")}  # fmt: skip
DERIVED_LAST = {"id", "ids", "hash", "hashes", "prefix", "masked", "last4", "fingerprint", "configured", "set", "present", "count", "len", "length", "uri", "url", "urls", "env", "name", "names", "kind", "type", "at", "ttl", "hint", "digest", "sha256", "version", "expires", "expiry", "error", "errors", "status", "scope", "scopes", "source", "provider"}  # fmt: skip
DERIVED_FIRST = {"has", "is", "was", "needs", "requires", "require", "num", "n"}


def is_secret_shaped(name: str) -> bool:
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s)  # APISecret -> API_Secret
    segs = [p for p in s.lower().replace("-", "_").split("_") if p]
    if not segs or segs[0] in DERIVED_FIRST or segs[-1] in DERIVED_LAST:
        return False
    return any(s in SECRET_WORDS for s in segs) or any(
        p in SECRET_PAIRS for p in itertools.pairwise(segs)
    )


CARRIER = re.compile(
    r"\b(?:String|str|Cow|Bytes|Value|Secret\w*|\w*Secret)\b|\bVec\s*<\s*u8\s*>|\[u8"
)
SKIP = re.compile(r"#\[serde\([^\]]*\bskip(?:_serializing)?\b\s*(?:,|\))")
RENAME = re.compile(r"#\[serde\([^\]]*\brename\s*=\s*\"([^\"]+)\"")
ITEM_HEAD = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum)\s+\w+")
ITEM = re.compile(r"^(\s*)(?:pub(?:\([^)]*\))?\s+)?(struct|enum)\s+(\w+).*\{\s*$")
STRUCT_FIELD = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:r#)?([A-Za-z_]\w*):\s*(.+?),?\s*(?://.*)?$"
)
VARIANT_FIELDS = re.compile(r"[{,]\s*(?:r#)?([A-Za-z_]\w*):\s*([^,}]+)")


def exempt(lines: list[str], i: int) -> str | None:
    """None when not annotated, else the reason (possibly too short) within 6 lines above or on the line."""
    for ln in reversed(lines[max(0, i - 6) : i + 1]):
        if MARK in ln:
            return ln.split(MARK, 1)[1].strip()
    return None


def finding(
    lines: list[str], i: int, name: str, wire: str, ty: str | None, attrs: str
) -> str | None:
    """Both the wire name and the Rust field name count — `#[serde(rename = "value")] pub secret`
    still ships the secret bytes."""
    if (
        not (is_secret_shaped(wire) or is_secret_shaped(name))
        or (ty is not None and not CARRIER.search(ty))
        or SKIP.search(attrs)
    ):
        return None
    reason = exempt(lines, i)
    if reason is None:
        return f"secret-shaped field `{wire}`" + (f": {ty}" if ty else "")
    return (
        None
        if len(reason) >= 20
        else f"`{wire}` carries a `{MARK}` reason shorter than 20 chars ({reason!r})"
    )


def normalize(text: str) -> list[str]:
    """rustfmt wraps three things over several lines: a long `#[derive(...)]` / `#[serde(...)]`,
    an item's `where` clause, and a long field type. Each is joined onto its first line, padded
    with blank lines so every line number below still holds."""
    lines, out, i = text.lstrip("\ufeff").split("\n"), [], 0

    def open_until(i: int, o: str, c: str) -> int:
        j = i
        while j + 1 < len(lines) and "".join(lines[i : j + 1]).count(o) > "".join(
            lines[i : j + 1]
        ).count(c):
            j += 1
        return j

    while i < len(lines):
        ln, j, s = lines[i], i, lines[i].strip()
        if s.startswith("#["):
            j = open_until(i, "[", "]")
        elif ITEM_HEAD.match(ln) and not s.endswith(("{", ";")):
            while j + 1 < len(lines) and not lines[j].rstrip().endswith(("{", ";")):
                j += 1
        elif ":" in ln and not s.startswith("//"):
            j = open_until(i, "<", ">")
        out.append(
            ln
            if j == i
            else ln + " " + " ".join(x.strip() for x in lines[i + 1 : j + 1])
        )
        out.extend([""] * (j - i))
        i = j + 1
    return out


def scan_rust(text: str) -> list[tuple[int, str]]:
    lines, hits, i = normalize(text), [], 0
    while i < len(lines):
        ln = lines[i]
        k = i + 1
        while (
            ln.strip() == "#[cfg(test)]"
            and k < len(lines)
            and lines[k].strip().startswith("#[")
        ):
            k += 1  # further attributes between #[cfg(test)] and the mod
        if (
            ln.strip() == "#[cfg(test)]"
            and k < len(lines)
            and re.match(r"\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{\s*$", lines[k])
        ):
            indent = lines[k][: len(lines[k]) - len(lines[k].lstrip())]
            close = re.compile(re.escape(indent) + r"\}\s*(?://.*)?$")
            i = k + 1
            while i < len(lines) and not close.match(lines[i]):
                i += 1
        elif re.match(r"\s*#\[derive\(", ln) and re.search(r"\bSerialize\b", ln):
            j = i + 1
            while j < len(lines) and re.match(r"\s*(?:#\[|//|$)", lines[j]):
                j += 1
            m = ITEM.match(lines[j]) if j < len(lines) else None
            if m:
                close, kind, item, attrs = m.group(1) + "}", m.group(2), m.group(3), ""
                j += 1
                while j < len(lines) and lines[j] != close:
                    fl, st = lines[j], lines[j].strip()
                    if st.startswith("#["):
                        attrs += " " + st  # accumulate until the field they decorate
                    elif st and not st.startswith("//"):
                        rn = RENAME.search(attrs)
                        sm = STRUCT_FIELD.match(fl)
                        fields = (
                            VARIANT_FIELDS.findall(fl)
                            if kind == "enum" and "{" in fl
                            else [sm.groups()]
                            if sm
                            else []
                        )
                        for name, ty in fields:
                            f = finding(
                                lines,
                                j,
                                name,
                                rn.group(1) if rn else name,
                                ty.strip(),
                                attrs,
                            )
                            if f:
                                hits.append((j + 1, f"{kind} {item}: {f}"))
                        attrs = ""
                    j += 1
            i = j
        i += 1
    return hits


def scan_ts(text: str) -> list[tuple[int, str]]:
    """Every key of every object literal inside a `NextResponse.json(...)` / `Response.json(...)`
    call — the body AND the ResponseInit (a `set-cookie` header carries a secret too)."""
    lines, hits = text.split("\n"), []
    for jm in re.finditer(r"\b(?:NextResponse|Response)\.json\(", text):
        depth, k, q = 1, jm.end(), None  # paren depth, skipping string literals
        while k < len(text) and depth:
            c = text[k]
            if q:
                if c == "\\":
                    k += 1
                elif c == q:
                    q = None
            elif c in "\"'`":
                q = c
            else:
                depth += {"(": 1, ")": -1}.get(c, 0)
            k += 1
        call = text[jm.end() : k]
        for km in re.finditer(
            r"[{,]\s*(?:\"([^\"]+)\"|'([^']+)'|([A-Za-z_$][\w$]*))\s*(?::|(?=\s*[,}]))",
            call,
        ):
            key, line = (
                km.group(1) or km.group(2) or km.group(3),
                text.count("\n", 0, jm.end() + km.start()) + 1,
            )
            f = finding(lines, line - 1, key, key, None, "")
            if f:
                hits.append((line, f"route object literal: {f}"))
    return hits


def scan_file(path: pathlib.Path) -> list[str]:
    text = path.read_text(errors="replace")
    hits = (
        scan_rust(text)
        if path.suffix == ".rs"
        else scan_ts(text)
        if path.suffix == ".ts"
        else []
    )
    rel = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
    return [f"{rel}:{line}: {what}" for line, what in hits]


def scan(paths: list[pathlib.Path]) -> list[str]:
    files = []
    for p in paths:
        if not p.exists():
            raise SystemExit(
                f"✗ {p} does not exist — a guard over nothing is not green (CLAUDE.md §14)"
            )
        if p.is_file():
            files.append(p)
        else:
            files += [x for x in p.rglob("*.rs") if "/target/" not in str(x)]
            files += [
                x
                for x in p.rglob("route.ts")
                if "node_modules" not in str(x) and not x.name.endswith(".test.ts")
            ]
    return [f for x in sorted(files) for f in scan_file(x)]


SER = "#[derive(Debug, Clone, Serialize)]\n"
CASES = [  # (name, suffix, source, expect_block)
    ("b430_shape_webhook_secret_on_a_serialize_struct", ".rs", SER + "pub struct EndpointRow {\n    pub id: String,\n    pub url: String,\n    pub webhook_secret: String,\n}\n", True),
    ("serde_skip_keeps_it_off_the_wire", ".rs", SER + "pub struct EndpointRow {\n    pub id: String,\n    #[serde(skip)]\n    pub webhook_secret: String,\n}\n", False),
    ("serde_skip_serializing_keeps_it_off_the_wire", ".rs", SER + "pub struct EndpointRow {\n    #[serde(skip_serializing)]\n    pub webhook_secret: String,\n}\n", False),
    ("skip_serializing_if_is_conditional_not_a_skip", ".rs", SER + 'pub struct EndpointRow {\n    #[serde(skip_serializing_if = "Option::is_none")]\n    pub webhook_secret: Option<String>,\n}\n', True),
    ("derived_names_pass", ".rs", SER + "pub struct KeyRow {\n    pub key_prefix: String,\n    pub api_key_id: Uuid,\n    pub token_hash: String,\n    pub has_secret: bool,\n    pub secret_count: u32,\n    pub max_tokens: u32,\n    pub secret_masked: String,\n    pub api_key_env: String,\n    pub session_id: String,\n}\n", False),
    ("annotated_with_a_reason_passes_on_the_line_or_above", ".rs", SER + "pub struct ProviderRequest {\n    // secret-field-ok: outbound body TO the provider, never served on a read path\n    pub api_key: String,\n    pub token: String, // secret-field-ok: one-time reveal at mint; list row has no token\n}\n", False),
    ("annotation_reason_too_short_blocks", ".rs", SER + "pub struct ProviderRequest {\n    // secret-field-ok: fine\n    pub api_key: String,\n}\n", True),
    ("deserialize_only_struct_is_not_a_wire_response", ".rs", "#[derive(Debug, Deserialize)]\npub struct Inbound {\n    pub secret: String,\n}\n", False),
    ("serde_rename_to_a_secret_name_is_the_wire_name", ".rs", SER + 'pub struct Row {\n    #[serde(rename = "secret")]\n    pub s: String,\n}\n', True),
    ("field_typed_as_another_struct_is_scanned_on_its_own", ".rs", SER + "pub struct Wrapper {\n    pub session: SessionRow,\n    pub cookie: Option<CookieMeta>,\n}\n", False),
    ("session_as_a_string_is_a_secret", ".rs", SER + "pub struct Wrapper {\n    pub session: String,\n}\n", True),
    ("option_string_and_camel_case_secret_string", ".rs", SER + "pub struct Keys {\n    pub access_token: Option<String>,\n    pub clientSecret: SecretString,\n}\n", True),
    ("acronym_prefixed_wire_name_is_secret_shaped", ".rs", SER + 'pub struct Keys {\n    #[serde(rename = "APISecret")]\n    pub s: String,\n}\n', True),
    ("enum_struct_variant_is_a_wire_shape", ".rs", SER + "pub enum Outcome {\n    Ok { id: String },\n    Issued { access_token: String },\n}\n", True),
    ("plural_tokens_and_sessions_are_counts_and_groups", ".rs", SER + "pub struct Usage {\n    pub tokens: u64,\n    pub sessions: Vec<SessionSummary>,\n    pub input_tokens: u64,\n}\n", False),
    ("test_module_is_not_scanned", ".rs", "fn prod() -> u32 {\n    1\n}\n#[cfg(test)]\nmod tests {\n    #[derive(Serialize)]\n    struct T {\n        pub secret: String,\n    }\n}\n", False),
    ("serde_path_derive_and_value_under_a_secret_key", ".rs", "#[derive(serde::Serialize)]\npub struct R {\n    pub password: String,\n    pub authorization: serde_json::Value,\n}\n", True),
    ("ts_object_literal_with_a_secret_key", ".ts", "export async function GET() {\n  return NextResponse.json({ id: row.id, secret: row.secret });\n}\n", True),
    ("ts_shorthand_secret_key", ".ts", "export async function GET() {\n  const token = await mint();\n  return NextResponse.json({ id, token });\n}\n", True),
    ("ts_derived_keys_pass", ".ts", "export async function GET() {\n  return NextResponse.json({ id, key_prefix, has_secret: true, secret_count: 3 });\n}\n", False),
    ("ts_annotated_passes", ".ts", "export async function POST() {\n  // secret-field-ok: one-time reveal at creation, never on a list or read\n  return NextResponse.json({ id, token: minted });\n}\n", False),
    ("ts_response_json_and_nested_object", ".ts", "export async function GET() {\n  return Response.json({ ok: true, data: { password: p } }, { status: 200 });\n}\n", True),
]  # fmt: skip


def selftest() -> int:
    bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        for name, suffix, src, expect_block in CASES:
            f = pathlib.Path(tmp) / f"{name}{suffix}"
            f.write_text(src)
            got = scan_file(f)
            ok = bool(got) == expect_block
            bad += not ok
            print(
                f"  {'✓' if ok else '✗'} {name}: {'BLOCKED' if got else 'passed'} (expected {'BLOCK' if expect_block else 'pass'})"
                + "".join(f"\n      {g}" for g in got)
            )
    if bad:
        print(f"✗ selftest: {bad} case(s) did not behave as expected")
        return 1
    print(
        f"✓ selftest: {len(CASES)} cases — a secret-shaped field on a Serialize struct or a route object literal blocks; skip / derived name / >=20-char reason pass"
    )
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if argv[:1] == ["--file"] and len(argv) == 2:
        paths = [pathlib.Path(argv[1])]
    elif argv:
        print((__doc__ or "").split("USAGE", 1)[1])
        return 2
    else:
        paths = [ROOT / r for r in ROOTS]
    findings = scan(paths)
    for f in findings:
        print(f"  {f}")
    if findings:
        print(
            "✗ secret-shaped fields on a serialized read/list shape (B-430 class) — #[serde(skip)] it, return a derived field (*_prefix / *_masked / *_id), or write `// secret-field-ok: <why this is not a secret>` (>= 20 chars)"
        )
        return 1
    print(
        f"✓ no-secret-fields-in-read-responses: no Serialize struct and no route object literal under {', '.join(ROOTS)} carries a secret-shaped field"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
