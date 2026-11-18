#!/usr/bin/env python3
"""Narrow structural exceptions for no-raw-ch-query; uncertain source stays blocked."""

import argparse
import importlib.util
import re
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "caps", Path(__file__).with_name("check-ch-reads-capped.py")
)
caps = importlib.util.module_from_spec(spec)
spec.loader.exec_module(caps)


def arguments(source, start):
    """Split balanced Rust call arguments after a known opening parenthesis."""
    stack, parts, begin = [")"], [], start
    pairs = {"(": ")", "[": "]", "{": "}"}
    for i in range(start, len(source)):
        c = source[i]
        if c in pairs:
            stack.append(pairs[c])
        elif c in ")]}":
            if not stack or c != stack.pop():
                return None
            if not stack:
                parts.append(source[begin:i].strip())
                return parts, i + 1
        elif c == "," and len(stack) == 1:
            parts.append(source[begin:i].strip())
            begin = i + 1
    return None


def capped_queries(source):
    code = caps._bp.production_part(caps._bp.strip_comments_and_strings(source))
    found = False
    for call in re.finditer(r"\.query\b", code):
        opening = re.match(r"\s*\(", code[call.end() :])
        if opening is None:  # includes turbofish: uncertain means blocked
            return False
        parsed = arguments(code, call.end() + opening.end())
        if parsed is None:
            return False
        args, _ = parsed
        if len(args) == 2 and args[1].startswith("&["):
            continue  # Postgres signature; ClickHouse query takes one argument
        if len(args) != 1 or not re.fullmatch(r"&[a-zA-Z_]\w*", args[0]):
            return False
        name = args[0][1:]
        # Exactly a declaration and this borrow. No mutation, re-use or shadowing.
        if len(re.findall(rf"\b{re.escape(name)}\b", code)) != 2:
            return False
        binding = re.search(
            rf"\blet\s+{re.escape(name)}\s*=\s*(?:crate::clickhouse_query::)?TenantQuery::new\s*\(",
            code[: call.start()],
        )
        if binding is None:
            return False
        new_args = arguments(code, binding.end())
        if new_args is None or len(new_args[0]) != 2:
            return False
        tail = code[new_args[1] : call.start()].lstrip()
        if tail.startswith(".with_log_comment("):
            comment = arguments(tail, len(".with_log_comment("))
            if comment is None or len(comment[0]) != 1:
                return False
            tail = tail[comment[1] :].lstrip()
        if not re.match(r"\.sql_with_settings\(\)\s*;", tail):
            return False
        found = True
    return found


def selftest():
    good = """use clickhouse::Client;
fn read() {
 let sql = TenantQuery::new("SELECT count() FROM spans", tier)
 .with_log_comment(format!("tenant_id={}", tenant)).sql_with_settings();
 ch.query(&sql).fetch_one::<Counts>();
 pg.query("SELECT 1", &[]);
}"""
    cases = [
        ("capped binding with unrelated Postgres call", good, True),
        (
            "wrong argument beside cap",
            good.replace("query(&sql)", 'query("SELECT 1")'),
            False,
        ),
        ("second raw query", good + '\nch.query("SELECT 1");', False),
        (
            "reassigned variable",
            good.replace("ch.query", 'sql = "SELECT 1"; ch.query'),
            False,
        ),
        (
            "shadowed variable",
            good.replace("ch.query", 'let sql = "SELECT 1"; ch.query'),
            False,
        ),
        ("mutated variable", good.replace("ch.query", "sql.clear(); ch.query"), False),
        (
            "cap text in comment",
            good.replace("let sql = TenantQuery", "// let sql = TenantQuery"),
            False,
        ),
        (
            "post-cap transform",
            good.replace(
                "sql_with_settings();", 'sql_with_settings().replace("SETTINGS", "");'
            ),
            False,
        ),
        ("uncapped turbofish", good + '\nch.query::<Row>("SELECT 1");', False),
    ]
    failed = []
    for name, source, expected in cases:
        if capped_queries(source) != expected:
            failed.append(name)
    if failed:
        print("FAIL:", failed)
        return 1
    print(f"raw CH exceptions selftest: {len(cases)} cases passed")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("file", nargs="?")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    if args.file is None:
        parser.error("file is required")
    path = Path(args.file)
    paths = sorted((Path.cwd() / "crates/gateway/src").rglob("*.rs"))
    if path.resolve() in caps.test_only_modules(paths):
        return 0
    return 0 if capped_queries(path.read_text()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
