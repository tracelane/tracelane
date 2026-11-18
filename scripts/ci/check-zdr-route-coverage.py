#!/usr/bin/env python3
"""Require explicit ZDR bindings and gates on companion dispatch entry points."""

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPANIONS = {
    "anthropic_messages.rs": "count_tokens_with_claims",
    "openai_responses.rs": "input_tokens_with_claims",
    "gemini_native.rs": "count_tokens_with_headers",
    "realtime.rs": "open_session",
}

# Delegated dispatch already covered at its request boundary, or background work
# whose capture decision excludes constrained requests. New call sites must gate.
EXEMPT = {
    (
        "semantic_cache.rs",
        "embed",
    ): "required requests bypass response cache before embeddings",
    ("online_eval.rs", "judge_one"): "capture-off requests are not enqueued",
    (
        "prompt_eval.rs",
        "execute_case",
    ): "explicit persisted eval; not a request-header dispatch route",
    (
        "openai_responses.rs",
        "provider_key",
    ): "credential helper, gated by request callers",
    (
        "openai_responses.rs",
        "companion_with_claims",
    ): "three companion entry points gate before this helper",
    (
        "passthrough.rs",
        "forward",
    ): "admission Opaque binding refuses required before forwarding",
}


def check(files):
    errors = []
    for name, source in files.items():
        for match in re.finditer(
            r"impl\s+(?:crate::admission::)?Route\s+for\s+(\w+)\s*\{", source
        ):
            body = source[match.end() :].split("async fn", 1)[0]
            if not re.search(r"const ZDR\s*:", body):
                errors.append(f"{name}: {match[1]} lacks explicit ZDR binding")
    for name, source in files.items():
        if "test" in Path(name).stem:
            continue
        source = re.split(r"#\[cfg\([^]]*test[^]]*\)\]\s*mod\s", source)[0]
        functions = list(re.finditer(r"\bfn (\w+)\s*(?:<[^;{}]*>)?\(", source))
        for i, match in enumerate(functions):
            end = functions[i + 1].start() if i + 1 < len(functions) else len(source)
            body = source[match.end() : end]
            if (
                re.search(
                    r"\b(?:resolve_provider_key|provider_key|provider_key_pooled)\s*\(",
                    body,
                )
                and "zdr::gate(" not in body
                and "zdr::constraint_from_headers(" not in body
                and (name, match[1]) not in EXEMPT
            ):
                errors.append(
                    f"{name}: {match[1]} resolves a dispatch key without a ZDR gate or reasoned exemption"
                )
    for name, function in COMPANIONS.items():
        source = files.get(name, "")
        match = re.search(rf"async fn {function}\b", source)
        body = source[match.end() :].split("\nasync fn", 1)[0] if match else ""
        if "zdr::gate(" not in body:
            errors.append(f"{name}: {function} lacks ZDR gate")
    return errors


def selftest():
    files = {
        name: f"async fn {fn}() {{ zdr::gate(); }}\nasync fn next() {{}}"
        for name, fn in COMPANIONS.items()
    }
    files["route.rs"] = (
        "impl Route for Probe { const ZDR: ZdrBinding = ZdrBinding::Gated; async fn run() {} }"
    )
    assert not check(files)
    bad = dict(files)
    bad["route.rs"] = "impl Route for Probe { async fn run() {} }"
    assert check(bad), "missing route binding escaped"
    for name in COMPANIONS:
        bad = dict(files)
        bad[name] = bad[name].replace("zdr::gate();", "")
        assert check(bad), f"missing companion gate escaped: {name}"
    bad = dict(files)
    bad["server.rs"] = (
        'async fn new_route() { resolve_provider_key("provider").await; }'
    )
    assert check(bad), "new ungated dispatch route escaped"
    print(
        "ZDR bindings selftest PASS: new ungated route, missing binding and four removed gates blocked"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        selftest()
    else:
        errors = check(
            {
                str(p.relative_to(ROOT / "crates/gateway/src")): p.read_text()
                for p in (ROOT / "crates/gateway/src").rglob("*.rs")
            }
        )
        for error in errors:
            print(error)
        if errors:
            raise SystemExit(1)
        print("ZDR bindings PASS: routes and companion gates present")
