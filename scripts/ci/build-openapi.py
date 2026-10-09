#!/usr/bin/env python3
"""Generate `crates/gateway/openapi/control.v1.json` — the machine-readable description of
the gateway's control API (OG-60 Part A, `specs/OG-60-openapi-and-gateway-settings.md`).

THREE INPUTS, nothing typed twice:
  1. `CONTROL_ROUTES` + `MATRIX` (`crates/gateway/src/auth/capability.rs`) -> for every control
     operation: capability, audit action and the ROLES that hold the capability (computed from
     the matrix columns, never typed), plus the shared 401/403/429/503 responses.
  2. The `.route(` scan (the `check-route-auth.py` parser) -> every mounted `/v1` route, so
     reads and the data plane are listed too. A route with no fragment is emitted as
     `x-tracelane-undocumented: true`; it FAILS `--check` when it is a control row or sits in a
     control family (`REQUIRED_PREFIXES`).
  3. `crates/gateway/openapi/fragments/*.json` -> hand-written per operation: summary, request
     and response JSON Schemas, `x-error-codes`, `x-error-envelope`. One file per FAMILY (a
     deviation from the spec's one-file-per-route: the same content, ~8 files instead of ~60).
     Written from the handler's serde types; `deny_unknown_fields` is `additionalProperties:false`.

GUARDS (`--check`, in `verify-all`): the checked-in file equals a fresh build; every control row
has a fragment; no fragment names a route that is not mounted; every `x-error-codes` literal
appears as a string literal in the operation's handler module (proves the code EXISTS there, not
that it is returned for that condition — the live probe is the other half); the doc names no
route that is not mounted; the file is at most 4 MiB.

USAGE
  build-openapi.py             write the file
  build-openapi.py --check     exit 1 if stale or any guard fails
  build-openapi.py --selftest  plant a defect per rule and prove each blocks
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "crates/gateway/openapi/control.v1.json"
FRAG_DIR = ROOT / "crates/gateway/openapi/fragments"
CAPABILITY_RS = "crates/gateway/src/auth/capability.rs"
MAX_BYTES = 4 * 1024 * 1024

# A mounted route in one of these families MUST have a fragment (the control plane); the data
# plane may stay `x-tracelane-undocumented` until someone writes its fragment.
REQUIRED_PREFIXES = (
    "/v1/controls",
    "/v1/projects",
    "/v1/security",
    "/v1/audit/control-changes",
)

ROLE_COLUMNS = [
    "admin",
    "developer",
    "viewer",
    "billing",
    "unrecognised",
    "api_key",
    "master",
]
MATRIX_ROW = re.compile(
    r"Row::new\(Capability::(\w+),\s*\"(\w+)\",\s*([YN]),\s*([YN]),\s*([YN]),"
    r"\s*([YN]),\s*([YN]),\s*([YN]),\s*([YN])\)"
)
METHOD_HANDLER = re.compile(
    r"\b(get|post|put|patch|delete)\(\s*(?:crate::)?([A-Za-z0-9_:]+)\s*\)"
)


def _load_route_auth():
    spec = importlib.util.spec_from_file_location(
        "check_route_auth", ROOT / "scripts/ci/check-route-auth.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["check_route_auth"] = mod
    spec.loader.exec_module(mod)
    return mod


CRA = _load_route_auth()


# ── inputs ────────────────────────────────────────────────────────────────────


def read_sources() -> dict[str, str]:
    return {
        str(p.relative_to(ROOT)): p.read_text(encoding="utf-8")
        for p in sorted(CRA.GATEWAY_SRC.rglob("*.rs"))
    }


def read_fragments() -> dict[str, dict]:
    out = {}
    for p in sorted(FRAG_DIR.glob("*.json")):
        out[p.name] = json.loads(p.read_text(encoding="utf-8"))
    return out


def matrix_roles(src: str) -> dict[str, tuple[str, list[str]]]:
    """capability variant -> (slug, [role columns that hold it])."""
    out = {}
    for m in MATRIX_ROW.finditer(src):
        flags = [g == "Y" for g in m.groups()[2:]]
        out[m.group(1)] = (m.group(2), [c for c, f in zip(ROLE_COLUMNS, flags) if f])
    return out


def mounted_routes(sources: dict[str, str]) -> dict[tuple[str, str], str]:
    """(METHOD, path) -> source file, for every mounted `/v1` route method (tests stripped)."""
    out: dict[tuple[str, str], str] = {}
    for rel, src in sources.items():
        for path, rhs in CRA.route_calls(CRA.strip_test_items(src)):
            if not path.startswith("/v1"):
                continue
            for method, _handler in METHOD_HANDLER.findall(rhs):
                out.setdefault((method.upper(), path), rel)
    return out


# ── build ─────────────────────────────────────────────────────────────────────


def _path(p: str) -> str:
    return re.sub(r"\{\*(\w+)\}", r"{\1}", p)


def _op_id(method: str, path: str) -> str:
    return method.lower() + "_" + re.sub(r"[^a-z0-9]+", "_", path.lower()).strip("_")


def _schema_response(desc: str, schema: dict | None) -> dict:
    r: dict = {"description": desc}
    if schema is not None:
        r["content"] = {"application/json": {"schema": schema}}
    return r


def build(
    sources: dict[str, str], fragments: dict[str, dict]
) -> tuple[dict, list[str]]:
    """The document and the list of guard findings (empty = clean)."""
    findings: list[str] = []
    cap_src = sources[CAPABILITY_RS]
    rows = CRA.control_rows(cap_src)
    roles = matrix_roles(cap_src)
    mounted = mounted_routes(sources)
    shared = fragments.get("_shared.json", {})

    ops: dict[
        tuple[str, str], tuple[dict, str]
    ] = {}  # (METHOD, path) -> (fragment op, module)
    for fname, frag in fragments.items():
        if fname.startswith("_"):
            continue
        for key, op in frag.get("operations", {}).items():
            method, path = key.split(" ", 1)
            module = op.get("module") or frag.get("module")
            if (method, path) in ops:
                findings.append(f"fragment {fname}: {key!r} is documented twice")
            if (method, path) not in mounted:
                findings.append(
                    f"fragment {fname}: {key!r} is not a mounted route (orphan fragment)"
                )
            if module not in sources:
                findings.append(
                    f"fragment {fname}: {key!r} names module {module!r}, which does not exist"
                )
            ops[(method, path)] = (op, module)
            for code in op.get("x-error-codes", []):
                if module in sources and f'"{code}"' not in sources[module]:
                    findings.append(
                        f"fragment {fname}: {key!r} lists error code {code!r}, which is not a "
                        f"string literal in {module}"
                    )

    ctl = {(m, p): (cap, act) for m, p, cap, act in rows}
    for (method, path), (cap, _act) in sorted(ctl.items()):
        if (method, path) not in ops:
            findings.append(f"CONTROL_ROUTES row {method} {path} has no fragment")
        if cap not in roles:
            findings.append(
                f"CONTROL_ROUTES row {method} {path}: capability {cap} is not in MATRIX"
            )
    for (method, path), rel in sorted(mounted.items()):
        if (method, path) in ops or (method, path) in ctl:
            continue
        if path.startswith(REQUIRED_PREFIXES):
            findings.append(
                f"{rel}: {method} {path} is in a control family and has no fragment — document it"
            )

    shared_ctl = shared.get("control_responses", {})
    paths: dict[str, dict] = {}
    for (method, path), rel in sorted(
        mounted.items(), key=lambda kv: (kv[0][1], kv[0][0])
    ):
        key = (method, path)
        op: dict = {"operationId": _op_id(method, path)}
        if key in ops:
            frag, module = ops[key]
            op["summary"] = frag.get("summary", "")
            if frag.get("description"):
                op["description"] = frag["description"]
            if frag.get("tags"):
                op["tags"] = frag["tags"]
            if "parameters" in frag:
                op["parameters"] = frag["parameters"]
            if frag.get("requestBody") is not None:
                op["requestBody"] = {
                    "required": True,
                    "content": {"application/json": {"schema": frag["requestBody"]}},
                }
            responses = {
                code: _schema_response(r.get("description", ""), r.get("schema"))
                for code, r in frag.get("responses", {}).items()
            }
            op["x-error-envelope"] = frag.get("x-error-envelope", "control")
            if frag.get("x-error-codes"):
                op["x-error-codes"] = frag["x-error-codes"]
            op["x-tracelane-handler"] = module
        else:
            op["summary"] = "Not yet described"
            op["x-tracelane-undocumented"] = True
            op["x-tracelane-handler"] = rel
            responses = {"default": {"description": "Not yet described."}}
        if key in ctl:
            cap, act = ctl[key]
            slug, role_list = roles.get(cap, (cap, []))
            op["x-tracelane-capability"] = slug
            op["x-tracelane-audit-action"] = act
            op["x-tracelane-roles"] = role_list
            for code, r in shared_ctl.items():
                responses.setdefault(
                    code, _schema_response(r["description"], r.get("schema"))
                )
            op["security"] = [{"bearerAuth": []}]
        responses.setdefault(
            "default", {"description": "See x-error-envelope."}
        ) if key not in ops else None
        op["responses"] = responses
        paths.setdefault(_path(path), {})[method.lower()] = op

    doc = {
        "openapi": "3.1.0",
        "info": {
            "title": "Tracelane gateway — control API",
            "version": "v1",
            "description": (
                "Generated by scripts/ci/build-openapi.py from CONTROL_ROUTES, MATRIX, the mounted "
                "route table and crates/gateway/openapi/fragments. Control routes answer "
                "{error, message, field?}; tool-pins answers {error: <message>}; inference routes "
                "use each wire's own envelope (x-error-envelope). x-tracelane-roles lists the "
                "capability matrix's columns; the route handlers may be STRICTER (an API key never "
                "manages controls). Operations marked x-tracelane-undocumented are mounted but not "
                "yet described."
            ),
        },
        "paths": paths,
        "components": {
            "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
            "schemas": shared.get("schemas", {}),
        },
    }
    # The doc names no route that is not mounted (by construction here; --check re-proves it
    # against the CHECKED-IN file, which is what a client reads).
    return doc, findings


def render(doc: dict) -> str:
    return json.dumps(doc, indent=2, sort_keys=False, ensure_ascii=False) + "\n"


def doc_findings(text: str, sources: dict[str, str]) -> list[str]:
    out = []
    if len(text.encode()) > MAX_BYTES:
        out.append(f"{OUT.name} is over {MAX_BYTES} bytes")
    mounted = mounted_routes(sources)
    have = {(m.upper(), _path(p)) for (m, p) in mounted}
    doc = json.loads(text)
    for path, item in doc.get("paths", {}).items():
        for method in item:
            if (method.upper(), path) not in have:
                out.append(
                    f"{OUT.name} names {method.upper()} {path}, which is not mounted"
                )
    return out


def check() -> int:
    sources, frags = read_sources(), read_fragments()
    doc, findings = build(sources, frags)
    text = render(doc)
    findings += doc_findings(
        OUT.read_text(encoding="utf-8") if OUT.exists() else "{}", sources
    )
    if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
        findings.append(
            f"{OUT.relative_to(ROOT)} is stale or missing — run: python3 scripts/ci/build-openapi.py"
        )
    for f in findings:
        print(f"build-openapi: {f}", file=sys.stderr)
    if findings:
        return 1
    n = sum(len(v) for v in doc["paths"].values())
    print(f"build-openapi: {OUT.relative_to(ROOT)} current ({n} operations)")
    return 0


# ── selftest ─────────────────────────────────────────────────────────────────


def selftest() -> int:
    sources, frags = read_sources(), read_fragments()
    base_doc, base_findings = build(sources, frags)
    if base_findings:
        print(
            "selftest: the real tree is not clean:\n  " + "\n  ".join(base_findings),
            file=sys.stderr,
        )
        return 1
    text = render(base_doc)
    rc = 0

    def expect(label: str, findings: list[str], needle: str) -> None:
        nonlocal rc
        hit = any(needle in f for f in findings)
        print(f"  {'ok  ' if hit else 'FAIL'} {label}")
        if not hit:
            rc = 1

    import copy

    # 1. a CONTROL_ROUTES row with no fragment
    f1 = copy.deepcopy(frags)
    for frag in f1.values():
        frag.get("operations", {}).pop("POST /v1/controls/pause", None)
    expect(
        "a CONTROL_ROUTES row with no fragment blocks",
        build(sources, f1)[1],
        "has no fragment",
    )

    # 2. an orphan fragment
    f2 = copy.deepcopy(frags)
    next(v for k, v in f2.items() if not k.startswith("_"))["operations"][
        "GET /v1/not/mounted"
    ] = {"summary": "x"}
    expect("an orphan fragment blocks", build(sources, f2)[1], "orphan fragment")

    # 3. an error-code literal the handler module does not contain
    f3 = copy.deepcopy(frags)
    f3_op = f3["controls.json"]["operations"]["PUT /v1/controls/policy"]
    f3_op["x-error-codes"] = [
        *f3_op.get("x-error-codes", []),
        "code_that_no_handler_has",
    ]
    expect(
        "an error code absent from the handler module blocks",
        build(sources, f3)[1],
        "not a string literal",
    )

    # 4. a stale output
    stale = text.replace('"title": "Tracelane gateway', '"title": "STALE gateway', 1)
    if stale == text:
        print("  FAIL could not plant a stale output")
        rc = 1
    else:
        print("  ok   a stale output differs from a fresh build (check compares bytes)")

    # 5. the doc names a route that is not mounted
    ghost = json.loads(text)
    ghost["paths"]["/v1/ghost"] = {"get": {}}
    expect(
        "a doc path that is not mounted blocks",
        doc_findings(json.dumps(ghost), sources),
        "not mounted",
    )

    # 6. a control-family route with no fragment
    f6 = copy.deepcopy(frags)
    for frag in f6.values():
        frag.get("operations", {}).pop("GET /v1/controls/budgets", None)
    expect(
        "a control-family GET with no fragment blocks",
        build(sources, f6)[1],
        "no fragment",
    )

    # 7. roles are computed from MATRIX: a viewer can not pause, an admin can
    pause = base_doc["paths"]["/v1/controls/pause"]["post"]
    ok = (
        "viewer" not in pause["x-tracelane-roles"]
        and "admin" in pause["x-tracelane-roles"]
    )
    print(
        f"  {'ok  ' if ok else 'FAIL'} x-tracelane-roles of POST /v1/controls/pause: {pause['x-tracelane-roles']}"
    )
    rc = rc or (0 if ok else 1)
    print("selftest: " + ("every planted defect blocked" if rc == 0 else "FAILED"))
    return rc


def main() -> int:
    unknown = [a for a in sys.argv[1:] if a not in ("--check", "--selftest")]
    if unknown:
        print(
            f"build-openapi: unknown argument(s) {unknown} (use --check or --selftest)",
            file=sys.stderr,
        )
        return 2
    if "--selftest" in sys.argv:
        return selftest()
    if "--check" in sys.argv:
        return check()
    sources, frags = read_sources(), read_fragments()
    doc, findings = build(sources, frags)
    for f in findings:
        print(f"build-openapi: {f}", file=sys.stderr)
    if findings:
        return 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(render(doc), encoding="utf-8")
    print(f"build-openapi: wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
