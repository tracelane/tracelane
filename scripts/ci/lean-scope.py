#!/usr/bin/env python3
"""Classify a candidate diff; unknown inputs select broad coverage."""

import argparse
import json
import subprocess
from pathlib import Path


def classify(
    paths,
    metadata,
    root,
    *,
    shared=None,
    mode_only=False,
    base="HEAD",
    multi_base=False,
):
    shared = {"tracelane-shared"} if shared is None else shared
    members = {}
    reverse = {}
    if metadata:
        ids = set(metadata.get("workspace_members", []))
        for package in metadata.get("packages", []):
            if package["id"] in ids:
                members[package["id"]] = package
        reverse = {id_: set() for id_ in members}
        for node in metadata.get("resolve", {}).get("nodes", []):
            if node["id"] not in members:
                continue
            for dep in node.get("deps", []):
                if dep["pkg"] in members:
                    reverse[dep["pkg"]].add(node["id"])

    selected = set()
    rust_all = False
    node = False
    node_all = False
    python = False
    rust_deps = False
    node_deps = False
    publication = True  # the source and built export are scanned for every candidate
    exec_bits = True
    reason = []
    roots = sorted(
        (
            (str(Path(p["manifest_path"]).parent.relative_to(root)), id_)
            for id_, p in members.items()
        ),
        key=lambda pair: len(pair[0]),
        reverse=True,
    )
    python_roots = ("packages/sdk-python/", "packages/verifier-python/", "ml/")
    if not paths:
        reason.append("no candidate diff")
    for path in paths:
        if mode_only:
            continue
        if metadata is None and path.startswith("packages/"):
            rust_all = node = node_all = python = True
            reason.append(f"cargo metadata unavailable for package: {path}")
            continue
        if path in {
            "Cargo.lock",
            "Cargo.toml",
            "rust-toolchain.toml",
        } or path.startswith(".cargo/"):
            rust_all = True
            rust_deps |= path in {"Cargo.lock", "Cargo.toml"}
            reason.append(f"workspace input: {path}")
        elif path.startswith("crates/") or any(
            path.startswith(prefix + "/") for prefix, _ in roots
        ):
            if not metadata:
                rust_all = True
                reason.append("cargo metadata unavailable")
                continue
            owner = next(
                (id_ for prefix, id_ in roots if path.startswith(prefix + "/")), None
            )
            if owner is None:
                rust_all = True
                reason.append(f"unknown crate: {path}")
            elif (
                path.endswith(("/Cargo.toml", "/build.rs"))
                or members[owner]["name"] in shared
            ):
                rust_all = True
                rust_deps |= path.endswith("/Cargo.toml")
                reason.append(f"workspace Rust input: {path}")
            else:
                selected.add(owner)
        elif path.startswith(python_roots) or path in {
            "pyproject.toml",
            "pytest.ini",
            "ruff.toml",
        }:
            python = True
        elif path.startswith(("apps/", "packages/")):
            node = True
            node_deps |= path.endswith("/package.json")
            if "/db/migrations/" in path or path.endswith("/db/schema.ts"):
                rust_all = True
        elif (
            path == "pnpm-lock.yaml"
            or path == "pnpm-workspace.yaml"
            or path in {"package.json", "biome.json"}
        ):
            node = node_all = True
            node_deps |= path in {"pnpm-lock.yaml", "package.json"}
        elif path.startswith(("evals/", "scripts/", "bench/", "ci/")):
            python = python or path.endswith(".py") or path.startswith("evals/")
            if path.startswith(
                (
                    "scripts/ci/",
                    "scripts/export/",
                    "scripts/release/",
                    "scripts/verify-all",
                )
            ):
                rust_all = node = node_all = python = True
        elif (
            path.endswith((".md", ".mdx", ".mdc"))
            or path.startswith(("docs/", "specs/", "brand/"))
            or path in {".export-sync", ".gitleaks.toml", "evals/uv.lock"}
        ):
            pass
        elif path.startswith((".github/", ".githooks/", ".claude/", "infra/")):
            rust_all = node = node_all = python = True
        else:
            rust_all = node = node_all = python = True
            reason.append(f"unclassified: {path}")
    if rust_all:
        selected = set(members)
    else:
        queue = list(selected)
        while queue:
            for dependent in reverse.get(queue.pop(), ()):
                if dependent not in selected:
                    selected.add(dependent)
                    queue.append(dependent)
    if multi_base and node:
        node_all = True
        reason.append("multiple push bases: broad pnpm coverage")
    return {
        "rust": sorted(members[id_]["name"] for id_ in selected)
        if members
        else ["workspace"]
        if rust_all
        else [],
        "metadata_ok": metadata is not None,
        "rust_all": rust_all,
        "node": node,
        "node_all": node_all,
        "node_filter": f"...[{base}]" if node and not node_all else "",
        "python": python,
        "rust_deps": rust_deps,
        "node_deps": node_deps,
        "export_compile": bool(selected)
        or rust_all
        or any(path.startswith("scripts/export/") for path in paths),
        "publication": publication,
        "exec_bits": exec_bits,
        "reason": reason,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", action="append", required=True)
    parser.add_argument("--mode-only", action="store_true")
    args = parser.parse_args()
    root = Path.cwd()
    files = set()
    bad_diff = False
    only_modes = True
    saw_mode = False
    for base in args.base:
        try:
            raw = subprocess.check_output(
                ["git", "diff", "--name-only", "-z", "--no-renames", base, "HEAD"]
            )
            files.update(part.decode() for part in raw.split(b"\0") if part)
            summary = subprocess.check_output(
                ["git", "diff", "--summary", "--no-renames", base, "HEAD"], text=True
            )
            stats = subprocess.check_output(
                ["git", "diff", "--numstat", "--no-renames", base, "HEAD"], text=True
            )
            saw_mode |= "mode change" in summary
            only_modes &= all(line.startswith("0\t0\t") for line in stats.splitlines())
            only_modes &= all("mode change" in line for line in summary.splitlines())
        except (OSError, subprocess.CalledProcessError, UnicodeError):
            bad_diff = True
    for command in (
        ["git", "diff", "--name-only", "-z"],
        ["git", "diff", "--cached", "--name-only", "-z"],
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
    ):
        try:
            raw = subprocess.check_output(command)
            files.update(part.decode() for part in raw.split(b"\0") if part)
            if command[1] == "ls-files" and raw:
                only_modes = False
            elif command[1] == "diff":
                extra = command[2:3] if "--cached" in command else []
                summary = subprocess.check_output(
                    ["git", "diff", *extra, "--summary"], text=True
                )
                stats = subprocess.check_output(
                    ["git", "diff", *extra, "--numstat"], text=True
                )
                saw_mode |= "mode change" in summary
                only_modes &= all(
                    line.startswith("0\t0\t") for line in stats.splitlines()
                )
                only_modes &= all(
                    "mode change" in line for line in summary.splitlines()
                )
        except (OSError, subprocess.CalledProcessError, UnicodeError):
            bad_diff = True
    if bad_diff:
        files.add("<unclassified-diff>")
    try:
        raw = subprocess.check_output(
            [
                "cargo",
                "metadata",
                "--locked",
                "--offline",
                "--format-version",
                "1",
                "--no-deps",
            ],
            stderr=subprocess.DEVNULL,
        )
        metadata = json.loads(raw)
        # --no-deps still includes workspace dependency edges in resolve only when omitted.
        if not metadata.get("resolve"):
            raw = subprocess.check_output(
                ["cargo", "metadata", "--locked", "--offline", "--format-version", "1"],
                stderr=subprocess.DEVNULL,
            )
            metadata = json.loads(raw)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError):
        metadata = None
    print(
        json.dumps(
            classify(
                sorted(files),
                metadata,
                root,
                base=args.base[0],
                multi_base=len(args.base) > 1,
                mode_only=only_modes and saw_mode and not bad_diff,
            )
        )
    )


if __name__ == "__main__":
    main()
