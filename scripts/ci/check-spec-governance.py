#!/usr/bin/env python3
"""Check build governance on the staged snapshot (default) or working tree.

Legacy finished specs remain visible without retroactive blocking. Active specs
and specs changed since the governance cutoff must satisfy the whole contract.
"""

import argparse
import ast
import re
import subprocess
import sys
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

SECTIONS = (
    "Design & alternatives",
    "Edge cases & decisions",
    "Evaluation",
    "Exit strategy",
    "Guardrails — product",
    "Guardrails — build",
    "Test matrix",
    "Skills used",
)
CUTOFF = "2026-10-08"
ROOT = Path(__file__).resolve().parents[2]


def git(root, *args):
    return subprocess.check_output(
        ["git", "-C", str(root), *args], text=True, timeout=30
    )


class Snapshot(Mapping):
    """Lazy text blobs; staged mode never follows a worktree symlink."""

    def __init__(self, root, staged=True):
        self.root, self.staged = root, staged
        self.paths = {}
        for entry in git(root, "ls-files", "--stage", "-z").split("\0"):
            if entry:
                meta, path = entry.split("\t", 1)
                mode, blob, stage = meta.split()
                if stage != "0":
                    raise ValueError("unmerged index: " + path)
                self.paths[path] = (mode, blob)
        self.cache = {}

    def __iter__(self):
        return iter(self.paths)

    def __len__(self):
        return len(self.paths)

    def __getitem__(self, path):
        mode, blob = self.paths[path]
        if mode not in ("100644", "100755"):
            raise ValueError("evidence must be a regular tracked file: " + path)
        if path not in self.cache:
            if self.staged:
                self.cache[path] = git(self.root, "cat-file", "blob", blob)
            else:
                p = self.root / path
                if p.is_symlink() or not p.resolve().is_relative_to(
                    self.root.resolve()
                ):
                    raise ValueError("evidence escapes root: " + path)
                self.cache[path] = p.read_text()
        return self.cache[path]


def sections(text):
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    result = {}
    for match in re.finditer(
        r"^## ([^\n]+)\n(.*?)(?=^## |\Z)", text, re.MULTILINE | re.DOTALL
    ):
        result[match[1].strip()] = match[2].strip()
    return result


def definition(source, name, path=""):
    if path.endswith(".py") or (not path and "def " in source):
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return False
        return any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
            for node in ast.walk(tree)
        )
    # Rust comments can contain unmatched backticks that would otherwise
    # consume real test definitions when the template-literal scrub runs.
    if path.endswith(".rs"):
        source = re.sub(r"^[ \t]*//[^\n]*", "", source, flags=re.MULTILINE)
    # Template literals can contain apparent test calls that never execute.
    source = re.sub(r"`(?:\\.|[^`\\])*`", "", source, flags=re.DOTALL)
    # Rust multiline/raw strings can contain apparent function definitions.
    if path.endswith(".rs"):
        source = re.sub(r'r(\#+)".*?"\1', "", source, flags=re.DOTALL)
        source = re.sub(r'"(?:\\.|[^"\\])*"', "", source, flags=re.DOTALL)
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    source = re.sub(r"//[^\n]*", "", source)
    escaped = re.escape(name)
    return bool(
        re.search(
            r"^\s*(?:(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+"
            + escaped
            + r"\s*\(|(?:it|test)\s*\(\s*[\"\x27]"
            + escaped
            + r"[\"\x27])",
            source,
            re.MULTILINE,
        )
    )


def matrix(text):
    body = sections(text).get("Test matrix", "")
    result = {"Positive": [], "Negative": []}
    for polarity, rows in result.items():
        match = re.search(
            r"^### " + polarity + r"\s*\n(.*?)(?=^### |\Z)",
            body,
            re.MULTILINE | re.DOTALL,
        )
        if not match:
            continue
        for line in match[1].splitlines():
            cells = [c.strip() for c in re.split(r"(?<!\\)\|", line)[1:-1]]
            if (
                len(cells) != 3
                or cells[0].lower() == "case"
                or re.fullmatch(r"[- :]+", cells[0])
            ):
                continue
            if all(cells) and "::" in cells[2]:
                rows.append(cells)
    return result


def validate(text, built, files):
    errors = []
    parts = sections(text)
    for heading in SECTIONS:
        body = parts.get(heading, "")
        meaningful = re.sub(r"[#*`_\s:.-]", "", body).lower()
        if not meaningful or meaningful in ("todo", "tbd", "pending", "placeholder"):
            errors.append("missing or placeholder section: " + heading)
    for polarity, rows in matrix(text).items():
        names = {r[2].strip("` ") for r in rows}
        cases = {r[0].lower() for r in rows}
        if min(len(names), len(cases)) < 10:
            errors.append(
                polarity + ": requires at least 10 distinct cases and test names"
            )
        if built:
            for _, _, reference in rows:
                path, name = reference.strip("` ").split("::", 1)
                p = PurePosixPath(path)
                if (
                    p.is_absolute()
                    or ".." in p.parts
                    or p.suffix
                    not in (".py", ".rs", ".js", ".ts", ".tsx", ".mjs", ".sh")
                ):
                    errors.append("invalid test path: " + path)
                    continue
                if path not in files or not definition(files[path], name, path):
                    errors.append("missing test definition: " + reference)
    return errors


def required(date, state, changed):
    return changed or not date or date >= CUTOFF or "IN-PROGRESS" in state


def roadmap_rows(text):
    rows = {}
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = re.split(r"(?<!\\)\|", line)
        if len(cells) < 4 or not cells[1].strip().startswith("`"):
            continue
        for key in re.findall(
            r"\b(?:[A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*-\d+[a-z]?|A\d+)\b", cells[1]
        ):
            rows.setdefault(key, []).append(cells[2].strip())
    return rows


def history_dates(root):
    dates = {}
    date = ""
    for line in git(
        root, "log", "--format=@%ct", "--name-only", "--", "specs"
    ).splitlines():
        if line.startswith("@"):
            date = (
                datetime.fromtimestamp(int(line[1:]), timezone.utc).date().isoformat()
            )
        elif line.startswith("specs/"):
            dates.setdefault(line, date)
    return dates


def check(root=ROOT, staged=True, only=None):
    files = Snapshot(root, staged)
    rows = roadmap_rows(files["docs/runbook/ROADMAP.md"])
    ordered_ids = sorted(rows, key=len, reverse=True)
    dates = history_dates(root)
    changed = set(
        git(root, "diff", "--cached", "--name-only", "--diff-filter=ACMR").splitlines()
    )
    if not staged:
        changed.update(
            git(root, "diff", "--name-only", "--diff-filter=ACMR").splitlines()
        )
    errors, governed, legacy = [], 0, 0
    seen_ids = set()
    for path in files:
        filename = Path(path).name
        if (
            not path.startswith("specs/")
            or not path.endswith(".md")
            or filename in ("README.md", "TEMPLATE.md")
        ):
            continue
        ident = next(
            (key for key in ordered_ids if filename.startswith(key + "-")),
            Path(path).stem,
        )
        filename_id = re.match(
            r"^([A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*-\d+[a-z]?|A\d+)(?:-|$)",
            Path(path).stem,
        )
        if ident == Path(path).stem and filename_id:
            ident = filename_id[1]
        title = re.search(r"^# ([^\n]+)", files[path], re.MULTILINE)
        if title:
            title_tokens = set(re.findall(r"[A-Za-z0-9-]+", title[1]))
            title_ids = [key for key in rows if key in title_tokens]
            if len(title_ids) == 1:
                ident = title_ids[0]
        seen_ids.add(ident)
        if only and ident not in only:
            continue
        state = " ".join(rows.get(ident, []))
        built = (
            any(
                re.match(r"\s*\**(?:BUILT|DEPLOYED|SHIPPED|DONE)\b", s)
                for s in rows.get(ident, [])
            )
            and "IN-PROGRESS" not in state
        )
        found = validate(files[path], built, files)
        if required(dates.get(path, ""), state, path in changed) or only:
            governed += 1
            errors.extend(path + ": " + e for e in found)
        elif found:
            legacy += 1
        else:
            governed += 1
    if only:
        for ident in only:
            if ident not in seen_ids:
                errors.append("missing spec: " + ident)
    return errors, governed, legacy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--worktree", action="store_true")
    parser.add_argument("--spec", action="append")
    args = parser.parse_args()
    if args.selftest:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                str(Path(__file__).parent),
                "-p",
                "test_governance.py",
            ],
            check=False,
        )
        return result.returncode
    try:
        errors, governed, legacy = check(staged=not args.worktree, only=args.spec)
        print(f"spec governance: governed={governed}; legacy-ungoverned={legacy}")
        for error in errors:
            print("BLOCKED: " + error)
        return bool(errors)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print("BLOCKED: cannot read governance evidence: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
