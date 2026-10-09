#!/usr/bin/env python3
"""Validate staged skill attestations and evidence. Not proof of review quality."""

import argparse
import importlib.util
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from decimal import Decimal, InvalidOperation
from itertools import permutations
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "spec_governance", Path(__file__).with_name("check-spec-governance.py")
)
governance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(governance)
SECURITY = re.compile(
    r"(?:^|/)(?:auth(?:entication|orization)?|crypto|billing|tenancy|byok|kms|encryption|entitlement_cache|api_keys|provider_keys|key_vault|tenant|rbac)(?:[./_-]|$)|^\.githooks/"
)


def feature_spec_ids(subject):
    return [
        key
        for key in re.findall(
            r"\b(?:[A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*-\d+[a-z]?|A\d+)\b", subject
        )
        if not key.startswith("B-")
    ]


def test_definition(source, name, path):
    """Comparable executable test definition; comments alone are not evidence."""
    import ast
    import textwrap

    source = textwrap.dedent(source)
    if path.endswith(".py"):
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return None
        for node in ast.walk(tree):
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == name
                and name.startswith("test_")
            ):
                if (
                    node.body
                    and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)
                ):
                    node.body = node.body[1:]
                return ast.dump(node, include_attributes=False)
        return None
    # Mask comments and literals together: a comment-looking string cannot expose code.
    token = re.compile(
        r'(?P<comment>//[^\n]*|/\*.*?\*/)|r(?P<hash>\#+)".*?"(?P=hash)|"(?:\\.|[^"\\])*"|\x27(?:\\.|[^\x27\\])*\x27|`(?:\\.|[^`\\])*`',
        re.DOTALL,
    )
    clean = token.sub(
        lambda m: (
            " " * len(m[0])
            if m.group("comment") or path.endswith(".rs") or m[0].startswith("`")
            else m[0]
        ),
        source,
    )
    if path.endswith(".rs"):
        pattern = (
            r"#\[(?:test|(?:tokio|async_std)::test)(?:\([^]\n]*\))?\]\s*(?:#\[[^]\n]+\]\s*)*(?:async\s+)?fn\s+"
            + re.escape(name)
            + r"\s*\([^)]*\)(?:\s*->[^{}]+)?\s*\{"
        )
    else:
        pattern = (
            r"\b(?:it|test)\s*\(\s*[\"\x27]" + re.escape(name) + r"[\"\x27]\s*,[^{}]*\{"
        )
    match = re.search(pattern, clean)
    if not match:
        return None
    depth = 1
    for index in range(match.end(), len(clean)):
        depth += (clean[index] == "{") - (clean[index] == "}")
        if depth == 0:
            # Retain literals in the body (assertion string changes are real changes),
            # while ignoring comments and whitespace outside literals.
            body = source[match.start() : index + 1]
            parts = []
            offset = 0
            for literal in token.finditer(body):
                parts.append(re.sub(r"\s+", "", body[offset : literal.start()]))
                if not literal.group("comment"):
                    parts.append(literal[0])
                offset = literal.end()
            parts.append(re.sub(r"\s+", "", body[offset:]))
            return "".join(parts)
    return None


def changed_test_definition(lines, name, path):
    return test_definition(lines, name, path) is not None


def trailers(message):
    paragraphs = re.split(r"\n\s*\n", message.strip())
    result = {}
    if len(paragraphs) < 2:
        return result
    for line in paragraphs[-1].splitlines():
        match = re.fullmatch(r"([A-Za-z][A-Za-z-]*):\s*(.*)", line)
        if not match:
            return {}
        result.setdefault(match[1].lower(), []).append(match[2].strip())
    return result


def evaluate(message, changed, files, added, public_errors=(), before=None):
    fields = trailers(message)
    errors = []

    def value(key):
        values = fields.get(key, [])
        return values[0] if len(values) == 1 else ""

    if not value("skills"):
        errors.append("one nonempty Skills trailer required")
    if any(SECURITY.search(p) and not p.startswith("tests/") for p in changed):
        report = value("security-review")
        path = PurePosixPath(report)
        if (
            not report
            or path.is_absolute()
            or ".." in path.parts
            or path.suffix != ".md"
            or report not in files
            or not files[report].strip()
        ):
            errors.append(
                "Security-Review must name a nonempty regular staged report inside the repository"
            )
    subject = message.splitlines()[0] if message.splitlines() else ""
    if re.search(r"\bB-\d+\b", subject) and re.search(
        r"\bfix(?:es|ed)?\b", subject, re.IGNORECASE
    ):
        test = value("red-test")
        if not test or not any(
            path in files
            and PurePosixPath(path).suffix
            in (".py", ".rs", ".ts", ".tsx", ".js", ".mjs")
            and governance.definition(files[path], test, path)
            and (
                changed_test_definition(lines, test, path)
                if before is None
                else test_definition(files[path], test, path) is not None
                and test_definition(files[path], test, path)
                != test_definition(before.get(path, ""), test, path)
            )
            for path, lines in added.items()
        ):
            errors.append("Red-Test must name a test definition added by this diff")
    if (
        any(
            PurePosixPath(p).name
            in ("Cargo.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock")
            for p in changed
        )
        and len(value("dep-review")) < 12
    ):
        errors.append("Dep-Review must describe the dependency review")
    errors.extend(public_errors)
    return errors


def public_paths(changed, files):
    def entries(path):
        result = [l.split("#", 1)[0].strip() for l in files[path].splitlines()]
        result = [l for l in result if l]
        if not result:
            raise ValueError("empty public scan configuration: " + path)
        return result

    allow = entries("scripts/export/export-allow.txt")
    deny = entries("scripts/export/export-deny.txt")
    under = lambda p, entry: p == entry or p.startswith(entry.rstrip("/") + "/")
    return [
        p
        for p in changed
        if PurePosixPath(p).suffix.lower() in (".md", ".mdx", ".mdc", ".astro", ".svg")
        and (
            p == "CLAUDE.public.md"
            or p.startswith("apps/site/")
            or (any(under(p, a) for a in allow) and not any(under(p, d) for d in deny))
        )
    ]


def public_copy(paths, files):
    """Staged-copy guard: canonical scope and phrase rules, no export/promotion.

    This is the commit-time honesty scan, not the broader export leakage gate.
    Uses grep ERE exactly as the export guard does, so POSIX classes retain meaning.
    """
    text = files["docs/reference/NEVER_SAY_AGAIN.md"]
    block = text.split("NEVER-SAY-AGAIN:BEGIN", 1)[1].split("NEVER-SAY-AGAIN:END", 1)[0]
    # Markers are HTML comments; rules themselves have a strict label prefix.
    rules = [l for l in block.splitlines() if re.match(r"^[A-Za-z0-9_-]+ *\|", l)]
    candidates = [
        l.strip()
        for l in block.splitlines()
        if l.strip()
        and l.strip() not in ("-->", "<!--")
        and not l.lstrip().startswith("#")
    ]
    if len(candidates) != len(rules):
        raise ValueError("public-copy rules contain malformed lines")
    if not rules:
        raise ValueError("public-copy rules empty")
    sources = {}
    for path in paths:
        if path.lower().endswith(".svg"):
            # A staged image is untrusted input to this commit-time guard. Refuse
            # pathological XML before parsing; no claim is silently skipped.
            if len(files[path].encode("utf-8")) > 1_000_000:
                raise ValueError("public SVG exceeds scan size limit: " + path)
            if any(
                marker in files[path].upper()
                for marker in ("<!DOCTYPE", "<!ENTITY", "<?XML-STYLESHEET")
            ):
                raise ValueError(
                    "public SVG contains an unsupported XML declaration: " + path
                )
            try:
                root = ET.fromstring(files[path])
            except ET.ParseError as exc:
                raise ValueError("invalid public SVG: " + path) from exc
            root_namespace = (
                root.tag.split("}", 1)[0][1:] if root.tag.startswith("{") else None
            )
            if root_namespace not in (None, "http://www.w3.org/2000/svg"):
                raise ValueError("public SVG has unsupported namespace: " + path)
            view_box = root.get("viewBox")
            if view_box is not None:
                values = re.split(r"[\s,]+", view_box.strip())
                try:
                    dimensions = [Decimal(value) for value in values]
                    width = root.get("width")
                    height = root.get("height")
                    viewport = [
                        Decimal(re.fullmatch(r"([\d.]+)(?:px)?", value)[1])
                        for value in (width, height)
                    ]
                except (TypeError, ValueError, AttributeError, InvalidOperation) as exc:
                    raise ValueError(
                        "public SVG has unsupported viewBox: " + path
                    ) from exc
                if (
                    len(dimensions) != 4
                    or any(not value.is_finite() for value in dimensions + viewport)
                    or dimensions[0:2] != [Decimal(0), Decimal(0)]
                    or dimensions[2:] != viewport
                    or any(value <= 0 for value in viewport)
                ):
                    raise ValueError(
                        "public SVG has unsupported viewBox scaling: " + path
                    )
            text_nodes = []
            text_rows = {}
            expansion_bytes = 0
            max_expansion_bytes = 4_000_000
            # The shipped diagram labels use only these non-ASCII glyphs.
            # A new glyph needs review before an invisible lookalike can enter.
            allowed_non_ascii = frozenset("·σ–—…←→⋮①②③④⑤")

            def coordinate(raw, axis, svg_path):
                if raw is None:
                    return Decimal(0)
                match = re.fullmatch(
                    r"([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)([a-zA-Z%]*)",
                    raw.strip(),
                )
                if not match or match[2].lower() not in ("", "px"):
                    raise ValueError(
                        "public SVG has unsupported text " + axis + ": " + svg_path
                    )
                return Decimal(match[1])

            stack = [(root, 0, False)]
            while stack:
                node, depth, in_text = stack.pop()
                if depth > 64:
                    raise ValueError("public SVG exceeds scan depth limit: " + path)
                namespace = (
                    node.tag.split("}", 1)[0][1:] if node.tag.startswith("{") else None
                )
                if namespace != root_namespace:
                    raise ValueError("public SVG has foreign text namespace: " + path)
                tag = node.tag.rsplit("}", 1)[-1]
                if (node is not root and tag == "svg") or tag in (
                    "style",
                    "link",
                    "switch",
                    "use",
                    "set",
                    "animate",
                    "animateMotion",
                    "animateTransform",
                    "mpath",
                    "discard",
                    "script",
                    "foreignObject",
                ):
                    raise ValueError(
                        "public SVG has unsupported nested layout: " + path
                    )
                if (
                    any(name.lower().startswith("on") for name in node.attrib)
                    or any(name.rsplit("}", 1)[-1] == "href" for name in node.attrib)
                    or "transform" in node.attrib
                    or "dy" in node.attrib
                    or "dx" in node.attrib
                    or "style" in node.attrib
                    or any("baseline" in name for name in node.attrib)
                    or "textLength" in node.attrib
                    or "lengthAdjust" in node.attrib
                    or any(
                        name in node.attrib
                        for name in (
                            "word-spacing",
                            "kerning",
                            "font-kerning",
                            "direction",
                            "unicode-bidi",
                            "writing-mode",
                            "text-orientation",
                            "glyph-orientation-horizontal",
                            "glyph-orientation-vertical",
                        )
                    )
                    or any(
                        name in node.attrib
                        for name in (
                            "requiredExtensions",
                            "requiredFeatures",
                            "systemLanguage",
                        )
                    )
                    or any(
                        name in node.attrib
                        for name in (
                            "display",
                            "visibility",
                            "opacity",
                            "fill-opacity",
                            "stroke-opacity",
                            "clip-path",
                            "mask",
                            "filter",
                        )
                    )
                ):
                    raise ValueError(
                        "public SVG has unsupported text positioning: " + path
                    )
                letter_spacing = node.get("letter-spacing")
                if letter_spacing is not None:
                    numeric_spacing = re.fullmatch(
                        r"\s*([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)(px)?\s*",
                        letter_spacing,
                    )
                    if (
                        in_text
                        or not numeric_spacing
                        or Decimal(numeric_spacing[1]) < 0
                    ):
                        raise ValueError(
                            "public SVG has unsupported letter spacing: " + path
                        )
                fill = node.get("fill", "").strip().lower()
                if fill and not (
                    re.fullmatch(r"#[0-9a-f]{3}(?:[0-9a-f]{3})?", fill)
                    or (tag == "rect" and fill == "white")
                ):
                    raise ValueError("public SVG has unsupported text paint: " + path)
                font_size = node.get("font-size")
                if font_size is not None:
                    numeric_size = re.fullmatch(
                        r"\s*([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)([a-zA-Z%]*)\s*",
                        font_size,
                    )
                    if in_text or not numeric_size or Decimal(numeric_size[1]) == 0:
                        raise ValueError(
                            "public SVG has unsupported font size: " + path
                        )
                if in_text and tag != "tspan":
                    raise ValueError(
                        "public SVG has unsupported text descendant: " + path
                    )
                if in_text and (
                    "x" in node.attrib or "y" in node.attrib or tag == "textPath"
                ):
                    raise ValueError(
                        "public SVG has unsupported nested text positioning: " + path
                    )
                is_text = tag == "text"
                if is_text and not in_text:
                    fragments = list(node.itertext())
                    if any(
                        (ord(char) > 127 and char not in allowed_non_ascii)
                        or (ord(char) < 32 and char not in "\t\n\r")
                        or ord(char) == 127
                        for fragment in fragments
                        for char in fragment
                    ):
                        raise ValueError(
                            "public SVG has invisible text characters: " + path
                        )
                    # A positioned tspan can create a gap while the next one
                    # stays joined. Enumerate those readings within one text
                    # element; refuse excessive splits instead of skipping one.
                    if len(fragments) > 12:
                        raise ValueError(
                            "public SVG text has too many fragments: " + path
                        )
                    fragment_bytes = sum(
                        len(fragment.encode("utf-8")) for fragment in fragments
                    )
                    projected_bytes = (1 << max(0, len(fragments) - 1)) * (
                        fragment_bytes + max(0, len(fragments) - 1)
                    )
                    if expansion_bytes + projected_bytes > max_expansion_bytes:
                        raise ValueError(
                            "public SVG text expansion exceeds limit: " + path
                        )
                    expansion_bytes += projected_bytes
                    readings = [fragments[0]] if fragments else [""]
                    for fragment in fragments[1:]:
                        readings = [
                            reading + separator + fragment
                            for reading in readings
                            for separator in ("", " ")
                        ]
                    text_nodes.append(readings)
                    row_y = coordinate(node.get("y"), "y", path)
                    row_x = coordinate(node.get("x"), "x", path)
                    text_rows.setdefault(row_y, []).append(
                        (row_x, len(text_nodes), readings)
                    )
                # LIFO traversal must push siblings in reverse to keep SVG
                # document order: adjacent text elements can form one claim.
                stack.extend(
                    (child, depth + 1, in_text or is_text)
                    for child in reversed(list(node))
                )
            # Separate text elements can also read as one word or two. Include
            # whole-document joins and each element's mixed tspan readings.
            variants = {reading for node in text_nodes for reading in node}
            compact = [node[0] for node in text_nodes]
            spaced = [node[-1] for node in text_nodes]
            for pieces in (compact, spaced):
                variants.add("".join(pieces))
                variants.add(" ".join(pieces))
            # A small visual stagger may still read as one line even when its
            # baselines differ. Check every bounded document-order window with
            # independent spacing at each text boundary.
            for start in range(len(text_nodes)):
                readings = [""]
                for offset, node_readings in enumerate(text_nodes[start : start + 6]):
                    separators = ("",) if offset == 0 else ("", " ")
                    next_count = len(readings) * len(node_readings) * len(separators)
                    next_max_bytes = (
                        max(
                            (len(value.encode("utf-8")) for value in readings),
                            default=0,
                        )
                        + max(
                            (len(value.encode("utf-8")) for value in node_readings),
                            default=0,
                        )
                        + (1 if offset else 0)
                    )
                    if (
                        next_count > 4096
                        or expansion_bytes + next_count * next_max_bytes
                        > max_expansion_bytes
                    ):
                        raise ValueError(
                            "public SVG text expansion exceeds limit: " + path
                        )
                    expansion_bytes += next_count * next_max_bytes
                    readings = [
                        prefix + separator + value
                        for prefix in readings
                        for separator in separators
                        for value in node_readings
                    ]
                    variants.update(readings)
            # Nearby SVG baselines can rasterize to the same pixel row. Merge
            # adjacent y values within one pixel before checking all bounded
            # orders; a source-coordinate distinction must not hide a claim.
            row_groups = []
            previous_y = None
            for y in sorted(text_rows):
                if previous_y is None or y - previous_y > 1:
                    row_groups.append([])
                row_groups[-1].extend(text_rows[y])
                previous_y = y
            # Anchoring can reverse visual order even when x values tie.
            # Enumerate short rows in every order; larger layouts refuse the
            # scan rather than choosing one potentially evasive reading.
            for nodes in row_groups:
                ordered = sorted(nodes, key=lambda item: (item[0], item[1]))
                if len(ordered) > 6:
                    raise ValueError(
                        "public SVG text row has too many elements: " + path
                    )
                for arrangement in permutations(ordered):
                    row_readings = [""]
                    for index, (_, _, readings) in enumerate(arrangement):
                        separators = ("",) if index == 0 else ("", " ")
                        next_count = len(row_readings) * len(readings) * len(separators)
                        if next_count > 4096:
                            raise ValueError(
                                "public SVG text row has too many readings: " + path
                            )
                        next_max_bytes = (
                            max(
                                (
                                    len(prefix.encode("utf-8"))
                                    for prefix in row_readings
                                ),
                                default=0,
                            )
                            + max(
                                (len(reading.encode("utf-8")) for reading in readings),
                                default=0,
                            )
                            + (1 if index else 0)
                        )
                        projected_bytes = next_count * next_max_bytes
                        if expansion_bytes + projected_bytes > max_expansion_bytes:
                            raise ValueError(
                                "public SVG text expansion exceeds limit: " + path
                            )
                        expansion_bytes += projected_bytes
                        row_readings = [
                            prefix + separator + reading
                            for prefix in row_readings
                            for separator in separators
                            for reading in readings
                        ]
                    variants.update(row_readings)
            variants = {re.sub(r"\s+", " ", value).strip() for value in variants}
            sources[path] = "\n".join(sorted(variants))
        else:
            sources[path] = re.sub(r"<!--.*?-->", "", files[path], flags=re.DOTALL)
    errors = []
    for rule in rules:
        label, pattern, *_ = rule.split(" | ")
        pattern = pattern.replace(r"\|", "|")
        pattern = re.sub(r"([0-9])([A-Za-z])", r"\1[[:space:]]*\2", pattern)
        for path in paths:
            result = subprocess.run(
                ["grep", "-qiE", pattern],
                input=sources[path],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode not in (0, 1):
                raise ValueError("invalid public-copy pattern: " + label)
            if result.returncode == 0:
                errors.append("public-copy: " + path + ": " + label)
    return errors


def override_message(message, reason):
    if len(reason.strip()) < 20 or "\n" in reason or "\r" in reason:
        raise ValueError(
            "override requires a single-line reason of at least 20 characters"
        )
    return message.rstrip() + "\n\nGovernance-Override: " + reason.strip() + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--msg-file", type=Path)
    args = parser.parse_args()
    if args.selftest:
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                str(Path(__file__).parent),
                "-p",
                "test_commit_governance.py",
            ],
            check=False,
        ).returncode
    if not args.msg_file:
        parser.error("--msg-file is required")
    try:
        message = args.msg_file.read_text()
        reason = os.environ.get("TRACELANE_GOVERNANCE_OVERRIDE")
        if reason is not None:
            args.msg_file.write_text(override_message(message, reason))
            print(
                "GOVERNANCE OVERRIDE recorded in commit message: " + reason,
                file=sys.stderr,
            )
            return 0
        files = governance.Snapshot(ROOT)
        changed = governance.git(
            ROOT, "diff", "--cached", "--name-only", "--diff-filter=ACMRD"
        ).splitlines()
        added = {}
        before = {}
        for path in changed:
            if path not in files:
                continue
            old = subprocess.run(
                ["git", "show", "HEAD:" + path],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            before[path] = old.stdout if old.returncode == 0 else ""
            diff = governance.git(
                ROOT, "diff", "--cached", "--no-ext-diff", "--unified=0", "--", path
            )
            added[path] = "\n".join(
                l[1:]
                for l in diff.splitlines()
                if l.startswith("+") and not l.startswith("+++")
            )

        errors = evaluate(message, changed, files, added, before=before)
        paths = public_paths([p for p in changed if p in files], files)
        if paths:
            if trailers(message).get("public-copy") != ["checked"]:
                errors.append(
                    "Public-Copy: checked required for customer-readable copy"
                )
            errors.extend(public_copy(paths, files))
            print(f"public-copy staged guard: {len(paths)} file(s) scanned")
        subject = message.splitlines()[0]
        ids = feature_spec_ids(subject)
        if ids and any(not p.endswith((".md", ".mdx", ".mdc")) for p in changed):
            errors.extend(governance.check(ROOT, only=ids)[0])
        for error in errors:
            print("BLOCKED: " + error, file=sys.stderr)
        return bool(errors)
    except (
        OSError,
        ValueError,
        KeyError,
        IndexError,
        subprocess.SubprocessError,
    ) as exc:
        print(
            "BLOCKED: cannot validate staged commit evidence: " + str(exc),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
