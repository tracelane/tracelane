#!/usr/bin/env python3
"""Fail if any Dockerfile `FROM` names an image without an `@sha256:` digest.

Why this exists
---------------
A tag is mutable. `cgr.dev/chainguard/rust:latest-dev` resolves to a different
image whenever Chainguard rebuilds it — which is often, by design. Two builds of
the *same commit* can therefore produce different images, and the Cosign
signature plus SLSA provenance we attach then attest a base layer nobody pinned.
For a product whose pitch is provenance, an unpinned base is not a lint nit: it
is the artifact being signed without being reproducible.

`CLAUDE.md` already requires "Pin every external version". This makes that
enforceable for container bases, the way the SHA-pin rule is already enforced for
GitHub Actions.

Scope: every `Dockerfile` and `*.Dockerfile` tracked in the repo, so a new one
cannot quietly skip the rule. `FROM <stage>` references (a named earlier stage,
e.g. `COPY --from=builder`) and `FROM scratch` are not registry pulls and are
exempt.

Exit codes: 0 clean, 1 violation(s) found.

Selftest: `--selftest` plants an unpinned FROM in a temp tree and asserts the
check reports it, so the guard is never trusted on the basis of having passed.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# `FROM <image>[ AS <stage>]` — capture the image reference.
FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", re.IGNORECASE)

# Not registry pulls: the scratch pseudo-image, and references to an earlier
# build stage declared in the same file.
EXEMPT_IMAGES = {"scratch"}


def dockerfiles() -> list[Path]:
    out = subprocess.run(
        [
            "git",
            "ls-files",
            "Dockerfile",
            "*/Dockerfile",
            "*.Dockerfile",
            "*/*.Dockerfile",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [ROOT / p for p in out.stdout.split("\n") if p.strip()]


def scan(path: Path) -> list[tuple[int, str]]:
    """Return [(lineno, image)] for every FROM lacking an @sha256: digest."""
    bad: list[tuple[int, str]] = []
    stages: set[str] = set()
    for i, line in enumerate(path.read_text(encoding="utf-8").split("\n"), start=1):
        m = FROM_RE.match(line)
        if not m:
            continue
        image = m.group(1)
        # Record `AS <stage>` so a later `FROM <stage>` is recognised as internal.
        as_m = re.search(r"\bAS\s+(\S+)", line, re.IGNORECASE)
        if as_m:
            stages.add(as_m.group(1).lower())
        if image.lower() in EXEMPT_IMAGES or image.lower() in stages:
            continue
        if "@sha256:" not in image:
            bad.append((i, image))
    return bad


def run(files: list[Path], root: Path) -> int:
    violations = 0
    for f in files:
        for lineno, image in scan(f):
            rel = f.relative_to(root)
            print(
                f"{rel}:{lineno}: FROM {image} is not pinned by digest", file=sys.stderr
            )
            violations += 1
    if violations:
        print(
            f"\n{violations} unpinned FROM line(s). A tag is mutable: the image we sign\n"
            "and attest must be the image we resolved. Pin with the multi-arch INDEX\n"
            "digest (keep the tag for readability):\n"
            "  FROM cgr.dev/chainguard/rust:latest-dev@sha256:<index-digest> AS builder\n\n"
            "Resolve it with:\n"
            '  tok=$(curl -sS "https://cgr.dev/token?scope=repository:chainguard/rust:pull" | jq -r .token)\n'
            '  curl -sSI -H "Authorization: Bearer $tok" \\\n'
            '    -H "Accept: application/vnd.oci.image.index.v1+json" \\\n'
            "    https://cgr.dev/v2/chainguard/rust/manifests/latest-dev | grep -i docker-content-digest\n"
            "\nUse the INDEX digest, not a per-platform one, or you break the other arch.",
            file=sys.stderr,
        )
        return 1
    print(f"dockerfile digest pins: clean ({len(files)} file(s))")
    return 0


def selftest() -> int:
    """Plant an unpinned FROM and assert the check reports it."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        good = tmp / "good.Dockerfile"
        good.write_text(
            "FROM cgr.dev/chainguard/rust:latest-dev@sha256:"
            + "a" * 64
            + " AS builder\n"
            "FROM builder AS second\n"
            "FROM scratch\n",
            encoding="utf-8",
        )
        if scan(good):
            print(
                "✗ selftest: a fully-pinned file was reported as unpinned",
                file=sys.stderr,
            )
            return 1

        bad = tmp / "bad.Dockerfile"
        bad.write_text(
            "FROM cgr.dev/chainguard/rust:latest-dev AS builder\n", encoding="utf-8"
        )
        hits = scan(bad)
        if not hits:
            print(
                "✗ selftest: an UNPINNED FROM was not reported — guard is decorative",
                file=sys.stderr,
            )
            return 1
        print(f"✓ selftest: unpinned FROM detected at line {hits[0][0]} ({hits[0][1]})")

        # A per-platform digest is still a digest — the index-vs-platform
        # distinction is advice in the error text, not something this can detect.
        print("✓ selftest: stage refs and `scratch` correctly exempt")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    files = dockerfiles()
    if not files:
        print(
            "✗ no Dockerfiles found — the guard would pass vacuously", file=sys.stderr
        )
        return 1
    return run(files, ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
