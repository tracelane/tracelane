#!/usr/bin/env python3
"""Offline identity catalog/asset contract; --selftest plants forbidden cases."""

import argparse
import copy
import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / "apps/web/public/kya"
CATALOG = ROOT / "apps/web/db/kya_catalog.v1.json"
PROVIDERS = ROOT / "crates/gateway/providers.tsv"
# Only the maker/family/glyph combinations explicitly reviewed for this catalog.
MOTIFS = {
    ("openai", "gpt-6-sol", "sun"),
    ("openai", "gpt-6-luna", "moon"),
    ("openai", "gpt-6-astra", "star"),
}


def validate(data, assets, providers):
    errors = []

    def require(condition, message):
        if not condition:
            errors.append(message)

    def asset(relative):
        path = (assets / relative).resolve()
        return (
            path.is_relative_to(assets.resolve())
            and path.is_file()
            and path.suffix == ".svg"
        )

    require(data.get("version") == "v1", "unknown catalog version")
    require(
        data.get("limits")
        == {
            "identities": 200,
            "cross_list": 10,
            "recent_traces": 20,
            "agent_name_chars": 64,
        },
        "catalog limits changed",
    )
    makers = {item["id"] for item in data["makers"]}
    agents = {item["id"] for item in data["agents"]}
    for group, key in (
        ("makers", "id"),
        ("agents", "id"),
        ("models", "family"),
        ("clients", "id"),
    ):
        rows = data[group]
        require(len({row[key] for row in rows}) == len(rows), f"{group}: duplicate key")
        for row in rows:
            name = row[key]
            require(
                bool(name.strip()) and bool(row.get("label", "").strip()),
                f"{group}: blank identity",
            )
            if row.get("maker"):
                require(row["maker"] in makers, f"{name}: unknown maker")
            if row.get("mark"):
                require(
                    bool(row.get("mark_source")) and bool(row.get("mark_license")),
                    f"{name}: mark needs source and license",
                )
                require(asset(row["mark"]), f"{name}: missing/local-only SVG mark")
    for model in data["models"]:
        name, face = model["family"], model["avatar"]
        try:
            require(
                bool(re.fullmatch(model["match"], name)),
                f"{name}: pattern misses its family",
            )
        except re.error:
            errors.append(f"{name}: invalid pattern")
        # Normalization is shared with SQL; catalog patterns cannot silently merge
        # families whose numbers the gateway returned separately.
        require(
            model["match"] == "^" + re.escape(name).replace(r"\-", "-") + "$",
            f"{name}: use an exact normalized family pattern",
        )
        require(face["kind"] in ("motif", "maker_mark"), f"{name}: unknown avatar kind")
        if face["kind"] == "motif":
            require(
                (model["maker"], name, face.get("glyph")) in MOTIFS,
                f"{name}: unapproved motif",
            )
            require(
                bool(model.get("motif_source")), f"{name}: missing motif naming source"
            )
            require(
                asset("glyphs/" + face.get("glyph", "") + ".svg"),
                f"{name}: missing motif asset",
            )
    for client in data["clients"]:
        require(client["id"] in agents, f"{client['id']}: unknown classified agent")
        observation = client.get("observed", {})
        require(
            all(
                observation.get(field)
                for field in ("date", "client_version", "request_path", "method")
            ),
            f"{client['id']}: missing real request observation",
        )
        try:
            re.compile(client["ua_pattern"])
            require(
                client["ua_pattern"].startswith("^"),
                f"{client['id']}: unanchored client pattern",
            )
        except re.error:
            errors.append(f"{client['id']}: invalid client pattern")
    # A reviewed universal monogram is the resolver's fallback, including every
    # provider absent from the much smaller maker catalog. TS render tests exercise
    # the actual resolver against every generated provider, not this approximation.
    for provider in providers:
        require(
            bool(provider["id"].strip())
            and bool(provider["label"].strip())
            and data.get("fallback", {}).get("kind") == "monogram",
            f"{provider['id']}: no provider avatar",
        )
    return errors


def selftest(data, providers):
    cases = []

    def plant(name, change):
        item = copy.deepcopy(data)
        change(item)
        cases.append((name, item))

    for group in ("makers", "agents"):
        for field in ("mark_source", "mark_license"):

            def missing(d, group=group, field=field):
                d[group][0].update(
                    mark="glyphs/sun.svg",
                    mark_source="https://example.com/mark.svg",
                    mark_license="test",
                )
                del d[group][0][field]

            plant(f"{group} missing {field}", missing)
    plant(
        "missing asset",
        lambda d: d["makers"][0].update(
            mark="makers/absent.svg",
            mark_source="https://example.com/mark.svg",
            mark_license="test",
        ),
    )
    plant("unapproved maker motif", lambda d: d["models"][0].update(maker="anthropic"))
    plant(
        "invented motif",
        lambda d: d["models"][3].update(
            avatar={"kind": "motif", "glyph": "sun"},
            motif_source="https://example.com/naming",
        ),
    )
    plant("provider has no avatar", lambda d: d.update(fallback={"kind": "none"}))
    plant("missing request observation", lambda d: d["clients"][0].pop("observed"))
    plant("unbounded name", lambda d: d["limits"].update(agent_name_chars=65))
    failures = []
    for name, item in cases:
        if not validate(item, ASSETS, providers):
            failures.append(f"DID NOT BLOCK: {name}")
        else:
            print(f"BLOCKED: {name}")
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    data = json.loads(CATALOG.read_text())
    providers = list(
        csv.DictReader(
            (
                line
                for line in PROVIDERS.read_text().splitlines()
                if not line.startswith("#")
            ),
            delimiter="\t",
        )
    )
    errors = validate(data, ASSETS, providers)
    if args.selftest:
        errors += selftest(data, providers)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(
        f"KYA catalog OK: {len(providers)} provider fallbacks, {len(data['clients'])} observed client patterns"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
