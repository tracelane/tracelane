#!/usr/bin/env python3
"""Generate the AUD-29 platform-key conformance vectors (offline, deterministic).

Three NDJSON ledgers the three verifiers (TS / Rust / Python) must agree on, each a
10-row chain in two signed-but-UNANCHORED batches (0-4, 5-9) — the platform-key path
does not need a public log, and unanchored batches are legitimate under ADR-062:

  platform-only.ndjson          both batches signed by the PLATFORM key
                                → pass; platform_signed_batches = 2
  platform-then-workspace.ndjson batch 0-4 platform, 5-9 workspace (the demo shape)
                                → pass; platform_signed_batches = 1
  workspace-then-platform.ndjson batch 0-4 workspace, 5-9 platform (the downgrade)
                                → platform_key_after_workspace_key
  platform-shadow.ndjson        a platform-signed copy of a workspace-signed batch
                                (same start) → platform_key_after_workspace_key

Keys are derived from fixed seeds so the vectors are reproducible byte-for-byte.
Reuses the frozen formats of generate_anchor_vectors.py (and its cross-check).

    cd evals/audit-ledger && python3 generate_platform_key_vectors.py
"""

import base64
import hashlib
import json
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from generate_anchor_vectors import (
    DOMAIN_ATTEST,
    build_chain,
    cross_check,
    merkle_root_v2,
)

UNANCHORED_COMMITMENT = b"\x00"


def seeded_key(label: str) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def pub_b64(key: ed25519.Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def unanchored_record(tenant, start, end, leaves, key):
    root = merkle_root_v2(leaves[start : end + 1])
    sig = key.sign(DOMAIN_ATTEST + root + UNANCHORED_COMMITMENT)
    return {
        "type": "anchor",
        "tenant_id": str(tenant),
        "batch_start_seq": start,
        "batch_end_seq": end,
        "merkle_root": root.hex(),
        "anchor_state": "unanchored",
        "ed25519": {"signature": base64.b64encode(sig).decode(), "pubkey": pub_b64(key)},
    }


def write(name, rows, anchors):
    with open(name, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
        for a in anchors:
            f.write(json.dumps(a) + "\n")


def main():
    cross_check()
    tenant = uuid.UUID("00000000-0000-0000-0000-0000000000b2")
    rows = [("chat.completions.request", "user1", {"action": "call", "step": i}) for i in range(10)]
    leaves, ndjson_rows = build_chain(tenant, rows)
    platform = seeded_key("tracelane-aud29-vector-platform-key")
    workspace = seeded_key("tracelane-aud29-vector-workspace-key")
    other = seeded_key("tracelane-aud29-vector-unrelated-key")

    def rec(start, end, key):
        return unanchored_record(tenant, start, end, leaves, key)

    write("platform-only.ndjson", ndjson_rows, [rec(0, 4, platform), rec(5, 9, platform)])
    write(
        "platform-then-workspace.ndjson", ndjson_rows, [rec(0, 4, platform), rec(5, 9, workspace)]
    )
    write(
        "workspace-then-platform.ndjson", ndjson_rows, [rec(0, 4, workspace), rec(5, 9, platform)]
    )
    # A platform-signed SHADOW of a workspace-signed batch (same start) — not a prefix.
    write(
        "platform-shadow.ndjson",
        ndjson_rows,
        [rec(0, 4, workspace), rec(0, 4, platform), rec(5, 9, workspace)],
    )
    meta = {
        "platform_ed25519_pubkey_b64": pub_b64(platform),
        "workspace_ed25519_pubkey_b64": pub_b64(workspace),
        "unrelated_ed25519_pubkey_b64": pub_b64(other),
        "expect": {
            "platform-only": {"ok": True, "platform_signed_batches": 2},
            "platform-then-workspace": {"ok": True, "platform_signed_batches": 1},
            "workspace-then-platform": {
                "ok": False,
                "error_kind": "platform_key_after_workspace_key",
            },
            "platform-shadow": {
                "ok": False,
                "error_kind": "platform_key_after_workspace_key",
            },
        },
    }
    with open("platform-key-vectors.meta.json", "w") as f:
        json.dump(meta, f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()
