#!/usr/bin/env python3
"""Generate the ADR-062 Amendment 1 anchor conformance vectors.

Produces two NDJSON fixtures the three verifiers (TS / Rust / Python) must agree on:

  anchored.v1.ndjson   — a real chain + a REAL Rekor v2 anchor. Verifies fully
                         when the trusted tenant Ed25519 pubkey is supplied.
  forged-anchor.ndjson — the C1/C2 attack made concrete: a genuinely-log-included
                         Rekor entry (real inclusion proof + checkpoint) whose
                         local attestation is signed by an ATTACKER key, not the
                         trusted tenant key. Every verifier MUST reject it.

This script is itself a faithful reference implementation of the gateway's frozen
crypto; it is CROSS-CHECKED against the Rust gateway's pinned test values before
minting anything (a mismatch aborts). Re-run only to regenerate (a new live Rekor
entry); the committed vectors are immutable + reproducible.

    python3 evals/audit-ledger/generate_anchor_vectors.py
"""

import base64
import hashlib
import json
import struct
import sys
import uuid

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

REKOR_V2 = "https://log2025-1.rekor.sigstore.dev/api/v2/log/entries"

# ---- FROZEN formats (must match crates/gateway/src/audit{,_format}.rs) --------
DOMAIN_ROW_V2 = b"tracelane-audit-row-v2\x00"
DOMAIN_GENESIS_V2 = b"tracelane-audit-v2-genesis\x00"
DOMAIN_ANCHOR = b"tracelane-anchor-ecdsa-v1\x00"
DOMAIN_ATTEST = b"tracelane-audit-ed25519-v1\x00"
LEAF, NODE = b"\x00", b"\x01"


def sha256(b):
    return hashlib.sha256(b).digest()


def u64be(n):
    return struct.pack(">Q", n)


def lp(b):
    return u64be(len(b)) + b


def canonical(payload: dict) -> str:
    # JCS subset: sorted keys, no whitespace. Our test payloads are scalar-only.
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def genesis(tenant_uuid16: bytes) -> bytes:
    return sha256(DOMAIN_GENESIS_V2 + tenant_uuid16)


def row_hash_v2(prev, tenant16, seq, event_type, actor, canon):
    return sha256(
        DOMAIN_ROW_V2
        + lp(tenant16)
        + u64be(seq)
        + lp(event_type.encode())
        + lp(actor.encode())
        + lp(canon.encode())
        + lp(prev)
    )


def merkle_root_v2(leaves):
    if not leaves:
        return sha256(b"")
    level = [sha256(LEAF + x) for x in leaves]
    while len(level) > 1:
        nxt = []
        i = 0
        while i + 1 < len(level):
            nxt.append(sha256(NODE + level[i] + level[i + 1]))
            i += 2
        if i < len(level):
            nxt.append(level[i])  # lone-odd: promote
        level = nxt
    return level[0]


def anchor_commitment(ecdsa_spki, log_url, log_index):
    return LEAF * 0 + b"\x01" + sha256(ecdsa_spki) + sha256(log_url.encode()) + u64be(log_index)


def local_attest_msg(root, commitment):
    return DOMAIN_ATTEST + root + commitment


def der_spki(pub):
    return pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


# ---- Cross-check against the Rust gateway's pinned values --------------------
def cross_check():
    t = uuid.UUID("00000000-0000-0000-0000-000000000009")
    g = genesis(t.bytes)
    assert g.hex() == "48151affc57484ee3bf4d013132e354cab5deb6134599089144f1228da5d7fa5", (
        f"genesis mismatch: {g.hex()}"
    )
    payload = {"big_int": 9007199254740993, "exp": 100.0, "temperature": 1.0, "top_p": 0.5}
    canon = canonical(payload)
    assert canon == '{"big_int":9007199254740993,"exp":100.0,"temperature":1.0,"top_p":0.5}', (
        f"canonical mismatch: {canon}"
    )
    h0 = row_hash_v2(g, t.bytes, 0, "chat.completions.request", "user1", canon)
    assert h0.hex() == "965997278c41ad63099b1179ff5a15031a412041f01cbc4f377cc8b7a852ae15", (
        f"row_hash mismatch: {h0.hex()}"
    )
    print("cross-check vs Rust gateway pinned values: OK", file=sys.stderr)


# ---- Build a chain + anchor + NDJSON ----------------------------------------
def build_chain(tenant: uuid.UUID, rows):
    """rows = [(event_type, actor, payload_dict), ...] → (leaves, ndjson_row_dicts)."""
    prev = genesis(tenant.bytes)
    leaves, out = [], []
    for seq, (et, actor, payload) in enumerate(rows):
        canon = canonical(payload)
        h = row_hash_v2(prev, tenant.bytes, seq, et, actor, canon)
        out.append(
            {
                "format": "v2.1",
                "tenant_id": str(tenant),
                "seq": seq,
                "event_time": f"2026-07-12T00:00:{seq:02d}.000000Z",
                "event_type": et,
                "actor": actor,
                "payload": canon,
                "prev_hash": prev.hex(),
                "row_hash": h.hex(),
                "rekor_entry_id": None,  # backfilled below to the log index when anchored
            }
        )
        leaves.append(h)
        prev = h
    return leaves, out


def anchor_to_rekor(root, ecdsa_priv):
    artifact = DOMAIN_ANCHOR + root
    digest = sha256(artifact)
    sig = ecdsa_priv.sign(artifact, ec.ECDSA(hashes.SHA256()))
    spki = der_spki(ecdsa_priv.public_key())
    body = {
        "hashedRekordRequestV002": {
            "digest": base64.b64encode(digest).decode(),
            "signature": {
                "content": base64.b64encode(sig).decode(),
                "verifier": {
                    "publicKey": {"rawBytes": base64.b64encode(spki).decode()},
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                },
            },
        }
    }
    r = requests.post(REKOR_V2, json=body, headers={"Accept": "application/json"}, timeout=30)
    r.raise_for_status()
    j = r.json()
    ip = j["inclusionProof"]
    return spki, {
        "log_url": "https://log2025-1.rekor.sigstore.dev",
        "log_index": j["logIndex"],
        "canonicalized_body": j["canonicalizedBody"],
        "inclusion_proof": {
            "log_index": ip["logIndex"],
            "tree_size": ip["treeSize"],
            "hashes": ip["hashes"],
        },
        "checkpoint": {"envelope": ip["checkpoint"]["envelope"]},
    }


def make_anchor_record(tenant, start, end, root, ecdsa_spki, rekor, ed_priv):
    log_index = int(rekor["log_index"])
    commitment = anchor_commitment(ecdsa_spki, rekor["log_url"], log_index)
    ed_sig = ed_priv.sign(local_attest_msg(root, commitment))
    ed_pub = ed_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {
        "type": "anchor",
        "tenant_id": str(tenant),
        "batch_start_seq": start,
        "batch_end_seq": end,
        "merkle_root": root.hex(),
        "anchor_state": "anchored",
        "ed25519": {
            "signature": base64.b64encode(ed_sig).decode(),
            "pubkey": base64.b64encode(ed_pub).decode(),
        },
        "rekor": rekor,
    }


def main():
    cross_check()
    tenant = uuid.UUID("00000000-0000-0000-0000-0000000000a1")
    rows = [
        ("chat.completions.request", "user1", {"action": "call", "step": 0}),
        ("guardrail.verdict", "system", {"outcome": "allow", "step": 1}),
        ("chat.completions.request", "user1", {"action": "call", "step": 2}),
        ("eval.verdict", "system", {"pass": 1, "step": 3}),
    ]
    leaves, ndjson_rows = build_chain(tenant, rows)
    root = merkle_root_v2(leaves)

    # The REAL tenant keys (honest) + the ATTACKER keys (forged).
    tenant_ecdsa = ec.generate_private_key(ec.SECP256R1())
    tenant_ed = ed25519.Ed25519PrivateKey.generate()
    attacker_ecdsa = ec.generate_private_key(ec.SECP256R1())
    attacker_ed = ed25519.Ed25519PrivateKey.generate()

    # --- anchored.v1.ndjson: real anchor, signed by the tenant keys ---
    spki, rekor = anchor_to_rekor(root, tenant_ecdsa)
    log_index = rekor["log_index"]
    honest_rows = [dict(r, rekor_entry_id=log_index) for r in ndjson_rows]
    honest_anchor = make_anchor_record(tenant, 0, len(rows) - 1, root, spki, rekor, tenant_ed)
    tenant_ed_pub_b64 = honest_anchor["ed25519"]["pubkey"]

    with open("anchored.v1.ndjson", "w") as f:
        for r in honest_rows:
            f.write(json.dumps(r) + "\n")
        f.write(json.dumps(honest_anchor) + "\n")

    # --- forged-anchor.ndjson: the attacker anchors THEIR OWN root+key for real,
    #     then signs the local attestation with the ATTACKER Ed25519 key. The
    #     Rekor entry is genuinely included, but the attestation is not the
    #     trusted tenant's → the verifier's trusted-key gate rejects it. ---
    a_spki, a_rekor = anchor_to_rekor(root, attacker_ecdsa)
    forged_rows = [dict(r, rekor_entry_id=a_rekor["log_index"]) for r in ndjson_rows]
    forged_anchor = make_anchor_record(tenant, 0, len(rows) - 1, root, a_spki, a_rekor, attacker_ed)
    with open("forged-anchor.ndjson", "w") as f:
        for r in forged_rows:
            f.write(json.dumps(r) + "\n")
        f.write(json.dumps(forged_anchor) + "\n")

    # Emit the trust config the conformance tests need (the TRUSTED tenant pubkey
    # + pinned log key). Committed as anchor-vectors.meta.json.
    meta = {
        "merkle_root_hex": root.hex(),
        "trusted_tenant_ed25519_pubkey_b64": tenant_ed_pub_b64,
        "attacker_tenant_ed25519_pubkey_b64": forged_anchor["ed25519"]["pubkey"],
        "log_host": "log2025-1.rekor.sigstore.dev",
        "log_ed25519_pubkey_b64": "t8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=",
        "anchored_log_index": log_index,
        "forged_log_index": a_rekor["log_index"],
    }
    with open("anchor-vectors.meta.json", "w") as f:
        json.dump(meta, f, indent=2)
    print(json.dumps(meta, indent=2), file=sys.stderr)
    print(
        "wrote anchored.v1.ndjson, forged-anchor.ndjson, anchor-vectors.meta.json", file=sys.stderr
    )


if __name__ == "__main__":
    main()
