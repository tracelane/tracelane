"""Reference verifier for Tracelane tamper-evident audit ledgers.

Mirrors the Rust verifier in ``packages/verifier-rust`` and the TypeScript
verifier in ``packages/verifier-typescript`` — see ``evals/audit-ledger/``
for shared conformance vectors. All three verifiers MUST agree on every
vector, byte-for-byte, in crypto behavior.

Each row may carry a ``format`` marker selecting its verification path;
unmarked rows fall back to :attr:`VerifyOptions.format_version`
(default ``V2``, for pre-ADR-050 packs).

- **v2.1 (ADR-050, current)**: ``payload`` is the **verbatim stored
  canonical JSON string** (the exact ``row_hash`` preimage). It is
  SHA-256'd byte-for-byte and NEVER re-derived. Because no component
  re-canonicalizes, the Rust / Python / TypeScript verifiers are
  **identical by construction** — the numeric-canonicalization parity bug
  class cannot exist.
- **v2 (legacy re-derive)**: length-prefixed, domain-separated framing
  matching ``crates/gateway/src/audit_format/mod.rs::row_hash_v2``, RFC 6962
  §2.1 Merkle tree — but ``payload`` is a nested object this verifier
  re-canonicalizes, which can disagree cross-language on JS-unsafe numbers.
  Kept read-only for pre-ADR-050 exports.
- **v1 (legacy)**: ``f"{tenant_id}|{seq}|..."`` row hash. Vulnerable to
  field-boundary attacks. Kept for migration of pre-Phase-3 logs.

Anchor verification is **OFFLINE** (ADR-062 Amendment 1). Rekor v2 has no
online entry lookup; the inclusion proof + C2SP checkpoint are bundled in
the export as ``type == "anchor"`` records. The single external trust root
is the caller-supplied :attr:`VerifyOptions.tenant_pubkey`; absent it, the
verifier runs chain-only and asserts nothing about anchors (never green).

The one representation difference from the TypeScript reference (not a
crypto-behavior difference): the P-256 entry public key is loaded from its
DER SubjectPublicKeyInfo directly via ``cryptography`` rather than manually
extracting the raw uncompressed point — the ECDSA verification is identical.

Usage::

    from pathlib import Path
    from tracelane_audit_verifier import verify_ledger, VerifyOptions

    report = verify_ledger(Path("audit.ndjson"), VerifyOptions(offline=True))
    assert report.hash_chain_valid
"""

from __future__ import annotations

import base64
import enum
import hashlib
import json
import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

__all__ = [
    "FormatVersion",
    "VerifyOptions",
    "VerifyError",
    "VerifyReport",
    "compute_row_hash",
    "verify_ledger",
]


class FormatVersion(enum.Enum):
    # v2.1 (ADR-050): payload is the verbatim stored canonical JSON string,
    # hashed byte-for-byte, never re-derived. The format for new exports.
    V2_1 = "v2.1"
    # v2: legacy re-derive path (payload as an object); lossy for JS-unsafe
    V2 = "v2"
    V1 = "v1"


def _is_v2_family(fmt: FormatVersion) -> bool:
    """v2 and v2.1 share identical framing; they differ only in how the
    canonical payload string is obtained (verbatim vs re-derived)."""
    return fmt in (FormatVersion.V2, FormatVersion.V2_1)


def _resolve_format(row: dict[str, Any], default: FormatVersion) -> FormatVersion:
    """Effective format for one row. The per-row ``format`` marker is
    authoritative (ADR-050: branch on the marker, never type-sniff); rows
    without a marker fall back to the caller default."""
    marker = row.get("format")
    if marker == "v2.1":
        return FormatVersion.V2_1
    if marker == "v2":
        return FormatVersion.V2
    if marker == "v1":
        return FormatVersion.V1
    return default


@dataclass
class VerifyOptions:
    """Verifier knobs."""

    format_version: FormatVersion = FormatVersion.V2
    # Vestigial since ADR-062 Amendment 1 — anchor verification is always
    # offline from the bundle. Accepted for backward-compatible constructors.
    offline: bool = False
    # 32-byte Ed25519 pubkey to pin every Rekor anchor against (R1 H2). Kept
    # for API symmetry with the TS/Rust verifiers; unused in the offline path.
    pinned_pubkey: bytes | None = None
    # ADR-062 C2: the TRUSTED tenant Ed25519 pubkey (32 raw bytes), obtained
    # out-of-band from Tracelane's TLS-authenticated domain (dashboard
    # /settings/audit or GET /v1/audit/pubkey). Anchor records whose embedded
    # pubkey differs are REJECTED (fail closed). Absent -> chain-only mode:
    # signatures/anchors are reported UNVERIFIED (never green).
    tenant_pubkey: bytes | None = None


# ---------------------------------------------------------------------
# Hash format (v2)
# ---------------------------------------------------------------------

DOMAIN_ROW_V2 = b"tracelane-audit-row-v2\x00"
DOMAIN_GENESIS_V2 = b"tracelane-audit-v2-genesis\x00"
MERKLE_LEAF_PREFIX = b"\x00"
MERKLE_NODE_PREFIX = b"\x01"

# ADR-062 Amendment 1 — FROZEN anchor domain tags + pinned log trust anchor.
DOMAIN_ANCHOR = b"tracelane-anchor-ecdsa-v1\x00"
DOMAIN_ATTEST = b"tracelane-audit-ed25519-v1\x00"
# The public Rekor v2 log this verifier trusts — HARDCODED, never read from the
# bundle (ADR-062 H5). Rotation = a new verifier release + ADR. Source: Sigstore
# TUF trusted_root (tlogs[log2025-1].publicKey).
LOG_HOST = "log2025-1.rekor.sigstore.dev"
# log2025-1 Ed25519 checkpoint key, raw 32 bytes.
LOG_ED25519_PUBKEY = base64.b64decode("t8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=")


def _uuid_bytes(tenant_id: str) -> bytes:
    """Decode a UUID string (hyphenated or bare) to 16 raw bytes."""
    cleaned = tenant_id.replace("-", "")
    if len(cleaned) != 32:
        raise ValueError(f"tenant_id is not a UUID: {tenant_id}")
    return bytes.fromhex(cleaned)


def _u64be(n: int) -> bytes:
    return struct.pack(">Q", n)


def _write_lp(parts: list[bytes], b: bytes) -> None:
    parts.append(_u64be(len(b)))
    parts.append(b)


def _row_hash_v2(
    prev_hash: bytes,
    tenant_uuid: bytes,
    seq: int,
    event_type: str,
    actor: str,
    canonical_payload: str,
) -> bytes:
    parts: list[bytes] = [DOMAIN_ROW_V2]
    _write_lp(parts, tenant_uuid)
    parts.append(_u64be(seq))
    _write_lp(parts, event_type.encode("utf-8"))
    _write_lp(parts, actor.encode("utf-8"))
    _write_lp(parts, canonical_payload.encode("utf-8"))
    _write_lp(parts, prev_hash)
    return hashlib.sha256(b"".join(parts)).digest()


def _genesis_v2(tenant_uuid: bytes) -> bytes:
    return hashlib.sha256(DOMAIN_GENESIS_V2 + tenant_uuid).digest()


def _merkle_root_v2(leaves: list[bytes]) -> bytes:
    """RFC 6962 §2.1 Merkle root. Lone-odd leaf is promoted, not duplicated."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    level = [hashlib.sha256(MERKLE_LEAF_PREFIX + leaf).digest() for leaf in leaves]
    while len(level) > 1:
        nxt: list[bytes] = []
        i = 0
        while i + 1 < len(level):
            nxt.append(hashlib.sha256(MERKLE_NODE_PREFIX + level[i] + level[i + 1]).digest())
            i += 2
        if i < len(level):
            nxt.append(level[i])  # lone odd: promote unchanged
        level = nxt
    return level[0]


def _canonical_payload_v2(value: Any) -> str:
    """JCS-subset canonical JSON: sorted keys, no whitespace, ASCII-only escapes
    for control chars. Matches Rust verifier's canonical_payload_v2.
    """
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------
# Hash format (v1 legacy)
# ---------------------------------------------------------------------


def compute_row_hash(
    prev_hash: str,
    tenant_id: str,
    seq: int,
    event_type: str,
    actor: str,
    payload_json: str,
) -> str:
    """v1 (legacy) row hash. Vulnerable to field-boundary attacks; kept for
    pre-Phase-3 ledger migration. New code should use v2 via ``verify_ledger``.
    """
    payload = f"{tenant_id}|{seq}|{event_type}|{actor}|{payload_json}|{prev_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _canonical_payload_v1(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


# ---------------------------------------------------------------------
# ADR-062 Amendment 1 — offline anchor crypto
# ---------------------------------------------------------------------


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(MERKLE_NODE_PREFIX + left + right).digest()


def _anchor_commitment(anchored: tuple[bytes, str, int] | None) -> bytes:
    """``anchor_commitment`` (ADR-062): ``None`` -> ``0x00``;
    anchored -> ``0x01 || SHA256(ecdsa_spki) || SHA256(log_url) || u64be(log_index)``.
    """
    if anchored is None:
        return b"\x00"
    ecdsa_spki, log_url, log_index = anchored
    return (
        b"\x01"
        + hashlib.sha256(ecdsa_spki).digest()
        + hashlib.sha256(log_url.encode("utf-8")).digest()
        + _u64be(log_index)
    )


def _rfc6962_root(leaf: bytes, index: int, size: int, proof: list[bytes]) -> bytes:
    """RFC 6962 §2.1.1 inclusion-proof root recomputation. ``leaf`` is already the
    RFC6962 leaf hash ``SHA256(0x00 || body)``. Raises on a malformed proof.
    """
    if index >= size:
        raise ValueError("leaf index >= tree size")
    fn = index
    sn = size - 1
    r = leaf
    for p in proof:
        if sn == 0:
            raise ValueError("inclusion proof too long")
        if (fn & 1) == 1 or fn == sn:
            r = _node_hash(p, r)
            while fn != 0 and (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            r = _node_hash(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("inclusion proof too short")
    return r


def _verify_checkpoint(envelope: str) -> tuple[int, bytes]:
    """Parse + verify a C2SP signed-note checkpoint against the PINNED log key
    (ADR-062 H5 — never a bundle-supplied key). Returns ``(tree_size, root)``.
    Raises ``ValueError`` on any structural or signature failure.
    """
    sep = envelope.find("\n\n")
    if sep < 0:
        raise ValueError("checkpoint has no signature separator")
    # Signed text = the body up to (and including the \n before) the blank line.
    body_text = envelope[: sep + 1]
    sig_block = envelope[sep + 2 :]
    body_lines = body_text.split("\n")
    origin = body_lines[0] if len(body_lines) > 0 else ""
    tree_size = int(body_lines[1]) if len(body_lines) > 1 else 0
    root_b64 = body_lines[2] if len(body_lines) > 2 else ""
    if origin != LOG_HOST:
        raise ValueError(f"checkpoint origin {origin} != pinned {LOG_HOST}")
    sig_line = next((line for line in sig_block.split("\n") if line.startswith("— ")), None)
    if sig_line is None:
        raise ValueError("checkpoint has no signature line")
    parts = sig_line.split(" ")
    sig_blob = base64.b64decode(parts[2]) if len(parts) > 2 else b""
    if len(sig_blob) != 4 + 64:
        raise ValueError("checkpoint sig blob wrong length")
    keyhint = sig_blob[:4]
    sig = sig_blob[4:]
    # keyhint = SHA256(name || 0x0A || 0x01 || pubkey)[:4] (C2SP signed-note, Ed25519).
    expect_hint = hashlib.sha256(
        LOG_HOST.encode("utf-8") + b"\x0a\x01" + LOG_ED25519_PUBKEY
    ).digest()[:4]
    if keyhint != expect_hint:
        raise ValueError("checkpoint key hint != pinned log key")
    try:
        Ed25519PublicKey.from_public_bytes(LOG_ED25519_PUBKEY).verify(
            sig, body_text.encode("utf-8")
        )
    except (InvalidSignature, ValueError) as e:
        raise ValueError("checkpoint signature invalid") from e
    return tree_size, base64.b64decode(root_b64)


# ---------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------


@dataclass
class VerifyError:
    """Single detected verification failure."""

    seq: int | None
    kind: str
    detail: str


@dataclass
class VerifyReport:
    """Verifier output. Byte-identical JSON to the Rust + TS verifiers."""

    ledger_path: str
    rows_seen: int = 0
    hash_chain_valid: bool = True
    signatures_valid: bool = True
    rekor_anchors_seen: int = 0
    rekor_anchors_resolved: int = 0
    # Anchors whose FULL public-inclusion proof + checkpoint verified (Layer 2+3).
    anchors_included: int = 0
    # True if any anchor committed to "anchored" but its rekor bundle is absent
    # (a strip/downgrade attack). ADR-062 H3.
    strip_detected: bool = False
    errors: list[VerifyError] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


# ---------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------


def verify_ledger(path: Path, options: VerifyOptions | None = None) -> VerifyReport:
    """Verify an NDJSON audit ledger end-to-end.

    Splits the NDJSON into row records (no ``type``) and anchor records
    (``type == "anchor"``). Recomputes every row hash and the prev-hash chain,
    then runs ADR-062 Amendment 1 OFFLINE anchor verification from the bundle.

    Raises :class:`OSError` on file I/O failures only. Logical errors land
    in ``report.errors`` and the ``*_valid`` booleans flip to ``False``.
    """
    opts = options or VerifyOptions()
    report = VerifyReport(ledger_path=str(path))

    # Split records: row records (no `type`) vs anchor records (`type:"anchor"`).
    rows: list[dict[str, Any]] = []
    anchors: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for line_idx, raw in enumerate(fh):
            line = raw.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                report.errors.append(
                    VerifyError(
                        seq=None,
                        kind="parse_error",
                        detail=f"line {line_idx + 1}: {exc}",
                    )
                )
                report.hash_chain_valid = False
                continue
            if isinstance(rec, dict) and rec.get("type") == "anchor":
                anchors.append(rec)
            else:
                rows.append(rec)
    report.rows_seen = len(rows)

    _verify_chain(report, rows, opts)

    # ADR-062 Amendment 1: OFFLINE anchor verification from the bundle (Rekor v2
    # has no online lookup). The trusted tenant pubkey is the single external
    # trust root; absent -> chain-only (anchors reported UNVERIFIED, never green).
    _verify_anchors_offline(report, rows, anchors, opts.tenant_pubkey)

    return report


def _verify_chain(
    report: VerifyReport,
    rows: list[dict[str, Any]],
    opts: VerifyOptions,
) -> None:
    # Per-tenant chain state: (next_expected_seq, expected_prev_hash_bytes).
    state: dict[str, tuple[int, bytes]] = {}

    for row in rows:
        tenant_id = str(row.get("tenant_id", ""))
        seq = int(row.get("seq", -1))
        try:
            tenant_uuid = _uuid_bytes(tenant_id)
        except ValueError as e:
            report.errors.append(VerifyError(seq=seq, kind="bad_tenant_id", detail=str(e)))
            report.hash_chain_valid = False
            continue

        # Per-row format: the ``format`` marker wins; else the caller default.
        fmt = _resolve_format(row, opts.format_version)
        v2_family = _is_v2_family(fmt)

        if tenant_id not in state:
            if v2_family:
                state[tenant_id] = (0, _genesis_v2(tenant_uuid))
            else:
                state[tenant_id] = (0, b"")  # v1 uses empty string

        expected_seq, expected_prev = state[tenant_id]

        if seq != expected_seq:
            report.errors.append(
                VerifyError(
                    seq=seq,
                    kind="seq_out_of_order",
                    detail=f"tenant {tenant_id}: expected seq {expected_seq}, got {seq}",
                )
            )
            report.hash_chain_valid = False

        prev_hash_str = str(row.get("prev_hash", ""))
        if v2_family:
            if seq == 0 and prev_hash_str == "":
                prev_ok = True
            else:
                try:
                    prev_ok = bytes.fromhex(prev_hash_str) == expected_prev
                except ValueError:
                    prev_ok = False
        else:
            expected_str = "" if seq == 0 else expected_prev.hex()
            prev_ok = prev_hash_str == expected_str

        if not prev_ok:
            report.errors.append(
                VerifyError(
                    seq=seq,
                    kind="prev_hash_mismatch",
                    detail=f"tenant {tenant_id}: prev_hash does not chain",
                )
            )
            report.hash_chain_valid = False

        # Obtain the canonical payload STRING (the row_hash preimage).
        #   v2.1 — the payload IS the verbatim canonical string; hash it
        #   v2   — re-canonicalize the object (legacy; lossy cross-language
        #   v1   — legacy pipe format.
        payload = row.get("payload")
        canon: str | None
        if fmt == FormatVersion.V2_1:
            if isinstance(payload, str):
                canon = payload
            else:
                report.errors.append(
                    VerifyError(
                        seq=seq,
                        kind="v2_1_payload_not_string",
                        detail=(
                            f"tenant {tenant_id}: v2.1 payload must be the verbatim "
                            "canonical JSON string, not a re-parsed object/number"
                        ),
                    )
                )
                report.hash_chain_valid = False
                canon = None
        elif fmt == FormatVersion.V2:
            canon = _canonical_payload_v2(payload)
        else:
            canon = _canonical_payload_v1(payload)

        stored_hex = str(row.get("row_hash", ""))
        try:
            stored = bytes.fromhex(stored_hex)
        except ValueError:
            report.errors.append(
                VerifyError(
                    seq=seq,
                    kind="bad_row_hash_encoding",
                    detail=f"row_hash is not 64-hex: {stored_hex}",
                )
            )
            report.hash_chain_valid = False
            continue

        if canon is not None:
            if v2_family:
                recomputed = _row_hash_v2(
                    expected_prev,
                    tenant_uuid,
                    seq,
                    str(row.get("event_type", "")),
                    str(row.get("actor", "")),
                    canon,
                )
            else:
                recomputed_hex = compute_row_hash(
                    prev_hash_str,
                    tenant_id,
                    seq,
                    str(row.get("event_type", "")),
                    str(row.get("actor", "")),
                    canon,
                )
                recomputed = bytes.fromhex(recomputed_hex)

            if recomputed != stored:
                report.errors.append(
                    VerifyError(
                        seq=seq,
                        kind="row_hash_mismatch",
                        detail=(
                            f"tenant {tenant_id}: expected row_hash "
                            f"{recomputed.hex()}, got {stored_hex}"
                        ),
                    )
                )
                report.hash_chain_valid = False

        # Advance chain state with the CLAIMED stored hash even if an error fired
        # above (v2_1_payload_not_string / row_hash_mismatch). Deliberate
        # continue-on-error so every downstream break is reported; it cannot hide
        # a break because hash_chain_valid is already False and consumers gate on
        # that boolean, never on len(errors).
        state[tenant_id] = (seq + 1, stored)


def _verify_anchors_offline(
    report: VerifyReport,
    rows: list[dict[str, Any]],
    anchors: list[dict[str, Any]],
    tenant_pubkey: bytes | None,
) -> None:
    """ADR-062 Amendment 1 — OFFLINE anchor verification. For each anchor record:

    0. recompute the batch Merkle root over the chain rows [start..end];
    2. trusted-key gate (C2) — the bundle Ed25519 pubkey MUST equal the trusted
       ``tenant_pubkey``, else fail closed; absent ``tenant_pubkey`` -> chain-only;
    3. bound Ed25519 attestation over ``DOMAIN_ATTEST || root || anchor_commitment``
       (catches strip / swap / downgrade — the attacker lacks the tenant key);
    when anchored also: 1. ECDSA entry sig binds the root; 2. RFC6962 inclusion
    proof; 3'. C2SP checkpoint sig against the PINNED log key.

    Any failure flips ``signatures_valid`` False; chain-only mode asserts nothing
    (callers gate a green "signed/anchored" claim on ``rekor_anchors_resolved > 0``
    and ``anchors_included > 0``, never on ``signatures_valid`` alone).
    """
    if not anchors:
        return

    row_hash_by_key: dict[str, bytes] = {}
    for row in rows:
        try:
            key = f"{row['tenant_id']}/{row['seq']}"
            row_hash_by_key[key] = bytes.fromhex(str(row["row_hash"]))
        except (KeyError, ValueError, TypeError):
            # a bad row_hash is already flagged by _verify_chain
            continue

    for a in anchors:
        committed = a.get("anchor_state") == "anchored"
        label = f"batch {a.get('batch_start_seq')}-{a.get('batch_end_seq')}"
        rekor = a.get("rekor")

        # H3: committed-anchored but no bundle = a strip/downgrade.
        if committed and not rekor:
            report.strip_detected = True
            report.errors.append(
                VerifyError(
                    seq=None,
                    kind="anchor_stripped",
                    detail=f"{label}: claims anchored but the rekor bundle is absent",
                )
            )
            report.signatures_valid = False
            continue

        # Layer 0: recompute the batch Merkle root over the chain rows.
        leaves: list[bytes] = []
        missing = False
        start = int(a.get("batch_start_seq", 0))
        end = int(a.get("batch_end_seq", -1))
        for seq in range(start, end + 1):
            h = row_hash_by_key.get(f"{a.get('tenant_id')}/{seq}")
            if h is None:
                missing = True
                break
            leaves.append(h)
        if missing:
            report.errors.append(
                VerifyError(
                    seq=None,
                    kind="anchor_rows_missing",
                    detail=f"{label}: not all covered rows are present",
                )
            )
            report.signatures_valid = False
            continue
        root = _merkle_root_v2(leaves)
        try:
            claimed_root = bytes.fromhex(str(a.get("merkle_root", "")))
        except ValueError:
            report.errors.append(
                VerifyError(
                    seq=None,
                    kind="bad_merkle_root",
                    detail=f"{label}: merkle_root is not hex",
                )
            )
            report.signatures_valid = False
            continue
        if root != claimed_root:
            report.errors.append(
                VerifyError(
                    seq=None,
                    kind="merkle_root_mismatch",
                    detail=f"{label}: recomputed root != anchor.merkle_root",
                )
            )
            report.signatures_valid = False
            continue

        # Layer 2 (trusted-key gate, C2). No trusted key -> chain-only: assert
        # nothing (never green), do not count as seen/resolved.
        if tenant_pubkey is None:
            continue
        ed25519_block = a.get("ed25519", {})
        try:
            bundle_pubkey = base64.b64decode(str(ed25519_block.get("pubkey", "")))
        except (ValueError, TypeError):
            report.errors.append(
                VerifyError(
                    seq=None,
                    kind="bad_tenant_pubkey",
                    detail=f"{label}: ed25519.pubkey is not base64",
                )
            )
            report.signatures_valid = False
            continue
        if bundle_pubkey != tenant_pubkey:
            report.errors.append(
                VerifyError(
                    seq=None,
                    kind="untrusted_tenant_key",
                    detail=(
                        f"{label}: anchor Ed25519 pubkey != trusted "
                        "--tenant-pubkey (rejected — ADR-062 C2)"
                    ),
                )
            )
            report.signatures_valid = False
            continue

        # Extract ECDSA material from the canonicalized body (anchored only).
        anchored_meta: tuple[bytes, str, int] | None = None
        artifact_hash: bytes | None = None
        entry_sig: bytes | None = None
        entry_pub: ec.EllipticCurvePublicKey | None = None
        if committed and rekor:
            try:
                decoded = json.loads(base64.b64decode(str(rekor.get("canonicalized_body", ""))))
                spec = decoded.get("spec", {}).get("hashedRekordV002", {})
                data = spec.get("data", {})
                sigb = spec.get("signature", {})
                verifier = sigb.get("verifier", {})
                pk = verifier.get("publicKey", {})
                if verifier.get("keyDetails") != "PKIX_ECDSA_P256_SHA_256":
                    raise ValueError(f"unexpected keyDetails {verifier.get('keyDetails')}")
                ecdsa_spki = base64.b64decode(str(pk.get("rawBytes", "")))
                artifact_hash = hashlib.sha256(DOMAIN_ANCHOR + root).digest()
                if base64.b64decode(str(data.get("digest", ""))) != artifact_hash:
                    raise ValueError("entry digest != SHA256(anchor artifact)")
                entry_sig = base64.b64decode(str(sigb.get("content", "")))
                loaded = serialization.load_der_public_key(ecdsa_spki)
                if not isinstance(loaded, ec.EllipticCurvePublicKey):
                    raise ValueError("entry public key is not ECDSA")
                entry_pub = loaded
                anchored_meta = (
                    ecdsa_spki,
                    str(rekor.get("log_url", "")),
                    int(rekor.get("log_index", 0)),
                )
            except Exception as e:  # noqa: BLE001 — any body defect fails the anchor
                report.errors.append(
                    VerifyError(
                        seq=None,
                        kind="anchor_body_invalid",
                        detail=f"{label}: {e}",
                    )
                )
                report.signatures_valid = False
                continue

        # Layer 3 (bound Ed25519 attestation) — the load-bearing check.
        commitment = _anchor_commitment(anchored_meta)
        msg = DOMAIN_ATTEST + root + commitment
        try:
            att_sig = base64.b64decode(str(ed25519_block.get("signature", "")))
        except (ValueError, TypeError):
            report.errors.append(
                VerifyError(
                    seq=None,
                    kind="bad_attestation_sig",
                    detail=f"{label}: ed25519.signature is not base64",
                )
            )
            report.signatures_valid = False
            continue
        try:
            Ed25519PublicKey.from_public_bytes(tenant_pubkey).verify(att_sig, msg)
        except (InvalidSignature, ValueError):
            report.errors.append(
                VerifyError(
                    seq=None,
                    kind="attestation_invalid",
                    detail=f"{label}: bound Ed25519 attestation failed (tamper/strip/downgrade)",
                )
            )
            report.signatures_valid = False
            continue

        if (
            not committed
            or not rekor
            or entry_sig is None
            or entry_pub is None
            or artifact_hash is None
        ):
            # Honest signed-but-unanchored batch: attestation verified, nothing more.
            continue
        report.rekor_anchors_seen += 1

        # Layer 1: ECDSA entry signature over the anchor-artifact hash. Rekor's
        # signatures are DER; `cryptography` verifies DER directly and does not
        # enforce low-S (matching Rekor's non-enforcement on submission).
        ecdsa_ok = False
        try:
            entry_pub.verify(entry_sig, artifact_hash, ec.ECDSA(Prehashed(hashes.SHA256())))
            ecdsa_ok = True
        except (InvalidSignature, ValueError):
            ecdsa_ok = False
        if not ecdsa_ok:
            report.errors.append(
                VerifyError(
                    seq=None,
                    kind="entry_signature_invalid",
                    detail=f"{label}: Rekor entry ECDSA sig did not verify over the anchor artifact",
                )
            )
            report.signatures_valid = False
            continue
        report.rekor_anchors_resolved += 1

        # Layer 2 (inclusion proof) + Layer 3' (checkpoint sig, pinned key).
        try:
            body = base64.b64decode(str(rekor.get("canonicalized_body", "")))
            leaf = hashlib.sha256(MERKLE_LEAF_PREFIX + body).digest()
            inclusion_proof = rekor.get("inclusion_proof", {})
            idx = int(inclusion_proof.get("log_index", 0))
            tree_size = int(inclusion_proof.get("tree_size", 0))
            proof = [base64.b64decode(h) for h in inclusion_proof.get("hashes", [])]
            computed_root = _rfc6962_root(leaf, idx, tree_size, proof)
            cp_tree_size, cp_root = _verify_checkpoint(
                str(rekor.get("checkpoint", {}).get("envelope", ""))
            )
            if cp_tree_size != tree_size:
                raise ValueError(f"checkpoint tree_size {cp_tree_size} != proof {tree_size}")
            if cp_root != computed_root:
                raise ValueError("inclusion-proof root != verified checkpoint root")
            report.anchors_included += 1
        except Exception as e:  # noqa: BLE001 — any proof defect fails the anchor
            report.errors.append(
                VerifyError(
                    seq=None,
                    kind="inclusion_proof_invalid",
                    detail=f"{label}: {e}",
                )
            )
            report.signatures_valid = False
