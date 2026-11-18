"""Regenerate synthetic RFC 3161 fixtures offline; requires Python cryptography.
Private keys are ephemeral and never written. Certificates are test fixtures only.
"""

import argparse
import json
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

parser = argparse.ArgumentParser()
parser.add_argument("--output", type=Path, default=Path(__file__).parent)
parser.add_argument("--checkpoint", type=Path)
args = parser.parse_args()
OUT = args.output
OUT.mkdir(parents=True, exist_ok=True)
tenant_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
tenant_pub = tenant_key.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
CHECKPOINT = json.dumps(
    {
        "domain": "tracelane.action-head.v1",
        "schema_version": 1,
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "seq": None,
        "head_hash": None,
        "created_at": "2026-11-13T11:59:00.000Z",
        "key_id": sha256(tenant_pub).hexdigest(),
        "previous_checkpoint_digest": None,
    },
    sort_keys=True,
    separators=(",", ":"),
).encode()
if args.checkpoint:
    CHECKPOINT = args.checkpoint.read_bytes()
(OUT / "checkpoint.sig").write_bytes(tenant_key.sign(CHECKPOINT))
(OUT / "tenant.pub").write_text(tenant_pub.hex())


def tlv(tag, data):
    length = len(data)
    return (
        bytes([tag])
        + (
            bytes([length])
            if length < 128
            else bytes([0x80 + (length.bit_length() + 7) // 8])
            + length.to_bytes((length.bit_length() + 7) // 8, "big")
        )
        + data
    )


def seq(*data):
    return tlv(0x30, b"".join(data))


def integer(n):
    b = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    return tlv(2, b"\0" + b if b[0] & 128 else b)


def oid(s):
    ns = list(map(int, s.split(".")))
    out = bytes([40 * ns[0] + ns[1]])
    for n in ns[2:]:
        enc = [n & 127]
        n >>= 7
        while n:
            enc.insert(0, (n & 127) | 128)
            n >>= 7
        out += bytes(enc)
    return tlv(6, out)


def octets(b):
    return tlv(4, b)


def attr(o, v):
    return seq(oid(o), tlv(0x31, v))


SHA = seq(oid("2.16.840.1.101.3.4.2.1"), b"\x05\0")
TST = "1.2.840.113549.1.9.16.1.4"
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name(
    [x509.NameAttribute(NameOID.COMMON_NAME, "SYNTHETIC TEST TSA - NOT FOR PRODUCTION")]
)
for label, eku, expiry in [
    ("good", ExtendedKeyUsageOID.TIME_STAMPING, 2027),
    ("wrong-eku", ExtendedKeyUsageOID.CODE_SIGNING, 2027),
    ("expired", ExtendedKeyUsageOID.TIME_STAMPING, 2025),
    ("key-usage", ExtendedKeyUsageOID.TIME_STAMPING, 2027),
    ("critical-extension", ExtendedKeyUsageOID.TIME_STAMPING, 2027),
    ("fractional-expiry", ExtendedKeyUsageOID.TIME_STAMPING, 2027),
    ("ecdsa", ExtendedKeyUsageOID.TIME_STAMPING, 2027),
]:
    signing_key = ec.generate_private_key(ec.SECP256R1()) if label == "ecdsa" else key
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(signing_key.public_key())
        .serial_number(7)
        .not_valid_before(datetime(2024, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(expiry, 12, 31, tzinfo=timezone.utc))
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=True)
    )
    if label == "key-usage":
        builder = builder.add_extension(
            x509.KeyUsage(False, False, True, False, False, False, False, None, None),
            critical=True,
        )
    if label == "critical-extension":
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.99"), b"\x05\x00"),
            critical=True,
        )
    cert = builder.sign(signing_key, hashes.SHA256())
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    (OUT / (label + ".der")).write_bytes(cert_der)

    def response(mode, label=label, cert_der=cert_der, signing_key=signing_key):
        imprint = sha256(
            CHECKPOINT if mode != "wrong-imprint" else b"other checkpoint"
        ).digest()
        info = seq(
            integer(1),
            oid("1.2.3.4"),
            seq(SHA, octets(imprint)),
            integer(42),
            tlv(
                0x18,
                b"20271231000000.5Z"
                if label == "fractional-expiry"
                else b"20261113120000Z",
            ),
        )
        attrs = [
            attr("1.2.840.113549.1.9.3", oid(TST)),
            attr("1.2.840.113549.1.9.4", octets(sha256(info).digest())),
            attr(
                "1.2.840.113549.1.9.16.2.47",
                seq(
                    seq(
                        seq(
                            octets(
                                sha256(
                                    cert_der if mode != "bad-cert-hash" else b"wrong"
                                ).digest()
                            )
                        )
                    )
                ),
            ),
        ]
        if mode == "missing-attrs":
            attrs = []
        content = b"".join(sorted(attrs))
        signed = tlv(0x31, content)
        signature = (
            signing_key.sign(signed, ec.ECDSA(hashes.SHA256()))
            if label == "ecdsa"
            else signing_key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
        )
        if mode == "bad-signature":
            signature = signature[:-1] + bytes([signature[-1] ^ 1])
        signer = seq(
            integer(1),
            seq(name.public_bytes(), integer(7)),
            SHA,
            tlv(0xA0, content),
            (
                seq(oid("1.2.840.10045.4.3.2"))
                if label == "ecdsa"
                else seq(oid("1.2.840.113549.1.1.1"), b"\x05\0")
            ),
            octets(signature),
        )
        sd = seq(
            integer(3),
            tlv(0x31, SHA),
            seq(oid(TST), tlv(0xA0, octets(info))),
            tlv(0xA0, cert_der),
            tlv(0x31, signer),
        )
        return seq(seq(integer(0)), seq(oid("1.2.840.113549.1.7.2"), tlv(0xA0, sd)))

    (OUT / (label + ".tsr")).write_bytes(response("good"))
    if label == "good":
        for mode in [
            "wrong-imprint",
            "bad-cert-hash",
            "missing-attrs",
            "bad-signature",
        ]:
            (OUT / (mode + ".tsr")).write_bytes(response(mode))
(OUT / "checkpoint.json").write_bytes(CHECKPOINT)
