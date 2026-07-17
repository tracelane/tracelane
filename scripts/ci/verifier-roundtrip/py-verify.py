"""Python reference-verifier wrapper for the cross-verifier round-trip (ADR-062).

argv: <ledger.ndjson> <tenant-pubkey-b64|"">
Prints one JSON line: {hash_chain_valid, signatures_valid, anchors_included}.
"""

import base64
import json
import sys
from pathlib import Path

from tracelane_audit_verifier import VerifyOptions, verify_ledger

ledger = sys.argv[1]
pk = sys.argv[2] if len(sys.argv) > 2 else ""
opts = VerifyOptions(tenant_pubkey=base64.b64decode(pk) if pk else None)
r = verify_ledger(Path(ledger), opts)
print(
    json.dumps(
        {
            "hash_chain_valid": r.hash_chain_valid,
            "signatures_valid": r.signatures_valid,
            "anchors_included": r.anchors_included,
        }
    )
)
