# tracelane-audit-verifier (Python)

Reference Python verifier for Tracelane tamper-evident audit ledgers.

Mirrors the Rust verifier (`packages/verifier-rust`) and the TypeScript
verifier (`packages/verifier-typescript`). All three produce identical
`VerifyReport` JSON for the same input — conformance vectors live in
`evals/audit-ledger/`.

## Install

```bash
pip install -e packages/verifier-python
```

## Usage

```python
from pathlib import Path
from tracelane_audit_verifier import verify_ledger, VerifyOptions

report = verify_ledger(Path("audit.ndjson"), VerifyOptions(offline=True))
assert report.hash_chain_valid
```

## Test

```bash
pytest packages/verifier-python
```
