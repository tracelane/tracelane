# Llama Prompt Guard 2 22M ONNX Export

Reproducible pipeline that exports Meta Llama Prompt Guard 2 22M to INT8 ONNX
for in-process inference in the Rust gateway via the [`ort`](https://docs.rs/ort) crate.

## Setup

```bash
pip install "optimum[onnxruntime]" transformers
export HF_TOKEN=<HuggingFace token with read access to meta-llama/Llama-Prompt-Guard-2-22M>
python export.py
```

PowerShell variant:

```powershell
pip install "optimum[onnxruntime]" transformers
$env:HF_TOKEN = "<token>"
python export.py
```

## Output

`llama-prompt-guard-2-22m-int8.onnx` (~25 MB). The intermediate `fp32/` directory
holds the unquantized export — safe to delete after regenerating `SHA256SUMS`.

Both the `.onnx` file and the `fp32/` directory are gitignored (see repo
`.gitignore` `ml/**/*.onnx` and `ml/prompt_guard_export/fp32/`).

## Verification

The gateway loads the model and verifies its SHA-256 against `SHA256SUMS` at
startup. Mismatch → build fail (CI hook to be added in `crates/gateway/src/predictive/prompt_guard.rs`
once the inference module lands).

After running `export.py`, regenerate the pin:

```bash
sha256sum llama-prompt-guard-2-22m-int8.onnx > SHA256SUMS
```

PowerShell:

```powershell
(Get-FileHash llama-prompt-guard-2-22m-int8.onnx -Algorithm SHA256).Hash.ToLower() + "  llama-prompt-guard-2-22m-int8.onnx" `
  | Set-Content -Encoding utf8 SHA256SUMS
```

Commit only `SHA256SUMS`, not the binary.

## License

Llama Prompt Guard 2 is distributed under the **Llama Community License**.
Verify the terms at https://www.llama.com/llama3/license/ before V1 ship —
documented separately in `LICENSE-PROMPT-GUARD-2.md` (founder to add).
