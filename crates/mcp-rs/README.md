# `crates/mcp-rs`

Rust-native MCP integration for the gateway hot path.

Handles **MCP tool-description hash watching** (rug-pull / tool-definition-drift
detection, PP-PR1) and MCP server discovery from inside the gateway. When a
tool's description hash changes between calls, that is a rug-pull signal the
predictive layer flags.

> Not to be confused with **`apps/mcp/`** — that is the TypeScript *read-only MCP
> server* that exposes Tracelane data to external LLMs. This crate is the
> gateway's MCP-*client*-side watcher.

Status: hash watcher wired to live MCP connections is a Week-7 completion item.
See `../../docs/REPO_MAP.md`.
