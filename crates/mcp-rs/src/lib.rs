//! Tracelane MCP-RS — Rust-native MCP gateway integration.
//!
//! Handles MCP tool-description hash watching (rug-pull detection) and
//! MCP server discovery within the gateway hot path. The read-only MCP
//! server for external LLM access is in `apps/mcp/` (TypeScript).
//!
//! Full implementation: Week 7 (hash watcher wired to live MCP connections).
