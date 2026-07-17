//! Wasm plugin sandbox for untrusted third-party provider extensions.
//!
//! (Wasm sandbox security model). A `WasmPluginAdapter` wraps a `.wasm`
//! binary compiled against the `tracelane-provider-abi` component interface
//! and exposes it as a standard `ProviderAdapter`.
//!
//!   - No network access from within the Wasm module (WASI `wasi:sockets` not
//!     offered; all HTTP calls go through the host's `reqwest` client after
//!     the module returns the request descriptor).
//!   - Memory cap: 64 MiB per plugin instance.
//!   - Fuel limit: 10^9 Cranelift instructions per call (~1 second of work).
//!   - No filesystem access (WASI preview2 `wasi:filesystem` not offered).
//!   - `tenant_id` is injected by the host; the plugin never reads it from
//!     the environment (it has no environment access at all).
//!
//! Compile gate: this module is only compiled when the `wasm-plugin` Cargo
//! feature is enabled (`cargo build --features wasm-plugin`). The default
//! gateway binary does not include wasmtime, keeping the binary ~15 MB
//! smaller for the common deployment path.

#![cfg(feature = "wasm-plugin")]

use anyhow::{Context as _, Result, bail};
use std::path::Path;
use std::sync::Arc;
use tracing::instrument;
use wasmtime::{Config, Engine, Linker, Module, ResourceLimiter, Store};

use tracelane_shared::{ChatRequest, TenantId};

use super::{ProviderAdapter, ProviderStream};

/// Maximum Wasm memory: 64 MiB (1024 × 64 KiB pages).
const MAX_MEMORY_PAGES: u64 = 1_024;

/// Cranelift fuel limit per call — prevents infinite loops in plugin code.
/// 10^9 ≈ ~1 second of work on a modern CPU.
const FUEL_PER_CALL: u64 = 1_000_000_000;

/// Per-call Store data. Holds the `ResourceLimiter` so it can be referenced
/// by `store.limiter()` without lifetime issues (the limiter must outlive
/// the callback, which requires it to live in the Store's data type).
struct StoreData {
    limiter: MemoryLimiter,
}

impl StoreData {
    fn new() -> Self {
        Self {
            limiter: MemoryLimiter,
        }
    }
}

/// Enforces the 64 MiB memory cap per Wasm plugin instance.
struct MemoryLimiter;

impl ResourceLimiter for MemoryLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool> {
        let cap = (MAX_MEMORY_PAGES * 65_536) as usize;
        Ok(desired <= cap)
    }

    fn table_growing(
        &mut self,
        _current: u32,
        _desired: u32,
        _maximum: Option<u32>,
    ) -> Result<bool> {
        Ok(true)
    }
}

/// A compiled Wasm module loaded from a `.wasm` file on disk.
///
/// `WasmPlugin` is the loaded-and-compiled artefact. One `WasmPlugin`
/// maps to one `.wasm` file; it is cloned cheaply (Arc-backed engine).
#[derive(Clone)]
pub struct WasmPlugin {
    engine: Engine,
    module: Arc<Module>,
    provider_id: String,
}

impl WasmPlugin {
    /// Load and AOT-compile a Wasm module from `path`.
    ///
    /// Compilation happens once at startup; subsequent calls to `chat()`
    /// instantiate the pre-compiled module without recompiling.
    pub fn load(path: &Path, provider_id: impl Into<String>) -> Result<Self> {
        let mut config = Config::new();
        config
            .async_support(true)
            .consume_fuel(true)
            .wasm_component_model(true)
            .max_wasm_stack(512 * 1024);

        let engine = Engine::new(&config).context("wasmtime Engine::new")?;
        let bytes =
            std::fs::read(path).with_context(|| format!("read wasm plugin: {}", path.display()))?;
        let module = Module::from_binary(&engine, &bytes).context("compile wasm module")?;

        Ok(Self {
            engine,
            module: Arc::new(module),
            provider_id: provider_id.into(),
        })
    }
}

/// Axum / gateway integration: wraps a `WasmPlugin` as a `ProviderAdapter`.
///
/// Each `chat()` call instantiates the module in a fresh `Store` with an
/// independent fuel budget and memory limit. No state persists between calls.
pub struct WasmPluginAdapter {
    plugin: WasmPlugin,
}

impl WasmPluginAdapter {
    pub fn new(plugin: WasmPlugin) -> Self {
        Self { plugin }
    }
}

impl ProviderAdapter for WasmPluginAdapter {
    fn provider_id(&self) -> &'static str {
        // SAFETY: provider_id is set at plugin load time and lives for
        // the process lifetime (leaked intentionally here for &'static str).
        Box::leak(self.plugin.provider_id.clone().into_boxed_str())
    }

    #[instrument(skip(self, request, _api_key), fields(tenant_id = %tenant_id))]
    fn chat(
        &self,
        request: ChatRequest,
        _api_key: &str,
        tenant_id: &TenantId,
    ) -> impl std::future::Future<Output = Result<ProviderStream>> + Send {
        let plugin = self.plugin.clone();
        let tenant_id = tenant_id.clone();
        let _request = request;

        async move {
            // Each call gets a fresh store with isolated memory + fuel.
            // StoreData holds the ResourceLimiter so it outlives the limiter callback.
            let mut store: Store<StoreData> = Store::new(&plugin.engine, StoreData::new());
            store.set_fuel(FUEL_PER_CALL).context("set_fuel")?;
            store.limiter(|data| &mut data.limiter as &mut dyn ResourceLimiter);

            let mut linker: Linker<StoreData> = Linker::new(&plugin.engine);
            link_host_functions(&mut linker).context("link host functions")?;

            let _instance = linker
                .instantiate_async(&mut store, &plugin.module)
                .await
                .context("instantiate wasm plugin")?;

            // TODO (Week 7): call the component-model `chat` export, serialize
            // ChatRequest as WIT value, drive the streaming response back
            // through a ProviderStream. This scaffold wires the sandbox;
            // the ABI surface is defined in `spec/provider-abi.wit`.
            bail!(
                "wasm-plugin: provider '{}' ABI not yet wired (Week 7)",
                tenant_id
            );
        }
    }
}

/// Register the host-side imports the provider ABI expects.
///
/// The ABI offers exactly one import group: `tracelane:host/http` — a
/// controlled HTTP call that routes through the gateway's reqwest client
/// (with SSRF protection). No raw socket access is offered.
fn link_host_functions(linker: &mut Linker<StoreData>) -> Result<()> {
    // tracelane:host/http.fetch — placeholder; full impl in Week 7.
    linker
        .func_wrap(
            "tracelane:host/http",
            "fetch",
            |_caller: wasmtime::Caller<'_, StoreData>, _ptr: i32, _len: i32| -> i32 {
                // Returns error code 1 (not-implemented) until ABI is wired.
                1_i32
            },
        )
        .context("link tracelane:host/http#fetch")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_sane() {
        assert_eq!(MAX_MEMORY_PAGES * 65_536, 64 * 1024 * 1024);
        // Compile-time check: clippy::assertions_on_constants (stable ≥1.95)
        // rejects a runtime `assert!` on a const-evaluable expression.
        const { assert!(FUEL_PER_CALL >= 1_000_000) };
    }

    #[test]
    fn wasm_plugin_load_rejects_missing_file() {
        let result = WasmPlugin::load(Path::new("/nonexistent/plugin.wasm"), "test");
        assert!(result.is_err());
    }
}
