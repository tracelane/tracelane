//! tonic-build code generator for the SPIRE Workload API proto.
//!
//! Generates a client stub (always) and a server stub (only in test /
//! debug builds, used by the in-process mock SPIRE harness). Output lands
//! in `OUT_DIR/spiffe_workload_api.rs` and is included from
//! `src/spire_proto.rs` via `tonic::include_proto!`.
//!
//! Uses a vendored `protoc` binary so CI containers without system
//! protobuf-compiler still build successfully.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Point tonic-build at the vendored protoc binary if the system one
    // isn't already set. Honour an externally-provided PROTOC so Wolfi
    // containers (which ship their own) work unchanged.
    if std::env::var_os("PROTOC").is_none() {
        let p = protoc_bin_vendored::protoc_bin_path()?;
        // SAFETY: build scripts run single-threaded before any user code.
        unsafe {
            std::env::set_var("PROTOC", p);
        }
    }

    // Build the gRPC server stub ONLY in non-release builds. Cargo
    // exposes the target crate's profile to build scripts via the
    // PROFILE env var (contractually documented, unlike
    // `cfg!(debug_assertions)` inside a build script — see Cargo
    // reference §3.10.4). The server stub is only ever instantiated
    // from `spire_mock.rs` which is `#[cfg(test)]`; gating at codegen
    // time keeps even the type definitions out of release binaries.
    // The server stub is only instantiated from `spire_mock.rs` (`#[cfg(test)]`).
    // It is kept out of production release binaries, BUT `cargo bench` uses the
    // release-derived bench profile (PROFILE=release) while still compiling the
    // bin's `#[cfg(test)]` modules — so a bench build needs the server stub even
    // though PROFILE says "release". The opt-in `INGEST_BUILD_SERVER=1` (set by
    // the `bench:ingest` script) re-enables codegen for that case; the tonic
    // `server` feature is present whenever dev-deps are (test + bench builds).
    println!("cargo:rerun-if-env-changed=INGEST_BUILD_SERVER");
    let build_server = std::env::var("PROFILE").as_deref() != Ok("release")
        || std::env::var("INGEST_BUILD_SERVER").is_ok();

    tonic_build::configure()
        .build_client(true)
        .build_server(build_server)
        .compile_protos(&["proto/workload.proto"], &["proto"])?;
    Ok(())
}
