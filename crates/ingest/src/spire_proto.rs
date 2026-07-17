//! Generated tonic stubs for the SPIRE Workload API.
//!
//! The actual code is produced at build time by `tonic-build` (see `build.rs`)
//! and included here via `tonic::include_proto!`. Wrapping the macro in a
//! dedicated module keeps clippy lint suppressions tightly scoped.

#![allow(
    clippy::derive_partial_eq_without_eq,
    clippy::large_enum_variant,
    clippy::doc_markdown,
    missing_docs
)]

// No proto `package` (see proto/workload.proto) → prost emits the root module as
// `_.rs`, so the include key is "_" (not "spiffe_workload_api").
tonic::include_proto!("_");

#[cfg(test)]
mod proto_guard_tests {
    //! Regression guard for the 2026-06-07 prod bug: a `package` declaration in
    //! `workload.proto` makes tonic call `/SpiffeWorkloadAPI.SpiffeWorkloadAPI/…`,
    //! but the real SPIRE agent serves `/SpiffeWorkloadAPI/…` and rejects the
    //! prefixed path with `Unimplemented: unknown service`. The in-process mock
    //! (`spire_mock.rs`) cannot catch this — it uses the same generated stub on
    //! both client and server — so this source-level guard stands in for the
    //! real-SPIRE integration check until one exists.

    /// The Workload API proto MUST NOT declare a `package` (see module doc).
    #[test]
    fn workload_proto_declares_no_package() {
        let proto = include_str!("../proto/workload.proto");
        let offending: Vec<_> = proto
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("package "))
            .collect();
        assert!(
            offending.is_empty(),
            "workload.proto must not declare a package (real SPIRE serves \
             /SpiffeWorkloadAPI/…, no prefix); found: {offending:?}"
        );
    }
}
