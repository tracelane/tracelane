// B-263 falsification fixture. Deliberately empty — see Cargo.toml.
// A manifest with no target fails `cargo metadata` to parse, and cargo-deny would
// then exit non-zero for a PARSE error while never evaluating the ban: a probe
// unable to reach the thing it tests.
