//! The CLI's control map cites `file:line` anchors into this crate. This test
//! lives here so that moving a cited line fails this crate's own tests.
use std::path::Path;

#[test]
fn control_map_anchors_still_name_their_source_lines() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let map = root.join("crates/tracelane-audit-cli/evidence/control-map.json");
    let map = std::fs::read_to_string(&map).expect("control map is part of this repository");
    let map: serde_json::Value = serde_json::from_str(&map).unwrap();
    let mut checked = 0;
    for control in map["controls"].as_array().unwrap() {
        let Some(anchor) = control["anchor"].as_str() else {
            continue;
        };
        let (file, line) = anchor.rsplit_once(':').unwrap();
        let source = std::fs::read_to_string(root.join(file)).unwrap();
        let text = source.lines().nth(line.parse::<usize>().unwrap() - 1);
        let want = control["anchor_text"].as_str().unwrap();
        assert!(
            text.is_some_and(|t| t.contains(want)),
            "{anchor} no longer holds {want:?}; update control-map.json (found {text:?})"
        );
        checked += 1;
    }
    assert!(checked >= 8, "only {checked} anchors checked");
}
