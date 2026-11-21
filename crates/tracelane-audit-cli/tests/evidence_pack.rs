//! End-to-end: the `evidence-pack` subcommand against synthetic action bundles.
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracelane_audit_verifier::action::{archive::Files, bundle::seal, canonical_json};

const TENANT: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const MAP: &str = include_str!("../evidence/control-map.json");
const SCHEMA: &str = include_str!("fixtures/oscal_component_schema-1.1.2.json");

fn lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend((bytes.len() as u64).to_be_bytes());
    buf.extend(bytes);
}
/// Synthetic three-row v2.1 ledger with a signed covering head. Not prod data.
fn bundle_files() -> (Files, [u8; 32]) {
    let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let pin: [u8; 32] = key.public_key().as_ref().try_into().unwrap();
    let tenant = uuid::Uuid::from_bytes(TENANT);
    let mut prev: [u8; 32] =
        Sha256::digest([b"tracelane-audit-v2-genesis\0", &TENANT[..]].concat()).into();
    let mut ledger = String::new();
    for seq in 0u64..3 {
        let mut buf = b"tracelane-audit-row-v2\0".to_vec();
        lp(&mut buf, &TENANT);
        buf.extend(seq.to_be_bytes());
        for part in [&b"fixture"[..], b"test", b"{}", &prev] {
            lp(&mut buf, part);
        }
        let hash: [u8; 32] = Sha256::digest(&buf).into();
        let row = json!({"format":"v2.1","tenant_id":tenant,"seq":seq,"event_time":"2026-10-30T12:00:00Z","event_type":"fixture","actor":"test","payload":"{}","prev_hash":hex::encode(prev),"row_hash":hex::encode(hash)});
        ledger.push_str(&format!("{row}\n"));
        prev = hash;
    }
    let head = canonical_json(&json!({"domain":"tracelane.action-head.v1","schema_version":1,"tenant_id":tenant,"seq":"2","head_hash":hex::encode(prev),"created_at":"2026-10-30T12:00:00Z","key_id":hex::encode(Sha256::digest(pin)),"previous_checkpoint_digest":null}).to_string()).unwrap();
    let sig = key.sign(head.as_bytes()).as_ref().to_vec();
    let files = [
        ("ledger.ndjson".to_owned(), ledger.into_bytes()),
        ("checkpoint.json".to_owned(), head.into_bytes()),
        ("checkpoint.sig".to_owned(), sig),
    ];
    (files.into(), pin)
}
struct Run {
    out: PathBuf,
    output: Output,
    _dir: tempfile::TempDir,
}
impl Run {
    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.out.join(name)).unwrap()
    }
    fn oscal(&self) -> Value {
        serde_json::from_str(&self.read("oscal-component-definition.json")).unwrap()
    }
    fn refused(&self, code: i32, why: &str) {
        let stderr = String::from_utf8_lossy(&self.output.stderr);
        assert_eq!(self.output.status.code(), Some(code), "{stderr}");
        assert!(stderr.contains(why), "{stderr}");
        assert!(!self.out.exists(), "a refused run must write no pack");
    }
}
fn run_with(files: Files, pin: Option<[u8; 32]>, prepare: impl FnOnce(&Path)) -> Run {
    let dir = tempfile::tempdir().unwrap();
    let (zip, out) = (dir.path().join("bundle.zip"), dir.path().join("pack"));
    std::fs::write(&zip, seal(files).unwrap()).unwrap();
    prepare(&out);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tracelane-audit"));
    cmd.arg("evidence-pack").arg("--file").arg(&zip);
    cmd.arg("--out").arg(&out);
    if let Some(pin) = pin {
        let key = dir.path().join("tenant.pub");
        std::fs::write(&key, hex::encode(pin)).unwrap();
        cmd.arg("--pubkey").arg(key);
    }
    let output = cmd.output().unwrap();
    Run {
        out,
        output,
        _dir: dir,
    }
}
fn good() -> Run {
    let (files, pin) = bundle_files();
    let run = run_with(files, Some(pin), |_| {});
    let stderr = String::from_utf8_lossy(&run.output.stderr);
    assert_eq!(run.output.status.code(), Some(0), "{stderr}");
    run
}
fn map() -> Value {
    serde_json::from_str(MAP).unwrap()
}
fn schema_errors(instance: &Value) -> Option<String> {
    let mut schemas = boon::Schemas::new();
    let mut compiler = boon::Compiler::new();
    let mut schema: Value = serde_json::from_str(SCHEMA).unwrap();
    assert!(schema["$id"].as_str().unwrap().contains("/oscal/1.1.2/"));
    // The NIST file is vendored byte-for-byte. Some of its definitions put `$id`
    // beside `$ref`; draft-07 ignores siblings of `$ref`, so a strict validator
    // cannot resolve those anchors. Wrap each such `$ref` in `allOf` in memory,
    // which keeps the `$id` live and constrains exactly the same.
    fn keep_anchors(node: &mut Value) {
        match node {
            Value::Object(map) => {
                if map.contains_key("$id") && map.contains_key("$ref") {
                    let target = map.remove("$ref").unwrap();
                    map.insert("allOf".into(), json!([{ "$ref": target }]));
                }
                map.values_mut().for_each(keep_anchors);
            }
            Value::Array(items) => items.iter_mut().for_each(keep_anchors),
            _ => {}
        }
    }
    keep_anchors(&mut schema["definitions"]);
    compiler.add_resource("oscal.json", schema).unwrap();
    let index = compiler.compile("oscal.json", &mut schemas).unwrap();
    schemas
        .validate(instance, index)
        .err()
        .map(|e| e.to_string())
}

#[test]
fn pack_writes_exactly_three_files() {
    let run = good();
    let mut names: Vec<_> = std::fs::read_dir(&run.out)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "controls.csv",
            "oscal-component-definition.json",
            "summary.html"
        ]
    );
}
#[test]
fn oscal_validates_against_pinned_schema() {
    let oscal = good().oscal();
    assert_eq!(schema_errors(&oscal), None);
    let definition = &oscal["component-definition"];
    assert_eq!(definition["metadata"]["oscal-version"], "1.1.2");
    let rows: usize = definition["components"][0]["control-implementations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["implemented-requirements"].as_array().unwrap().len())
        .sum();
    assert_eq!(rows, map()["controls"].as_array().unwrap().len());
}
#[test]
fn schema_rejects_a_broken_oscal_document() {
    // Proves the validator blocks: a missing required field and a bad token both fail.
    let mut missing = good().oscal();
    let metadata = missing["component-definition"]["metadata"].as_object_mut();
    metadata.unwrap().remove("oscal-version");
    assert!(schema_errors(&missing).is_some());
    let mut bad_token = good().oscal();
    bad_token["component-definition"]["components"][0]["control-implementations"][0]["implemented-requirements"]
        [0]["control-id"] = json!("Art. 12(1)");
    assert!(schema_errors(&bad_token).is_some());
}
#[test]
fn csv_has_one_row_per_control_and_per_limit() {
    let csv = good().read("controls.csv");
    let (controls, limits) = (map()["controls"].clone(), map()["limits"].clone());
    let (controls, limits) = (
        controls.as_array().unwrap().len(),
        limits.as_array().unwrap().len(),
    );
    assert_eq!(csv.matches("\r\n").count(), 1 + controls + limits);
    assert!(csv.starts_with("\"framework\",\"framework_title\",\"control_id\",\"status\""));
    assert!(
        csv.lines()
            .next()
            .unwrap()
            .ends_with(",\"gap\",\"records_in_bundle\"")
    );
    assert!(csv.contains("\"Art. 12(2)(a)\",\"partial\""), "{csv}");
    assert!(csv.contains("\"pack\",\"Limits of this pack\",\"limit-2\",\"not covered\""));
}
#[test]
fn html_lists_the_verifier_report_numbers() {
    let run = good();
    let html = run.read("summary.html");
    let head = bundle_files().0["checkpoint.json"].clone();
    let head: Value = serde_json::from_slice(&head).unwrap();
    assert!(
        html.contains("<th>Ledger rows verified</th><td>3</td>"),
        "{html}"
    );
    assert!(html.contains("<th>Signed head sequence</th><td>2</td>"));
    assert!(html.contains(head["head_hash"].as_str().unwrap()));
    assert!(html.contains("00000000-0000-0000-0000-000000000001"));
    assert!(html.contains("no (the bundle carries no timestamp)"));
    let props = run.oscal()["component-definition"]["components"][0]["props"].clone();
    assert!(
        props
            .as_array()
            .unwrap()
            .contains(&json!({"name":"rows","ns":"https://tracelane.dev/ns/oscal","value":"3"}))
    );
}
#[test]
fn every_output_lists_every_gap() {
    let run = good();
    let escape = |s: &str| s.replace('&', "&amp;").replace('"', "&quot;");
    let (csv, html) = (run.read("controls.csv"), run.read("summary.html"));
    let oscal = run.oscal().to_string();
    let json_text = |s: &str| serde_json::to_string(s).unwrap();
    let map = map();
    let gaps = map["controls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| &c["gap"]);
    for text in map["limits"].as_array().unwrap().iter().chain(gaps) {
        let text = text.as_str().unwrap();
        assert!(csv.contains(&text.replace('"', "\"\"")), "csv: {text}");
        assert!(html.contains(&escape(text)), "html: {text}");
        let inner = json_text(text);
        assert!(oscal.contains(&inner[1..inner.len() - 1]), "oscal: {text}");
    }
    assert!(
        html.contains("A single row's hash can be checked alone against the signed tree root when")
    );
    assert!(html.contains("No signed scope attestation"));
}
#[test]
fn pack_never_claims() {
    let run = good();
    for name in [
        "controls.csv",
        "oscal-component-definition.json",
        "summary.html",
    ] {
        let text = run.read(name).to_lowercase();
        let words: Vec<&str> = text.split(|c: char| !c.is_alphanumeric()).collect();
        for banned in [
            "compliant",
            "complete",
            "immutable",
            "certified",
            "conformant",
        ] {
            assert!(!words.contains(&banned), "{name} says {banned}");
        }
        assert!(!text.contains("tamper-proof"), "{name}");
        assert!(text.contains("not an assessment"), "{name}");
    }
}
#[test]
fn output_is_deterministic() {
    let (a, b) = (good(), good());
    for name in [
        "controls.csv",
        "oscal-component-definition.json",
        "summary.html",
    ] {
        assert_eq!(a.read(name), b.read(name), "{name}");
    }
}
#[test]
fn anchors_resolve_to_the_named_source_line() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut checked = 0;
    for control in map()["controls"].as_array().unwrap() {
        let Some(anchor) = control["anchor"].as_str() else {
            assert_eq!(control["status"], "not covered");
            continue;
        };
        let (file, line) = anchor.rsplit_once(':').unwrap();
        let source = std::fs::read_to_string(root.join(file)).unwrap();
        let text = source.lines().nth(line.parse::<usize>().unwrap() - 1);
        let want = control["anchor_text"].as_str().unwrap();
        assert!(text.is_some_and(|t| t.contains(want)), "{anchor}: {text:?}");
        checked += 1;
    }
    assert!(checked >= 8, "only {checked} anchors checked");
}
#[test]
fn csv_rows_match_the_map_statuses() {
    let csv = good().read("controls.csv");
    for control in map()["controls"].as_array().unwrap() {
        let cell = |k: &str| format!("\"{}\"", control[k].as_str().unwrap());
        let want = format!("{},{},", cell("control_id"), cell("status"));
        assert!(csv.contains(&want), "{want}");
    }
}

#[test]
fn tampered_bundle_produces_no_pack() {
    let (mut files, pin) = bundle_files();
    let ledger = String::from_utf8(files["ledger.ndjson"].clone()).unwrap();
    let mut rows: Vec<&str> = ledger.lines().collect();
    rows.remove(1);
    files.insert(
        "ledger.ndjson".into(),
        format!("{}\n", rows.join("\n")).into_bytes(),
    );
    run_with(files, Some(pin), |_| {}).refused(4, "previous hash mismatch at 1");
}
#[test]
fn wrong_key_produces_no_pack() {
    let (files, _) = bundle_files();
    run_with(files, Some([9; 32]), |_| {}).refused(5, "does not verify under external pin");
}
#[test]
fn missing_pubkey_produces_no_pack() {
    let (files, _) = bundle_files();
    run_with(files, None, |_| {}).refused(5, "external --pubkey file required");
}
#[test]
fn stripped_checkpoint_signature_produces_no_pack() {
    let (mut files, pin) = bundle_files();
    files.remove("checkpoint.sig");
    run_with(files, Some(pin), |_| {}).refused(4, "missing checkpoint.sig");
}
#[cfg(unix)]
#[test]
fn symlink_in_out_dir_is_refused_and_its_target_untouched() {
    let (files, pin) = bundle_files();
    let run = run_with(files, Some(pin), |out| {
        std::fs::create_dir(out).unwrap();
        let target = out.parent().unwrap().join("victim");
        std::fs::write(&target, "keep").unwrap();
        std::os::unix::fs::symlink(&target, out.join("controls.csv")).unwrap();
    });
    assert_eq!(run.output.status.code(), Some(2));
    let victim = run.out.parent().unwrap().join("victim");
    assert_eq!(std::fs::read_to_string(victim).unwrap(), "keep");
    assert!(!run.out.join("summary.html").exists());
}
#[test]
fn non_empty_out_dir_is_refused_and_left_untouched() {
    let (files, pin) = bundle_files();
    let run = run_with(files, Some(pin), |out| {
        std::fs::create_dir(out).unwrap();
        std::fs::write(out.join("summary.html"), "stale").unwrap();
    });
    assert_eq!(run.output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&run.output.stderr);
    assert!(stderr.contains("new or empty directory"), "{stderr}");
    assert_eq!(run.read("summary.html"), "stale");
    assert!(!run.out.join("controls.csv").exists());
}

// Ordinary synthetic policy fixtures, never a downloaded or production bundle.
fn tree_policy_fixture(state: &str) -> (Files, [u8; 32]) {
    use tracelane_audit_verifier::action::tree;
    let (mut files, pin) = bundle_files();
    if state != "absent" {
        let seed = if state == "wrong signer" { 8 } else { 7 };
        let key = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
        let public: [u8; 32] = key.public_key().as_ref().try_into().unwrap();
        let tenant = if state == "wrong tenant" { 2 } else { 1 };
        let origin = tree::origin(uuid::Uuid::from_u128(tenant));
        let mut leaves = tree::ledger_leaves(&files["ledger.ndjson"]).unwrap();
        if state == "wrong size" {
            leaves.pop();
        }
        let body = tree::checkpoint_body(&origin, leaves.len() as u64, &tree::root(&leaves));
        let note = if state == "malformed" {
            "synthetic malformed note".to_owned()
        } else {
            tree::signed_note(&body, &origin, &public, key.sign(body.as_bytes()).as_ref())
        };
        files.insert(tree::MEMBER.into(), note.into_bytes());
    }
    (files, pin)
}

fn run_tree_policy(command: &str, required: bool, state: &str, pin_state: &str) -> Run {
    let (files, pin) = tree_policy_fixture(state);
    let dir = tempfile::tempdir().unwrap();
    let (zip, out) = (dir.path().join("synthetic.zip"), dir.path().join("pack"));
    std::fs::write(&zip, seal(files).unwrap()).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tracelane-audit"));
    cmd.arg(command).arg("--file").arg(zip);
    if command == "evidence-pack" {
        cmd.arg("--out").arg(&out);
    }
    if required {
        cmd.arg("--require-tree");
    }
    if pin_state != "missing" {
        let path = dir.path().join("pin.pub");
        let pin = if pin_state == "wrong" { [8; 32] } else { pin };
        std::fs::write(&path, hex::encode(pin)).unwrap();
        cmd.arg("--pubkey").arg(path);
    }
    Run {
        out,
        output: cmd.output().unwrap(),
        _dir: dir,
    }
}

#[test]
fn require_tree_verify_refuses_synthetic_absence() {
    run_tree_policy("verify", true, "absent", "right")
        .refused(4, "required tree checkpoint is absent");
}

#[test]
fn require_tree_pack_refuses_synthetic_absence_without_output() {
    run_tree_policy("evidence-pack", true, "absent", "right")
        .refused(4, "required tree checkpoint is absent");
}

#[test]
fn require_tree_policy_invariant_sweep() {
    let mut scenarios = 0;
    for command in ["verify", "evidence-pack"] {
        for required in [false, true] {
            for state in [
                "absent",
                "valid",
                "wrong signer",
                "wrong tenant",
                "wrong size",
                "malformed",
            ] {
                for pin in ["right", "wrong", "missing"] {
                    scenarios += 1;
                    let run = run_tree_policy(command, required, state, pin);
                    let accepted =
                        pin == "right" && (state == "valid" || (state == "absent" && !required));
                    assert_eq!(
                        run.output.status.success(),
                        accepted,
                        "command={command}, required={required}, state={state}, pin={pin}: {}",
                        String::from_utf8_lossy(&run.output.stderr)
                    );
                    if accepted {
                        let stdout = String::from_utf8_lossy(&run.output.stdout);
                        assert!(stdout.contains(if state == "absent" {
                            "tree checkpoint: absent"
                        } else {
                            "tree checkpoint: size 3 root"
                        }));
                    } else {
                        assert!(!run.out.exists(), "no pack on refusal");
                        assert!(
                            matches!(run.output.status.code(), Some(4 | 5)),
                            "verification refusal, not parser failure"
                        );
                    }
                }
            }
        }
    }
    assert_eq!(scenarios, 72);
}

#[test]
fn require_tree_rejects_online_mode_without_fetching() {
    let output = Command::new(env!("CARGO_BIN_EXE_tracelane-audit"))
        .args(["verify", "--require-tree"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("require --file"));
}

#[test]
fn require_tree_rejects_non_zip_input() {
    let input = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(input.path(), "{}\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_tracelane-audit"))
        .args(["verify", "--require-tree", "--file"])
        .arg(input.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&output.stderr).contains("require an action ZIP"));
}

#[test]
fn require_tree_refusal_preserves_existing_output() {
    let dir = tempfile::tempdir().unwrap();
    let (files, pin) = tree_policy_fixture("absent");
    let zip = dir.path().join("fixture.zip");
    let key = dir.path().join("pin.pub");
    let out = dir.path().join("existing");
    std::fs::write(&zip, seal(files).unwrap()).unwrap();
    std::fs::write(&key, hex::encode(pin)).unwrap();
    std::fs::create_dir(&out).unwrap();
    std::fs::write(out.join("sentinel.txt"), "existing synthetic output").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_tracelane-audit"))
        .args(["evidence-pack", "--require-tree", "--file"])
        .arg(zip)
        .arg("--pubkey")
        .arg(key)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(
        std::fs::read_to_string(out.join("sentinel.txt")).unwrap(),
        "existing synthetic output"
    );
    assert_eq!(std::fs::read_dir(out).unwrap().count(), 1);
}

#[test]
fn require_tree_json_report_retains_verified_tree_measurements() {
    let dir = tempfile::tempdir().unwrap();
    let (files, pin) = tree_policy_fixture("valid");
    let zip = dir.path().join("fixture.zip");
    let key = dir.path().join("pin.pub");
    std::fs::write(&zip, seal(files).unwrap()).unwrap();
    std::fs::write(&key, hex::encode(pin)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_tracelane-audit"))
        .args(["verify", "--require-tree", "--format", "json", "--file"])
        .arg(zip)
        .arg("--pubkey")
        .arg(key)
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["tree_size"], 3);
    assert_eq!(report["tree_root"].as_str().unwrap().len(), 64);
}

#[test]
fn fixture_bundle_counts_its_rows_and_zero_elsewhere() {
    let run = good();
    let (csv, html) = (run.read("controls.csv"), run.read("summary.html"));
    let cell = |framework: &str, control: &str| -> String {
        let line = csv
            .split("\r\n")
            .find(|l| {
                l.starts_with(&format!("\"{framework}\","))
                    && l.contains(&format!("\"{control}\","))
            })
            .unwrap();
        line.rsplit(',')
            .next()
            .unwrap()
            .trim_matches('"')
            .to_owned()
    };
    assert_eq!(cell("eu-ai-act", "Art. 12(1)"), "3");
    assert_eq!(cell("occ-2026-54", "2.14"), "3");
    assert_eq!(
        cell("occ-2026-54", "2.10"),
        "0",
        "no paused refusals in the fixture"
    );
    assert!(html.contains("3 records in this bundle"));
    assert!(html.contains("0 in this bundle"));
}
#[test]
fn records_column_is_digits_or_empty_and_oscal_prop_matches() {
    let run = good();
    let csv = run.read("controls.csv");
    for line in csv.split("\r\n").skip(1).filter(|l| !l.is_empty()) {
        let last = line.rsplit(',').next().unwrap().trim_matches('"');
        assert!(
            last.chars().all(|c| c.is_ascii_digit()),
            "formula-safe cell: {last}"
        );
    }
    let oscal = run.oscal();
    assert_eq!(schema_errors(&oscal), None);
    let text = oscal.to_string();
    assert!(text.contains(
        r#"{"name":"records-in-bundle","ns":"https://tracelane.dev/ns/oscal","value":"3"}"#
    ));
}
