//! Runs the real `crdgen` binary and checks that what it writes is exactly
//! the committed `deploy/crd/` — the same guarantee CI's regen-and-diff
//! gives, caught by `cargo test` already.

use std::path::Path;
use std::process::Command;

#[test]
fn generated_crds_match_the_committed_ones() {
    let out = std::env::temp_dir().join(format!("crdgen-test-{}", std::process::id()));
    let status = Command::new(env!("CARGO_BIN_EXE_crdgen"))
        .arg("--out")
        .arg(&out)
        .status()
        .expect("crdgen runs");
    assert!(status.success());

    let committed = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/crd");
    let mut names: Vec<_> = std::fs::read_dir(&committed)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    names.sort();
    let mut generated: Vec<_> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    generated.sort();
    assert_eq!(generated, names, "set of CRD files differs");
    for name in names {
        let want = std::fs::read_to_string(committed.join(&name)).unwrap();
        let got = std::fs::read_to_string(out.join(&name)).unwrap();
        assert_eq!(got, want, "{name:?} is stale: run `task recu`");
    }
    std::fs::remove_dir_all(&out).unwrap();
}
