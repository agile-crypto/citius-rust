//! The headers are read in place from citius-c-api (see build.rs). This test
//! fails when that checkout is not at the revision in HEADERS_PIN, or when the
//! headers have uncommitted changes, so the library is never silently built
//! against a contract nobody agreed on.

use std::path::Path;
use std::process::Command;

const C_API_DIR: &str = "../citius-c-api";

fn git(args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(C_API_DIR)
        .args(args)
        .output()
        .expect("git must be installed to check the header pin");
    assert!(out.status.success(), "git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

#[test]
fn headers_match_pinned_revision() {
    if std::env::var_os("AGC_INCLUDE_DIR").is_some() {
        eprintln!("AGC_INCLUDE_DIR is set: headers come from elsewhere, pin not checked");
        return;
    }
    let pin = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("HEADERS_PIN")).unwrap();
    assert_eq!(git(&["rev-parse", "HEAD"]), pin.trim(), "citius-c-api is not at the revision in HEADERS_PIN");
    assert_eq!(git(&["status", "--porcelain", "--", "include/agc"]), "", "citius-c-api headers have uncommitted changes");
}
