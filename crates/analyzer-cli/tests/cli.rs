use std::{
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};
fn exe() -> Command {
    Command::new(env!("CARGO_BIN_EXE_easy-analyzer"))
}
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}
#[test]
fn mixed_routing_and_three_outputs() {
    let dir = tempfile::tempdir().unwrap();
    let json = dir.path().join("result.json");
    let html = dir.path().join("result.html");
    let out = exe()
        .arg("analyze")
        .args([
            fixture("auth.log"),
            fixture("processes.json"),
            fixture("sample.pcap"),
        ])
        .arg("--json-out")
        .arg(&json)
        .arg("--html-out")
        .arg(&html)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(json).unwrap()).unwrap();
    assert_eq!(report["records"].as_array().unwrap().len(), 11);
    assert_eq!(report["sources"].as_array().unwrap().len(), 3);
    let html = std::fs::read_to_string(html).unwrap();
    assert!(html.contains("进程关系"));
    assert!(html.contains("网络会话"));
    assert!(String::from_utf8_lossy(&out.stdout).contains("Findings"));
}
#[test]
fn stdin_and_json_stdout() {
    let mut cmd = exe();
    let mut child = cmd
        .args(["logs", "-", "--format", "text", "--output", "json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"2026-09-30T02:00:00Z demo sshd: Failed password for demo from 192.0.2.10 port 50000\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["records"].as_array().unwrap().len(), 1);
}
#[test]
fn malformed_source_reports_failure_but_retains_good_evidence() {
    let out = exe()
        .arg("analyze")
        .args([fixture("auth.log"), fixture("malformed.evtx")])
        .args(["--output", "json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let r: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["records"].as_array().unwrap().len(), 7);
    assert!(!r["diagnostics"].as_array().unwrap().is_empty());
}
#[test]
fn outputs_cannot_overwrite_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("auth.log");
    std::fs::copy(fixture("auth.log"), &input).unwrap();
    let before = std::fs::read(&input).unwrap();
    let out = exe()
        .arg("logs")
        .arg(&input)
        .arg("--out")
        .arg(&input)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(std::fs::read(input).unwrap(), before);
}
#[test]
fn config_creation_does_not_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let first = exe()
        .arg("--config")
        .arg(&config)
        .args(["config", "init"])
        .output()
        .unwrap();
    assert!(first.status.success());
    let before = std::fs::read(&config).unwrap();
    assert!(
        !exe()
            .arg("--config")
            .arg(&config)
            .args(["config", "init"])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(std::fs::read(config).unwrap(), before);
}
#[test]
fn explicit_queries_and_suspicious_mode() {
    let out = exe()
        .arg("logs")
        .arg(fixture("access.log"))
        .args(["--suspicious", "--output", "json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["query_matches"].as_array().unwrap().len(), 1);
}
