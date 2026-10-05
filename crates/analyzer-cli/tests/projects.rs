use std::{
    path::Path,
    process::{Command, Output},
};
fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_easy-analyzer"))
        .env("EASY_ANALYZER_DATA_DIR", root.join("catalog"))
        .current_dir(root)
        .args(args)
        .output()
        .unwrap()
}
fn ok(root: &Path, args: &[&str]) -> serde_json::Value {
    let output = run(root, args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
#[test]
fn cli_projects_create_append_note_edit_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("input.log"), "contact a.example.com\n").unwrap();
    let created = ok(
        root,
        &[
            "project",
            "create",
            "a.eair",
            "--name",
            "合成甲项目",
            "--client",
            "合成单位",
        ],
    );
    let id = created["info"]["id"].clone();
    let imported = ok(
        root,
        &[
            "project",
            "import",
            "a.eair",
            "input.log",
            "--ioc-value",
            "example.com",
            "--output",
            "json",
        ],
    );
    let record = imported["records"][0]["id"].as_str().unwrap();
    assert_eq!(imported["records"].as_array().unwrap().len(), 1);
    assert!(!imported["findings"].as_array().unwrap().is_empty());
    ok(
        root,
        &[
            "project",
            "note",
            "a.eair",
            "--record",
            record,
            "--text",
            "合成备注",
        ],
    );
    assert_eq!(
        ok(root, &["project", "note", "a.eair", "--record", record]),
        "合成备注"
    );
    let edited = ok(
        root,
        &[
            "project",
            "edit",
            "a.eair",
            "--name",
            "合成乙项目",
            "--response-start",
            "2026-10-04T09:00:00+08:00",
        ],
    );
    assert_eq!(edited["info"]["id"], id);
    std::fs::remove_file(root.join("input.log")).unwrap();
    let reopened = ok(root, &["project", "open", "a.eair", "--output", "json"]);
    assert_eq!(reopened["records"].as_array().unwrap().len(), 1);
    let list = ok(
        root,
        &[
            "project",
            "list",
            "--search",
            "合成乙",
            "--from",
            "2026-10-04",
            "--until",
            "2026-10-04",
        ],
    );
    assert_eq!(list.as_array().unwrap().len(), 1);
    let direct = ok(
        root,
        &["analyze", "--project", "a.eair", "--output", "json"],
    );
    assert_eq!(direct["records"], reopened["records"]);
}
#[test]
fn saving_new_project_requires_metadata_and_protects_all_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("input.log"), "visit 192.0.2.1\n").unwrap();
    std::fs::write(root.join("ioc.txt"), "192.0.2.1").unwrap();
    assert!(
        !run(root, &["analyze", "input.log", "--save-project", "a.eair"])
            .status
            .success()
    );
    let report = ok(
        root,
        &[
            "analyze",
            "input.log",
            "--save-project",
            "a.eair",
            "--project-name",
            "合成项目",
            "--client",
            "合成客户",
            "--ioc",
            "ioc.txt",
            "--ioc-value",
            "2001:db8::1",
            "--output",
            "json",
        ],
    );
    assert_eq!(report["records"].as_array().unwrap().len(), 1);
    assert!(root.join("a.eair").exists());
    let original = std::fs::read(root.join("ioc.txt")).unwrap();
    assert!(
        !run(
            root,
            &[
                "analyze",
                "input.log",
                "--ioc",
                "ioc.txt",
                "--json-out",
                "ioc.txt"
            ]
        )
        .status
        .success()
    );
    assert_eq!(original, std::fs::read(root.join("ioc.txt")).unwrap());
    assert!(!run(root, &["analyze", "-", "--ioc-stdin"]).status.success());
}
