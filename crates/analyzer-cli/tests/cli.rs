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
fn offline_windows_and_linux_logs_on_current_host() {
    let inputs = [
        "synthetic.evtx",
        "sample.utmp",
        "sample.wtmp",
        "sample.btmp",
        "auth.log",
        "access.log",
    ];
    let out = exe()
        .arg("logs")
        .args(inputs.map(fixture))
        .args(["--output", "json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["sources"].as_array().unwrap().len(), 6);
    let records = report["records"].as_array().unwrap();
    assert_eq!(records.len(), 25);
    assert!(
        records
            .iter()
            .all(|r| !r["raw"].as_str().unwrap().is_empty())
    );
    assert!(records.iter().any(|r| {
        r["data"]["fields"]["fields"]["event_id"] == "4625" && r["status"] == "parsed"
    }));
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| { f["origin"] == "local:login-failures" })
    );
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
    assert!(html.contains("进程父子关系"));
    assert!(html.contains("网络会话"));
    assert!(String::from_utf8_lossy(&out.stdout).contains("分析发现"));
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

fn normalize_report(mut value: serde_json::Value) -> serde_json::Value {
    value.as_object_mut().unwrap().remove("generated_at");
    for source in value["sources"].as_array_mut().unwrap() {
        source.as_object_mut().unwrap().remove("collected_at");
    }
    value
}

#[test]
fn cli_and_shared_service_have_identical_evidence_and_reports() {
    use analyzer_app::{
        AnalysisInput, AnalysisRequest, AnalysisService, ExecutionContext, QueryOptions,
    };
    let paths = [
        fixture("auth.log"),
        fixture("processes.json"),
        fixture("sample.pcap"),
    ];
    let request = AnalysisRequest {
        inputs: paths.iter().cloned().map(AnalysisInput::File).collect(),
        query: Some(QueryOptions {
            expression: Some("failed|powershell|GET".into()),
            regex: true,
            suspicious: true,
        }),
        ..Default::default()
    };
    let service = AnalysisService::execute(&request, &ExecutionContext::default()).unwrap();
    let expected = service
        .session
        .with_report(|r| {
            serde_json::from_str::<serde_json::Value>(&analyzer_app::core::report::json(r).unwrap())
                .unwrap()
        })
        .unwrap();
    let output = exe()
        .arg("analyze")
        .args(&paths)
        .args([
            "-q",
            "failed|powershell|GET",
            "-r",
            "-s",
            "-o",
            "json",
            "-n",
            "5",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(normalize_report(actual), normalize_report(expected));
}

#[test]
fn html_auto_save_preserves_existing_reports_and_stdout() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("report.html"), "original report").unwrap();
    let out = exe()
        .current_dir(dir.path())
        .arg("logs")
        .arg(fixture("auth.log"))
        .args(["-o", "html"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("report.html")).unwrap(),
        "original report"
    );
    assert!(
        std::fs::read_to_string(dir.path().join("report-2.html"))
            .unwrap()
            .contains("<!doctype html>")
    );
}

#[cfg(unix)]
#[test]
fn ctrl_c_retains_ai_reply_and_saves_json_without_another_batch() {
    use std::{
        io::Read,
        net::TcpListener,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    };
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("auth.log");
    std::fs::write(
        &input,
        format!(
            "2026-09-30T00:00:00Z sshd: Failed password for demo from 192.0.2.10 port 22 {}\n",
            "x".repeat(150)
        )
        .repeat(40),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = analyzer_app::core::ai::AiConfig {
        base_url: format!("http://{}/v1", listener.local_addr().unwrap()),
        model: "mock".into(),
        api_key: "fake-signal-test-key".into(),
        batch_bytes: 4096,
        context_tokens: None,
        ..Default::default()
    };
    let config_path = dir.path().join("config.toml");
    analyzer_app::ConfigService::save(&config_path, &config).unwrap();
    let (started, receiver) = mpsc::channel();
    let (release, ready) = mpsc::channel();
    let count = Arc::new(AtomicUsize::new(0));
    let captured = count.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut bytes = vec![];
        let mut buffer = [0; 4096];
        loop {
            let n = stream.read(&mut buffer).unwrap();
            assert_ne!(n, 0);
            bytes.extend_from_slice(&buffer[..n]);
            if let Some(pos) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                let len = String::from_utf8_lossy(&bytes[..pos])
                    .lines()
                    .find_map(|line| {
                        line.to_lowercase()
                            .strip_prefix("content-length:")
                            .map(|n| n.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                if bytes.len() >= pos + 4 + len {
                    break;
                }
            }
        }
        captured.fetch_add(1, Ordering::SeqCst);
        started.send(()).unwrap();
        ready.recv_timeout(Duration::from_secs(10)).unwrap();
        let reply = serde_json::json!({"choices":[{"message":{"content":"{\"findings\":[]}"},"finish_reason":"stop"}]}).to_string();
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", reply.len(), reply).unwrap();
        drop(stream);
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            if let Ok((mut stream, _)) = listener.accept() {
                captured.fetch_add(1, Ordering::SeqCst);
                let _ = write!(
                    stream,
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
            }
            thread::sleep(Duration::from_millis(5));
        }
    });
    let child = exe()
        .current_dir(dir.path())
        .arg("logs")
        .arg(&input)
        .arg("-c")
        .arg(&config_path)
        .args(["-a", "-o", "json"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    receiver.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(
        Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    thread::sleep(Duration::from_millis(50));
    release.send(()).unwrap();
    let output = child.wait_with_output().unwrap();
    server.join().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["records"].as_array().unwrap().len(), 40);
    assert_eq!(report["ai_runs"][0]["completed_batches"], 1);
    assert_eq!(
        report["ai_runs"][0]["batch_results"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(report["ai_runs"][0]["batch_results"][0]["attempts"][0]["response"].is_string());
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["message"].as_str().unwrap().contains("已取消"))
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("fake-signal-test-key"));
}
