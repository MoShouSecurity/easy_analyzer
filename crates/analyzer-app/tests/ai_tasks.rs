use analyzer_app::{core::ai::AiConfig, *};
use std::{
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

struct Server {
    url: String,
    requests: Arc<Mutex<Vec<serde_json::Value>>>,
    count: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn new(delay: Duration, invalid_after_first: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/v1", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(vec![]));
        let captured = requests.clone();
        let count = Arc::new(AtomicUsize::new(0));
        let counter = count.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = vec![];
                let mut buffer = [0; 4096];
                let body_offset;
                loop {
                    let n = stream.read(&mut buffer).unwrap();
                    assert_ne!(n, 0);
                    bytes.extend_from_slice(&buffer[..n]);
                    if let Some(pos) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&bytes[..pos]);
                        let size = header
                            .lines()
                            .find_map(|line| {
                                line.to_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|n| n.trim().parse::<usize>().unwrap())
                            })
                            .unwrap();
                        if bytes.len() >= pos + 4 + size {
                            body_offset = pos + 4;
                            break;
                        }
                    }
                }
                let value: serde_json::Value =
                    serde_json::from_slice(&bytes[body_offset..]).unwrap();
                let evidence_id = value["messages"][1]["content"]
                    .as_str()
                    .unwrap()
                    .lines()
                    .find_map(|line| line.strip_prefix("证据编号: "))
                    .unwrap()
                    .to_owned();
                captured.lock().unwrap().push(value);
                let index = counter.fetch_add(1, Ordering::SeqCst);
                thread::sleep(delay);
                let content = if invalid_after_first && index > 0 {
                    "{".to_owned()
                } else {
                    serde_json::json!({"findings":[{"severity":"high","title":"mock finding","description":"test analysis","evidence_ids":[evidence_id],"confidence":0.8,"recommendations":["verify"]}]}).to_string()
                };
                let reply = serde_json::json!({"choices":[{"message":{"content":content},"finish_reason":"stop"}]}).to_string();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", reply.len(), reply).unwrap();
            }
        });
        Self {
            url,
            requests,
            count,
            stop,
            worker: Some(worker),
        }
    }
    fn wait_request(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.count.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < deadline, "no request reached mock AI");
            thread::sleep(Duration::from_millis(5));
        }
    }
    fn options(&self, dir: &Path, batch_bytes: usize, scope: AiScope, payload: bool) -> AiOptions {
        let path = dir.join("config.toml");
        let config = AiConfig {
            base_url: self.url.clone(),
            api_key: "fake-test-key".into(),
            model: "mock".into(),
            batch_bytes,
            ..Default::default()
        };
        ConfigService::save(&path, &config).unwrap();
        AiOptions {
            config_path: path,
            scope,
            include_payload: payload,
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}
fn session(name: &str) -> AnalysisSession {
    AnalysisService::load(
        &AnalysisRequest {
            inputs: vec![AnalysisInput::File(fixture(name))],
            ..Default::default()
        },
        &ExecutionContext::default(),
    )
    .unwrap()
    .session
}
fn large_request() -> AnalysisRequest {
    let bytes = (0..40).map(|i| format!("2026-09-30T01:00:00Z sshd: Failed password for test{i} from 192.0.2.1 port 12345 {}\n", "x".repeat(200))).collect::<String>().into_bytes();
    AnalysisRequest {
        inputs: vec![AnalysisInput::Bytes {
            label: "auth.log".into(),
            bytes: bytes.into(),
        }],
        ..Default::default()
    }
}

#[test]
fn ai_scopes_reuse_evidence_and_keep_unique_findings() {
    let server = Server::new(Duration::ZERO, false);
    let dir = tempfile::tempdir().unwrap();
    let session = session("auth.log");
    let selection = session
        .query(
            &QueryOptions {
                expression: Some("Accepted".into()),
                ..Default::default()
            },
            &ExecutionContext::default(),
        )
        .unwrap();
    assert_eq!(selection.len(), 1);
    let mut options = server.options(dir.path(), 98_304, AiScope::Matches, false);
    assert_eq!(
        AnalysisService::analyze_ai(
            &session,
            &options,
            Some(&selection),
            &ExecutionContext::default()
        )
        .unwrap()
        .status,
        TaskStatus::Completed
    );
    let suspicious = session
        .query(
            &QueryOptions {
                suspicious: true,
                ..Default::default()
            },
            &ExecutionContext::default(),
        )
        .unwrap();
    options.scope = AiScope::Suspicious;
    AnalysisService::analyze_ai(&session, &options, None, &ExecutionContext::default()).unwrap();
    options.scope = AiScope::All;
    AnalysisService::analyze_ai(&session, &options, None, &ExecutionContext::default()).unwrap();
    session
        .with_report(|report| {
            assert_eq!(
                report
                    .ai_runs
                    .iter()
                    .map(|r| r.selected())
                    .collect::<Vec<_>>(),
                [1, suspicious.len(), report.records.len()]
            );
            let ids: std::collections::HashSet<_> = report.findings.iter().map(|f| &f.id).collect();
            assert_eq!(ids.len(), report.findings.len());
            assert!(report.ai_runs.iter().all(|r| r.is_complete()));
        })
        .unwrap();
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    let user = requests[0]["messages"][1]["content"].as_str().unwrap();
    assert_eq!(user.matches("证据编号: ").count(), 1);
    assert!(user.contains(&selection.ids()[0]));
}

#[test]
fn explicit_ai_settings_are_frozen_without_reloading_the_file() {
    let server = Server::new(Duration::ZERO, false);
    let dir = tempfile::tempdir().unwrap();
    let session = session("auth.log");
    let options = server.options(dir.path(), 98_304, AiScope::All, false);
    let mut config = ConfigService::load(&options.config_path).unwrap();
    config.model = "previewed-model".into();
    std::fs::remove_file(&options.config_path).unwrap();
    let outcome = AnalysisService::analyze_ai_with_config(
        &session,
        &options,
        None,
        &config,
        &ExecutionContext::default(),
    )
    .unwrap();
    assert_eq!(outcome.status, TaskStatus::Completed);
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["model"], "previewed-model");
}

#[test]
fn pcap_ai_payload_policy_is_unchanged() {
    let server = Server::new(Duration::ZERO, false);
    let dir = tempfile::tempdir().unwrap();
    let session = session("sample.pcap");
    let mut options = server.options(dir.path(), 98_304, AiScope::All, false);
    AnalysisService::analyze_ai(&session, &options, None, &ExecutionContext::default()).unwrap();
    options.include_payload = true;
    AnalysisService::analyze_ai(&session, &options, None, &ExecutionContext::default()).unwrap();
    let requests = server.requests.lock().unwrap();
    assert!(
        !requests[0]["messages"][1]["content"]
            .as_str()
            .unwrap()
            .contains("payload_hex")
    );
    assert!(
        requests[1]["messages"][1]["content"]
            .as_str()
            .unwrap()
            .contains("payload_hex")
    );
    assert!(
        requests[1]["messages"][1]["content"]
            .as_str()
            .unwrap()
            .contains("原始包十六进制")
    );
}

#[test]
fn in_flight_cancel_retains_response_and_stops_later_batches() {
    let server = Server::new(Duration::from_millis(300), false);
    let dir = tempfile::tempdir().unwrap();
    let session = AnalysisService::load(&large_request(), &ExecutionContext::default())
        .unwrap()
        .session;
    let options = server.options(dir.path(), 4096, AiScope::All, false);
    let task = task::spawn_ai(session.clone(), options, None);
    server.wait_request();
    assert_eq!(session.page(None, 0, 5).unwrap().items.len(), 5); // concurrent reads during blocking HTTP
    assert_eq!(
        session
            .query(&QueryOptions::default(), &ExecutionContext::default())
            .unwrap()
            .len(),
        40
    );
    task.cancel();
    assert_eq!(task.status(), TaskStatus::Cancelling);
    let mut terminal = vec![];
    loop {
        if let TaskEvent::Status { status, .. } =
            task.events.recv_timeout(Duration::from_secs(5)).unwrap()
            && status.is_terminal()
        {
            terminal.push(status);
            break;
        }
    }
    assert_eq!(terminal, [TaskStatus::Cancelled]);
    assert!(task.events.try_recv().is_err());
    let outcome = task.wait().unwrap();
    assert_eq!(outcome.status, TaskStatus::Cancelled);
    assert_eq!(server.count.load(Ordering::SeqCst), 1);
    outcome
        .session
        .with_report(|r| {
            let run = &r.ai_runs[0];
            assert_eq!(run.completed(), 1);
            assert!(run.batches > 1);
            assert!(run.batch_results[0].attempts[0].response.is_some());
            assert!(!run.is_complete());
            assert!(r.findings.iter().any(|f| f.origin == "ai:mock"));
            assert!(r.diagnostics.iter().any(|d| d.message.contains("已取消")));
        })
        .unwrap();
}

#[test]
fn same_session_serializes_writes_and_queued_cancel_is_terminal() {
    let server = Server::new(Duration::from_millis(300), false);
    let dir = tempfile::tempdir().unwrap();
    let session = session("auth.log");
    let options = server.options(dir.path(), 98_304, AiScope::All, false);
    let first = task::spawn_ai(session.clone(), options.clone(), None);
    server.wait_request();
    let queued = task::spawn_ai(session.clone(), options, None);
    queued.cancel();
    loop {
        if let TaskEvent::Status { status, .. } =
            queued.events.recv_timeout(Duration::from_secs(5)).unwrap()
            && status.is_terminal()
        {
            assert_eq!(status, TaskStatus::Cancelled);
            break;
        }
    }
    assert!(queued.wait().is_err());
    assert_eq!(first.wait().unwrap().status, TaskStatus::Completed);
    assert_eq!(server.count.load(Ordering::SeqCst), 1);
    assert_eq!(session.with_report(|r| r.ai_runs.len()).unwrap(), 1);
}

#[test]
fn invalid_reply_retries_keep_prior_results_and_reports() {
    let server = Server::new(Duration::ZERO, true);
    let dir = tempfile::tempdir().unwrap();
    let mut request = large_request();
    request.ai = Some(server.options(dir.path(), 4096, AiScope::All, false));
    let outcome = AnalysisService::execute(&request, &ExecutionContext::default()).unwrap();
    assert_eq!(outcome.status, TaskStatus::Partial);
    assert_eq!(server.count.load(Ordering::SeqCst), 4);
    outcome
        .session
        .with_report(|r| {
            assert_eq!(r.ai_runs[0].completed(), 1);
            assert_eq!(r.ai_runs[0].batch_results[1].attempts.len(), 3);
            assert!(r.findings.iter().any(|f| f.origin == "ai:mock"));
            assert!(
                r.ai_runs[0].batch_results[1]
                    .attempts
                    .iter()
                    .all(|a| a.response.as_deref() == Some("{"))
            );
        })
        .unwrap();
    let result = ExportPlan {
        format: OutputFormat::Json,
        html_path: Some(dir.path().join("report.html")),
        ..Default::default()
    }
    .save(&outcome.session, &dir.path().join("config.toml"))
    .unwrap();
    let value: serde_json::Value = serde_json::from_str(result.stdout.as_ref().unwrap()).unwrap();
    assert_eq!(value["ai_runs"][0]["completed_batches"], 1);
    assert_eq!(
        value["ai_runs"][0]["batch_results"][1]["attempts"][0]["response"],
        "{"
    );
    assert!(
        std::fs::read_to_string(dir.path().join("report.html"))
            .unwrap()
            .contains("mock finding")
    );
}
