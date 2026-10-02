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
        Self::with_behavior(delay, invalid_after_first, false)
    }
    fn with_behavior(delay: Duration, invalid_after_first: bool, invalid_summary: bool) -> Self {
        Self::make(delay, invalid_after_first, invalid_summary, false)
    }
    fn make(
        delay: Duration,
        invalid_after_first: bool,
        invalid_summary: bool,
        large_clues: bool,
    ) -> Self {
        Self::with_failures(
            delay,
            invalid_after_first,
            invalid_summary,
            large_clues,
            vec![],
            false,
            false,
        )
    }
    fn with_failures(
        delay: Duration,
        invalid_after_first: bool,
        invalid_summary: bool,
        large_clues: bool,
        failed_evidence_batches: Vec<usize>,
        failed_summary: bool,
        failed_first_summary: bool,
    ) -> Self {
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
            let mut summary_requests = 0;
            while !stopped.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                // Accepted sockets may inherit nonblocking mode; HTTP reads need the timeout.
                stream.set_nonblocking(false).unwrap();
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
                let user = value["messages"][1]["content"].as_str().unwrap();
                let summary = user.starts_with("阶段：跨批汇总");
                let evidence_batch = user.lines().find_map(|line| {
                    line.strip_prefix("当前批次 batch: ")
                        .and_then(|n| n.parse::<usize>().ok())
                });
                if summary {
                    summary_requests += 1;
                }
                let http_failure = evidence_batch
                    .is_some_and(|n| failed_evidence_batches.contains(&n))
                    || (summary
                        && (failed_summary || (failed_first_summary && summary_requests == 1)));
                let mut evidence_ids: Vec<String> = if summary {
                    // Retry instructions may follow the JSON; deserialize the first value only.
                    let text = user.split_once('\n').unwrap().1;
                    let clues = serde_json::Deserializer::from_str(text)
                        .into_iter::<Vec<serde_json::Value>>()
                        .next()
                        .unwrap()
                        .unwrap();
                    clues
                        .iter()
                        .flat_map(|f| {
                            f["evidence_ids"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|id| id.as_str().unwrap().to_owned())
                        })
                        .collect()
                } else {
                    vec![
                        user.lines()
                            .find_map(|line| line.strip_prefix("证据编号: "))
                            .unwrap()
                            .to_owned(),
                    ]
                };
                evidence_ids.sort();
                evidence_ids.dedup();
                captured.lock().unwrap().push(value);
                let index = counter.fetch_add(1, Ordering::SeqCst);
                thread::sleep(delay);
                if http_failure {
                    write!(
                        stream,
                        "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .unwrap();
                    continue;
                }
                let content = if (invalid_after_first && index > 0) || (summary && invalid_summary)
                {
                    "{".to_owned()
                } else {
                    serde_json::json!({"findings":[{"severity":"high","title":if summary {"cross-batch finding"} else {"mock finding"},"description":if large_clues && !summary { "x".repeat(7000) } else { "test analysis".into() },"evidence_ids":evidence_ids,"confidence":0.8,"recommendations":["verify"]}],"context":[]}).to_string()
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
    outcome
        .session
        .with_report(|r| {
            assert_eq!(r.ai_runs[0].completed(), 1);
            assert_eq!(
                server.count.load(Ordering::SeqCst),
                1 + (r.ai_runs[0].batches - 1) * 3
            );
            assert_eq!(r.ai_runs[0].batch_results.len(), r.ai_runs[0].batches);
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

fn context_config(server: &Server, context: usize) -> AiConfig {
    AiConfig {
        base_url: server.url.clone(),
        model: "mock".into(),
        context_tokens: Some(context),
        max_output_tokens: 512,
        batch_bytes: 256,
        ..Default::default()
    }
}
fn context_session() -> AnalysisSession {
    AnalysisService::load(&large_request(), &ExecutionContext::default())
        .unwrap()
        .session
}
fn all_options() -> AiOptions {
    AiOptions {
        scope: AiScope::All,
        include_payload: false,
        config_path: "unused.toml".into(),
    }
}

#[test]
fn local_preview_single_request_ignores_legacy_byte_limit_and_freezes_scope() {
    let server = Server::new(Duration::ZERO, false);
    let session = context_session();
    let mut config = context_config(&server, 1_000_000);
    let selection = session
        .query(
            &QueryOptions {
                expression: Some("test1 ".into()),
                ..Default::default()
            },
            &ExecutionContext::default(),
        )
        .unwrap();
    let options = AiOptions {
        scope: AiScope::Matches,
        ..all_options()
    };
    let prepared = AnalysisService::prepare_ai_with_config(
        &session,
        &options,
        Some(&selection),
        &config,
        &ExecutionContext::default(),
    )
    .unwrap();
    assert_eq!(prepared.plan().selected_records, 1);
    assert_eq!(prepared.plan().evidence_batches, 1);
    assert!(!prepared.plan().summary_planned);
    assert_eq!(server.count.load(Ordering::SeqCst), 0);
    config.base_url = "http://127.0.0.1:1".into();
    assert_eq!(
        AnalysisService::analyze_prepared_ai(prepared, &ExecutionContext::default())
            .unwrap()
            .status,
        TaskStatus::Completed
    );
    let captured = server.requests.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert_eq!(
        captured[0]["messages"][1]["content"]
            .as_str()
            .unwrap()
            .matches("证据编号: ")
            .count(),
        1
    );
}

#[test]
fn context_batches_synthesize_validated_cross_batch_references_without_double_counting() {
    let server = Server::new(Duration::ZERO, false);
    let session = context_session();
    let prepared = AnalysisService::prepare_ai_with_config(
        &session,
        &all_options(),
        None,
        &context_config(&server, 12000),
        &ExecutionContext::default(),
    )
    .unwrap();
    let batches = prepared.plan().evidence_batches;
    assert!(batches > 1);
    assert!(prepared.plan().summary_planned);
    assert_eq!(
        AnalysisService::analyze_prepared_ai(prepared, &ExecutionContext::default())
            .unwrap()
            .status,
        TaskStatus::Completed
    );
    session
        .with_report(|r| {
            let run = &r.ai_runs[0];
            assert_eq!(run.analyzed_records, r.records.len());
            assert_eq!(run.batches, batches + 1);
            assert!(run.is_complete());
            let cross = r
                .findings
                .iter()
                .find(|f| f.title == "cross-batch finding")
                .unwrap();
            assert!(cross.evidence_ids.len() >= 2);
            assert!(
                cross
                    .evidence_ids
                    .iter()
                    .all(|id| r.records.iter().any(|record| &record.id == id))
            );
        })
        .unwrap();
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), batches + 1);
    assert!(
        requests.last().unwrap()["messages"][1]["content"]
            .as_str()
            .unwrap()
            .starts_with("阶段：跨批汇总")
    );
}

#[test]
fn failed_summary_retains_all_evidence_batch_results_and_raw_replies() {
    let server = Server::with_behavior(Duration::ZERO, false, true);
    let session = context_session();
    let prepared = AnalysisService::prepare_ai_with_config(
        &session,
        &all_options(),
        None,
        &context_config(&server, 12000),
        &ExecutionContext::default(),
    )
    .unwrap();
    let batches = prepared.plan().evidence_batches;
    assert_eq!(
        AnalysisService::analyze_prepared_ai(prepared, &ExecutionContext::default())
            .unwrap()
            .status,
        TaskStatus::Partial
    );
    session
        .with_report(|r| {
            let run = &r.ai_runs[0];
            assert_eq!(run.completed(), batches);
            assert_eq!(run.analyzed_records, r.records.len());
            assert_eq!(run.batch_results.last().unwrap().attempts.len(), 3);
            assert!(
                run.batch_results
                    .last()
                    .unwrap()
                    .attempts
                    .iter()
                    .all(|a| a.response.is_some() && a.error.is_some())
            );
            assert!(
                r.diagnostics
                    .iter()
                    .any(|d| d.message.contains("跨批汇总未完成"))
            );
            assert!(r.findings.iter().any(|f| f.origin.starts_with("ai:")));
            assert!(
                r.diagnostics
                    .iter()
                    .any(|d| d.source == "AI 本地整理" && d.message.contains("mock finding"))
            );
        })
        .unwrap();
}

#[test]
fn failed_evidence_batch_continues_and_summarizes_only_accepted_replies() {
    let server = Server::with_failures(Duration::ZERO, false, false, false, vec![2], false, false);
    let session = context_session();
    let prepared = AnalysisService::prepare_ai_with_config(
        &session,
        &all_options(),
        None,
        &context_config(&server, 12000),
        &ExecutionContext::default(),
    )
    .unwrap();
    let batches = prepared.plan().evidence_batches;
    assert!(batches > 2);
    let outcome =
        AnalysisService::analyze_prepared_ai(prepared, &ExecutionContext::default()).unwrap();
    assert_eq!(outcome.status, TaskStatus::Partial);
    assert_eq!(server.count.load(Ordering::SeqCst), batches + 1);
    session
        .with_report(|r| {
            let run = &r.ai_runs[0];
            assert_eq!(run.batch_results.len(), batches + 1);
            assert_eq!(run.completed(), batches); // all but failed evidence + one summary
            assert!(run.batch_results[1].error.as_ref().unwrap().contains("400"));
            assert!(run.batch_results[2].error.is_none());
            assert_eq!(
                run.analyzed_records,
                r.records.len() - run.batch_results[1].evidence_ids.len()
            );
            let cross = r
                .findings
                .iter()
                .find(|f| f.title == "cross-batch finding")
                .unwrap();
            assert!(cross.evidence_ids.len() >= 2);
            assert!(
                cross
                    .evidence_ids
                    .iter()
                    .all(|id| !run.batch_results[1].evidence_ids.contains(id))
            );
            assert!(
                r.diagnostics
                    .iter()
                    .any(|d| d.source == "AI 本地整理" && d.message.contains("失败证据批次：2"))
            );
        })
        .unwrap();
    let requests = server.requests.lock().unwrap();
    let user = requests.last().unwrap()["messages"][1]["content"]
        .as_str()
        .unwrap();
    assert!(user.contains("失败证据批次：2"));
    assert!(user.contains("缺失范围不能视为正常"));
}

#[test]
fn http400_summary_creates_exportable_local_recap_without_extra_requests() {
    let server = Server::with_failures(Duration::ZERO, false, false, false, vec![], true, false);
    let session = context_session();
    let prepared = AnalysisService::prepare_ai_with_config(
        &session,
        &all_options(),
        None,
        &context_config(&server, 12000),
        &ExecutionContext::default(),
    )
    .unwrap();
    let batches = prepared.plan().evidence_batches;
    let outcome =
        AnalysisService::analyze_prepared_ai(prepared, &ExecutionContext::default()).unwrap();
    assert_eq!(outcome.status, TaskStatus::Partial);
    assert_eq!(server.count.load(Ordering::SeqCst), batches + 1);
    session
        .with_report(|r| {
            assert_eq!(r.ai_runs[0].analyzed_records, r.records.len());
            assert_eq!(r.ai_runs[0].completed(), batches);
            let recap = r
                .diagnostics
                .iter()
                .find(|d| d.source == "AI 本地整理")
                .unwrap();
            assert_eq!(recap.position.as_deref(), Some("ai-run:1"));
            assert!(recap.message.contains("不是新的 AI 关联推理"));
            assert!(recap.message.contains(&format!(
                "请求阶段成功 {}/{}，失败 1，未执行 0",
                batches,
                batches + 1
            )));
            assert!(recap.message.contains("mock finding"));
            assert!(!r.findings.iter().any(|f| f.title.contains("本地结果整理")));
        })
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let paths = ExportPlan {
        format: OutputFormat::Json,
        html_path: Some(dir.path().join("report.html")),
        ..Default::default()
    }
    .save(&session, &dir.path().join("config.toml"))
    .unwrap();
    assert!(paths.stdout.unwrap().contains("AI 本地整理"));
    assert!(
        std::fs::read_to_string(dir.path().join("report.html"))
            .unwrap()
            .contains("本地结果整理")
    );
}

#[test]
fn failed_summary_group_does_not_stop_other_groups_or_discard_accepted_input() {
    let server = Server::with_failures(Duration::ZERO, false, false, true, vec![], false, true);
    let session = context_session();
    let prepared = AnalysisService::prepare_ai_with_config(
        &session,
        &all_options(),
        None,
        &context_config(&server, 12000),
        &ExecutionContext::default(),
    )
    .unwrap();
    let batches = prepared.plan().evidence_batches;
    assert_eq!(
        AnalysisService::analyze_prepared_ai(prepared, &ExecutionContext::default())
            .unwrap()
            .status,
        TaskStatus::Partial
    );
    session
        .with_report(|r| {
            let run = &r.ai_runs[0];
            assert_eq!(run.analyzed_records, r.records.len());
            assert!(run.batch_results[batches].error.is_some());
            assert!(run.batch_results[batches + 1].error.is_none());
            assert_eq!(run.completed() + 1, run.batches);
            let last = run.batch_results.last().unwrap();
            assert!(last.error.is_none());
            let failed_summary = &run.batch_results[batches];
            assert!(
                failed_summary
                    .evidence_ids
                    .iter()
                    .all(|id| last.evidence_ids.contains(id))
            );
            assert!(r.findings.iter().any(|f| f.title == "cross-batch finding"));
            assert!(r.diagnostics.iter().any(|d| d.source == "AI 本地整理"));
        })
        .unwrap();
}

#[test]
fn no_successful_evidence_produces_no_fabricated_content_or_summary_request() {
    let server = Server::with_failures(
        Duration::ZERO,
        false,
        false,
        false,
        (1..=40).collect(),
        false,
        false,
    );
    let session = context_session();
    let prepared = AnalysisService::prepare_ai_with_config(
        &session,
        &all_options(),
        None,
        &context_config(&server, 12000),
        &ExecutionContext::default(),
    )
    .unwrap();
    let batches = prepared.plan().evidence_batches;
    assert_eq!(
        AnalysisService::analyze_prepared_ai(prepared, &ExecutionContext::default())
            .unwrap()
            .status,
        TaskStatus::Partial
    );
    assert_eq!(server.count.load(Ordering::SeqCst), batches);
    session
        .with_report(|r| {
            assert_eq!(r.ai_runs[0].completed(), 0);
            assert_eq!(r.ai_runs[0].analyzed_records, 0);
            assert!(!r.findings.iter().any(|f| f.origin.starts_with("ai:")));
            assert!(
                r.diagnostics
                    .iter()
                    .any(|d| d.source == "AI 本地整理" && d.message.contains("无法形成内容总结"))
            );
        })
        .unwrap();
}

#[test]
fn cancel_in_flight_summary_preserves_reply_and_starts_no_later_request() {
    let server = Server::new(Duration::from_millis(100), false);
    let session = context_session();
    let prepared = AnalysisService::prepare_ai_with_config(
        &session,
        &all_options(),
        None,
        &context_config(&server, 12000),
        &ExecutionContext::default(),
    )
    .unwrap();
    let batches = prepared.plan().evidence_batches;
    let ctx = ExecutionContext::default();
    let work = ctx.clone();
    let join =
        thread::spawn(move || AnalysisService::analyze_prepared_ai(prepared, &work).unwrap());
    let deadline = Instant::now() + Duration::from_secs(10);
    while server.count.load(Ordering::SeqCst) <= batches {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
    ctx.cancellation.cancel();
    assert_eq!(join.join().unwrap().status, TaskStatus::Cancelled);
    assert_eq!(server.count.load(Ordering::SeqCst), batches + 1);
    session
        .with_report(|r| {
            assert_eq!(r.ai_runs[0].analyzed_records, r.records.len());
            assert!(
                r.ai_runs[0].batch_results.last().unwrap().attempts[0]
                    .response
                    .is_some()
            );
            assert!(r.findings.iter().any(|f| f.title == "cross-batch finding"));
        })
        .unwrap();
}

#[test]
fn hierarchical_summary_reports_current_batch_and_total_for_each_round() {
    let server = Server::make(Duration::ZERO, false, false, true);
    let session = context_session();
    let events = Arc::new(Mutex::new(vec![]));
    let collected = events.clone();
    let ctx = ExecutionContext::new(CancellationToken::default(), move |p| {
        if p.stage == analyzer_app::core::execution::Stage::Ai {
            collected.lock().unwrap().push(p);
        }
    });
    let prepared = AnalysisService::prepare_ai_with_config(
        &session,
        &all_options(),
        None,
        &context_config(&server, 12000),
        &ctx,
    )
    .unwrap();
    let batches = prepared.plan().evidence_batches;
    assert_eq!(
        AnalysisService::analyze_prepared_ai(prepared, &ctx)
            .unwrap()
            .status,
        TaskStatus::Completed
    );
    session
        .with_report(|r| {
            let run = &r.ai_runs[0];
            assert!(run.batches > batches + 1);
            assert_eq!(run.batches, server.count.load(Ordering::SeqCst));
            assert!(run.is_complete());
            assert_eq!(run.analyzed_records, r.records.len());
        })
        .unwrap();
    let events = events.lock().unwrap();
    assert!(!events.is_empty());
    let evidence: Vec<_> = events.iter().filter(|p| p.source.is_none()).collect();
    assert_eq!(evidence.len(), batches);
    for (i, event) in evidence.iter().enumerate() {
        assert_eq!(event.completed, i + 1);
        assert_eq!(event.total, Some(batches));
    }
    let mut rounds = std::collections::BTreeMap::new();
    for event in events.iter().filter(|p| p.source.is_some()) {
        let total = event.total.expect("each planned round has a known total");
        assert!((1..=total).contains(&event.completed));
        rounds
            .entry(event.source.as_deref().unwrap())
            .or_insert_with(Vec::new)
            .push((event.completed, total));
    }
    assert!(rounds.len() >= 2);
    for (round, events) in rounds {
        assert!(round.starts_with("跨批汇总（第 "));
        let total = events[0].1;
        assert_eq!(events, (1..=total).map(|i| (i, total)).collect::<Vec<_>>());
    }
}
