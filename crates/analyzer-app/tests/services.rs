use analyzer_app::{
    core::{self, execution::Stage},
    *,
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}
fn request(names: &[&str]) -> AnalysisRequest {
    AnalysisRequest {
        inputs: names
            .iter()
            .map(|n| AnalysisInput::File(fixture(n)))
            .collect(),
        ..Default::default()
    }
}
fn load(names: &[&str]) -> AnalysisSession {
    AnalysisService::load(&request(names), &ExecutionContext::default())
        .unwrap()
        .session
}

#[test]
fn file_bytes_mixed_dedup_and_partial_errors() {
    let mut req = request(&["auth.log", "processes.json", "sample.pcap", "auth.log"]);
    let outcome = AnalysisService::execute(&req, &ExecutionContext::default()).unwrap();
    assert_eq!(outcome.status, TaskStatus::Completed);
    outcome
        .session
        .with_report(|r| {
            assert_eq!(r.sources.len(), 3);
            assert_eq!(r.records.len(), 11);
            assert!(!r.flows.is_empty());
        })
        .unwrap();
    req.inputs
        .push(AnalysisInput::File(fixture("malformed.evtx")));
    let outcome = AnalysisService::execute(&req, &ExecutionContext::default()).unwrap();
    assert_eq!(outcome.status, TaskStatus::Partial);
    assert_eq!(outcome.session.page(None, 0, 100).unwrap().total, 11);
    let file = core::ingest_file(&fixture("auth.log"), &IngestOptions::default()).unwrap();
    let path = fixture("auth.log");
    let req = AnalysisRequest {
        inputs: vec![AnalysisInput::Bytes {
            label: path.to_string_lossy().into_owned(),
            bytes: std::fs::read(&path).unwrap().into(),
        }],
        ..Default::default()
    };
    let bytes = AnalysisService::load(&req, &ExecutionContext::default()).unwrap();
    bytes
        .session
        .with_report(|r| {
            assert_eq!(
                r.records.iter().map(|r| &r.id).collect::<Vec<_>>(),
                file.records.iter().map(|r| &r.id).collect::<Vec<_>>()
            )
        })
        .unwrap();
}

#[test]
fn session_queries_and_pages_survive_file_removal() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("auth.log");
    std::fs::copy(fixture("auth.log"), &input).unwrap();
    let req = AnalysisRequest {
        inputs: vec![AnalysisInput::File(input.clone())],
        ..Default::default()
    };
    let session = AnalysisService::load(&req, &ExecutionContext::default())
        .unwrap()
        .session;
    std::fs::remove_file(&input).unwrap();
    let selection = session
        .query(
            &QueryOptions {
                expression: Some("failed".into()),
                ..Default::default()
            },
            &ExecutionContext::default(),
        )
        .unwrap();
    assert!(!selection.is_empty());
    assert_eq!(session.page(Some(&selection), 0, 2).unwrap().items.len(), 2);
    assert!(
        session
            .page(Some(&selection), usize::MAX, 5)
            .unwrap()
            .items
            .is_empty()
    );
    assert!(session.page(None, 0, 0).is_err());
    assert!(session.page(None, 0, 1001).is_err());
    let id = &selection.ids()[0];
    assert!(!session.record(id).unwrap().unwrap().raw.is_empty());
    assert!(session.record("foreign").unwrap().is_none());
    assert!(session.select_ids(["foreign".into()]).is_err());
    assert_eq!(
        session.select_ids([id.clone(), id.clone()]).unwrap().len(),
        1
    );
    let foreign = load(&["auth.log"])
        .query(&QueryOptions::default(), &ExecutionContext::default())
        .unwrap();
    assert!(session.page(Some(&foreign), 0, 10).is_err());
    assert!(
        session
            .query(
                &QueryOptions {
                    expression: Some("[".into()),
                    regex: true,
                    suspicious: false
                },
                &ExecutionContext::default()
            )
            .is_err()
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
    let intersection = session
        .query(
            &QueryOptions {
                expression: Some("failed".into()),
                suspicious: true,
                regex: false,
            },
            &ExecutionContext::default(),
        )
        .unwrap();
    assert!(
        intersection
            .ids()
            .iter()
            .all(|id| suspicious.ids().contains(id))
    );
    assert!(session.with_report(|r| r.query_matches.is_none()).unwrap()); // pure query
    session
        .set_selection(Some(&selection), &ExecutionContext::default())
        .unwrap();
    assert_eq!(
        session
            .with_report(|r| r.query_matches.clone())
            .unwrap()
            .unwrap(),
        selection.ids()
    );
}

#[test]
fn cancelled_read_has_no_fabricated_source_and_parse_keeps_verified_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.log");
    let bytes = "unrecognized line\n".repeat(10_000).into_bytes();
    std::fs::write(&path, &bytes).unwrap();
    let token = CancellationToken::default();
    let signal = token.clone();
    let ctx = ExecutionContext::new(token, move |event| {
        if event.stage == Stage::Reading && event.completed > 0 {
            signal.cancel();
        }
    });
    let result =
        core::ingest::ingest_file_with_context(&path, &IngestOptions::default(), &ctx).unwrap();
    assert!(result.cancelled);
    assert!(result.report.sources.is_empty());
    assert!(result.report.records.is_empty());
    let token = CancellationToken::default();
    let signal = token.clone();
    let ctx = ExecutionContext::new(token, move |event| {
        if event.stage == Stage::Parsing && event.completed >= 256 {
            signal.cancel();
        }
    });
    let result =
        core::ingest::ingest_bytes_with_context("big.log", &bytes, &IngestOptions::default(), &ctx)
            .unwrap();
    assert!(result.cancelled);
    assert_eq!(result.report.records.len(), 256);
    let source = &result.report.sources[0];
    let expected = core::ingest::source_for("big.log", "text", &bytes);
    assert_eq!(source.id, expected.id);
    assert_eq!(source.sha256, expected.sha256);
    assert_eq!(source.bytes, bytes.len() as u64);
    assert!(
        result
            .report
            .records
            .iter()
            .all(|r| r.source_id == source.id)
    );
}

#[test]
fn cancellation_preserves_previous_sources_and_discards_partial_query() {
    let mut req = request(&["auth.log"]);
    req.inputs.push(AnalysisInput::Bytes {
        label: "cancel.log".into(),
        bytes: Arc::from(b"line\n".repeat(1000)),
    });
    let token = CancellationToken::default();
    let signal = token.clone();
    let ctx = ExecutionContext::new(token, move |event| {
        if event.stage == Stage::Parsing
            && event.source.as_deref() == Some("cancel.log")
            && event.completed >= 256
        {
            signal.cancel();
        }
    });
    let outcome = AnalysisService::execute(&req, &ctx).unwrap();
    assert_eq!(outcome.status, TaskStatus::Cancelled);
    assert_eq!(outcome.session.page(None, 0, 1000).unwrap().total, 263);
    let session = load(&["auth.log"]);
    let selection = session
        .query(&QueryOptions::default(), &ExecutionContext::default())
        .unwrap();
    session
        .set_selection(Some(&selection), &ExecutionContext::default())
        .unwrap();
    let token = CancellationToken::default();
    token.cancel();
    let ctx = ExecutionContext::new(token, |_| {});
    assert!(session.query(&QueryOptions::default(), &ctx).is_err());
    assert_eq!(
        session
            .with_report(|r| r.query_matches.as_ref().unwrap().len())
            .unwrap(),
        selection.len()
    );
}

#[test]
fn modes_formats_and_limits_are_shared() {
    let mut req = request(&["sample.pcap"]);
    req.mode = AnalysisMode::Logs;
    let out = AnalysisService::execute(&req, &ExecutionContext::default()).unwrap();
    assert_eq!(out.status, TaskStatus::Partial);
    assert_eq!(out.session.page(None, 0, 10).unwrap().total, 0);
    req = request(&["auth.log"]);
    req.ingest.max_records = 1;
    assert_eq!(
        AnalysisService::load(&req, &ExecutionContext::default())
            .unwrap()
            .status,
        TaskStatus::Partial
    );
    req.ingest.max_records = 0;
    assert!(AnalysisService::validate(&req).is_err());
    req.ingest.max_records = 1000;
    req.ingest.max_file_bytes = 1;
    assert_eq!(
        AnalysisService::load(&req, &ExecutionContext::default())
            .unwrap()
            .status,
        TaskStatus::Partial
    );
    req = request(&["custom.log"]);
    req.web_format_file = Some(fixture("custom-format.conf"));
    assert_eq!(
        AnalysisService::load(&req, &ExecutionContext::default())
            .unwrap()
            .status,
        TaskStatus::Completed
    );
    req = request(&["auth.log"]);
    req.mode = AnalysisMode::Pcap;
    req.auto_load = true;
    assert!(AnalysisService::validate(&req).is_err());
}

#[test]
fn forest_namespaces_orphans_and_cycles() {
    let value = serde_json::json!([
        {"pid":1,"parent_pid":2,"name":"a"}, {"pid":2,"parent_pid":1,"name":"b"},
        {"pid":3,"parent_pid":999,"name":"orphan"}, {"pid":4,"parent_pid":4,"name":"self"}, {"pid":5,"parent_pid":1,"name":"child"}
    ]);
    let req = AnalysisRequest {
        inputs: vec![
            AnalysisInput::Bytes {
                label: "a.json".into(),
                bytes: serde_json::to_vec(&value).unwrap().into(),
            },
            AnalysisInput::Bytes {
                label: "b.json".into(),
                bytes: serde_json::to_vec(&value).unwrap().into(),
            },
        ],
        ..Default::default()
    };
    let session = AnalysisService::load(&req, &ExecutionContext::default())
        .unwrap()
        .session;
    let forest = session.process_forest().unwrap();
    assert_eq!(forest.trees.len(), 2);
    for tree in &forest.trees {
        assert_eq!(tree.cycle_roots.len(), 2);
        assert_eq!(tree.nodes.iter().filter(|n| n.cyclic).count(), 3);
        assert!(tree.nodes.iter().find(|n| n.pid == 3).unwrap().orphan);
        let child = tree.nodes.iter().find(|n| n.pid == 5).unwrap();
        assert!(!child.cyclic);
        assert!(tree.nodes.iter().all(|n| {
            n.parent_id
                .as_ref()
                .is_none_or(|id| id.starts_with(&tree.source_id))
        }));
        let root = tree.nodes.iter().find(|n| n.pid == 1).unwrap();
        assert!(root.children.contains(&child.record_id));
    }
    session
        .with_report(|r| assert!(core::collect::process_tree(&r.records).contains("orphan")))
        .unwrap();
}

#[test]
fn config_save_is_validated_atomic_and_secret_safe() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    ConfigService::create(&path).unwrap();
    assert!(ConfigService::create(&path).is_err());
    let mut config = ConfigService::load(&path).unwrap();
    config.api_key = "fake-private-test-key".into();
    ConfigService::save(&path, &config).unwrap();
    assert_eq!(ConfigService::load(&path).unwrap().api_key, config.api_key);
    assert!(
        !ConfigService::redacted(&config)
            .unwrap()
            .contains(&config.api_key)
    );
    let before = std::fs::read(&path).unwrap();
    config.model.clear();
    assert!(ConfigService::save(&path, &config).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(ConfigService::default_path(), PathBuf::from("config.toml"));
}

#[test]
fn report_exports_and_path_guards() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("auth.log");
    std::fs::copy(fixture("auth.log"), &input).unwrap();
    let config = dir.path().join("config.toml");
    let req = AnalysisRequest {
        inputs: vec![AnalysisInput::File(input.clone())],
        ..Default::default()
    };
    let session = AnalysisService::load(&req, &ExecutionContext::default())
        .unwrap()
        .session;
    let bad = ExportPlan {
        path: Some(input.clone()),
        ..Default::default()
    };
    assert!(bad.validate_inputs(&req, &config).is_err());
    assert!(bad.save(&session, &config).is_err());
    let bad = ExportPlan {
        path: Some(config.clone()),
        ..Default::default()
    };
    assert!(bad.save(&session, &config).is_err());
    let same = dir.path().join("same");
    let bad = ExportPlan {
        path: Some(same.clone()),
        json_path: Some(same),
        ..Default::default()
    };
    assert!(bad.save(&session, &config).is_err());
    #[cfg(unix)]
    {
        let link = dir.path().join("alias");
        std::os::unix::fs::symlink(&input, &link).unwrap();
        assert!(
            ExportPlan {
                path: Some(link),
                ..Default::default()
            }
            .save(&session, &config)
            .is_err()
        );
    }
    let plan = ExportPlan {
        format: OutputFormat::Html,
        html_path: Some(dir.path().join("report.html")),
        json_path: Some(dir.path().join("report.json")),
        ..Default::default()
    };
    let result = plan.save(&session, &config).unwrap();
    assert!(result.stdout.is_none());
    assert_eq!(result.saved_paths.len(), 2);
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("report.json")).unwrap()).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert!(report.get("summary").is_some());
    assert!(
        std::fs::read_to_string(dir.path().join("report.html"))
            .unwrap()
            .contains("<!doctype html>")
    );
}

#[test]
fn task_ids_progress_and_single_terminal_event() {
    let task = task::spawn_analysis(request(&["auth.log"]));
    let id = task.id;
    let mut terminal = vec![];
    let mut stages = vec![];
    loop {
        let event = task.events.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(event.task_id(), id);
        match event {
            TaskEvent::Progress { progress, .. } => stages.push(progress.stage),
            TaskEvent::Status { status, .. } if status.is_terminal() => {
                terminal.push(status);
                break;
            }
            _ => {}
        }
    }
    assert!(task.events.try_recv().is_err());
    assert_eq!(terminal, [TaskStatus::Completed]);
    assert!(stages.contains(&Stage::Reading));
    assert!(stages.contains(&Stage::Parsing));
    assert!(stages.contains(&Stage::Rules));
    assert_eq!(task.wait().unwrap().status, TaskStatus::Completed);
    let task = task::spawn_analysis(AnalysisRequest::default());
    let other_id = task.id;
    assert_ne!(other_id, id);
    loop {
        if let TaskEvent::Status { status, .. } =
            task.events.recv_timeout(Duration::from_secs(5)).unwrap()
            && status.is_terminal()
        {
            assert_eq!(status, TaskStatus::Failed);
            break;
        }
    }
    assert!(task.wait().is_err());
}

#[test]
fn metadata_only_capture_does_not_flood_progress_events() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let mut bytes = vec![];
    bytes.extend(0x0a0d0d0au32.to_le_bytes());
    bytes.extend(28u32.to_le_bytes());
    bytes.extend(0x1a2b3c4du32.to_le_bytes());
    bytes.extend(1u16.to_le_bytes());
    bytes.extend(0u16.to_le_bytes());
    bytes.extend((-1i64).to_le_bytes());
    bytes.extend(28u32.to_le_bytes());
    for _ in 0..2048 {
        bytes.extend(0x12345678u32.to_le_bytes());
        bytes.extend(12u32.to_le_bytes());
        bytes.extend(12u32.to_le_bytes());
    }
    let count = Arc::new(AtomicUsize::new(0));
    let captured = count.clone();
    let ctx = ExecutionContext::new(CancellationToken::default(), move |event| {
        if event.stage == Stage::Parsing {
            captured.fetch_add(1, Ordering::Relaxed);
        }
    });
    let outcome = core::ingest::ingest_bytes_with_context(
        "metadata.pcapng",
        &bytes,
        &IngestOptions::default(),
        &ctx,
    )
    .unwrap();
    assert!(!outcome.cancelled);
    assert!(outcome.report.records.is_empty());
    assert!(count.load(Ordering::Relaxed) <= 3);
}

#[test]
fn rules_cancellation_and_failed_background_operation_are_visible() {
    let token = CancellationToken::default();
    let signal = token.clone();
    let ctx = ExecutionContext::new(token, move |event| {
        if event.stage == Stage::Rules {
            signal.cancel();
        }
    });
    let outcome = AnalysisService::execute(&request(&["auth.log"]), &ctx).unwrap();
    assert_eq!(outcome.status, TaskStatus::Cancelled);
    assert_eq!(outcome.session.page(None, 0, 100).unwrap().total, 7);
    assert!(
        outcome
            .session
            .with_report(|r| r.diagnostics.iter().any(|d| d.message.contains("已取消")))
            .unwrap()
    );
    let worker = task::spawn_operation::<()>(|_| panic!("mock operation failure"));
    loop {
        if let TaskEvent::Status { status, .. } =
            worker.events.recv_timeout(Duration::from_secs(5)).unwrap()
            && status.is_terminal()
        {
            assert_eq!(status, TaskStatus::Failed);
            break;
        }
    }
    assert!(worker.wait().is_err());
}
