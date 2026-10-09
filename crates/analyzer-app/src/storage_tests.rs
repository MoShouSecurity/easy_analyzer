use super::*;

fn project() -> AnalysisSession {
    ProjectService::create(ProjectInfo::new("合成性能验证", "合成客户")).unwrap()
}
fn append(session: &AnalysisSession, label: &str, text: &str) {
    ProjectService::append(
        session,
        &AnalysisRequest {
            inputs: vec![AnalysisInput::Bytes {
                label: label.into(),
                bytes: text.as_bytes().into(),
            }],
            ..Default::default()
        },
        &ExecutionContext::default(),
    )
    .unwrap();
}

#[test]
fn typed_selection_is_lazy_frozen_and_materializes_only_when_requested() {
    let session = project();
    append(&session, "first.log", "alpha\nbeta\ngamma");
    let ctx = ExecutionContext::default();
    let selected = session
        .select_records(
            &RecordFilter {
                kind: RecordKind::Log,
                ..Default::default()
            },
            &ctx,
        )
        .unwrap();
    let db = session.0.store.as_ref().unwrap();
    assert_eq!(selected.len(), 3);
    assert_eq!(
        scalar(&db.lock().unwrap(), "SELECT COUNT(*) FROM selection_refs").unwrap(),
        0
    );
    let page = session.page_metadata(Some(&selected), 1, 2).unwrap();
    assert_eq!(
        session
            .locate_record(Some(&selected), &page.items[1].id)
            .unwrap(),
        Some(2)
    );
    append(&session, "later.log", "delta");
    let current = session
        .select_records(
            &RecordFilter {
                kind: RecordKind::Log,
                ..Default::default()
            },
            &ctx,
        )
        .unwrap();
    assert_eq!(current.len(), 4);
    assert_eq!(selected.len(), 3);
    assert!(
        session
            .page(Some(&selected), 3, 1)
            .unwrap()
            .items
            .is_empty()
    );
    let last = session.page(Some(&current), 3, 1).unwrap().items.remove(0);
    assert_eq!(
        session.locate_record(Some(&selected), &last.id).unwrap(),
        None
    );
    let token = CancellationToken::default();
    token.cancel();
    assert!(
        selected
            .stored_id(&ExecutionContext::new(token, |_| {}))
            .is_err()
    );
    assert_eq!(
        scalar(&db.lock().unwrap(), "SELECT COUNT(*) FROM selection_refs").unwrap(),
        0
    );
    session.set_selection(Some(&selected), &ctx).unwrap();
    assert_eq!(selected.try_ids().unwrap().len(), 3);
    assert_eq!(
        scalar(&db.lock().unwrap(), "SELECT COUNT(*) FROM selection_refs").unwrap(),
        3
    );
    let mut report = Vec::new();
    ExportPlan {
        format: OutputFormat::Json,
        ..Default::default()
    }
    .write_primary(&session, &mut report, &ctx)
    .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&report).unwrap();
    assert_eq!(report["query_matches"].as_array().unwrap().len(), 3);
    assert_eq!(report["records"].as_array().unwrap().len(), 4);
}

#[test]
fn selection_cache_is_bounded_refreshes_and_does_not_retain_closed_projects() {
    let session = project();
    append(
        &session,
        "cache.log",
        "needle0 example.com\nneedle1\nneedle2\nneedle3\nneedle4\nneedle5",
    );
    let weak = Arc::downgrade(session.0.store.as_ref().unwrap());
    let ctx = ExecutionContext::default();
    let query = QueryOptions {
        expression: Some("needle0".into()),
        ..Default::default()
    };
    let first = session.query(&query, &ctx).unwrap();
    session.overview(&ctx).unwrap();
    let content_version = session
        .0
        .store
        .as_ref()
        .unwrap()
        .overview_cache
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .0;
    let id = session.page(Some(&first), 0, 1).unwrap().items[0]
        .id
        .clone();
    ProjectService::note(&session, &id, "只更新备注", &ctx).unwrap();
    ProjectService::save_view_state(&session, &serde_json::json!({"offset":100})).unwrap();
    session.overview(&ctx).unwrap();
    assert_eq!(
        session
            .0
            .store
            .as_ref()
            .unwrap()
            .overview_cache
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .0,
        content_version
    );
    let again = session.query(&query, &ctx).unwrap();
    assert!(Arc::ptr_eq(
        first.stored.as_ref().unwrap(),
        again.stored.as_ref().unwrap()
    ));
    append(&session, "later.log", "needle0");
    let fresh = session.query(&query, &ctx).unwrap();
    assert_eq!(fresh.len(), 2);
    assert_eq!(first.len(), 1);
    let suspicious = session
        .query(
            &QueryOptions {
                suspicious: true,
                ..Default::default()
            },
            &ctx,
        )
        .unwrap();
    IocService::add_value(&session, "example.com", None, "", &ctx).unwrap();
    IocService::scan(&session, true, &ctx).unwrap();
    assert!(
        session
            .query(
                &QueryOptions {
                    suspicious: true,
                    ..Default::default()
                },
                &ctx
            )
            .unwrap()
            .len()
            > suspicious.len()
    );
    drop((first, again, fresh, suspicious));
    for i in 0..6 {
        session
            .query(
                &QueryOptions {
                    expression: Some(format!("needle{i}")),
                    ..Default::default()
                },
                &ctx,
            )
            .unwrap();
    }
    assert_eq!(session.0.selections.lock().unwrap().len(), 4);
    assert_eq!(
        scalar(
            &session.0.store.as_ref().unwrap().lock().unwrap(),
            "SELECT COUNT(*) FROM selections"
        )
        .unwrap(),
        4
    );
    drop(session);
    assert!(weak.upgrade().is_none());
}

#[test]
fn process_and_flow_views_use_frozen_predicates_and_refresh_the_forest() {
    let session = project();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let ctx = ExecutionContext::default();
    ProjectService::append(
        &session,
        &AnalysisRequest {
            inputs: vec![
                AnalysisInput::File(root.join("processes.json")),
                AnalysisInput::File(root.join("sample.pcapng")),
            ],
            ..Default::default()
        },
        &ctx,
    )
    .unwrap();
    let packets = session
        .select_records(
            &RecordFilter {
                kind: RecordKind::Packet,
                ..Default::default()
            },
            &ctx,
        )
        .unwrap();
    let flows = session.flow_page(Some(&packets), 0, 100, &ctx).unwrap();
    assert!(!flows.items.is_empty());
    assert_eq!(
        flows.items.iter().map(|f| f.matched_packets).sum::<usize>(),
        packets.len()
    );
    let flow = session
        .flow_selection(flows.items[0].key, Some(&packets), &ctx)
        .unwrap();
    assert_eq!(flow.len(), flows.items[0].matched_packets);
    drop(flow);
    let processes = session
        .select_records(
            &RecordFilter {
                kind: RecordKind::Process,
                ..Default::default()
            },
            &ctx,
        )
        .unwrap();
    assert_eq!(
        session.process_rows(&processes, &ctx).unwrap().len(),
        processes.len()
    );
    let db = session.0.store.as_ref().unwrap();
    assert_eq!(
        scalar(&db.lock().unwrap(), "SELECT COUNT(*) FROM selection_refs").unwrap(),
        0
    );
    let forest = db.process_forest(&ctx).unwrap();
    assert!(Arc::ptr_eq(&forest, &db.process_forest(&ctx).unwrap()));
    let old_count = forest.trees.iter().map(|t| t.nodes.len()).sum::<usize>();
    append(
        &session,
        "additional-process.json",
        r#"[{"pid":999,"name":"synthetic-process","parent_pid":null,"command":[]}]"#,
    );
    let fresh = db.process_forest(&ctx).unwrap();
    assert_eq!(
        fresh.trees.iter().map(|t| t.nodes.len()).sum::<usize>(),
        old_count + 1
    );
    assert!(!Arc::ptr_eq(&forest, &fresh));
}

#[test]
fn diagnostic_caches_and_paged_ai_headers_refresh_without_loading_replies() {
    let session = project();
    let db = session.0.store.as_ref().unwrap();
    let ctx = ExecutionContext::default();
    assert_eq!(db.diagnostic_levels(&ctx).unwrap(), (0, 0));
    assert_eq!(session.diagnostic_count().unwrap(), 0);
    {
        let c = db.lock().unwrap();
        for i in 0..45 {
            let run = core::AiRun {
                model: format!("synthetic-{i}"),
                endpoint: "https://api.invalid".into(),
                batches: 1,
                analyzed_records: 0,
                include_payload: false,
                completed_batches: Some(0),
                selected_records: Some(0),
                batch_results: vec![],
            };
            c.execute(
                "INSERT INTO ai_runs(json) VALUES(?1)",
                [json(&run).unwrap()],
            )
            .unwrap();
        }
        c.execute(
            "INSERT INTO diagnostics(json) VALUES(?1)",
            [packed_json(&core::Diagnostic {
                level: DiagnosticLevel::Error,
                source: "合成诊断".into(),
                position: None,
                message: "合成错误诊断".repeat(100),
            })
            .unwrap()],
        )
        .unwrap();
    }
    assert_eq!(session.diagnostic_count().unwrap(), 1);
    assert_eq!(db.diagnostic_levels(&ctx).unwrap(), (1, 0));
    let page = session.ai_run_header_page(20, 20).unwrap();
    assert_eq!(page.total, 45);
    assert_eq!(page.items.len(), 20);
    assert_eq!(page.items[0].0, 24);
    assert_eq!(page.items[19].0, 5);
    assert!(page.items.iter().all(|(_, r)| r.batch_results.is_empty()));
    assert!(
        session
            .ai_run_header_page(999, 20)
            .unwrap()
            .items
            .is_empty()
    );
    let token = CancellationToken::default();
    token.cancel();
    assert!(
        db.diagnostic_levels(&ExecutionContext::new(token, |_| {}))
            .is_err()
    );
}
