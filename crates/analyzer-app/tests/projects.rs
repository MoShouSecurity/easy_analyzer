use analyzer_app::{
    core::{self, execution::Stage},
    *,
};
use std::{path::Path, sync::Arc};
fn ctx() -> ExecutionContext {
    ExecutionContext::default()
}
fn create() -> AnalysisSession {
    ProjectService::create(ProjectInfo::new("合成响应 <script>", "合成客户甲")).unwrap()
}
fn append(session: &AnalysisSession, label: &str, text: &str) {
    ProjectService::append(
        session,
        &AnalysisRequest {
            inputs: vec![AnalysisInput::Bytes {
                label: label.into(),
                bytes: Arc::from(text.as_bytes()),
            }],
            ingest: IngestOptions {
                format: InputFormat::Text,
                ..Default::default()
            },
            ..Default::default()
        },
        &ctx(),
    )
    .unwrap();
}
#[test]
fn identity_time_validation_and_catalog_relocation() {
    let a = create();
    let b = create();
    assert_ne!(
        ProjectService::status(&a).unwrap().info.id,
        ProjectService::status(&b).unwrap().info.id
    );
    let cloned = ProjectService::create(ProjectService::status(&a).unwrap().info).unwrap();
    assert_ne!(
        ProjectService::status(&cloned).unwrap().info.id,
        ProjectService::status(&a).unwrap().info.id
    );
    let mut info = ProjectService::status(&a).unwrap().info;
    info.response_start = "2026-10-03T09:00:00+08:00".into();
    info.response_end = Some("2026-10-03T00:59:00Z".into());
    assert!(ProjectService::edit(&a, info.clone(), &ctx()).is_err());
    info.response_end = Some("2026-10-04T17:00:00+08:00".into());
    ProjectService::edit(&a, info, &ctx()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.eair");
    let catalog = ProjectCatalog::open(&dir.path().join("catalog")).unwrap();
    assert!(
        catalog
            .list(&ProjectSearch {
                from: Some("2026-10-04".into()),
                until: Some("2026-10-03".into()),
                ..Default::default()
            })
            .is_err()
    );
    ProjectService::save(&a, &p, Path::new("missing-config.toml"), false, &ctx()).unwrap();
    catalog.register(&a).unwrap();
    let entries = catalog
        .list(&ProjectSearch {
            text: "客户甲".into(),
            from: Some("2026-10-03".into()),
            until: Some("2026-10-03".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].info.response_start, "2026-10-03T09:00:00+08:00");
    let new = dir.path().join("moved.eair");
    std::fs::rename(&p, &new).unwrap();
    assert!(catalog.list(&Default::default()).unwrap()[0].missing);
    let open = ProjectService::open(&new, &ctx()).unwrap();
    catalog.register(&open).unwrap();
    let entry = &catalog.list(&Default::default()).unwrap()[0];
    assert!(!entry.missing);
    assert_eq!(
        entry.path,
        new.canonicalize().unwrap().display().to_string()
    );
}
#[test]
fn append_dedup_notes_ioc_and_recovery_without_originals() {
    let session = create();
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("host-a.log");
    std::fs::write(&evidence, "visit a.example.com\nconnect 2001:db8::1\n").unwrap();
    let request = AnalysisRequest {
        inputs: vec![AnalysisInput::File(evidence.clone())],
        ..Default::default()
    };
    ProjectService::append(&session, &request, &ctx()).unwrap();
    let count = session.overview(&ctx()).unwrap().records;
    let snapshot = dir.path().join("before-repeat.eair");
    ProjectService::save(&session, &snapshot, Path::new("config"), false, &ctx()).unwrap();
    ProjectService::append(&session, &request, &ctx()).unwrap();
    assert_eq!(session.overview(&ctx()).unwrap().records, count);
    assert!(!ProjectService::status(&session).unwrap().dirty);
    let id = session.page(None, 0, 1).unwrap().items[0].id.clone();
    ProjectService::note(&session, &id, "已关联客户业务记录", &ctx()).unwrap();
    IocService::add_text(
        &session,
        "example.com\ninvalid/IOC\n2001:db8::1",
        false,
        "粘贴",
        &ctx(),
    )
    .unwrap();
    IocService::scan(&session, true, &ctx()).unwrap();
    let hits = IocService::matches(&session, 0, 100).unwrap().total;
    assert!(hits >= 2);
    IocService::scan(&session, true, &ctx()).unwrap();
    assert_eq!(IocService::matches(&session, 0, 100).unwrap().total, hits);
    let prior = session
        .finding_page(&Default::default(), 0, 100, &ctx())
        .unwrap()
        .total;
    std::fs::write(&evidence, "new line example.com\n").unwrap();
    ProjectService::append(&session, &request, &ctx()).unwrap();
    assert_eq!(IocService::matches(&session, 0, 100).unwrap().total, hits);
    assert!(IocService::status(&session).unwrap().needs_rescan);
    assert_eq!(
        session
            .finding_page(&Default::default(), 0, 100, &ctx())
            .unwrap()
            .total,
        prior
    );
    assert_eq!(
        ProjectService::read_note(&session, &id).unwrap().as_deref(),
        Some("已关联客户业务记录")
    );
    let p = dir.path().join("project.eair");
    ProjectService::save(&session, &p, Path::new("config.toml"), false, &ctx()).unwrap();
    std::fs::remove_file(evidence).unwrap();
    let reopened = ProjectService::open(&p, &ctx()).unwrap();
    assert_eq!(
        ProjectService::read_note(&reopened, &id)
            .unwrap()
            .as_deref(),
        Some("已关联客户业务记录")
    );
    assert_eq!(IocService::matches(&reopened, 0, 100).unwrap().total, hits);
    assert!(reopened.overview(&ctx()).unwrap().records > count);
    assert!(!ProjectService::status(&reopened).unwrap().dirty);
    assert!(!dir.path().join("project.eair-wal").exists());
}

#[test]
fn ioc_databases_remain_project_scoped_after_save_and_reopen() {
    let a = ProjectService::create(ProjectInfo::new("响应甲", "合成客户甲")).unwrap();
    let b = ProjectService::create(ProjectInfo::new("响应乙", "合成客户乙")).unwrap();
    let evidence = "visit shared.example.com\nvisit child.shared.example.com\nvisit alpha.example.net\nvisit beta.example.net";
    for session in [&a, &b] {
        append(session, "same-host", evidence);
        assert_eq!(IocService::indicators(session, 0, 100).unwrap().total, 0);
        assert!(IocService::status(session).unwrap().run.is_none());
    }
    let shared_a = IocService::add_value(&a, "shared.example.com", None, "甲的说明", &ctx())
        .unwrap()
        .indicators[0]
        .id
        .clone();
    let shared_b = IocService::add_value(&b, "SHARED.example.com", None, "乙的说明", &ctx())
        .unwrap()
        .indicators[0]
        .id
        .clone();
    // Equal normalized IOC IDs must still refer to independent project rows.
    assert_eq!(shared_a, shared_b);
    let unique_a = IocService::add_value(&a, "alpha.example.net", None, "仅甲", &ctx())
        .unwrap()
        .indicators[0]
        .id
        .clone();
    IocService::add_value(&b, "beta.example.net", None, "仅乙", &ctx()).unwrap();
    IocService::scan(&a, true, &ctx()).unwrap();
    IocService::scan(&b, false, &ctx()).unwrap();

    let snapshot = |session: &AnalysisSession| {
        serde_json::json!({
            "indicators": IocService::indicators(session, 0, 100).unwrap(),
            "hits": IocService::matches(session, 0, 100).unwrap(),
            "status": IocService::status(session).unwrap(),
        })
    };
    let unchanged_b = snapshot(&b);
    IocService::edit_note(&a, &shared_a, "甲修改后的说明", &ctx()).unwrap();
    assert_eq!(snapshot(&b), unchanged_b);
    assert!(
        IocService::edit_note(&b, &unique_a, "不得写入乙", &ctx())
            .unwrap_err()
            .to_string()
            .contains("不属于当前项目")
    );
    assert_eq!(snapshot(&b), unchanged_b);

    for (session, unique, shared_note, subdomains) in [
        (&a, "alpha.example.net", "甲修改后的说明", true),
        (&b, "beta.example.net", "乙的说明", false),
    ] {
        let indicators = IocService::indicators(session, 0, 100).unwrap();
        assert_eq!(indicators.total, 2);
        assert!(indicators.items.iter().any(|i| i.value == unique));
        assert!(
            indicators
                .items
                .iter()
                .any(|i| i.id == shared_a && i.note == shared_note)
        );
        let hits = IocService::matches(session, 0, 100).unwrap();
        assert!(hits.items.iter().any(|h| h.value == unique));
        assert!(hits.items.iter().any(|h| h.indicator_id == shared_a));
        assert_eq!(
            hits.items
                .iter()
                .any(|h| h.matched_value == "child.shared.example.com"),
            subdomains
        );
        for hit in hits.items {
            assert!(hit.value == unique || hit.indicator_id == shared_a);
            if hit.indicator_id == shared_a {
                assert_eq!(hit.note, shared_note);
            }
            assert!(session.record(&hit.record_id).unwrap().is_some());
        }
        let status = IocService::status(session).unwrap();
        assert!(!status.needs_rescan);
        assert_eq!(status.run.unwrap().include_subdomains, subdomains);
    }

    let dir = tempfile::tempdir().unwrap();
    let catalog_dir = dir.path().join("catalog");
    let catalog = ProjectCatalog::open(&catalog_dir).unwrap();
    let mut saved = Vec::new();
    for (session, name) in [(&a, "a.eair"), (&b, "b.eair")] {
        let path = dir.path().join(name);
        ProjectService::save(
            session,
            &path,
            Path::new("missing-config.toml"),
            false,
            &ctx(),
        )
        .unwrap();
        catalog.register(session).unwrap();
        saved.push((
            path,
            ProjectService::status(session).unwrap().info,
            snapshot(session),
        ));
    }
    drop(a);
    drop(b);
    // Alternate opening independent snapshots, without the original live sessions.
    for index in [1, 0, 1, 0] {
        let (path, info, expected) = &saved[index];
        let reopened = ProjectService::open(path, &ctx()).unwrap();
        assert_eq!(ProjectService::status(&reopened).unwrap().info.id, info.id);
        assert_eq!(&snapshot(&reopened), expected);
    }
    let fresh = create();
    assert_eq!(IocService::indicators(&fresh, 0, 100).unwrap().total, 0);
    assert_eq!(IocService::matches(&fresh, 0, 100).unwrap().total, 0);
    assert!(IocService::status(&fresh).unwrap().run.is_none());

    let db = rusqlite::Connection::open(catalog_dir.join("projects.sqlite")).unwrap();
    let tables = db
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(tables, ["projects"]);
    for (_, info, _) in saved {
        let stored: String = db
            .query_row("SELECT json FROM projects WHERE id=?1", [&info.id], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&stored).unwrap(),
            serde_json::to_value(info).unwrap()
        );
    }
}
#[test]
fn save_as_cancel_conflicts_and_input_protection() {
    let session = create();
    append(&session, "host-a", "hello example.com");
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.eair");
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "do not replace").unwrap();
    assert!(ProjectService::save(&session, &config, &config, true, &ctx()).is_err());
    ProjectService::save(&session, &p, &config, false, &ctx()).unwrap();
    let original = std::fs::read(&p).unwrap();
    append(&session, "host-b", "new evidence");
    let cancel = CancellationToken::default();
    cancel.cancel();
    assert!(
        ProjectService::save(
            &session,
            &p,
            &config,
            false,
            &ExecutionContext::new(cancel, |_| {})
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&p).unwrap(), original);
    assert!(ProjectService::status(&session).unwrap().dirty);
    let save_as = dir.path().join("b.eair");
    ProjectService::save(&session, &save_as, &config, false, &ctx()).unwrap();
    assert_eq!(std::fs::read(&p).unwrap(), original);
    assert_eq!(
        ProjectService::status(&ProjectService::open(&p, &ctx()).unwrap())
            .unwrap()
            .info
            .id,
        ProjectService::status(&session).unwrap().info.id
    );
    let bad = dir.path().join("bad.eair");
    std::fs::write(&bad, "not sqlite").unwrap();
    assert!(ProjectService::open(&bad, &ctx()).is_err());
    assert!(
        session
            .record(&session.page(None, 0, 1).unwrap().items[0].id)
            .unwrap()
            .is_some()
    );
    let external = ProjectService::open(&save_as, &ctx()).unwrap();
    append(&external, "other", "external changes");
    ProjectService::save(&external, &save_as, &config, false, &ctx()).unwrap();
    assert!(ProjectService::save(&session, &save_as, &config, false, &ctx()).is_err());
}
#[test]
fn project_scope_ai_freeze_streaming_reports_and_filters() {
    let a = create();
    let b = create();
    append(&a, "host-a", "first example.com\nother data");
    append(&a, "host-b", "first example.com\nother data");
    assert_eq!(a.overview(&ctx()).unwrap().sources, 2);
    let selected = a
        .query(
            &QueryOptions {
                expression: Some("first".into()),
                ..Default::default()
            },
            &ctx(),
        )
        .unwrap();
    assert!(b.page(Some(&selected), 0, 10).is_err());
    a.set_selection(Some(&selected), &ctx()).unwrap();
    let config = core::ai::AiConfig {
        base_url: "http://127.0.0.1:1".into(),
        api_key: "synthetic".into(),
        ..Default::default()
    };
    let options = AiOptions {
        config_path: "unused".into(),
        scope: AiScope::All,
        include_payload: false,
    };
    let prepared =
        AnalysisService::prepare_ai_with_config(&a, &options, None, &config, &ctx()).unwrap();
    append(&a, "host-c", "new");
    assert!(
        AnalysisService::analyze_prepared_ai(prepared, &ctx())
            .err()
            .unwrap()
            .to_string()
            .contains("预览")
    );
    let mut json = Vec::new();
    ExportPlan {
        format: OutputFormat::Json,
        ..Default::default()
    }
    .write_primary(&a, &mut json, &ctx())
    .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(
        report["records"].as_array().unwrap().len(),
        a.overview(&ctx()).unwrap().records
    );
    assert_eq!(
        report["query_matches"].as_array().unwrap().len(),
        selected.len()
    );
    assert!(report.get("project").is_none());
    let mut html = Vec::new();
    ExportPlan {
        format: OutputFormat::Html,
        ..Default::default()
    }
    .write_primary(&a, &mut html, &ctx())
    .unwrap();
    let html = String::from_utf8(html).unwrap();
    assert!(html.contains("合成客户甲"));
    assert!(html.contains("&lt;script&gt;"));
    assert!(!html.contains("合成响应 <script>"));
    ProjectService::save_view_state(&a, &serde_json::json!({"logs":{"text":"first"}})).unwrap();
    assert!(ProjectService::view_state(&a).unwrap().is_some());
    let query = QueryOptions {
        expression: Some("first".into()),
        ..Default::default()
    };
    ProjectService::save_query_options(&a, &query).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("filters.eair");
    ProjectService::save(&a, &path, Path::new("config"), false, &ctx()).unwrap();
    let restored = ProjectService::open(&path, &ctx()).unwrap();
    assert_eq!(
        ProjectService::query_options(&restored)
            .unwrap()
            .unwrap()
            .expression,
        query.expression
    );
    let selected = restored.query(&query, &ctx()).unwrap();
    let first = restored.page(Some(&selected), 0, 1).unwrap().items[0]
        .id
        .clone();
    assert_ne!(
        restored.page(Some(&selected), 1, 1).unwrap().items[0].id,
        first
    );
}
#[test]
fn mixed_ioc_inputs_notes_and_cancel_coverage() {
    let session = create();
    let lines = (0..600)
        .map(|i| format!("line {i} example.com 2001:db8::1"))
        .collect::<Vec<_>>()
        .join("\n");
    append(&session, "host-a", &lines);
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("iocs.csv");
    std::fs::write(
        &input,
        "type,value,note\ndomain,example.com,\"file, note\"\nip,bad,invalid\n",
    )
    .unwrap();
    assert_eq!(
        IocService::add_file(&session, &input, &ctx())
            .unwrap()
            .issues
            .len(),
        1
    );
    IocService::add_value(&session, "EXAMPLE.com", None, "", &ctx()).unwrap();
    IocService::add_text(&session, "2001:db8::1", false, "paste", &ctx()).unwrap();
    assert_eq!(IocService::indicators(&session, 0, 100).unwrap().total, 2);
    let mixed = IocService::import(
        &session,
        &[
            IocSource::File(dir.path().join("missing.csv")),
            IocSource::Value {
                value: "invalid/value".into(),
                kind: None,
                note: String::new(),
            },
            IocSource::Text {
                text: "EXAMPLE.com".into(),
                csv: false,
                origin: "paste".into(),
            },
        ],
        &ctx(),
    )
    .unwrap();
    assert_eq!(mixed.issues.len(), 2);
    assert_eq!(IocService::indicators(&session, 0, 100).unwrap().total, 2);
    assert!(IocService::add_text(&session, "bad/input", false, "paste", &ctx()).is_err());
    assert_eq!(IocService::indicators(&session, 0, 100).unwrap().total, 2);
    let token = CancellationToken::default();
    let trigger = token.clone();
    let run = IocService::scan(
        &session,
        true,
        &ExecutionContext::new(token, move |p| {
            if p.stage == Stage::Rules && p.completed >= 300 {
                trigger.cancel();
            }
        }),
    )
    .unwrap();
    assert!(!run.complete);
    assert_eq!(run.scanned_records, 300);
    assert_eq!(IocService::matches(&session, 0, 100).unwrap().total, 600);
    IocService::scan(&session, true, &ctx()).unwrap();
    let token = CancellationToken::default();
    let trigger = token.clone();
    IocService::scan(
        &session,
        true,
        &ExecutionContext::new(token, move |p| {
            if p.stage == Stage::Rules && p.completed >= 20 {
                trigger.cancel();
            }
        }),
    )
    .unwrap();
    // Earlier valid hits outside the new scan's coverage remain available.
    assert_eq!(IocService::matches(&session, 0, 100).unwrap().total, 1200);
    IocService::scan(&session, true, &ctx()).unwrap();
    assert_eq!(IocService::matches(&session, 0, 100).unwrap().total, 1200);
    let id = IocService::indicators(&session, 0, 100)
        .unwrap()
        .items
        .into_iter()
        .find(|i| i.kind == IocType::Domain)
        .unwrap()
        .id;
    IocService::edit_note(&session, &id, "edited note", &ctx()).unwrap();
    assert!(
        IocService::matches(&session, 0, 100)
            .unwrap()
            .items
            .iter()
            .filter(|h| h.indicator_id == id)
            .all(|h| h.note == "edited note")
    );
    let p = dir.path().join("a.eair");
    assert!(ProjectService::save(&session, &input, Path::new("config"), true, &ctx()).is_err());
    ProjectService::save(&session, &p, Path::new("config"), false, &ctx()).unwrap();
    let changed = rusqlite::Connection::open(&p).unwrap();
    changed.execute_batch("DROP INDEX record_category").unwrap();
    drop(changed);
    assert!(ProjectService::open(&p, &ctx()).is_err());
}

#[test]
fn overview_cache_refreshes_after_append_and_ioc_changes() {
    let session = create();
    append(&session, "a", "example.com\nsecond line");
    let first = session.overview(&ctx()).unwrap();
    assert_eq!(first.records, 2);
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(session.overview(&ctx()).unwrap()).unwrap()
    );
    append(&session, "b", "example.com");
    let second = session.overview(&ctx()).unwrap();
    assert_eq!(second.records, 3);
    assert_eq!(second.sources, 2);
    assert_eq!(second.logs, 3);
    assert_eq!(second.parse_counts.iter().sum::<usize>(), 3);
    IocService::add_value(&session, "example.com", None, "", &ctx()).unwrap();
    IocService::scan(&session, true, &ctx()).unwrap();
    let third = session.overview(&ctx()).unwrap();
    assert!(third.local_findings > second.local_findings);
    assert!(third.suspicious > second.suspicious);
}

#[test]
fn open_snapshots_are_independent_and_include_uncheckpointed_wal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snapshot.eair");
    let session = create();
    append(&session, "a", "first evidence");
    ProjectService::save(&session, &path, Path::new("config"), false, &ctx()).unwrap();
    let original = std::fs::read(&path).unwrap();
    let a = ProjectService::open(&path, &ctx()).unwrap();
    let b = ProjectService::open(&path, &ctx()).unwrap();
    let id = a.page(None, 0, 1).unwrap().items[0].id.clone();
    ProjectService::note(&a, &id, "only in working copy A", &ctx()).unwrap();
    append(&a, "new", "second evidence");
    assert_eq!(a.overview(&ctx()).unwrap().records, 2);
    assert_eq!(b.overview(&ctx()).unwrap().records, 1);
    assert_eq!(ProjectService::read_note(&b, &id).unwrap(), None);
    assert_eq!(std::fs::read(&path).unwrap(), original);

    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch("PRAGMA journal_mode=WAL;PRAGMA wal_autocheckpoint=0;")
        .unwrap();
    let diagnostic = serde_json::to_string(&core::Diagnostic {
        source: "snapshot regression".into(),
        position: None,
        level: DiagnosticLevel::Warning,
        message: "committed WAL evidence".into(),
    })
    .unwrap();
    c.execute("INSERT INTO diagnostics(json) VALUES(?1)", [diagnostic])
        .unwrap();
    let reopened = ProjectService::open(&path, &ctx()).unwrap();
    let diagnostics = reopened.diagnostic_page(0, 100).unwrap();
    assert!(
        diagnostics
            .items
            .iter()
            .any(|d| d.message == "committed WAL evidence")
    );
    assert!(!ProjectService::status(&reopened).unwrap().dirty);
}

#[test]
fn ai_summary_lookup_is_bounded_cached_and_keeps_latest_message() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("summaries.eair");
    let session = create();
    ProjectService::save(&session, &path, Path::new("config"), false, &ctx()).unwrap();
    let c = rusqlite::Connection::open(&path).unwrap();
    for (source, position, message) in [
        ("parser", "line:1", "unrelated"),
        ("AI 本地整理", "ai-run:1", "old"),
        ("AI 本地整理", "ai-run:2", "second"),
        ("AI 本地整理", "ai-run:1", "latest"),
    ] {
        let diagnostic = serde_json::to_string(&core::Diagnostic {
            source: source.into(),
            position: Some(position.into()),
            level: DiagnosticLevel::Warning,
            message: message.into(),
        })
        .unwrap();
        c.execute("INSERT INTO diagnostics(json) VALUES(?1)", [diagnostic])
            .unwrap();
    }
    drop(c);
    let reopened = ProjectService::open(&path, &ctx()).unwrap();
    assert!(reopened.ai_local_summaries(&[], &ctx()).unwrap().is_empty());
    let first = reopened.ai_local_summaries(&[0], &ctx()).unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first["ai-run:1"], "latest");
    assert_eq!(
        reopened.ai_local_summaries(&[1], &ctx()).unwrap()["ai-run:2"],
        "second"
    );
    let cancelled = CancellationToken::default();
    cancelled.cancel();
    assert!(
        reopened
            .ai_local_summaries(&[0], &ExecutionContext::new(cancelled, |_| {}))
            .is_err()
    );
    assert_eq!(reopened.ai_local_summaries(&[0], &ctx()).unwrap(), first);
}

#[test]
fn empty_ai_history_does_not_read_unrequested_diagnostics() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("no-ai.eair");
    let session = create();
    ProjectService::save(&session, &path, Path::new("config"), false, &ctx()).unwrap();
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute(
        "INSERT INTO diagnostics(json) VALUES('invalid diagnostic JSON')",
        [],
    )
    .unwrap();
    drop(c);
    let reopened = ProjectService::open(&path, &ctx()).unwrap();
    assert!(reopened.diagnostic_page(0, 1).is_err());
    assert!(reopened.ai_run_headers().unwrap().is_empty());
    assert!(reopened.ai_local_summaries(&[], &ctx()).unwrap().is_empty());
}

#[test]
fn compressed_project_preserves_unicode_records_queries_notes_and_reports() {
    let session = create();
    let lines = (0..300)
        .map(|i| {
            format!(
                "证据编号 {i} {} example.com",
                "相同业务日志，保持原文；".repeat(40)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    append(&session, "compressed-unicode", &lines);
    let id = session.page(None, 0, 1).unwrap().items[0].id.clone();
    ProjectService::note(&session, &id, "备注完整保留", &ctx()).unwrap();
    IocService::add_value(&session, "example.com", None, "域名 IOC", &ctx()).unwrap();
    IocService::scan(&session, true, &ctx()).unwrap();
    let snapshot = |session: &AnalysisSession| {
        let mut report = Vec::new();
        ExportPlan {
            format: OutputFormat::Json,
            ..Default::default()
        }
        .write_primary(session, &mut report, &ctx())
        .unwrap();
        report
    };
    let before = snapshot(&session);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("compressed.eair");
    ProjectService::save(&session, &path, Path::new("config"), false, &ctx()).unwrap();
    let c = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        c.pragma_query_value(None, "user_version", |r| r.get::<_, i32>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        c.query_row(
            "SELECT COUNT(*) FROM records WHERE typeof(raw)='blob' AND preview=''",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        300
    );
    drop(c);
    let reopened = ProjectService::open(&path, &ctx()).unwrap();
    assert_eq!(before, snapshot(&reopened));
    assert_eq!(
        ProjectService::read_note(&reopened, &id).unwrap().unwrap(),
        "备注完整保留"
    );
    assert_eq!(IocService::matches(&reopened, 0, 100).unwrap().total, 300);
    assert_eq!(
        reopened
            .query(
                &QueryOptions {
                    expression: Some("证据编号 299".into()),
                    ..Default::default()
                },
                &ctx()
            )
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        reopened.page_metadata(None, 200, 100).unwrap().items.len(),
        100
    );
    assert_eq!(
        reopened.record(&id).unwrap().unwrap().raw,
        session.record(&id).unwrap().unwrap().raw
    );
}

#[test]
fn previous_project_format_is_rejected_before_loading_evidence() {
    let session = create();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unsupported.eair");
    ProjectService::save(&session, &path, Path::new("config"), false, &ctx()).unwrap();
    let c = rusqlite::Connection::open(&path).unwrap();
    c.pragma_update(None, "user_version", 1).unwrap();
    drop(c);
    assert!(
        ProjectService::open(&path, &ctx())
            .err()
            .unwrap()
            .to_string()
            .contains("不支持该项目文件版本")
    );
}
