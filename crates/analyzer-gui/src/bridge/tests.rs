use super::*;
fn load(names: &[&str]) -> AnalysisSession {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    AnalysisService::load(
        &AnalysisRequest {
            inputs: names
                .iter()
                .map(|n| AnalysisInput::File(root.join(n)))
                .collect(),
            ..Default::default()
        },
        &ExecutionContext::default(),
    )
    .unwrap()
    .session
}
fn request(session: &AnalysisSession, screen: Screen) -> ViewRequest {
    ViewRequest {
        session_id: session.id(),
        revision: 1,
        screen,
        filters: Filters::default(),
        focus_id: None,
        commit_selection: true,
        source_offset: 0,
        diagnostic_offset: 0,
        run_offset: 0,
    }
}
fn publish(
    desktop: &Desktop,
    session: &AnalysisSession,
    request: &ViewRequest,
) -> Result<ViewResponse> {
    let (mut view, selected) = build_view(session, request, &ExecutionContext::default())?;
    commit_view(desktop, session, request, &mut view, selected)?;
    Ok(view)
}
#[test]
#[ignore = "set EASY_ANALYZER_BENCH_PROJECT to a local .eair file"]
fn benchmark_large_project_overview() {
    use std::time::Instant;
    let path = std::env::var_os("EASY_ANALYZER_BENCH_PROJECT").expect("project path required");
    let ctx = ExecutionContext::default();
    let start = Instant::now();
    let session = ProjectService::open(Path::new(&path), &ctx).unwrap();
    println!("open_seconds={:.3}", start.elapsed().as_secs_f64());
    for n in 1..=2 {
        let start = Instant::now();
        let (view, _) = build_view(&session, &request(&session, Screen::Overview), &ctx).unwrap();
        println!(
            "overview_{n}_seconds={:.3} records={} diagnostics={}",
            start.elapsed().as_secs_f64(),
            view.overview.records,
            view.diagnostics.total
        );
    }
}

#[test]
#[ignore = "set EASY_ANALYZER_BENCH_PROJECT to a local .eair file"]
fn benchmark_large_project_modules() {
    let path = std::env::var_os("EASY_ANALYZER_BENCH_PROJECT").expect("project path required");
    let ctx = ExecutionContext::default();
    let session = ProjectService::open(Path::new(&path), &ctx).unwrap();
    let mut selections = Vec::new();
    for screen in [
        Screen::Overview,
        Screen::Logs,
        Screen::Processes,
        Screen::Network,
        Screen::Ai,
        Screen::Reports,
        Screen::Settings,
    ] {
        for n in 0..2 {
            let mut req = request(&session, screen);
            req.filters.offset = n * 100;
            let start = Instant::now();
            let (view, selection) = build_view(&session, &req, &ctx).unwrap();
            println!(
                "screen={screen:?} page={n} seconds={:.3} items={}",
                start.elapsed().as_secs_f64(),
                view.records.as_ref().map_or(0, |p| p.items.len())
            );
            selections.push(selection);
            ProjectService::save_view_state(
                &session,
                &serde_json::json!({"screen":screen,"offset":req.filters.offset}),
            )
            .unwrap();
        }
    }
    let mut req = request(&session, Screen::Reports);
    req.diagnostic_offset = session
        .diagnostic_page(0, 1)
        .unwrap()
        .total
        .saturating_sub(50);
    let start = Instant::now();
    build_view(&session, &req, &ctx).unwrap();
    println!(
        "deep_diagnostics_seconds={:.3}",
        start.elapsed().as_secs_f64()
    );
}

#[test]
#[ignore = "synthetic 10000-process and 10000-packet module benchmark"]
fn benchmark_synthetic_modules() {
    let ctx = ExecutionContext::default();
    let session = ProjectService::create(ProjectInfo::new("合成模块性能验证", "合成客户")).unwrap();
    let processes = (0..10000).map(|i| serde_json::json!({"pid":i,"parent_pid":if i==0 {None} else {Some((i-1)/2)},"name":format!("synthetic-process-{i}"),"command":[]})).collect::<Vec<_>>();
    let fixture =
        fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sample.pcap"))
            .unwrap();
    let mut packets = fixture[..24].to_vec();
    for _ in 0..10000 {
        packets.extend_from_slice(&fixture[24..]);
    }
    let start = Instant::now();
    ProjectService::append(
        &session,
        &AnalysisRequest {
            inputs: vec![
                AnalysisInput::Bytes {
                    label: "synthetic-processes.json".into(),
                    bytes: serde_json::to_vec(&processes).unwrap().into(),
                },
                AnalysisInput::Bytes {
                    label: "synthetic-packets.pcap".into(),
                    bytes: packets.into(),
                },
            ],
            ..Default::default()
        },
        &ctx,
    )
    .unwrap();
    println!(
        "synthetic_import_seconds={:.3}",
        start.elapsed().as_secs_f64()
    );
    let overview = session.overview(&ctx).unwrap();
    println!(
        "synthetic_processes={} packets={}",
        overview.processes, overview.packets
    );
    assert_eq!(overview.processes, 10000);
    assert!(overview.packets >= 10000);
    for screen in [
        Screen::Overview,
        Screen::Processes,
        Screen::Network,
        Screen::Ai,
        Screen::Reports,
        Screen::Settings,
    ] {
        for n in 0..2 {
            let mut req = request(&session, screen);
            req.filters.offset = n * 100;
            let start = Instant::now();
            let (view, _) = build_view(&session, &req, &ctx).unwrap();
            println!(
                "synthetic_screen={screen:?} page={n} seconds={:.3}",
                start.elapsed().as_secs_f64()
            );
            if screen == Screen::Processes {
                assert_eq!(view.records.unwrap().total, 10000);
            }
        }
    }
}
#[test]
fn ai_page_excludes_local_findings_without_removing_them_from_session() {
    let session = load(&["auth.log"]);
    let ctx = ExecutionContext::default();
    let (overview, _) = build_view(&session, &request(&session, Screen::Overview), &ctx).unwrap();
    assert!(overview.findings.unwrap().total > 0);
    let mut ai = request(&session, Screen::Ai);
    // Even an old frontend's explicit local/all filter cannot mix local results into AI pages.
    for origin in ["all", "local", "ai"] {
        ai.filters.origin = origin.into();
        let (view, _) = build_view(&session, &ai, &ctx).unwrap();
        assert_eq!(view.findings.unwrap().total, 0);
    }
    let (overview, _) = build_view(&session, &request(&session, Screen::Overview), &ctx).unwrap();
    assert!(overview.findings.unwrap().total > 0);
}
#[test]
fn page_does_not_limit_ai_selection_and_bad_query_keeps_valid_scope() {
    let text = (0..175)
        .map(|i| format!("record {i} needle\n"))
        .collect::<String>();
    let session = AnalysisService::load(
        &AnalysisRequest {
            inputs: vec![AnalysisInput::Bytes {
                label: "large.log".into(),
                bytes: text.into_bytes().into(),
            }],
            ..Default::default()
        },
        &ExecutionContext::default(),
    )
    .unwrap()
    .session;
    let desktop = Desktop::new(PathBuf::new(), Args::default());
    {
        let mut s = desktop.lock().unwrap();
        s.session = Some(session.clone());
        s.latest_view = 1;
    }
    let mut req = request(&session, Screen::Logs);
    req.filters.limit = 50;
    req.filters.text = "needle".into();
    let view = publish(&desktop, &session, &req).unwrap();
    assert_eq!(view.records.as_ref().unwrap().items.len(), 50);
    assert_eq!(view.selection.count, 175);
    let valid = view.selection.id;
    req.filters.text = "[".into();
    req.filters.regex = true;
    assert!(publish(&desktop, &session, &req).is_err());
    assert_eq!(desktop.lock().unwrap().selection_info.id, valid);
    assert_eq!(
        desktop.lock().unwrap().selection.as_ref().unwrap().len(),
        175
    );
}
#[test]
fn focus_outside_filter_and_return_preserve_selection() {
    let session = load(&["auth.log"]);
    let desktop = Desktop::new(PathBuf::new(), Args::default());
    {
        let mut s = desktop.lock().unwrap();
        s.session = Some(session.clone());
        s.latest_view = 1;
    }
    let all = session.page(None, 0, 100).unwrap();
    let target = all.items.last().unwrap().id.clone();
    let mut req = request(&session, Screen::Logs);
    req.filters.text = "never-match-this".into();
    let initial = publish(&desktop, &session, &req).unwrap();
    assert_eq!(initial.selection.count, 0);
    req.focus_id = Some(target.clone());
    let focused = publish(&desktop, &session, &req).unwrap();
    assert!(focused.outside);
    assert_eq!(focused.records.unwrap().items[0].id, target);
    assert_eq!(focused.selection.id, initial.selection.id);
    req.focus_id = None;
    let restored = publish(&desktop, &session, &req).unwrap();
    assert_eq!(restored.records.unwrap().total, 0);
}
#[test]
fn old_session_and_old_revision_cannot_commit() {
    let session = load(&["auth.log"]);
    let desktop = Desktop::new(PathBuf::new(), Args::default());
    let req = request(&session, Screen::Logs);
    {
        let mut s = desktop.lock().unwrap();
        s.session = Some(session.clone());
        s.latest_view = 2;
    }
    assert!(publish(&desktop, &session, &req).is_err());
    {
        let mut s = desktop.lock().unwrap();
        s.session = Some(load(&["access.log"]));
        s.latest_view = 1;
    }
    assert!(publish(&desktop, &session, &req).is_err());
    assert_eq!(desktop.lock().unwrap().selection_info.id, 0);
}
#[test]
fn packet_pages_omit_payload_and_raw_but_detail_is_complete() {
    let session = load(&["sample.pcapng"]);
    let req = request(&session, Screen::Network);
    let (view, _) = build_view(&session, &req, &ExecutionContext::default()).unwrap();
    let page = view.records.unwrap();
    let serialized = serde_json::to_value(&page).unwrap();
    assert!(serialized["items"][0].get("raw").is_none());
    for r in page.items {
        if let core::RecordData::Packet(p) = r.data {
            assert!(p.payload_hex.is_empty());
        }
    }
    assert!(
        !session
            .record(serialized["items"][0]["id"].as_str().unwrap())
            .unwrap()
            .unwrap()
            .raw
            .is_empty()
    );
}
#[test]
fn process_context_never_expands_selection_and_collapse_is_presentation_only() {
    let session = load(&["processes.json"]);
    let mut req = request(&session, Screen::Processes);
    req.filters.text = "powershell".into();
    let (view, selected) = build_view(&session, &req, &ExecutionContext::default()).unwrap();
    let selected = selected.unwrap();
    assert!(view.process_rows.iter().any(|r| r.context));
    assert!(view.process_rows.len() > selected.len());
    req.filters.collapsed = view
        .process_rows
        .iter()
        .filter(|r| r.has_children)
        .map(|r| r.record_id.clone())
        .collect();
    let (_, collapsed) = build_view(&session, &req, &ExecutionContext::default()).unwrap();
    assert_eq!(selected.ids(), collapsed.unwrap().ids());
}
#[test]
fn config_transport_redacts_keys_and_explicit_actions_preserve_or_clear() {
    let original = core::ai::AiConfig {
        api_key: "sk-synthetic-private-key".into(),
        ..Default::default()
    };
    let public = PublicConfig::from(&original);
    let json = serde_json::to_string(&public).unwrap();
    assert!(!json.contains("sk-synthetic"));
    assert!(public.api_key_configured);
    let make = |action: &str, value: &str| ConfigInput {
        base_url: original.base_url.clone(),
        model: original.model.clone(),
        api_key_env: String::new(),
        timeout_seconds: original.timeout_seconds,
        batch_bytes: original.batch_bytes,
        context_tokens: original.context_tokens,
        max_output_tokens: original.max_output_tokens,
        response_format: original.response_format.clone(),
        token_parameter: original.token_parameter.clone(),
        key_action: action.into(),
        key_value: value.into(),
    };
    assert_eq!(
        make("keep", "").apply(&original).unwrap().api_key,
        original.api_key
    );
    assert_eq!(
        make("replace", "sk-replacement")
            .apply(&original)
            .unwrap()
            .api_key,
        "sk-replacement"
    );
    assert!(
        make("clear", "")
            .apply(&original)
            .unwrap()
            .api_key
            .is_empty()
    );
    let legacy = core::ai::AiConfig {
        api_key_env: "sk-accidentally-in-env-field".into(),
        ..Default::default()
    };
    assert!(
        !serde_json::to_string(&PublicConfig::from(&legacy))
            .unwrap()
            .contains("sk-accidentally")
    );
}

#[test]
fn ai_preview_rejects_changed_settings_payload_selection_or_session() {
    let session = load(&["auth.log"]);
    let desktop = Desktop::new(PathBuf::new(), Args::default());
    let mut state = desktop.lock().unwrap();
    state.session = Some(session.clone());
    state.config_loaded = true;
    let request = AiRequest {
        session_id: session.id(),
        scope: "all".into(),
        selection_id: None,
        include_payload: false,
        plan_id: Some(9),
    };
    let prepared = AnalysisService::prepare_ai_with_config(
        &session,
        &AiOptions {
            config_path: "unused".into(),
            scope: AiScope::All,
            include_payload: false,
        },
        None,
        &state.config,
        &ExecutionContext::default(),
    )
    .unwrap();
    state.ai_preview = Some(FrozenAi {
        id: 9,
        request: request.clone(),
        config: state.config.clone(),
        epoch: state.epoch,
        prepared,
    });
    let mut changed = request.clone();
    changed.include_payload = true;
    assert!(take_ai_plan(&mut state, &changed).is_err());
    changed = request.clone();
    changed.plan_id = Some(8);
    assert!(take_ai_plan(&mut state, &changed).is_err());
    changed = request.clone();
    changed.session_id += 1;
    assert!(take_ai_plan(&mut state, &changed).is_err());
    changed = request.clone();
    changed.scope = "matches".into();
    changed.selection_id = Some(123);
    assert!(take_ai_plan(&mut state, &changed).is_err());
    state.config.model = "changed".into();
    assert!(take_ai_plan(&mut state, &request).is_err());
    state.config.model = state.ai_preview.as_ref().unwrap().config.model.clone();
    state.epoch += 1;
    assert!(take_ai_plan(&mut state, &request).is_err());
    state.epoch -= 1;
    assert_eq!(
        take_ai_plan(&mut state, &request)
            .unwrap()
            .plan()
            .selected_records,
        session.page(None, 0, 100).unwrap().total
    );
    assert!(take_ai_plan(&mut state, &request).is_err());
}
#[test]
fn database_project_pages_notes_and_stale_views_are_isolated() {
    let first = ProjectService::create(ProjectInfo::new("合成甲响应", "合成甲客户")).unwrap();
    let second = ProjectService::create(ProjectInfo::new("合成乙响应", "合成乙客户")).unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    ProjectService::append(
        &first,
        &AnalysisRequest {
            inputs: vec![
                AnalysisInput::File(root.join("auth.log")),
                AnalysisInput::File(root.join("sample.pcap")),
            ],
            ..Default::default()
        },
        &ExecutionContext::default(),
    )
    .unwrap();
    let (view, selection) = build_view(
        &first,
        &request(&first, Screen::Logs),
        &ExecutionContext::default(),
    )
    .unwrap();
    assert!(view.project.is_some());
    assert!(!selection.unwrap().is_empty());
    assert!(view.records.as_ref().unwrap().total > 0);
    let id = view.records.unwrap().items[0].id.clone();
    ProjectService::note(&first, &id, "合成备注", &ExecutionContext::default()).unwrap();
    assert!(ProjectService::read_note(&second, &id).unwrap().is_none());
    let desktop = Desktop::new(PathBuf::new(), Args::default());
    {
        let mut s = desktop.lock().unwrap();
        s.session = Some(second);
        s.latest_view = 1;
    }
    let (mut stale, selected) = build_view(
        &first,
        &request(&first, Screen::Logs),
        &ExecutionContext::default(),
    )
    .unwrap();
    assert!(
        commit_view(
            &desktop,
            &first,
            &request(&first, Screen::Logs),
            &mut stale,
            selected
        )
        .is_err()
    );
}
