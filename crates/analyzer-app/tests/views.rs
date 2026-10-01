use analyzer_app::{
    core::{ParseStatus, RecordData},
    *,
};
use std::path::Path;
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
#[test]
fn typed_filters_counts_and_locating_are_session_bound() {
    let session = load(&["auth.log", "access.log", "processes.json", "sample.pcapng"]);
    let ctx = ExecutionContext::default();
    let overview = session.overview(&ctx).unwrap();
    assert_eq!(
        overview.records,
        overview.logs + overview.processes + overview.packets
    );
    assert_eq!(
        overview.parse_counts.iter().sum::<usize>(),
        overview.records
    );
    let logs = session
        .select_records(
            &RecordFilter {
                kind: RecordKind::Log,
                ..Default::default()
            },
            &ctx,
        )
        .unwrap();
    assert_eq!(logs.len(), overview.logs);
    let first = session.page(Some(&logs), 0, 1).unwrap().items.remove(0);
    let source = session
        .select_records(
            &RecordFilter {
                kind: RecordKind::Log,
                source: Some(first.source_id.clone()),
                status: Some(ParseStatus::Parsed),
                ..Default::default()
            },
            &ctx,
        )
        .unwrap();
    assert!(
        session
            .page(Some(&source), 0, 100)
            .unwrap()
            .items
            .iter()
            .all(|r| r.source_id == first.source_id && r.status == ParseStatus::Parsed)
    );
    assert_eq!(
        session.locate_record(Some(&logs), &first.id).unwrap(),
        Some(0)
    );
    let foreign = load(&["auth.log"])
        .select_records(&RecordFilter::default(), &ctx)
        .unwrap();
    assert!(session.flow_page(Some(&foreign), 0, 100, &ctx).is_err());
    assert!(session.locate_record(Some(&foreign), &first.id).is_err());
    let filtered = session
        .finding_page(
            &FindingFilter {
                origin: FindingOrigin::Local,
                ..Default::default()
            },
            0,
            100,
            &ctx,
        )
        .unwrap();
    assert!(
        filtered
            .items
            .iter()
            .all(|f| f.origin.starts_with("local:"))
    );
}
#[test]
fn flow_intersection_preserves_full_statistics() {
    let session = load(&["sample.pcapng"]);
    let ctx = ExecutionContext::default();
    let all = session.flow_page(None, 0, 100, &ctx).unwrap();
    let f = &all.items[0];
    let selected = session.flow_selection(f.key, None, &ctx).unwrap();
    let one = session.select_ids([selected.ids()[0].clone()]).unwrap();
    let page = session.flow_page(Some(&one), 0, 100, &ctx).unwrap();
    assert_eq!(page.items[0].matched_packets, 1);
    assert_eq!(page.items[0].packets, f.packets);
    assert_eq!(
        session
            .flow_selection(f.key, Some(&one), &ctx)
            .unwrap()
            .len(),
        1
    );
    let metadata = session.page_metadata(Some(&one), 0, 1).unwrap();
    let original = session.record(&metadata.items[0].id).unwrap().unwrap();
    let legacy = session.page(Some(&one), 0, 1).unwrap();
    let RecordData::Packet(metadata_packet) = &metadata.items[0].data else {
        panic!("expected packet");
    };
    let RecordData::Packet(full_packet) = &original.data else {
        panic!("expected packet");
    };
    let RecordData::Packet(legacy_packet) = &legacy.items[0].data else {
        panic!("expected packet");
    };
    assert!(metadata_packet.payload_hex.is_empty());
    assert!(!full_packet.payload_hex.is_empty());
    assert_eq!(legacy_packet.payload_hex, full_packet.payload_hex);
    assert_eq!(metadata_packet.application, full_packet.application);
}
#[test]
fn hundred_thousand_records_page_and_cancel() {
    let bytes = (0..100_000)
        .map(|i| format!("row {i} {}\n", if i % 2 == 0 { "needle" } else { "other" }))
        .collect::<String>()
        .into_bytes();
    let session = AnalysisService::load(
        &AnalysisRequest {
            inputs: vec![AnalysisInput::Bytes {
                label: "large.log".into(),
                bytes: bytes.into(),
            }],
            ..Default::default()
        },
        &ExecutionContext::default(),
    )
    .unwrap()
    .session;
    let ctx = ExecutionContext::default();
    let selected = session
        .select_records(
            &RecordFilter {
                query: QueryOptions {
                    expression: Some("needle".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
            &ctx,
        )
        .unwrap();
    assert_eq!(selected.len(), 50_000);
    let page = session.page(Some(&selected), 49_900, 100).unwrap();
    assert_eq!(page.total, 50_000);
    assert_eq!(page.items.len(), 100);
    assert!(matches!(page.items[0].data, RecordData::Log(_)));
    let token = CancellationToken::default();
    token.cancel();
    let cancelled = ExecutionContext::new(token, |_| {});
    assert!(session.overview(&cancelled).is_err());
    assert!(session.process_rows(&selected, &cancelled).is_err());
}
#[test]
fn process_context_is_not_an_ai_match() {
    let session = load(&["processes.json"]);
    let ctx = ExecutionContext::default();
    let selected = session
        .select_records(
            &RecordFilter {
                kind: RecordKind::Process,
                query: QueryOptions {
                    expression: Some("powershell".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
            &ctx,
        )
        .unwrap();
    assert_eq!(selected.len(), 1);
    let rows = session.process_rows(&selected, &ctx).unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows.iter().filter(|r| !r.context).count(), 1);
}
