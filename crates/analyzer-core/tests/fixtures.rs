use analyzer_core::{
    collect,
    ingest::{IngestOptions, InputFormat, ingest_bytes, ingest_file},
    model::*,
    report, rules,
};
use std::path::{Path, PathBuf};
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}
fn load(name: &str) -> AnalysisReport {
    ingest_file(&fixture(name), &IngestOptions::default()).unwrap()
}
#[test]
fn synthetic_evtx_records_and_auth_rules() {
    let mut r = load("synthetic.evtx");
    assert_eq!(r.records.len(), 7);
    assert!(r.diagnostics.is_empty(), "{:?}", r.diagnostics);
    rules::analyze(&mut r);
    assert!(
        r.findings
            .iter()
            .any(|f| f.origin == "local:login-failures")
    );
    assert!(
        r.findings
            .iter()
            .any(|f| f.origin == "local:success-after-failures")
    );
    if let RecordData::Log(l) = &r.records[0].data {
        assert_eq!(l.fields["event_id"], "4625");
        assert_eq!(l.fields["user"], "demo");
    } else {
        panic!();
    }
}
#[test]
fn empty_and_bad_evtx() {
    assert!(load("empty.evtx").records.is_empty());
    assert!(ingest_file(&fixture("malformed.evtx"), &IngestOptions::default()).is_err());
}
#[test]
fn all_login_variants() {
    for (name, count) in [("sample.utmp", 1), ("sample.wtmp", 1), ("sample.btmp", 6)] {
        let r = load(name);
        assert_eq!(r.records.len(), count);
        assert!(r.records.iter().all(|r| r.status == ParseStatus::Parsed));
        assert!(r.records[0].raw.len() == 768);
    }
}
#[test]
fn mixed_text_bad_record_and_query() {
    let mut r = load("access.log");
    assert_eq!(r.records.len(), 3);
    assert_eq!(r.records[2].status, ParseStatus::Unrecognized);
    rules::analyze(&mut r);
    assert!(r.findings.iter().any(|f| f.origin == "local:web-probe"));
    assert_eq!(rules::query(&r.records, "%2e%2e", false).unwrap().len(), 1);
    assert!(report::html(&r).contains("&lt;script&gt;"));
    assert!(load("empty.log").records.is_empty());
}
#[test]
fn custom_definition() {
    let opts = IngestOptions {
        web_format: Some(std::fs::read_to_string(fixture("custom-format.conf")).unwrap()),
        ..Default::default()
    };
    let r = ingest_file(&fixture("custom.log"), &opts).unwrap();
    if let RecordData::Log(l) = &r.records[0].data {
        assert_eq!(l.fields["uri"], "/.env");
        assert_eq!(l.fields["status"], "403");
    } else {
        panic!();
    }
    assert!(r.records[0].timestamp.is_some());
}
#[test]
fn pcap_ng_sections_and_truncation() {
    let a = load("sample.pcap");
    let b = load("sample.pcapng");
    assert_eq!(a.records.len(), 1);
    assert_eq!(b.records.len(), 2);
    assert!(b.diagnostics.is_empty(), "{:?}", b.diagnostics);
    assert_eq!(a.records[0].timestamp, b.records[0].timestamp);
    assert_eq!(b.records[0].timestamp, b.records[1].timestamp);
    if let RecordData::Packet(p) = &a.records[0].data {
        assert_eq!(p.application["uri"], "/.env");
        assert_eq!(p.destination_port, Some(80));
    } else {
        panic!();
    }
    let t = load("truncated.pcap");
    assert_eq!(t.records[0].status, ParseStatus::Malformed);
    assert!(!t.diagnostics.is_empty());
}
#[test]
fn imported_processes_roundtrip_and_rules() {
    let mut r = load("processes.json");
    rules::analyze(&mut r);
    assert_eq!(r.records.len(), 3);
    assert!(
        r.findings
            .iter()
            .any(|f| f.origin == "local:process-temp-path")
    );
    assert!(
        r.findings
            .iter()
            .any(|f| f.origin == "local:process-command")
    );
    let json = serde_json::to_vec(&r).unwrap();
    let restored = ingest_bytes(
        "snapshot.json",
        &json,
        &IngestOptions {
            format: InputFormat::Processes,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(restored.records.len(), 3);
    assert!(collect::process_tree(&restored.records).contains("100 demo"));
}
#[test]
fn limits_and_dedup() {
    let opts = IngestOptions {
        max_records: 1,
        ..Default::default()
    };
    assert!(ingest_file(&fixture("auth.log"), &opts).is_err());
    let opts = IngestOptions {
        max_file_bytes: 2,
        ..Default::default()
    };
    assert!(ingest_file(&fixture("auth.log"), &opts).is_err());
    let mut r = load("auth.log");
    r.merge(load("auth.log"));
    assert_eq!(r.records.len(), 7);
    assert_eq!(r.sources.len(), 1);
}
#[test]
fn live_collection_has_current_process() {
    let r = collect::collect_processes().unwrap();
    assert!(
        r.records
            .iter()
            .any(|r| matches!(&r.data,RecordData::Process(p) if p.pid==std::process::id()))
    );
}

#[test]
fn report_import_preserves_independent_process_sources() {
    let mut r = load("processes.json");
    let mut extra = r.records[0].clone();
    extra.id = "other:pid:1".into();
    extra.source_id = "other-host".into();
    r.records.push(extra);
    let bytes = serde_json::to_vec(&r).unwrap();
    let imported = ingest_bytes(
        "case.json",
        &bytes,
        &IngestOptions {
            format: InputFormat::Processes,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(imported.records.len(), 4);
    assert_ne!(imported.records[0].source_id, imported.records[3].source_id);
    assert!(
        !imported
            .diagnostics
            .iter()
            .any(|d| d.message.contains("duplicate PID"))
    );
}
