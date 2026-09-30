use crate::execution::{ExecutionContext, ReportOutcome, Stage};
use crate::{
    ingest::{IngestOptions, make_record, source_for},
    model::*,
};
use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use std::path::Path;

pub fn collect_processes() -> Result<AnalysisReport> {
    Ok(collect_processes_with_context(&ExecutionContext::default())?.report)
}

pub fn collect_processes_with_context(ctx: &ExecutionContext) -> Result<ReportOutcome> {
    ctx.emit(Stage::Collecting, Some("local processes"), 0, None);
    ctx.check()?;
    if !sysinfo::IS_SUPPORTED_SYSTEM {
        bail!("process collection unsupported on this operating system");
    }
    let mut system = sysinfo::System::new_all();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let mut processes: Vec<ProcessData> = system
        .processes()
        .iter()
        .map(|(pid, p)| ProcessData {
            pid: pid.as_u32(),
            parent_pid: p.parent().map(|n| n.as_u32()),
            name: p.name().to_string_lossy().into_owned(),
            path: p.exe().map(|s| s.to_string_lossy().into_owned()),
            command: p
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().into_owned())
                .collect(),
            user: p.user_id().map(|s| s.to_string()),
            start_time: DateTime::from_timestamp(p.start_time() as i64, 0).map(|t| t.to_rfc3339()),
            status: Some(p.status().to_string()),
        })
        .collect();
    processes.sort_by_key(|p| p.pid);
    let bytes = serde_json::to_vec(&processes)?;
    let source = source_for(
        &format!(
            "live://{}/processes/{}",
            sysinfo::System::host_name().unwrap_or_else(|| "localhost".into()),
            Utc::now().to_rfc3339()
        ),
        "processes",
        &bytes,
    );
    let mut report = AnalysisReport::default();
    report.sources.push(source.clone());
    for (i, p) in processes.into_iter().enumerate() {
        if ctx
            .tick(Stage::Collecting, Some(&source.path), i, None)
            .is_err()
        {
            return Ok(ReportOutcome::cancelled(report, &source.path));
        }
        if p.path.as_deref().is_none_or(str::is_empty) {
            report.warn(
                &source.path,
                Some(format!("pid:{}", p.pid)),
                "executable path unavailable (permissions, kernel process, or process exit)",
            );
        }
        report.records.push(make_record(
            &source,
            format!("pid:{}", p.pid),
            Some(source.collected_at.clone()),
            serde_json::to_string(&p)?,
            ParseStatus::Parsed,
            RecordData::Process(p),
        ));
    }
    ctx.emit(
        Stage::Collecting,
        Some(&source.path),
        report.records.len(),
        Some(report.records.len()),
    );
    if ctx.cancellation.is_cancelled() {
        Ok(ReportOutcome::cancelled(report, &source.path))
    } else {
        Ok(ReportOutcome::complete(report))
    }
}

/// Read standard locations on Linux; retain native event-log exports on Windows.
pub fn collect_common_logs(options: &IngestOptions, evidence_dir: &Path) -> Result<AnalysisReport> {
    Ok(
        collect_common_logs_with_context(options, evidence_dir, &ExecutionContext::default())?
            .report,
    )
}

pub fn collect_common_logs_with_context(
    options: &IngestOptions,
    evidence_dir: &Path,
    ctx: &ExecutionContext,
) -> Result<ReportOutcome> {
    ctx.emit(Stage::Collecting, Some("local logs"), 0, None);
    ctx.check()?;
    let mut report = AnalysisReport::default();
    #[cfg(target_os = "linux")]
    {
        let _ = evidence_dir;
        let paths = [
            "/run/utmp",
            "/var/log/wtmp",
            "/var/log/btmp",
            "/var/log/auth.log",
            "/var/log/secure",
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/httpd/access_log",
            "/var/log/httpd/error_log",
        ];
        for path in paths {
            if ctx.cancellation.is_cancelled() {
                return Ok(ReportOutcome::cancelled(report, "local logs"));
            }
            ctx.emit(Stage::Collecting, Some(path), report.sources.len(), None);
            if !Path::new(path).exists() {
                continue;
            }
            let mut opts = options.clone();
            opts.format = crate::InputFormat::Auto;
            match crate::ingest::ingest_file_with_context(Path::new(path), &opts, ctx) {
                Ok(r) => {
                    let cancelled = r.cancelled;
                    report.merge(r.report);
                    if cancelled {
                        return Ok(ReportOutcome { report, cancelled });
                    }
                }
                Err(e) => report.error(path, None, e.to_string()),
            }
        }
        if report.sources.is_empty() {
            report.error("local log collection",None,"no readable logs at standard locations; check permissions or import an exported file. Journald-only hosts need journalctl export (--format text).");
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::{fs, process::Command};
        fs::create_dir_all(evidence_dir)?;
        for channel in [
            "Security",
            "System",
            "Application",
            "Microsoft-Windows-PowerShell/Operational",
        ] {
            if ctx.cancellation.is_cancelled() {
                return Ok(ReportOutcome::cancelled(report, "local logs"));
            }
            ctx.emit(
                Stage::Collecting,
                Some(channel),
                report.sources.len(),
                Some(4),
            );
            if ctx.cancellation.is_cancelled() {
                return Ok(ReportOutcome::cancelled(report, "local logs"));
            }
            let file = evidence_dir.join(format!(
                "{}-{}.evtx",
                channel.replace('/', "_"),
                Utc::now().format("%Y%m%dT%H%M%S%f")
            ));
            let output = Command::new("wevtutil.exe")
                .arg("epl")
                .arg(channel)
                .arg(&file)
                .output();
            match output {
                Ok(out) if out.status.success() => {
                    let mut options = options.clone();
                    options.format = crate::InputFormat::Evtx;
                    match crate::ingest::ingest_file_with_context(&file, &options, ctx) {
                        Ok(r) => {
                            let cancelled = r.cancelled;
                            report.merge(r.report);
                            if cancelled {
                                return Ok(ReportOutcome { report, cancelled });
                            }
                        }
                        Err(e) => report.error(file.to_string_lossy(), None, e.to_string()),
                    }
                }
                Ok(out) => report.error(
                    channel,
                    None,
                    format!(
                        "event log export failed (run elevated for Security): {}",
                        String::from_utf8_lossy(&out.stderr)
                    ),
                ),
                Err(e) => report.error(channel, None, format!("could not run wevtutil: {e}")),
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (options, evidence_dir, &mut report, ctx);
        bail!("automatic log collection supports Windows/Linux; import files on this OS");
    }
    #[allow(unreachable_code)]
    if ctx.cancellation.is_cancelled() {
        Ok(ReportOutcome::cancelled(report, "local logs"))
    } else {
        Ok(ReportOutcome::complete(report))
    }
}

/// Text process trees grouped by source. Orphans and cyclic snapshots stay visible.
pub fn process_tree(records: &[Record]) -> String {
    use std::collections::{BTreeMap, HashSet};
    let mut groups: BTreeMap<&str, Vec<&ProcessData>> = BTreeMap::new();
    for r in records {
        if let RecordData::Process(p) = &r.data {
            groups.entry(&r.source_id).or_default().push(p);
        }
    }
    let mut out = String::new();
    for (source, mut processes) in groups {
        processes.sort_by_key(|p| p.pid);
        out.push_str(&format!("Source {source}\n"));
        let pids: HashSet<u32> = processes.iter().map(|p| p.pid).collect();
        let mut visited = HashSet::new();
        fn visit(
            p: &ProcessData,
            all: &[&ProcessData],
            visited: &mut HashSet<u32>,
            depth: usize,
            out: &mut String,
        ) {
            if !visited.insert(p.pid) {
                return;
            }
            out.push_str(&format!(
                "{}{} {} [parent={}] {}\n",
                "  ".repeat(depth.min(50)),
                p.pid,
                p.name,
                p.parent_pid
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "-".into()),
                p.path.as_deref().unwrap_or("<unavailable>")
            ));
            // Iteration remains finite even when a snapshot contains cycles.
            if depth >= 100 {
                return;
            }
            for child in all
                .iter()
                .filter(|c| c.parent_pid == Some(p.pid) && c.pid != p.pid)
            {
                visit(child, all, visited, depth + 1, out);
            }
        }
        for p in &processes {
            if p.parent_pid
                .is_none_or(|id| !pids.contains(&id) || id == p.pid)
            {
                visit(p, &processes, &mut visited, 0, &mut out);
            }
        }
        for p in &processes {
            if !visited.contains(&p.pid) {
                out.push_str("[cycle/orphan group]\n");
                visit(p, &processes, &mut visited, 0, &mut out);
            }
        }
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cyclic_tree_and_orphans() {
        let s = source_for("snapshot", "processes", b"fixture");
        let records: Vec<_> = [(1, Some(2)), (2, Some(1)), (3, Some(99))]
            .into_iter()
            .map(|(pid, parent_pid)| {
                make_record(
                    &s,
                    format!("pid:{pid}"),
                    None,
                    String::new(),
                    ParseStatus::Parsed,
                    RecordData::Process(ProcessData {
                        pid,
                        parent_pid,
                        name: format!("p{pid}"),
                        path: None,
                        command: vec![],
                        user: None,
                        start_time: None,
                        status: None,
                    }),
                )
            })
            .collect();
        let tree = process_tree(&records);
        for pid in 1..=3 {
            assert!(tree.contains(&format!("{pid} p{pid}")));
        }
        assert!(tree.contains("cycle"));
    }
}
