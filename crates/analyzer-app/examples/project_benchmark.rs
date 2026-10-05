//! Synthetic, offline performance check. Writes only into its own temporary directory.
use analyzer_app::*;
use anyhow::Result;
use std::{
    io::{BufWriter, Write},
    path::Path,
    sync::Arc,
    time::Instant,
};
fn timed<T>(name: &str, run: impl FnOnce() -> Result<T>) -> Result<T> {
    let start = Instant::now();
    let result = run()?;
    println!("{name}: {:.3}s", start.elapsed().as_secs_f64());
    Ok(result)
}
fn main() -> Result<()> {
    let count: usize = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "100000".into())
        .parse()?;
    let payload: usize = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "1024".into())
        .parse()?;
    let mode = std::env::args().nth(3).unwrap_or_else(|| "all".into());
    let dir = tempfile::tempdir()?;
    let path = std::env::args()
        .nth(4)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| dir.path().join("synthetic.eair"));
    if mode == "resume" {
        let reopened = timed("reopen", || {
            ProjectService::open(&path, &ExecutionContext::default())
        })?;
        return exercise(&reopened, count, dir.path(), &mode);
    }

    let session = ProjectService::create(ProjectInfo::new(
        "Synthetic performance response",
        "Synthetic customer",
    ))?;
    let ctx = ExecutionContext::default();
    let padding = "x".repeat(payload);
    timed("initial_parse_and_import", || {
        for offset in (0..count).step_by(25000) {
            let mut text = String::new();
            for i in offset..(offset + 25000).min(count) {
                text.push_str(&format!(
                    "synthetic {i} {} {padding}\n",
                    if i % 10000 == 0 {
                        "https://indicator.invalid/test"
                    } else {
                        "ordinary"
                    }
                ));
            }
            ProjectService::append(
                &session,
                &AnalysisRequest {
                    inputs: vec![AnalysisInput::Bytes {
                        label: format!("synthetic-host-{offset}.log"),
                        bytes: Arc::from(text.into_bytes()),
                    }],
                    ingest: IngestOptions {
                        format: InputFormat::Text,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                &ctx,
            )?;
        }
        Ok(())
    })?;
    timed("snapshot_save", || {
        ProjectService::save(
            &session,
            &path,
            Path::new("synthetic-config.toml"),
            false,
            &ctx,
        )
    })?;
    println!("project_bytes: {}", std::fs::metadata(&path)?.len());
    if mode == "import" {
        return Ok(());
    }
    drop(session);
    let reopened = timed("reopen", || ProjectService::open(&path, &ctx))?;
    exercise(&reopened, count, dir.path(), &mode)
}
fn exercise(reopened: &AnalysisSession, count: usize, dir: &Path, mode: &str) -> Result<()> {
    let ctx = ExecutionContext::default();
    timed("page_100", || {
        reopened.page_metadata(None, count.saturating_sub(100), 100)
    })?;
    let selected = timed("text_filter", || {
        reopened.query(
            &QueryOptions {
                expression: Some("indicator.invalid".into()),
                ..Default::default()
            },
            &ctx,
        )
    })?;
    println!("selected: {}", selected.len());
    timed("regex_filter", || {
        reopened.query(
            &QueryOptions {
                expression: Some(r"indicator\.invalid/test".into()),
                regex: true,
                ..Default::default()
            },
            &ctx,
        )
    })?;
    IocService::add_value(reopened, "indicator.invalid", None, "Synthetic IOC", &ctx)?;
    timed("ioc_scan", || IocService::scan(reopened, true, &ctx))?;
    timed("json_stream_export", || {
        let mut out = BufWriter::new(std::fs::File::create(dir.join("report.json"))?);
        ExportPlan {
            format: OutputFormat::Json,
            ..Default::default()
        }
        .write_primary(reopened, &mut out, &ctx)?;
        out.flush()?;
        Ok(())
    })?;
    if mode == "all" || mode == "resume" {
        timed("html_stream_export", || {
            let mut out = BufWriter::new(std::fs::File::create(dir.join("report.html"))?);
            ExportPlan {
                format: OutputFormat::Html,
                ..Default::default()
            }
            .write_primary(reopened, &mut out, &ctx)?;
            out.flush()?;
            Ok(())
        })?;
    }
    println!("hits: {}", IocService::matches(reopened, 0, 100)?.total);
    Ok(())
}
