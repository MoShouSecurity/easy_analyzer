//! Read-only source benchmark; all runtime changes stay in the private working copy.
use analyzer_app::{ExecutionContext, ProjectService};
use std::{path::Path, time::Instant};

fn main() -> anyhow::Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .expect("usage: project_open_bench FILE.eair");
    let ctx = ExecutionContext::default();
    let start = Instant::now();
    let session = ProjectService::open(Path::new(&path), &ctx)?;
    println!("open_seconds={:.3}", start.elapsed().as_secs_f64());
    for n in 1..=2 {
        let start = Instant::now();
        let overview = session.overview(&ctx)?;
        println!(
            "overview_{n}_seconds={:.3} records={}",
            start.elapsed().as_secs_f64(),
            overview.records
        );
    }
    let start = Instant::now();
    let runs = session.ai_run_headers()?;
    let indices: Vec<_> = (0..runs.len()).rev().take(20).collect();
    session.ai_local_summaries(&indices, &ctx)?;
    println!("ai_history_seconds={:.3}", start.elapsed().as_secs_f64());
    let start = Instant::now();
    let page = session.page_metadata(None, 0, 100)?;
    println!(
        "page_seconds={:.3} items={}",
        start.elapsed().as_secs_f64(),
        page.items.len()
    );
    Ok(())
}
