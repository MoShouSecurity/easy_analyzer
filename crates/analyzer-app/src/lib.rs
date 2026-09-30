//! Shared application services. No terminal, GUI framework, or async runtime dependency.
//!
//! ```no_run
//! use analyzer_app::{AnalysisInput, AnalysisMode, AnalysisRequest, AnalysisService,
//!     ExecutionContext, QueryOptions};
//! # fn main() -> anyhow::Result<()> {
//! let request = AnalysisRequest {
//!     mode: AnalysisMode::Logs,
//!     inputs: vec![AnalysisInput::File("cases/access.log".into())],
//!     ..Default::default()
//! };
//! let outcome = AnalysisService::load(&request, &ExecutionContext::default())?;
//! let selection = outcome.session.query(
//!     &QueryOptions { suspicious: true, ..Default::default() },
//!     &ExecutionContext::default(),
//! )?;
//! let first_page = outcome.session.page(Some(&selection), 0, 100)?;
//! // GUI adapters use task::spawn_analysis/spawn_ai and nonblocking event polling.
//! # let _ = first_page;
//! # Ok(()) }
//! ```
pub mod config;
pub mod export;
mod service;
mod session;
pub mod task;
mod types;

pub use analyzer_core as core;
pub use analyzer_core::{
    AnalysisReport, CancellationToken, DiagnosticLevel, ExecutionContext, IngestOptions,
    InputFormat,
};
pub use config::ConfigService;
pub use export::{ExportPlan, ExportResult, OutputFormat, RenderOptions};
pub use service::AnalysisService;
pub use session::{AnalysisSession, Page, RecordSelection, RecordSummary};
pub use task::{TaskEvent, TaskHandle, TaskId};
pub use types::*;
