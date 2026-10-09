use crate::cli::{AnalysisArgs, ProjectCommand, ProjectMetadata};
use analyzer_app::*;
use anyhow::{Context, Result};
use std::path::Path;
fn apply(info: &mut ProjectInfo, patch: ProjectMetadata) {
    if let Some(v) = patch.name {
        info.name = v;
    }
    if let Some(v) = patch.client {
        info.client = v;
    }
    if let Some(v) = patch.response_start {
        info.response_start = v;
    }
    if let Some(v) = patch.response_end {
        info.response_end = if v.is_empty() { None } else { Some(v) };
    }
    if let Some(v) = patch.location {
        info.location = v;
    }
    if let Some(v) = patch.responders {
        info.responders = v;
    }
    if let Some(v) = patch.description {
        info.description = v;
    }
}
pub fn catalog() -> Result<ProjectCatalog> {
    ProjectCatalog::open(&project_data_dir()?)
}
pub fn command(
    command: ProjectCommand,
    config: &Path,
    ctx: &ExecutionContext,
) -> Result<Option<AnalysisArgs>> {
    match command {
        ProjectCommand::Open { path, common } => {
            let mut args = AnalysisArgs::new(vec![], common);
            args.project = Some(path);
            Ok(Some(args))
        }
        ProjectCommand::Import { path, args } => {
            let mut args = AnalysisArgs::from(args);
            args.project = Some(path.clone());
            args.save_project = Some(path);
            Ok(Some(args))
        }
        ProjectCommand::List {
            search,
            client,
            from,
            until,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&catalog()?.list(&ProjectSearch {
                    text: search,
                    client,
                    from,
                    until
                })?)?
            );
            Ok(None)
        }
        ProjectCommand::Create { path, info } => {
            let mut metadata = ProjectInfo::new(
                info.name.as_deref().unwrap_or_default(),
                info.client.as_deref().context("--client 为必填项")?,
            );
            apply(&mut metadata, info);
            let session = ProjectService::create(metadata)?;
            ProjectService::save(&session, &path, config, false, ctx)?;
            catalog()?.register(&session)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&ProjectService::status(&session)?)?
            );
            Ok(None)
        }
        ProjectCommand::Edit { path, info } => {
            let session = ProjectService::open(&path, ctx)?;
            let mut metadata = ProjectService::status(&session)?.info;
            apply(&mut metadata, info);
            ProjectService::edit(&session, metadata, ctx)?;
            ProjectService::save(&session, &path, config, false, ctx)?;
            catalog()?.register(&session)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&ProjectService::status(&session)?)?
            );
            Ok(None)
        }
        ProjectCommand::Note { path, record, text } => {
            let session = ProjectService::open(&path, ctx)?;
            if let Some(text) = text {
                ProjectService::note(&session, &record, &text, ctx)?;
                ProjectService::save(&session, &path, config, false, ctx)?;
            }
            catalog()?.register(&session)?;
            println!(
                "{}",
                serde_json::to_string(&ProjectService::read_note(&session, &record)?)?
            );
            Ok(None)
        }
    }
}
