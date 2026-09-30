use crate::{AnalysisInput, AnalysisRequest, AnalysisSession, core::report};
use anyhow::{Context, Result, bail};
use std::{
    collections::HashSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Html,
}
#[derive(Debug, Clone)]
pub struct RenderOptions {
    pub limit: usize,
    pub raw: bool,
    pub tree: bool,
}
impl Default for RenderOptions {
    fn default() -> Self {
        Self {
            limit: 50,
            raw: false,
            tree: false,
        }
    }
}
#[derive(Debug, Clone)]
pub struct ExportPlan {
    pub format: OutputFormat,
    pub path: Option<PathBuf>,
    pub json_path: Option<PathBuf>,
    pub html_path: Option<PathBuf>,
    pub render: RenderOptions,
}
impl Default for ExportPlan {
    fn default() -> Self {
        Self {
            format: OutputFormat::Text,
            path: None,
            json_path: None,
            html_path: None,
            render: RenderOptions::default(),
        }
    }
}
pub struct ExportResult {
    pub stdout: Option<String>,
    pub saved_paths: Vec<PathBuf>,
}

impl ExportPlan {
    fn normalized(&self) -> Self {
        let mut plan = self.clone();
        if plan.format == OutputFormat::Html && plan.path.is_none() {
            plan.path = plan.html_path.take();
        }
        plan
    }
    /// Preflight before reading input or invoking AI.
    pub fn validate_inputs(&self, request: &AnalysisRequest, config_path: &Path) -> Result<()> {
        let mut inputs: Vec<_> = request
            .inputs
            .iter()
            .filter_map(|i| {
                if let AnalysisInput::File(p) = i {
                    Some(p.clone())
                } else {
                    None
                }
            })
            .collect();
        inputs.extend(request.web_format_file.iter().cloned());
        self.normalized().validate_paths(&inputs, config_path)
    }
    fn validate_paths(&self, protected: &[PathBuf], config_path: &Path) -> Result<()> {
        let inputs: HashSet<_> = protected
            .iter()
            .map(|p| resolved_path(p))
            .collect::<Result<_>>()?;
        let config = resolved_path(config_path)?;
        let mut outputs = HashSet::new();
        for path in [&self.path, &self.json_path, &self.html_path]
            .into_iter()
            .flatten()
        {
            let resolved = resolved_path(path)?;
            if inputs.contains(&resolved) || resolved == config {
                bail!("报告输出会覆盖输入文件或配置：{}", path.display());
            }
            if !outputs.insert(resolved) {
                bail!("各个报告输出路径必须不同");
            }
        }
        Ok(())
    }
    /// Rendering returns stdout text to the adapter; this layer never prints.
    pub fn save(&self, session: &AnalysisSession, config_path: &Path) -> Result<ExportResult> {
        let plan = self.normalized();
        session.with_report(|analysis| {
            let mut protected = session.0.protected.clone();
            protected.extend(
                analysis
                    .sources
                    .iter()
                    .filter(|s| !s.path.contains("://") && s.path != "stdin")
                    .map(|s| PathBuf::from(&s.path)),
            );
            plan.validate_paths(&protected, config_path)?;
            let json = if plan.format == OutputFormat::Json || plan.json_path.is_some() {
                Some(report::json(analysis)?)
            } else {
                None
            };
            let html = if plan.format == OutputFormat::Html || plan.html_path.is_some() {
                Some(report::html(analysis))
            } else {
                None
            };
            let mut saved_paths = vec![];
            if let Some(path) = &plan.json_path {
                save_file(path, json.as_deref().context("无法生成 JSON 报告")?)?;
                saved_paths.push(path.clone());
            }
            if let Some(path) = &plan.html_path {
                save_file(path, html.as_deref().context("无法生成 HTML 报告")?)?;
                saved_paths.push(path.clone());
            }
            let primary = match plan.format {
                OutputFormat::Text => report::terminal_with_raw(
                    analysis,
                    plan.render.limit,
                    plan.render.tree,
                    plan.render.raw,
                ),
                OutputFormat::Json => json.context("无法生成 JSON 报告")?,
                OutputFormat::Html => html.context("无法生成 HTML 报告")?,
            };
            let stdout = if let Some(path) = &plan.path {
                save_file(path, &primary)?;
                saved_paths.push(path.clone());
                None
            } else if plan.format == OutputFormat::Html {
                saved_paths.push(save_html_auto(&primary)?);
                None
            } else {
                Some(primary)
            };
            Ok(ExportResult {
                stdout,
                saved_paths,
            })
        })?
    }
}
fn save_file(path: &Path, data: &str) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, data).with_context(|| format!("无法写入报告 {}", path.display()))
}
fn save_html_auto(data: &str) -> Result<PathBuf> {
    for index in 1..=10_000 {
        let path = PathBuf::from(if index == 1 {
            "report.html".to_owned()
        } else {
            format!("report-{index}.html")
        });
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(data.as_bytes())
                    .with_context(|| format!("无法写入报告 {}", path.display()))?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| format!("无法创建报告 {}", path.display()));
            }
        }
    }
    bail!("无法自动分配 HTML 报告文件名，请用 -O 指定输出路径。")
}
fn resolved_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for part in absolute.components() {
        match part {
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::CurDir => {}
            _ => normalized.push(part.as_os_str()),
        }
    }
    let mut ancestor = normalized.as_path();
    let mut tail = vec![];
    while !ancestor.exists() {
        tail.push(
            ancestor
                .file_name()
                .context("无法解析报告输出路径")?
                .to_os_string(),
        );
        ancestor = ancestor.parent().context("无法解析报告输出的父目录")?;
    }
    let mut result = ancestor.canonicalize()?;
    for part in tail.into_iter().rev() {
        result.push(part);
    }
    Ok(result)
}
