#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
mod bridge;
mod model;
use std::path::PathBuf;
use tauri::Manager;
#[derive(Clone, Default)]
pub struct Args {
    pub inputs: Vec<PathBuf>,
    pub config: Option<PathBuf>,
    pub temporary: bool,
    pub qa: bool,
    pub qa_ai: bool,
    pub narrow: bool,
}
fn arguments() -> anyhow::Result<Args> {
    let mut result = Args::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--input" => result.inputs.push(
                args.next()
                    .ok_or_else(|| anyhow::anyhow!("--input 需要路径"))?
                    .into(),
            ),
            "--config" => {
                result.config = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--config 需要路径"))?
                        .into(),
                )
            }
            "--temporary" => result.temporary = true,
            "--qa" => {
                result.qa = true;
                result.temporary = true;
            }
            "--qa-ai" => result.qa_ai = true,
            "--narrow" => result.narrow = true,
            "--version" => {
                println!("easy-analyzer-gui {} (Tauri)", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--help" => {
                println!(
                    "easy-analyzer-gui [--input 文件]... [--config 配置]\n合成验收：--qa [--qa-ai] [--narrow] [--temporary]"
                );
                std::process::exit(0);
            }
            _ => anyhow::bail!("未知参数：{arg}"),
        }
    }
    if result.qa_ai && (!result.qa || result.config.is_none()) {
        anyhow::bail!("--qa-ai 需要 --qa 和本机回环 --config");
    }
    Ok(result)
}
fn main() -> anyhow::Result<()> {
    let args = arguments()?;
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(move |app| {
            let data = app.path().app_data_dir()?;
            app.manage(bridge::Desktop::new(data, args.clone()));
            let size = if args.narrow {
                (960., 600.)
            } else {
                (1280., 720.)
            };
            let builder = tauri::WebviewWindowBuilder::new(
                app,
                "main",
                tauri::WebviewUrl::App("index.html".into()),
            )
            .title("Easy Analyzer")
            .inner_size(size.0, size.1)
            .decorations(cfg!(target_os = "macos"))
            .min_inner_size(960., 600.)
            .resizable(true);
            #[cfg(target_os = "macos")]
            let builder = builder
                .title_bar_style(tauri::TitleBarStyle::Overlay)
                .hidden_title(true)
                .traffic_light_position(tauri::LogicalPosition::new(16., 20.));
            builder.build()?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            bridge::initialize,
            bridge::save_preferences,
            bridge::start_import,
            bridge::cancel_task,
            bridge::reset_session,
            bridge::get_view,
            bridge::get_detail,
            bridge::get_ai_batches,
            bridge::apply_config,
            bridge::config_operation,
            bridge::start_ai,
            bridge::start_export,
            bridge::pick_paths
        ])
        .run(tauri::generate_context!())?;
    Ok(())
}
