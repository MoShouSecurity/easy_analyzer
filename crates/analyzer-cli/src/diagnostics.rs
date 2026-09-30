//! Render structured parser errors in Chinese while preserving arguments and values.
use clap::error::{ContextKind, ContextValue, ErrorKind};
use std::{fmt::Write, process::ExitCode};

fn context(error: &clap::Error, kind: ContextKind) -> String {
    error.get(kind).map(ToString::to_string).unwrap_or_default()
}

pub fn render(error: &clap::Error) -> String {
    let arg = context(error, ContextKind::InvalidArg);
    let value = context(error, ContextKind::InvalidValue);
    let mut out = String::from("错误：");
    match error.kind() {
        ErrorKind::MissingRequiredArgument => {
            out.push_str("缺少以下必填参数或输入来源：\n");
            if let Some(ContextValue::Strings(args)) = error.get(ContextKind::InvalidArg) {
                for arg in args {
                    let _ = writeln!(out, "  {arg}");
                }
            }
        }
        ErrorKind::UnknownArgument => {
            let _ = writeln!(out, "无法识别参数“{arg}”。");
        }
        ErrorKind::InvalidSubcommand => {
            let subcommand = context(error, ContextKind::InvalidSubcommand);
            let _ = writeln!(out, "无法识别命令“{subcommand}”。");
        }
        ErrorKind::MissingSubcommand => {
            out.push_str("请指定要执行的子命令。\n");
        }
        ErrorKind::InvalidValue if value.is_empty() => {
            let _ = writeln!(out, "参数“{arg}”需要一个值。");
        }
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => {
            let _ = writeln!(out, "参数“{arg}”的值“{value}”无效。");
            if ["--limit", "--max-file-mb", "--max-records"]
                .iter()
                .any(|name| arg.starts_with(name))
            {
                out.push_str("  此参数需要合法的非负整数。\n");
            }
        }
        ErrorKind::ArgumentConflict => {
            let prior = context(error, ContextKind::PriorArg);
            if arg == prior {
                let _ = writeln!(out, "参数“{arg}”不能重复指定。");
            } else {
                let _ = writeln!(out, "参数“{arg}”不能与“{prior}”同时使用。");
            }
        }
        ErrorKind::NoEquals => {
            let _ = writeln!(out, "请用等号为“{arg}”赋值，例如 --参数=值。");
        }
        ErrorKind::TooManyValues => {
            let _ = writeln!(out, "参数“{arg}”收到了多余的值“{value}”。");
        }
        ErrorKind::TooFewValues | ErrorKind::WrongNumberOfValues => {
            let expected = if error.kind() == ErrorKind::TooFewValues {
                context(error, ContextKind::MinValues)
            } else {
                context(error, ContextKind::ExpectedNumValues)
            };
            let actual = context(error, ContextKind::ActualNumValues);
            let _ = writeln!(
                out,
                "参数“{arg}”需要 {expected} 个值，实际提供了 {actual} 个。"
            );
        }
        ErrorKind::InvalidUtf8 => out.push_str("命令行参数包含无效的 UTF-8 文本。\n"),
        ErrorKind::Io => out.push_str("读取或输出命令行数据失败。\n"),
        ErrorKind::Format => out.push_str("生成命令行输出失败。\n"),
        _ => out.push_str("无法解析命令行参数，请检查参数名称和输入格式。\n"),
    }
    for (kind, label) in [
        (ContextKind::ValidValue, "可选值"),
        (ContextKind::ValidSubcommand, "可用命令"),
        (ContextKind::SuggestedArg, "是否想使用参数"),
        (ContextKind::SuggestedSubcommand, "是否想使用命令"),
        (ContextKind::SuggestedValue, "是否想使用值"),
    ] {
        let value = context(error, kind);
        if !value.is_empty() {
            let _ = writeln!(out, "  {label}：{value}");
        }
    }
    let usage = context(error, ContextKind::Usage);
    if !usage.is_empty() {
        // Translate only generated usage syntax, never user-supplied values.
        let usage = usage.strip_prefix("Usage:").unwrap_or(&usage).trim_start();
        let usage = usage
            .replace("[OPTIONS]", "[选项]")
            .replace("<COMMAND>", "<命令>");
        let _ = writeln!(out, "\n用法：{usage}");
    }
    out.push_str("\n更多说明和示例，请在当前命令后加 -h 或 --help。\n");
    out
}

pub fn report(error: clap::Error) -> ExitCode {
    let code = error.exit_code() as u8;
    if matches!(
        error.kind(),
        ErrorKind::DisplayHelp
            | ErrorKind::DisplayVersion
            | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    ) {
        if let Err(error) = error.print() {
            eprintln!("错误：无法显示帮助或版本信息：{error}");
            return ExitCode::FAILURE;
        }
    } else {
        eprint!("{}", render(&error));
    }
    ExitCode::from(code)
}
