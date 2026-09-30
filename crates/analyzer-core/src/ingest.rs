use crate::{
    model::*,
    web::{WebErrorParser, WebParser},
};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs::File, io::Read, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputFormat {
    Auto,
    Evtx,
    Utmp,
    Wtmp,
    Btmp,
    Web,
    Text,
    Processes,
    Pcap,
}
impl std::str::FromStr for InputFormat {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "auto" => Self::Auto,
            "evtx" => Self::Evtx,
            "utmp" => Self::Utmp,
            "wtmp" => Self::Wtmp,
            "btmp" => Self::Btmp,
            "web" => Self::Web,
            "text" => Self::Text,
            "processes" => Self::Processes,
            "pcap" | "pcapng" => Self::Pcap,
            _ => bail!("unknown format: {s}"),
        })
    }
}
impl std::fmt::Display for InputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            serde_json::to_value(self).unwrap().as_str().unwrap()
        )
    }
}
#[derive(Debug, Clone)]
pub struct IngestOptions {
    pub format: InputFormat,
    pub web_format: Option<String>,
    pub max_file_bytes: u64,
    pub max_records: usize,
}
impl Default for IngestOptions {
    fn default() -> Self {
        Self {
            format: InputFormat::Auto,
            web_format: None,
            max_file_bytes: 512 * 1024 * 1024,
            max_records: 1_000_000,
        }
    }
}

pub fn source_for(path: &str, format: &str, bytes: &[u8]) -> Source {
    let sha256 = hex(&Sha256::digest(bytes));
    let id = hex(&Sha256::digest(format!("{path}\0{sha256}").as_bytes()));
    Source {
        id,
        path: path.into(),
        format: format.into(),
        sha256,
        bytes: bytes.len() as u64,
        collected_at: Utc::now().to_rfc3339(),
    }
}
pub fn make_record(
    source: &Source,
    position: String,
    timestamp: Option<String>,
    raw: String,
    status: ParseStatus,
    data: RecordData,
) -> Record {
    Record {
        id: format!("{}:{position}", source.id),
        source_id: source.id.clone(),
        position,
        timestamp,
        raw,
        status,
        data,
    }
}

pub fn ingest_file(path: &Path, options: &IngestOptions) -> Result<AnalysisReport> {
    if options.max_file_bytes == 0 || options.max_records == 0 {
        bail!("input limits must be positive");
    }
    let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(options.max_file_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > options.max_file_bytes {
        bail!(
            "{} exceeds the file size limit ({} bytes)",
            path.display(),
            options.max_file_bytes
        );
    }
    ingest_bytes(&path.to_string_lossy(), &bytes, options)
}

/// Shared input API for CLI stdin and future GUI drag/drop or pasted text.
pub fn ingest_bytes(label: &str, bytes: &[u8], options: &IngestOptions) -> Result<AnalysisReport> {
    if bytes.len() as u64 > options.max_file_bytes || options.max_records == 0 {
        bail!("input exceeds configured limits");
    }
    if bytes.starts_with(&[0x1f, 0x8b]) {
        bail!("gzip input must be decompressed before import");
    }
    let path = Path::new(label);
    let mut format = if options.format == InputFormat::Auto {
        detect(path, bytes)?
    } else {
        options.format
    };
    if options.web_format.is_some() && matches!(format, InputFormat::Text | InputFormat::Web) {
        format = InputFormat::Web;
    }
    let source = source_for(label, &format.to_string(), bytes);
    let mut report = AnalysisReport::default();
    match format {
        InputFormat::Evtx => parse_evtx(bytes, &source, options.max_records, &mut report)?,
        InputFormat::Utmp | InputFormat::Wtmp | InputFormat::Btmp => {
            parse_utmp(bytes, &source, format, options.max_records, &mut report)?
        }
        InputFormat::Processes => {
            parse_processes(bytes, &source, options.max_records, &mut report)?
        }
        InputFormat::Pcap => {
            crate::network::parse_capture(bytes, &source, options.max_records, &mut report)?
        }
        InputFormat::Web | InputFormat::Text => {
            parse_text(bytes, &source, format, options, &mut report)?
        }
        InputFormat::Auto => unreachable!(),
    }
    report.sources.push(source);
    Ok(report)
}

fn detect(path: &Path, bytes: &[u8]) -> Result<InputFormat> {
    if bytes.starts_with(b"ElfFile\0") {
        return Ok(InputFormat::Evtx);
    }
    if crate::network::is_capture(bytes) {
        return Ok(InputFormat::Pcap);
    }
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    for (token, format) in [
        ("btmp", InputFormat::Btmp),
        ("wtmp", InputFormat::Wtmp),
        ("utmp", InputFormat::Utmp),
    ] {
        if name == token
            || name.starts_with(&format!("{token}."))
            || name.ends_with(&format!(".{token}"))
        {
            return Ok(format);
        }
    }
    if name.ends_with(".evtx") {
        return Ok(InputFormat::Evtx);
    }
    if name.ends_with(".pcap") || name.ends_with(".pcapng") {
        return Ok(InputFormat::Pcap);
    }
    if bytes.is_empty() {
        return Ok(InputFormat::Text);
    }
    if name.ends_with(".json") {
        return Ok(InputFormat::Processes);
    }
    if bytes.contains(&0) {
        bail!("unknown binary input; specify --format (utmp/wtmp/btmp files have no magic header)");
    }
    let sample = String::from_utf8_lossy(bytes);
    if sample
        .lines()
        .take(20)
        .any(|l| WebParser::combined().parse(l).is_some() || WebParser::common().parse(l).is_some())
    {
        return Ok(InputFormat::Web);
    }
    Ok(InputFormat::Text)
}

fn parse_evtx(
    bytes: &[u8],
    source: &Source,
    max: usize,
    report: &mut AnalysisReport,
) -> Result<()> {
    let mut parser =
        evtx::EvtxParser::from_buffer(bytes.to_vec()).context("invalid EVTX header")?;
    for (i, event) in parser.records_json_value().enumerate() {
        if i >= max {
            bail!("EVTX exceeds max records ({max}); increase --max-records");
        }
        match event {
            Ok(event) => {
                let mut fields = BTreeMap::new();
                flatten("", &event.data, &mut fields);
                for (short, suffix) in [
                    ("event_id", "EventID"),
                    ("user", "TargetUserName"),
                    ("client_ip", "IpAddress"),
                    ("host", "Computer"),
                ] {
                    if let Some(value) = fields
                        .iter()
                        .find(|(k, _)| {
                            k.ends_with(suffix) || k.ends_with(&format!("{suffix}.#text"))
                        })
                        .map(|(_, v)| v.clone())
                    {
                        fields.insert(short.into(), value);
                    }
                }
                report.records.push(make_record(
                    source,
                    format!("event:{}", event.event_record_id),
                    Some(event.timestamp.to_string()),
                    serde_json::to_string(&event.data)?,
                    ParseStatus::Parsed,
                    RecordData::Log(LogData {
                        category: "windows_event".into(),
                        fields,
                    }),
                ));
            }
            Err(e) => report.warn(
                &source.path,
                Some(format!("record:{i}")),
                format!(
                    "EVTX record could not be rendered: {e}; original file retained by source hash"
                ),
            ),
        }
    }
    Ok(())
}
fn flatten(prefix: &str, value: &serde_json::Value, fields: &mut BTreeMap<String, String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                flatten(
                    &if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    },
                    value,
                    fields,
                );
            }
        }
        serde_json::Value::Array(values) => {
            for (i, value) in values.iter().enumerate() {
                flatten(&format!("{prefix}[{i}]"), value, fields);
            }
        }
        _ => {
            fields.insert(
                prefix.into(),
                value
                    .as_str()
                    .map(String::from)
                    .unwrap_or_else(|| value.to_string()),
            );
        }
    }
}

fn parse_utmp(
    bytes: &[u8],
    source: &Source,
    format: InputFormat,
    max: usize,
    report: &mut AnalysisReport,
) -> Result<()> {
    // Linux glibc x86_64-compatible layout. Explicit little endian; never transmute host ABI.
    if bytes.len() / 384 > max {
        bail!("login file exceeds max records ({max})");
    }
    for (i, chunk) in bytes.chunks(384).enumerate() {
        let offset = i * 384;
        if chunk.len() != 384 {
            report.warn(
                &source.path,
                Some(format!("offset:{offset}")),
                "truncated 384-byte Linux utmp record",
            );
            report.records.push(make_record(
                source,
                format!("offset:{offset}"),
                None,
                hex(chunk),
                ParseStatus::Malformed,
                RecordData::Log(LogData {
                    category: format.to_string(),
                    fields: BTreeMap::new(),
                }),
            ));
            continue;
        }
        let record_type = i16::from_le_bytes(chunk[0..2].try_into()?);
        let pid = i32::from_le_bytes(chunk[4..8].try_into()?);
        let seconds = i32::from_le_bytes(chunk[340..344].try_into()?);
        let micros = i32::from_le_bytes(chunk[344..348].try_into()?);
        let valid = (0..=9).contains(&record_type) && (0..1_000_000).contains(&micros);
        let mut fields = BTreeMap::from([
            ("record_type".into(), record_type.to_string()),
            ("pid".into(), pid.to_string()),
            ("terminal".into(), cstr(&chunk[8..40])),
            ("user".into(), cstr(&chunk[44..76])),
            ("host".into(), cstr(&chunk[76..332])),
        ]);
        fields.insert(
            "action".into(),
            match (format, record_type) {
                (InputFormat::Btmp, _) => "login_failure",
                (_, 7) => "login_success",
                (_, 8) => "logout",
                (_, 2) => "boot",
                _ => "session_record",
            }
            .into(),
        );
        let addr = &chunk[348..364];
        if addr.iter().any(|b| *b != 0) {
            let ip = if addr[4..].iter().all(|b| *b == 0) {
                std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string()
            } else {
                std::net::Ipv6Addr::from(<[u8; 16]>::try_from(addr)?).to_string()
            };
            fields.insert("client_ip".into(), ip);
        } else if !fields["host"].is_empty() {
            fields.insert("client_ip".into(), fields["host"].clone());
        }
        let timestamp = if valid {
            DateTime::from_timestamp(seconds as i64, micros as u32 * 1000).map(|t| t.to_rfc3339())
        } else {
            None
        };
        if !valid {
            report.warn(
                &source.path,
                Some(format!("offset:{offset}")),
                "invalid Linux utmp fields; possible unsupported ABI/endian layout",
            );
        }
        report.records.push(make_record(
            source,
            format!("offset:{offset}"),
            timestamp,
            hex(chunk),
            if valid {
                ParseStatus::Parsed
            } else {
                ParseStatus::Malformed
            },
            RecordData::Log(LogData {
                category: format.to_string(),
                fields,
            }),
        ));
    }
    Ok(())
}
fn cstr(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes.split(|b| *b == 0).next().unwrap_or_default()).into_owned()
}

fn parse_text(
    bytes: &[u8],
    source: &Source,
    format: InputFormat,
    opts: &IngestOptions,
    report: &mut AnalysisReport,
) -> Result<()> {
    let text = String::from_utf8_lossy(bytes);
    if std::str::from_utf8(bytes).is_err() {
        report.warn(
            &source.path,
            None,
            "non-UTF-8 text decoded lossily; original bytes available in source file",
        );
    }
    let custom = opts
        .web_format
        .as_deref()
        .map(WebParser::compile)
        .transpose()?;
    let errors = WebErrorParser::default();
    let common = WebParser::common();
    let combined = WebParser::combined();
    let failed =
        Regex::new(r"(?i)Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)")?;
    let accepted = Regex::new(r"(?i)Accepted \S+ for (\S+) from (\S+)")?;
    let invalid = Regex::new(r"(?i)Invalid user (\S+) from (\S+)")?;
    for (i, line) in text.lines().enumerate() {
        if i >= opts.max_records {
            bail!(
                "text exceeds max records ({}); increase --max-records",
                opts.max_records
            );
        }
        let mut timestamp = None;
        let mut status = ParseStatus::Parsed;
        let mut fields = BTreeMap::new();
        let category;
        if custom.is_none() && errors.parse(line).is_some() {
            fields = errors.parse(line).unwrap();
            category = "web_error";
        } else if format == InputFormat::Web {
            let parsed = if let Some(p) = &custom {
                p.parse(line)
            } else {
                combined.parse(line).or_else(|| common.parse(line))
            };
            category = "web_access";
            if let Some(f) = parsed {
                timestamp = f
                    .get("time")
                    .and_then(|s| {
                        DateTime::parse_from_str(s, "%d/%b/%Y:%H:%M:%S %z")
                            .or_else(|_| DateTime::parse_from_rfc3339(s))
                            .ok()
                    })
                    .map(|t| t.to_rfc3339());
                fields = f;
            } else {
                status = ParseStatus::Unrecognized;
            }
        } else {
            category = "auth_text";
            if let Some((caps, action)) = failed
                .captures(line)
                .map(|c| (c, "login_failure"))
                .or_else(|| accepted.captures(line).map(|c| (c, "login_success")))
                .or_else(|| invalid.captures(line).map(|c| (c, "login_failure")))
            {
                fields.insert("user".into(), caps[1].into());
                fields.insert("client_ip".into(), caps[2].into());
                fields.insert("action".into(), action.into());
            } else {
                status = ParseStatus::Unrecognized;
            }
            if let Some(first) = line.split_whitespace().next() {
                timestamp = DateTime::parse_from_rfc3339(first)
                    .ok()
                    .map(|t| t.to_rfc3339());
            }
        }
        if category == "web_error" {
            timestamp = fields
                .get("time")
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|t| t.to_rfc3339());
        }
        if status == ParseStatus::Unrecognized {
            report.warn(
                &source.path,
                Some(format!("line:{}", i + 1)),
                "line did not match a supported format; raw text retained",
            );
        }
        report.records.push(make_record(
            source,
            format!("line:{}", i + 1),
            timestamp,
            line.into(),
            status,
            RecordData::Log(LogData {
                category: category.into(),
                fields,
            }),
        ));
    }
    Ok(())
}
fn parse_processes(
    bytes: &[u8],
    source: &Source,
    max: usize,
    report: &mut AnalysisReport,
) -> Result<()> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).context("invalid process snapshot JSON")?;
    let processes: Vec<(Option<String>, Option<String>, String, ProcessData)> = if value.is_array()
    {
        let processes: Vec<ProcessData> = serde_json::from_value(value)?;
        processes
            .into_iter()
            .map(|p| Ok((None, p.start_time.clone(), serde_json::to_string(&p)?, p)))
            .collect::<Result<_>>()?
    } else if let Some(records) = value.get("records") {
        let records: Vec<Record> = serde_json::from_value(records.clone())?;
        records
            .into_iter()
            .filter_map(|r| {
                if let RecordData::Process(p) = r.data {
                    Some((Some(r.source_id), r.timestamp, r.raw, p))
                } else {
                    None
                }
            })
            .collect()
    } else {
        bail!("process snapshot must be a ProcessData array or an analysis report with records");
    };
    if processes.len() > max {
        bail!("process snapshot exceeds max records ({max})");
    }
    let mut groups = BTreeMap::new();
    let mut pids = std::collections::HashSet::new();
    for (i, (original_group, timestamp, raw, process)) in processes.into_iter().enumerate() {
        // Namespace report snapshots by their original source; never connect PIDs across hosts.
        let record_source = if let Some(original) = original_group {
            let group = groups.entry(original.clone()).or_insert_with(|| {
                let mut group = source.clone();
                group.id = hex(&Sha256::digest(
                    format!("{}#{}", source.id, original).as_bytes(),
                ));
                group.path = format!("report://{}#{}", source.path, original);
                group
            });
            group.clone()
        } else {
            source.clone()
        };
        if !pids.insert((record_source.id.clone(), process.pid)) {
            report.warn(
                &source.path,
                Some(format!("index:{i}")),
                "duplicate PID in snapshot",
            );
        }
        report.records.push(make_record(
            &record_source,
            format!("index:{i}"),
            timestamp,
            raw,
            ParseStatus::Parsed,
            RecordData::Process(process),
        ));
    }
    report.sources.extend(groups.into_values());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn linux_login_and_truncation() {
        let mut bytes = vec![0; 384];
        bytes[0..2].copy_from_slice(&7i16.to_le_bytes());
        bytes[44..48].copy_from_slice(b"root");
        bytes[340..344].copy_from_slice(&1_700_000_000i32.to_le_bytes());
        bytes.extend([1, 2]);
        let source = source_for("wtmp", "wtmp", &bytes);
        let mut r = AnalysisReport::default();
        parse_utmp(&bytes, &source, InputFormat::Wtmp, 10, &mut r).unwrap();
        assert_eq!(r.records.len(), 2);
        assert_eq!(r.records[1].status, ParseStatus::Malformed);
        if let RecordData::Log(l) = &r.records[0].data {
            assert_eq!(l.fields["user"], "root");
            assert_eq!(l.fields["action"], "login_success");
        } else {
            panic!();
        }
        assert!(r.records[0].timestamp.is_some());
    }
    #[test]
    fn auto_magic_and_unknown_binary() {
        assert_eq!(
            detect(Path::new("unknown"), b"ElfFile\0").unwrap(),
            InputFormat::Evtx
        );
        assert!(detect(Path::new("unknown"), &[0, 1]).is_err());
        assert_eq!(
            detect(Path::new("wtmp.1"), &[0; 384]).unwrap(),
            InputFormat::Wtmp
        );
        assert_eq!(detect(Path::new("empty"), b"").unwrap(), InputFormat::Text);
    }
}
