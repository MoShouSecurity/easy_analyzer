//! Lossless, independently compressed SQLite cells. Indices remain directly queryable.
use anyhow::{Result, bail};
use flate2::{Compression, bufread::ZlibDecoder, write::ZlibEncoder};
use rusqlite::{
    Connection,
    functions::FunctionFlags,
    types::{Value, ValueRef},
};
use std::io::{Read, Write};

const MAGIC: &[u8; 4] = b"EAZ1";
const MAX_TEXT: usize = 64 * 1024 * 1024;

pub(crate) fn encode(text: String) -> Result<Value> {
    // Small and unusually large cells stay plain; no evidence is truncated.
    if !(128..=MAX_TEXT).contains(&text.len()) {
        return Ok(Value::Text(text));
    }
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(text.as_bytes())?;
    let compressed = encoder.finish()?;
    if compressed.len() + 8 >= text.len() {
        return Ok(Value::Text(text));
    }
    let mut bytes = Vec::with_capacity(compressed.len() + 8);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(text.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&compressed);
    Ok(Value::Blob(bytes))
}

pub(crate) fn text(value: ValueRef<'_>) -> Result<String> {
    match value {
        ValueRef::Text(bytes) => Ok(std::str::from_utf8(bytes)?.to_owned()),
        ValueRef::Blob(bytes) => {
            if bytes.len() < 8 || &bytes[..4] != MAGIC {
                bail!("不支持的项目压缩编码");
            }
            let length = u32::from_le_bytes(bytes[4..8].try_into()?) as usize;
            if !(128..=MAX_TEXT).contains(&length) {
                bail!("无效的项目压缩长度");
            }
            let mut decoder = ZlibDecoder::new(&bytes[8..]);
            let mut restored = Vec::new();
            decoder
                .by_ref()
                .take(length as u64 + 1)
                .read_to_end(&mut restored)?;
            if restored.len() != length || !decoder.get_ref().is_empty() {
                bail!("项目压缩数据损坏或长度不一致");
            }
            Ok(String::from_utf8(restored)?)
        }
        _ => bail!("项目文本字段类型不正确"),
    }
}

pub(crate) fn row_text(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<String> {
    text(row.get_ref(index)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Blob, error.into())
    })
}

pub(crate) fn register(connection: &Connection) -> Result<()> {
    connection.create_scalar_function(
        "eair_text",
        1,
        FunctionFlags::SQLITE_UTF8
            | FunctionFlags::SQLITE_DETERMINISTIC
            | FunctionFlags::SQLITE_INNOCUOUS,
        |ctx| {
            text(ctx.get_raw(0)).map_err(|error| rusqlite::Error::UserFunctionError(error.into()))
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unicode_roundtrip_and_corruption_rejection() {
        let original = "证据日志 example.com\n".repeat(100);
        let value = encode(original.clone()).unwrap();
        assert!(matches!(value, Value::Blob(_)));
        assert_eq!(text(ValueRef::from(&value)).unwrap(), original);
        let Value::Blob(bytes) = value else {
            unreachable!()
        };
        for bad in [
            bytes[..bytes.len() - 1].to_vec(),
            {
                let mut b = bytes.clone();
                b[8] ^= 0xff;
                b
            },
            {
                let mut b = bytes.clone();
                b.push(0);
                b
            },
            {
                let mut b = bytes;
                b[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
                b
            },
        ] {
            assert!(text(ValueRef::Blob(&bad)).is_err());
        }
        assert_eq!(
            encode("短文本".into()).unwrap(),
            Value::Text("短文本".into())
        );
    }
    #[test]
    fn compressed_diagnostics_support_pages_ai_summaries_and_streaming_reports() {
        use crate::*;
        let session = ProjectService::create(ProjectInfo::new("压缩测试", "合成客户")).unwrap();
        let message = "中文摘要与原始诊断完整保存。".repeat(100);
        let diagnostic = core::Diagnostic {
            level: DiagnosticLevel::Warning,
            source: "AI 本地整理".into(),
            position: Some("ai-run:1".into()),
            message: message.clone(),
        };
        {
            let c = session.0.store.as_ref().unwrap().lock().unwrap();
            let json = crate::storage::packed_json(&diagnostic).unwrap();
            assert!(matches!(json, Value::Blob(_)));
            c.execute("INSERT INTO diagnostics(json) VALUES(?1)", [json])
                .unwrap();
        }
        let ctx = ExecutionContext::default();
        assert_eq!(
            session.diagnostic_page(0, 1).unwrap().items[0].message,
            message
        );
        assert_eq!(
            session.ai_local_summaries(&[0], &ctx).unwrap()["ai-run:1"],
            message
        );
        let mut output = Vec::new();
        ExportPlan {
            format: OutputFormat::Json,
            ..Default::default()
        }
        .write_primary(&session, &mut output, &ctx)
        .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(report["diagnostics"][0]["message"], message);
    }
}

/// Large-file comparison fixture only; production never opens or migrates legacy formats.
#[cfg(test)]
#[test]
#[ignore = "set EASY_ANALYZER_COMPRESSION_SOURCE and EASY_ANALYZER_COMPRESSION_OUTPUT"]
fn benchmark_compressed_storage() {
    use crate::ExecutionContext;
    use rusqlite::{OpenFlags, backup::Backup, params};
    use std::{path::PathBuf, time::Instant};
    let source = PathBuf::from(
        std::env::var_os("EASY_ANALYZER_COMPRESSION_SOURCE").expect("source required"),
    );
    let output = PathBuf::from(
        std::env::var_os("EASY_ANALYZER_COMPRESSION_OUTPUT").expect("output required"),
    );
    assert!(!output.exists(), "benchmark output must be new");
    let temporary = tempfile::NamedTempFile::new_in(output.parent().unwrap()).unwrap();
    let before = std::fs::metadata(&source).unwrap().len();
    let start = Instant::now();
    {
        let source =
            Connection::open_with_flags(&source, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let mut c = Connection::open(temporary.path()).unwrap();
        Backup::new(&source, &mut c)
            .unwrap()
            .run_to_completion(1024, std::time::Duration::ZERO, None)
            .unwrap();
        crate::storage::Database::configure(&c).unwrap();
        let ctx = ExecutionContext::default();
        let tx = c.transaction().unwrap();
        let mut after = 0i64;
        let mut count = 0usize;
        let mut update = tx
            .prepare("UPDATE records SET raw=?1,data=?2,preview=?3 WHERE ordinal=?4")
            .unwrap();
        loop {
            let rows = tx.prepare("SELECT ordinal,raw,data,preview FROM records WHERE ordinal>?1 ORDER BY ordinal LIMIT 256").unwrap().query_map([after], |r| Ok((r.get::<_, i64>(0)?,row_text(r,1)?,row_text(r,2)?,row_text(r,3)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            if rows.is_empty() {
                break;
            }
            for (ordinal, raw, data, preview) in rows {
                ctx.check().unwrap();
                let preview = if data == preview {
                    Value::Text(String::new())
                } else {
                    encode(preview).unwrap()
                };
                update
                    .execute(params![
                        encode(raw).unwrap(),
                        encode(data).unwrap(),
                        preview,
                        ordinal
                    ])
                    .unwrap();
                after = ordinal;
                count += 1;
            }
            if count.is_multiple_of(131072) {
                println!(
                    "compressed_records={count} elapsed_seconds={:.1}",
                    start.elapsed().as_secs_f64()
                );
            }
        }
        drop(update);
        println!(
            "records_done={count} elapsed_seconds={:.1}",
            start.elapsed().as_secs_f64()
        );
        let mut after = 0i64;
        let mut count = 0usize;
        let mut update = tx
            .prepare("UPDATE diagnostics SET json=?1 WHERE ordinal=?2")
            .unwrap();
        loop {
            let rows = tx.prepare("SELECT ordinal,json FROM diagnostics WHERE ordinal>?1 ORDER BY ordinal LIMIT 256").unwrap().query_map([after], |r| Ok((r.get::<_, i64>(0)?,row_text(r,1)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            if rows.is_empty() {
                break;
            }
            for (ordinal, json) in rows {
                update
                    .execute(params![encode(json).unwrap(), ordinal])
                    .unwrap();
                after = ordinal;
                count += 1;
            }
        }
        drop(update);
        let mut after = 0i64;
        let mut batches = 0usize;
        loop {
            let rows = tx
                .prepare("SELECT rowid,json FROM ai_batches WHERE rowid>?1 ORDER BY rowid LIMIT 1")
                .unwrap()
                .query_map([after], |r| Ok((r.get::<_, i64>(0)?, row_text(r, 1)?)))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let Some((rowid, json)) = rows.into_iter().next() else {
                break;
            };
            ctx.check().unwrap();
            tx.execute(
                "UPDATE ai_batches SET json=?1 WHERE rowid=?2",
                params![encode(json).unwrap(), rowid],
            )
            .unwrap();
            after = rowid;
            batches += 1;
        }
        println!("ai_batches_done={batches}");
        tx.pragma_update(None, "user_version", crate::storage::VERSION)
            .unwrap();
        tx.commit().unwrap();
        println!(
            "diagnostics_done={count} elapsed_seconds={:.1}",
            start.elapsed().as_secs_f64()
        );
        c.execute_batch("VACUUM;").unwrap();
    }
    temporary.as_file().sync_all().unwrap();
    temporary.persist_noclobber(&output).unwrap();
    let after = std::fs::metadata(&output).unwrap().len();
    println!(
        "before_bytes={before} after_bytes={after} retained_percent={:.1} total_seconds={:.1}",
        after as f64 / before as f64 * 100.,
        start.elapsed().as_secs_f64()
    );
}
