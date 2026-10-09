import {
  FileText,
  Link2,
  PanelRightClose,
  ShieldCheck,
  ExternalLink,
  LoaderCircle,
} from "lucide-react";
import { useState, useEffect } from "react";
import { Button } from "./ui/button";
import { api } from "../lib/api";
import { Tabs } from "./ui/tabs";
import { basename, bytes } from "../lib/utils";
import { logFieldLabel } from "../lib/field-labels";
import {
  severityLabel,
  statusLabel,
  type Source,
  type Finding,
  type DetailResponse,
} from "../types";
export function Risk({ finding }: { finding: Finding }) {
  return (
    <span className={`risk risk-${finding.severity}`}>
      <span className="risk-dot" />
      {severityLabel[finding.severity]}
    </span>
  );
}
function Field({
  name,
  value,
  mono = false,
  originalName,
}: {
  name: string;
  value: string | null | undefined;
  mono?: boolean;
  originalName?: string;
}) {
  return (
    <div className="detail-field">
      <span title={originalName}>{name}</span>
      <div className={mono ? "mono" : ""}>{value || "未知"}</div>
    </div>
  );
}
export function Inspector({
  finding,
  detail,
  loading,
  onJump,
  onFinding,
  onClose,
  onSaveNote,
  sessionId,
}: {
  finding: Finding | null;
  detail: DetailResponse | null;
  loading: boolean;
  onJump: (id: string) => void;
  onFinding: (f: Finding) => void;
  onClose: () => void;
  onSaveNote?: (text: string) => Promise<void>;
  sessionId?: number | null;
}) {
  const [refs, setRefs] = useState(finding?.evidence_ids ?? []);
  const [refOffset, setRefOffset] = useState(0);
  const [refError, setRefError] = useState("");
  useEffect(() => {
    setRefs(finding?.evidence_ids ?? []);
    setRefOffset(0);
    setRefError("");
  }, [finding?.id]);
  const loadRefs = async (offset: number) => {
    if (!finding || sessionId == null) return;
    try {
      const page = await api.findingRefs(sessionId, finding.id, offset);
      setRefs(page.items);
      setRefOffset(offset);
    } catch (e) {
      setRefError(String(e));
    }
  };
  const [note, setNote] = useState(detail?.note ?? "");
  const [savingNote, setSavingNote] = useState(false);
  useEffect(
    () => setNote(detail?.note ?? ""),
    [detail?.record.id, detail?.note],
  );
  const [tab, setTab] = useState("explanation");
  useEffect(
    () => setTab(finding ? "explanation" : "fields"),
    [finding?.id, detail?.record.id],
  );
  const fields = detail?.record.data;
  return (
    <div className="inspector-content">
      <div className="inspector-heading">
        <span>
          <FileText size={15} />
          证据详情
        </span>
        <Button
          variant="ghost"
          size="icon"
          aria-label="收起详情"
          onClick={onClose}
        >
          <PanelRightClose size={15} />
        </Button>
      </div>
      {!finding && !detail ? (
        <div className="inspector-empty">
          {loading ? (
            <LoaderCircle className="spin" size={25} />
          ) : (
            <FileText size={30} strokeWidth={1} />
          )}
          <strong>{loading ? "正在读取证据" : "选择一条发现或证据"}</strong>
          <p>
            核查解释与原始记录，
            <br />
            追溯每一项分析结果。
          </p>
        </div>
      ) : (
        <>
          <Tabs
            value={tab}
            onChange={setTab}
            items={
              finding
                ? [
                    { value: "explanation", label: "解释" },
                    { value: "references", label: "证据引用" },
                  ]
                : [
                    { value: "fields", label: "字段" },
                    { value: "raw", label: "原文" },
                    { value: "source", label: "来源" },
                    ...(onSaveNote ? [{ value: "note", label: "备注" }] : []),
                  ]
            }
          />
          <div className="inspector-scroll">
            {finding &&
              (tab === "references" || tab === "explanation") &&
              (finding.evidence_count ?? 0) > 100 && (
                <div className="project-actions">
                  <Button
                    variant="ghost"
                    disabled={!refOffset}
                    onClick={() => void loadRefs(Math.max(0, refOffset - 100))}
                  >
                    上一页引用
                  </Button>
                  <span>
                    {refOffset + 1}–
                    {Math.min(refOffset + 100, finding.evidence_count ?? 0)} /{" "}
                    {finding.evidence_count}
                  </span>
                  <Button
                    variant="ghost"
                    disabled={refOffset + 100 >= (finding.evidence_count ?? 0)}
                    onClick={() => void loadRefs(refOffset + 100)}
                  >
                    下一页引用
                  </Button>
                </div>
              )}
            {refError && <p role="alert">{refError}</p>}

            {detail && tab === "note" && onSaveNote && (
              <div className="evidence-note">
                <label>
                  证据备注
                  <textarea
                    aria-label="证据备注"
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                  />
                </label>
                <Button
                  disabled={savingNote}
                  onClick={() => {
                    setSavingNote(true);
                    void onSaveNote(note).finally(() => setSavingNote(false));
                  }}
                >
                  保存备注
                </Button>
              </div>
            )}
            {finding && tab === "explanation" && (
              <>
                <div className="detail-eyebrow">
                  <Risk finding={finding} />
                  <span className="small-badge">
                    {finding.origin.startsWith("local:")
                      ? "本地规则"
                      : "AI 发现"}
                  </span>
                </div>
                <h3>{finding.title}</h3>
                <p className="detail-description">{finding.description}</p>
                <div className="detail-section">
                  <h4>
                    <ShieldCheck size={14} />
                    核查建议
                  </h4>
                  {finding.recommendations.map((r, i) => (
                    <div className="recommendation" key={i}>
                      <span>{i + 1}</span>
                      <p>{r}</p>
                    </div>
                  ))}
                </div>
                <div className="detail-section">
                  <h4>
                    <Link2 size={14} />
                    关联证据{" "}
                    <small>
                      {finding.evidence_count ?? finding.evidence_ids.length}
                    </small>
                  </h4>
                  {refs.map((id) => (
                    <button
                      className="evidence-link"
                      key={id}
                      onClick={() => onJump(id)}
                    >
                      <span className="mono">{id}</span>
                      <ExternalLink size={12} />
                    </button>
                  ))}
                </div>
                <Field name="发现来源" value={finding.origin} mono />
                <div className="detail-note">
                  分析结果是待核查线索，需结合原始证据确认。
                </div>
              </>
            )}
            {finding && tab === "references" && (
              <>
                <p className="muted">点击引用跳转并定位原始记录。</p>
                {refs.map((id) => (
                  <button
                    className="evidence-link"
                    key={id}
                    onClick={() => onJump(id)}
                  >
                    <span className="mono">{id}</span>
                    <ExternalLink size={12} />
                  </button>
                ))}
              </>
            )}
            {detail && tab === "fields" && (
              <>
                <div className="detail-eyebrow">
                  <span className="small-badge">
                    {statusLabel[detail.record.status]}
                  </span>
                  <span className="muted">
                    {basename(detail.source?.path || "")}
                  </span>
                </div>
                <Field name="证据编号" value={detail.record.id} mono />
                <Field name="时间" value={detail.record.timestamp} mono />
                <Field name="位置" value={detail.record.position} mono />
                {fields?.kind === "log" && (
                  <>
                    <Field name="类别" value={fields.fields.category} />
                    {Object.entries(fields.fields.fields).map(([k, v]) => (
                      <Field
                        key={k}
                        name={logFieldLabel(k)}
                        originalName={k}
                        value={v}
                        mono
                      />
                    ))}
                  </>
                )}
                {fields?.kind === "process" && (
                  <>
                    <div className="detail-pair">
                      <Field
                        name="PID"
                        value={String(fields.fields.pid)}
                        mono
                      />
                      <Field
                        name="父 PID"
                        value={
                          fields.fields.parent_pid === null
                            ? "未知"
                            : String(fields.fields.parent_pid)
                        }
                        mono
                      />
                    </div>
                    <Field name="名称" value={fields.fields.name} />
                    <Field name="路径" value={fields.fields.path} mono />
                    <Field
                      name="命令行"
                      value={fields.fields.command.join(" ")}
                      mono
                    />
                    <Field name="用户" value={fields.fields.user} />
                  </>
                )}
                {fields?.kind === "packet" && (
                  <>
                    <Field
                      name="源端点"
                      value={`${fields.fields.source || "未知"}:${fields.fields.source_port ?? "—"}`}
                      mono
                    />
                    <Field
                      name="目标端点"
                      value={`${fields.fields.destination || "未知"}:${fields.fields.destination_port ?? "—"}`}
                      mono
                    />
                    <div className="detail-pair">
                      <Field name="协议" value={fields.fields.protocol} />
                      <Field
                        name="字节"
                        value={`${fields.fields.captured_bytes} / ${fields.fields.original_bytes}`}
                        mono
                      />
                    </div>
                    {Object.entries(fields.fields.application).map(([k, v]) => (
                      <Field key={k} name={k} value={v} mono />
                    ))}
                    {fields.fields.payload_hex && (
                      <details className="raw-reply">
                        <summary>载荷十六进制</summary>
                        <pre>{fields.fields.payload_hex}</pre>
                      </details>
                    )}
                  </>
                )}
                {detail.related.length > 0 && (
                  <div className="detail-section">
                    <h4>
                      关联发现 <small>{detail.related.length}</small>
                    </h4>
                    {detail.related.map((f) => (
                      <button
                        className="related-finding"
                        key={f.id}
                        onClick={() => onFinding(f)}
                      >
                        <Risk finding={f} />
                        <span>{f.title}</span>
                      </button>
                    ))}
                  </div>
                )}
              </>
            )}
            {detail && tab === "raw" && (
              <>
                <div className="detail-note">
                  {fields?.kind === "packet"
                    ? "原始捕获包 · 十六进制"
                    : "原始记录 · 按来源保留"}
                </div>
                <pre className="raw-evidence">{detail.record.raw}</pre>
              </>
            )}
            {detail && tab === "source" && (
              <>
                <Field name="来源路径" value={detail.source?.path} mono />
                <Field name="格式" value={detail.source?.format} />
                <Field
                  name="大小"
                  value={detail.source ? bytes(detail.source.bytes) : null}
                />
                <Field name="SHA-256" value={detail.source?.sha256} mono />
                <Field name="来源编号" value={detail.record.source_id} mono />
              </>
            )}
          </div>
        </>
      )}
    </div>
  );
}

export function SourceInspector({
  source,
  onClose,
}: {
  source: Source;
  onClose: () => void;
}) {
  return (
    <div className="inspector-content">
      <div className="inspector-heading">
        <span>
          <FileText size={15} />
          来源详情
        </span>
        <Button
          variant="ghost"
          size="icon"
          aria-label="收起详情"
          onClick={onClose}
        >
          <PanelRightClose size={15} />
        </Button>
      </div>
      <div className="inspector-scroll">
        <div className="detail-eyebrow">
          <span className="small-badge">{source.format}</span>
        </div>
        <h3>{basename(source.path)}</h3>
        <Field name="完整路径" value={source.path} mono />
        <Field name="格式" value={source.format} />
        <Field
          name="大小"
          value={`${bytes(source.bytes)} · ${source.bytes.toLocaleString()} 字节`}
          mono
        />
        <Field name="SHA-256" value={source.sha256} mono />
        <Field name="来源编号" value={source.id} mono />
        <div className="detail-note">
          哈希基于原始文件计算。导出报告保留全部来源与完整证据。
        </div>
      </div>
    </div>
  );
}
