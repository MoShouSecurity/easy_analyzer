import { useState, useEffect, useCallback, useRef } from "react";
import { api } from "../lib/api";
import type {
  IocView as Model,
  IocInput,
  Indicator,
  TaskMessage,
} from "../types";
import { Button } from "./ui/button";
import { Checkbox } from "./ui/checkbox";
export function IocView({
  sessionId,
  busy,
  revision,
  onTask,
  onJump,
  onChanged,
  onError,
}: {
  sessionId: number;
  busy: boolean;
  revision: number;
  onTask: (f: () => Promise<TaskMessage>) => Promise<void>;
  onJump: (id: string) => void;
  onChanged: () => Promise<void>;
  onError: (e: string) => void;
}) {
  const [view, setView] = useState<Model | null>(null);
  const [offset, setOffset] = useState(0);
  const [hitOffset, setHitOffset] = useState(0);
  const [text, setText] = useState("");
  const [csv, setCsv] = useState(false);
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const [kind, setKind] = useState<Indicator["kind"] | "">("");
  const [subdomains, setSubdomains] = useState(true);
  const [issues, setIssues] = useState<string[]>([]);
  const [working, setWorking] = useState(false);
  const policySession = useRef<number | null>(null);
  const load = useCallback(async () => {
    try {
      const next = await api.ioc(sessionId, offset, hitOffset);
      if (policySession.current !== sessionId) {
        policySession.current = sessionId;
        setSubdomains(next.status.run?.include_subdomains ?? true);
      }
      setView(next);
    } catch (e) {
      onError(String(e));
    }
  }, [sessionId, offset, hitOffset]);
  useEffect(() => {
    void load();
  }, [load, revision]);
  const add = async (input: IocInput) => {
    setWorking(true);
    try {
      const result = await api.importIoc(sessionId, input);
      setIssues(result.issues.map((e) => `第 ${e.line} 行：${e.message}`));
      await load();
      await onChanged();
      if (input.text) setText("");
      if (input.value) {
        setValue("");
        setNote("");
      }
    } catch (e) {
      onError(String(e));
    } finally {
      setWorking(false);
    }
  };
  const disabled = busy || working;
  const page = (o: number, total: number, set: (v: number) => void) => (
    <div className="project-actions">
      <Button
        variant="ghost"
        disabled={!o || disabled}
        onClick={() => set(Math.max(0, o - 100))}
      >
        上一页
      </Button>
      <span>
        {total ? o + 1 : 0}–{Math.min(o + 100, total)} / {total}
      </span>
      <Button
        variant="ghost"
        disabled={o + 100 >= total || disabled}
        onClick={() => set(o + 100)}
      >
        下一页
      </Button>
    </div>
  );
  return (
    <div className="ioc-page">
      <section className="ioc-input">
        <h2>添加 IOC</h2>
        <Button
          disabled={disabled}
          onClick={() =>
            void api
              .pick("ioc")
              .then((paths) => {
                if (paths.length) void add({ paths });
              })
              .catch((e) => onError(String(e)))
          }
        >
          导入 TXT / CSV 文件
        </Button>
        <label>
          粘贴清单
          <textarea
            aria-label="IOC 清单"
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={
              csv
                ? "type,value,note\ndomain,example.com,待核查"
                : "每行一个 IPv4 / IPv6、域名或完整 HTTP/HTTPS URL"
            }
          />
        </label>
        <div className="project-actions">
          <Checkbox
            checked={csv}
            onChange={setCsv}
            label="CSV 格式（type,value，可选 note）"
          />
          <Button
            disabled={disabled || !text.trim()}
            onClick={() => void add({ text, csv })}
          >
            追加粘贴清单
          </Button>
        </div>
        <div className="ioc-manual">
          <select
            aria-label="IOC 类型"
            value={kind}
            onChange={(e) => setKind(e.target.value as typeof kind)}
          >
            <option value="">自动识别</option>
            <option value="ip">IP 地址</option>
            <option value="domain">域名</option>
            <option value="url">URL</option>
          </select>
          <input
            aria-label="手动 IOC"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="IOC 值"
          />
          <input
            aria-label="IOC 说明"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="说明（可选）"
          />
          <Button
            disabled={disabled || !value.trim()}
            onClick={() => void add({ value, note, ...(kind ? { kind } : {}) })}
          >
            手动添加
          </Button>
        </div>
        {issues.length > 0 && (
          <div role="alert">
            有效条目已追加，以下条目无效：
            {issues.map((v, i) => (
              <p key={i}>{v}</p>
            ))}
          </div>
        )}
      </section>
      <section>
        <h2>项目 IOC 清单</h2>
        <p>{view?.status.indicators ?? 0} 个 IOC · 统一去重</p>
        <div className="project-actions">
          <Checkbox
            checked={subdomains}
            onChange={setSubdomains}
            label="域名包含子域名"
          />
          <Button
            disabled={disabled || !view?.status.indicators}
            onClick={() =>
              void onTask(() => api.scanIoc(sessionId, subdomains))
            }
          >
            扫描当前项目
          </Button>
        </div>
        {view?.status.needs_rescan && (
          <p className="ioc-pending">
            有新增证据或清单变更尚未扫描，请主动重新扫描。
          </p>
        )}
        {view?.status.run && (
          <p>
            最近扫描：{view.status.run.scanned_records} /{" "}
            {view.status.run.total_records} 条 ·{" "}
            {view.status.run.complete ? "已完成" : "未完成，保留有效命中"} ·{" "}
            {view.status.run.include_subdomains ? "包含子域名" : "精确域名"}
          </p>
        )}
        <table className="project-table">
          <thead>
            <tr>
              <th>类型</th>
              <th>值</th>
              <th>说明</th>
            </tr>
          </thead>
          <tbody>
            {view?.indicators.items.map((i) => (
              <tr key={i.id}>
                <td>{i.kind}</td>
                <td className="mono">{i.value}</td>
                <td>
                  <input
                    aria-label={`说明 ${i.value}`}
                    disabled={disabled}
                    defaultValue={i.note}
                    key={`${i.id}:${i.note}`}
                    onBlur={(e) => {
                      if (e.target.value !== i.note)
                        void api
                          .iocNote(sessionId, i.id, e.target.value)
                          .then(async () => {
                            await load();
                            await onChanged();
                          })
                          .catch((e) => onError(String(e)));
                    }}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {view && page(offset, view.indicators.total, setOffset)}
      </section>
      <section>
        <h2>匹配结果 · 待核查线索</h2>
        <table className="project-table">
          <thead>
            <tr>
              <th>IOC</th>
              <th>匹配值 / 位置</th>
              <th>证据</th>
            </tr>
          </thead>
          <tbody>
            {view?.hits.items.map((hit, i) => (
              <tr key={`${hit.record_id}:${hit.indicator_id}:${i}`}>
                <td>
                  {hit.value}
                  <small>{hit.note}</small>
                </td>
                <td>
                  {hit.matched_value}
                  <small>
                    {hit.field}
                    {hit.byte_offset !== null
                      ? ` · 字节偏移 ${hit.byte_offset}`
                      : ""}
                  </small>
                </td>
                <td>
                  <Button variant="ghost" onClick={() => onJump(hit.record_id)}>
                    {hit.position}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {view && page(hitOffset, view.hits.total, setHitOffset)}
      </section>
    </div>
  );
}
