import { useRef, useState } from "react";
import { LoaderCircle } from "lucide-react";
import { Dialog } from "./ui/dialog";
import { Select } from "./ui/select";
import { Checkbox } from "./ui/checkbox";
import { Button } from "./ui/button";
import { basename } from "../lib/utils";
import {
  defaultFilters,
  statusLabel,
  type Filters,
  type Screen,
  type Source,
} from "../types";

export interface EvidenceFilterContext {
  screen: Screen;
  filters: Filters;
}

export function AiEvidenceFilter({
  initial,
  sources,
  categories,
  protocols,
  busy,
  onApply,
  onClose,
}: {
  initial: EvidenceFilterContext;
  sources: Source[];
  categories: string[];
  protocols: string[];
  busy: boolean;
  onApply: (value: EvidenceFilterContext) => Promise<void>;
  onClose: () => void;
}) {
  const [draft, setDraft] = useState(() => structuredClone(initial));
  const [error, setError] = useState<string | null>(null);
  const composing = useRef(false);
  const change = (value: Partial<Filters>) =>
    setDraft((v) => ({ ...v, filters: { ...v.filters, ...value } }));
  const apply = async () => {
    if (busy || composing.current) return;
    setError(null);
    try {
      await onApply(draft);
    } catch (e) {
      setError(String(e));
    }
  };
  const f = draft.filters;
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open && !busy) onClose();
      }}
      title="筛选发送证据"
      description="在本地查询完整证据集合，应用后更新“当前筛选”。此操作不会发送 AI 请求。"
      className="ai-filter-dialog"
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void apply();
        }}
      >
        <fieldset disabled={busy}>
          <label className="form-field">
            证据类型
            <Select
              label="发送证据类型"
              value={draft.screen}
              options={[
                { value: "logs", label: "日志" },
                { value: "processes", label: "进程" },
                { value: "network", label: "网络数据包" },
              ]}
              onChange={(screen) =>
                setDraft({
                  screen: screen as Screen,
                  filters: {
                    ...defaultFilters(),
                    text: f.text,
                    regex: f.regex,
                    suspicious: f.suspicious,
                    source: f.source,
                    status: f.status,
                    limit: f.limit,
                    packets: true,
                    tree: false,
                  },
                })
              }
            />
          </label>
          <label className="form-field">
            关键词或正则表达式
            <input
              className="input"
              aria-label="发送证据查询"
              placeholder="输入关键词，留空表示该类型的全部证据"
              value={f.text}
              onChange={(e) => change({ text: e.target.value })}
              onCompositionStart={() => {
                composing.current = true;
              }}
              onCompositionEnd={() => {
                composing.current = false;
              }}
              onKeyDown={(e) => {
                if (
                  e.key === "Enter" &&
                  (composing.current ||
                    e.nativeEvent.isComposing ||
                    e.keyCode === 229)
                )
                  e.preventDefault();
              }}
            />
          </label>
          <div className="filter-row">
            <Checkbox
              label="正则表达式"
              checked={f.regex}
              onChange={(regex) => change({ regex })}
              disabled={busy}
            />
            <Checkbox
              label="仅本地可疑项"
              checked={f.suspicious}
              onChange={(suspicious) => change({ suspicious })}
              disabled={busy}
            />
          </div>
          <div className="ai-filter-fields">
            <Select
              label="发送证据来源"
              value={f.source || ""}
              onChange={(source) => change({ source: source || null })}
              options={[
                { value: "", label: "全部来源" },
                ...sources.map((s) => ({
                  value: s.id,
                  label: basename(s.path),
                })),
                ...(f.source && !sources.some((s) => s.id === f.source)
                  ? [{ value: f.source, label: "指定来源" }]
                  : []),
              ]}
            />
            <Select
              label="发送证据解析状态"
              value={f.status || ""}
              onChange={(status) =>
                change({ status: (status as Filters["status"]) || null })
              }
              options={[
                { value: "", label: "全部状态" },
                ...Object.entries(statusLabel).map(([value, label]) => ({
                  value,
                  label,
                })),
              ]}
            />
            {draft.screen === "logs" && (
              <Select
                label="发送日志类别"
                value={f.category || ""}
                onChange={(category) => change({ category: category || null })}
                options={[
                  { value: "", label: "全部类别" },
                  ...categories.map((value) => ({ value, label: value })),
                ]}
              />
            )}
            {draft.screen === "network" && (
              <Select
                label="发送协议"
                value={f.protocol || ""}
                onChange={(protocol) => change({ protocol: protocol || null })}
                options={[
                  { value: "", label: "全部协议" },
                  ...protocols.map((value) => ({ value, label: value })),
                ]}
              />
            )}
          </div>
          {f.flow !== null && (
            <div className="ai-filter-flow">
              限定网络会话 #{f.flow + 1}
              <Button
                type="button"
                size="sm"
                variant="ghost"
                onClick={() => change({ flow: null })}
              >
                移除会话限制
              </Button>
            </div>
          )}
        </fieldset>
        {error && (
          <div className="warning-note" role="alert">
            {error}。保留上一次有效筛选。
          </div>
        )}
        <div className="dialog-actions">
          <Button
            type="button"
            variant="ghost"
            disabled={busy}
            onClick={onClose}
          >
            取消
          </Button>
          <Button type="submit" disabled={busy}>
            {busy && <LoaderCircle size={14} className="spin" />}
            {busy ? "正在查询…" : "应用筛选"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
