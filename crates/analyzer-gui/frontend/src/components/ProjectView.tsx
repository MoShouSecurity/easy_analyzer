import { useState, useEffect } from "react";
import { api } from "../lib/api";
import type { ProjectEntry, ProjectInfo } from "../types";
import { Button } from "./ui/button";
import { Dialog } from "./ui/dialog";
export function localTimestamp() {
  const now = new Date();
  const offset = -now.getTimezoneOffset();
  const sign = offset >= 0 ? "+" : "-";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}T${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}${sign}${pad(Math.floor(Math.abs(offset) / 60))}:${pad(Math.abs(offset) % 60)}`;
}
export function newProject(): ProjectInfo {
  const time = localTimestamp();
  return {
    id: crypto.randomUUID(),
    name: "",
    client: "",
    response_start: time,
    response_end: null,
    location: "",
    responders: "",
    description: "",
    created_at: time,
    updated_at: time,
  };
}
export function ProjectEditor({
  info,
  busy,
  onClose,
  onSave,
}: {
  info: ProjectInfo;
  busy: boolean;
  onClose: () => void;
  onSave: (v: ProjectInfo) => Promise<void>;
}) {
  const [value, setValue] = useState(info);
  const [nameEdited, setNameEdited] = useState(Boolean(info.name.trim()));
  const [error, setError] = useState("");
  const fields: [keyof ProjectInfo, string, boolean][] = [
    ["client", "客户单位", true],
    ["name", "项目名称", false],
    ["response_start", "响应开始时间（含时区）", true],
    ["response_end", "响应结束时间（含时区）", false],
    ["location", "响应地点", false],
    ["responders", "服务人员", false],
  ];
  const submit = async () => {
    const name = value.name.trim() || value.client.trim();
    if (
      !value.client.trim() ||
      Number.isNaN(Date.parse(value.response_start))
    ) {
      setError("请填写客户单位和包含时区的开始时间");
      return;
    }
    if (
      value.response_end &&
      Date.parse(value.response_end) < Date.parse(value.response_start)
    ) {
      setError("响应结束时间不能早于开始时间");
      return;
    }
    setError("");
    try {
      await onSave({ ...value, name });
    } catch (e) {
      setError(String(e));
    }
  };
  return (
    <Dialog
      open
      onOpenChange={(v) => {
        if (!v && !busy) onClose();
      }}
      title={info.name ? "编辑项目资料" : "新建应急响应项目"}
      description="同一次响应可以持续多天，并追加多次证据。"
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
        className="project-form"
      >
        {fields.map(([key, label, required]) => (
          <label key={key}>
            {label}
            {required ? " *" : ""}
            <input
              required={required}
              value={value[key] ?? ""}
              placeholder={
                key === "name"
                  ? "默认使用客户单位，可修改"
                  : key.includes("response_")
                    ? "2026-10-05T09:00:00+08:00"
                    : ""
              }
              onChange={(e) => {
                const next = e.target.value;
                if (key === "name") setNameEdited(Boolean(next.trim()));
                setValue((v) => ({
                  ...v,
                  [key]: next || (key === "response_end" ? null : ""),
                  ...(key === "client" && !nameEdited ? { name: next } : {}),
                }));
              }}
            />
          </label>
        ))}
        <label className="full">
          项目说明
          <textarea
            value={value.description}
            onChange={(e) =>
              setValue((v) => ({ ...v, description: e.target.value }))
            }
          />
        </label>
        {error && (
          <p role="alert" className="error-text full">
            {error}
          </p>
        )}
        <div className="dialog-actions full">
          <Button
            variant="ghost"
            type="button"
            onClick={onClose}
            disabled={busy}
          >
            取消
          </Button>
          <Button type="submit" disabled={busy}>
            确认项目资料
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
export function ProjectHome({
  busy,
  onNew,
  onOpen,
  onPick,
  onError,
}: {
  busy: boolean;
  onNew: () => void;
  onOpen: (path: string) => void;
  onPick: () => void;
  onError: (e: string) => void;
}) {
  const [text, setText] = useState("");
  const [client, setClient] = useState("");
  const [from, setFrom] = useState("");
  const [until, setUntil] = useState("");
  const [rows, setRows] = useState<ProjectEntry[]>([]);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    let stale = false;
    const timeout = setTimeout(() => {
      setLoading(true);
      api
        .projects({ text, client, from: from || null, until: until || null })
        .then((v) => {
          if (!stale) setRows(v ?? []);
        })
        .catch((e) => {
          if (!stale) onError(String(e));
        })
        .finally(() => {
          if (!stale) setLoading(false);
        });
    }, 200);
    return () => {
      stale = true;
      clearTimeout(timeout);
    };
  }, [text, client, from, until]);
  return (
    <div className="project-page">
      <section className="project-start" aria-labelledby="project-start-title">
        <div>
          <h3 id="project-start-title">新建或续办应急响应</h3>
          <p>点击“新建项目”填写客户单位、响应时间等资料。</p>
        </div>
        <div className="project-actions">
          <Button disabled={busy} onClick={onNew}>
            新建项目
          </Button>
          <Button variant="secondary" disabled={busy} onClick={onPick}>
            打开项目文件
          </Button>
        </div>
      </section>
      <section className="project-browser" aria-labelledby="project-list-title">
        <div className="project-list-heading">
          <h3 id="project-list-title">已有项目</h3>
          <p>
            按最近打开排序 · {loading ? "正在查询…" : `${rows.length} 个项目`}
          </p>
        </div>
        <details className="project-filters">
          <summary>筛选已有项目</summary>
          <p>以下条件用于查找项目列表。</p>
          <div className="project-search">
            <label>
              搜索项目名称或客户单位
              <input
                aria-label="项目搜索"
                placeholder="输入关键词查找已有项目"
                value={text}
                onChange={(e) => setText(e.target.value)}
              />
            </label>
            <label>
              按客户单位筛选
              <input
                value={client}
                placeholder="全部客户单位"
                onChange={(e) => setClient(e.target.value)}
              />
            </label>
            <label>
              响应开始日期不早于
              <input
                type="date"
                value={from}
                onChange={(e) => setFrom(e.target.value)}
              />
            </label>
            <label>
              响应开始日期不晚于
              <input
                type="date"
                value={until}
                onChange={(e) => setUntil(e.target.value)}
              />
            </label>
          </div>
        </details>
        <div className="project-list">
          {rows.map((row) => (
            <article key={row.info.id}>
              <div>
                <h3>{row.info.name}</h3>
                <p>
                  {row.info.client} · {row.info.response_start}
                </p>
                <small>{row.path}</small>
                {row.missing && (
                  <p className="error-text">
                    项目文件缺失，请重新打开移动后的文件
                  </p>
                )}
              </div>
              <Button
                variant="secondary"
                disabled={busy || row.missing}
                onClick={() => onOpen(row.path)}
              >
                继续项目
              </Button>
            </article>
          ))}
          {!rows.length && !loading && (
            <p>
              {text.trim() || client.trim() || from || until
                ? "没有符合筛选条件的项目，请调整筛选条件。"
                : "还没有已保存的项目。点击上方“新建项目”开始响应，或打开已有 .eair 文件。"}
            </p>
          )}
        </div>
      </section>
    </div>
  );
}
