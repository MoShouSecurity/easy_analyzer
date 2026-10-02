import {
  UploadCloud,
  Plus,
  X,
  FileText,
  FolderOpen,
  ChevronDown,
  ArrowRight,
  ShieldCheck,
} from "lucide-react";
import { Button } from "./ui/button";
import { Checkbox } from "./ui/checkbox";
import { Select } from "./ui/select";
import { basename } from "../lib/utils";
import type { ImportRequest } from "../types";
export function ImportView({
  request,
  onChange,
  busy,
  platform,
  onPick,
  onStart,
  dragging,
  elevated,
  elevationError,
  elevationBusy,
  onElevate,
}: {
  request: ImportRequest;
  onChange: (v: ImportRequest) => void;
  busy: boolean;
  platform: string;
  onPick: (kind: string) => void;
  onStart: () => void;
  dragging: boolean;
  elevated: boolean | null;
  elevationError: string | null;
  elevationBusy: boolean;
  onElevate: () => void;
}) {
  return (
    <div className="import-page">
      <div className="import-scroll">
        <button
          className={`drop-zone ${dragging ? "dragging" : ""}`}
          onClick={() => onPick("inputs")}
          disabled={busy}
        >
          <div className="drop-icon">
            <UploadCloud size={23} strokeWidth={1.5} />
          </div>
          <div>
            <strong>拖入证据文件，开始分析</strong>
            <p>EVTX、系统日志、Web 日志、进程快照、PCAP / PCAPNG</p>
          </div>
          <span className="btn btn-secondary">
            <Plus size={14} />
            选择文件
          </span>
        </button>
        <div className="collection-row">
          <Checkbox
            label="采集本机进程"
            checked={request.live}
            disabled={busy}
            onChange={(live) => onChange({ ...request, live })}
          />
          <span
            title={
              platform === "macos"
                ? "macOS 暂不支持本机通用日志采集，请导入离线日志。"
                : ""
            }
          >
            <Checkbox
              label="加载本机日志"
              checked={request.auto_logs}
              disabled={busy || platform === "macos"}
              onChange={(auto_logs) => onChange({ ...request, auto_logs })}
            />
          </span>
          <Button
            variant="ghost"
            size="sm"
            disabled={busy}
            onClick={() => onPick("capture")}
          >
            <FolderOpen size={14} />
            采集保存目录
          </Button>
        </div>
        {platform === "windows" && (
          <div className="collection-permissions">
            <div>
              <span className="small-badge" title={elevationError || undefined}>
                <ShieldCheck size={13} />
                {elevated === true
                  ? "管理员权限"
                  : elevated === false
                    ? "普通权限"
                    : "权限状态未知"}
              </span>
              <p>
                {elevated === true
                  ? "采集时尝试启用调试权限；受保护或已退出的进程仍可能缺失字段。"
                  : "提升权限有助于读取更多路径、命令行及账户信息。新窗口会话为空，当前证据保留。"}
              </p>
            </div>
            {elevated !== true && (
              <Button
                variant="outline"
                size="sm"
                disabled={busy}
                onClick={onElevate}
              >
                <ShieldCheck size={14} />
                {elevationBusy ? "等待 UAC 授权…" : "以管理员身份启动"}
              </Button>
            )}
          </div>
        )}
        <div className="capture-path mono" title={request.capture_dir}>
          {request.capture_dir}
        </div>
        <div className="section-label">
          <span>
            待分析文件 <small>{request.paths.length}</small>
          </span>
          <Button
            variant="ghost"
            size="sm"
            disabled={busy || !request.paths.length}
            onClick={() => onChange({ ...request, paths: [] })}
          >
            清空
          </Button>
        </div>
        <div className="file-list">
          {request.paths.map((path) => (
            <div className="file-item" key={path}>
              <FileText size={17} />
              <div title={path}>
                <strong>{basename(path)}</strong>
                <span className="mono">{path}</span>
              </div>
              <span className="small-badge">自动识别</span>
              <Button
                variant="ghost"
                size="icon"
                disabled={busy}
                aria-label={`移除 ${basename(path)}`}
                onClick={() =>
                  onChange({
                    ...request,
                    paths: request.paths.filter((p) => p !== path),
                  })
                }
              >
                <X size={13} />
              </Button>
            </div>
          ))}
          {!request.paths.length && (
            <div className="file-empty">
              <FileText size={24} strokeWidth={1.2} />
              <span>尚未添加文件</span>
              <p>选择文件或将文件拖到窗口，也可采集本机进程。</p>
            </div>
          )}
        </div>
        <details className="advanced-import">
          <summary>
            <ChevronDown size={13} />
            高级选项 <span>格式、输入限制与 Web 定义</span>
          </summary>
          <div className="advanced-grid">
            <label>
              整批格式
              <Select
                label="整批格式"
                disabled={busy}
                value={request.format}
                onChange={(format) => onChange({ ...request, format })}
                options={[
                  "auto",
                  "evtx",
                  "utmp",
                  "wtmp",
                  "btmp",
                  "web",
                  "text",
                  "processes",
                  "pcap",
                ].map((value) => ({
                  value,
                  label: value === "auto" ? "自动识别（混合导入）" : value,
                }))}
              />
            </label>
            <label>
              最大 MiB / 文件
              <input
                className="input"
                type="number"
                min={1}
                max={8192}
                disabled={busy}
                value={request.max_file_bytes / 1048576}
                onChange={(e) =>
                  onChange({
                    ...request,
                    max_file_bytes: Number(e.target.value) * 1048576,
                  })
                }
              />
            </label>
            <label>
              最大记录 / 输入
              <input
                className="input"
                type="number"
                min={1}
                max={10000000}
                disabled={busy}
                value={request.max_records}
                onChange={(e) =>
                  onChange({ ...request, max_records: Number(e.target.value) })
                }
              />
            </label>
            <label className="wide">
              Web 格式定义
              <div className="input-action">
                <input
                  className="input mono"
                  disabled={busy}
                  value={request.web_format || ""}
                  onChange={(e) =>
                    onChange({ ...request, web_format: e.target.value })
                  }
                  placeholder="可选的 Apache / Nginx 格式定义文件"
                />
                <Button
                  variant="outline"
                  disabled={busy}
                  onClick={() => onPick("web")}
                >
                  选择
                </Button>
              </div>
            </label>
          </div>
        </details>
      </div>
      <div className="import-action">
        <span>
          <span className="status-dot" />
          默认只进行本地分析，证据不会自动发送。
        </span>
        <Button
          disabled={
            busy ||
            (!request.paths.length && !request.live && !request.auto_logs)
          }
          onClick={onStart}
        >
          开始本地分析
          <ArrowRight size={14} />
        </Button>
      </div>
    </div>
  );
}
