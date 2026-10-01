import {
  KeyRound,
  FolderOpen,
  PlugZap,
  Save,
  CheckCircle2,
  EyeOff,
} from "lucide-react";
import { Button } from "./ui/button";
import { Select } from "./ui/select";
import type { ConfigInput, PublicConfig } from "../types";
export function SettingsView({
  config,
  draft,
  onChange,
  path,
  onPath,
  busy,
  checkStatus,
  onPick,
  onApply,
  onSave,
  onLoad,
  onCheck,
}: {
  config: PublicConfig;
  draft: ConfigInput;
  onChange: (v: ConfigInput) => void;
  path: string;
  onPath: (v: string) => void;
  busy: boolean;
  checkStatus: string;
  onPick: () => void;
  onApply: () => void;
  onSave: () => void;
  onLoad: () => void;
  onCheck: () => void;
}) {
  return (
    <div className="settings-page">
      <div className="settings-scroll">
        <div className="form-section">
          <h3>配置文件</h3>
          <p>可使用已有 CLI 配置。只有主动保存才写入磁盘。</p>
          <div className="input-action">
            <input
              className="input mono"
              aria-label="配置文件路径"
              value={path}
              onChange={(e) => onPath(e.target.value)}
              disabled={busy}
            />
            <Button
              variant="outline"
              size="icon"
              aria-label="选择配置"
              disabled={busy}
              onClick={onPick}
            >
              <FolderOpen size={15} />
            </Button>
            <Button variant="outline" disabled={busy} onClick={onLoad}>
              加载
            </Button>
          </div>
        </div>
        <div className="form-section">
          <h3>AI 服务</h3>
          <p>兼容 OpenAI Chat Completions 的服务与模型。</p>
          <label className="form-field">
            服务地址
            <input
              className="input"
              aria-label="服务地址"
              placeholder="https://api.example.com/v1"
              value={draft.base_url}
              disabled={busy}
              onChange={(e) => onChange({ ...draft, base_url: e.target.value })}
            />
          </label>
          <label className="form-field">
            模型
            <input
              className="input"
              aria-label="模型"
              value={draft.model}
              disabled={busy}
              onChange={(e) => onChange({ ...draft, model: e.target.value })}
            />
          </label>
          <label className="form-field">
            <span>
              API 密钥{" "}
              <span
                className={`key-status ${config.api_key_configured ? "configured" : ""}`}
              >
                {config.api_key_configured ? (
                  <>
                    <CheckCircle2 size={11} />
                    已配置
                  </>
                ) : (
                  <>
                    <KeyRound size={11} />
                    未配置
                  </>
                )}
              </span>
            </span>
            <div className="key-input">
              <input
                className="input"
                aria-label="新的 API 密钥"
                type="password"
                autoComplete="new-password"
                placeholder={
                  config.api_key_configured
                    ? "留空保留现有密钥"
                    : "输入新的 API 密钥"
                }
                disabled={busy}
                value={draft.key_value}
                onChange={(e) =>
                  onChange({
                    ...draft,
                    key_value: e.target.value,
                    key_action: e.target.value ? "replace" : "keep",
                  })
                }
              />
              <EyeOff size={14} />
            </div>
          </label>
          <div className="key-actions">
            <span>已保存的密钥不会返回到界面。</span>
            {config.api_key_configured && (
              <button
                disabled={busy}
                onClick={() =>
                  onChange({
                    ...draft,
                    key_action: draft.key_action === "clear" ? "keep" : "clear",
                    key_value: "",
                  })
                }
              >
                {draft.key_action === "clear" ? "撤销清除" : "清除已有密钥"}
              </button>
            )}
          </div>
        </div>
        <details className="form-section advanced-settings">
          <summary>高级参数</summary>
          <div className="advanced-grid">
            <label>
              超时 / 秒
              <input
                className="input"
                type="number"
                aria-label="超时秒数"
                value={draft.timeout_seconds}
                disabled={busy}
                onChange={(e) =>
                  onChange({
                    ...draft,
                    timeout_seconds: Number(e.target.value),
                  })
                }
              />
            </label>
            <label>
              批次字节预算
              <input
                className="input"
                type="number"
                value={draft.batch_bytes}
                disabled={busy}
                onChange={(e) =>
                  onChange({ ...draft, batch_bytes: Number(e.target.value) })
                }
              />
            </label>
            <label>
              输出 token 上限
              <input
                className="input"
                type="number"
                value={draft.max_output_tokens}
                disabled={busy}
                onChange={(e) =>
                  onChange({
                    ...draft,
                    max_output_tokens: Number(e.target.value),
                  })
                }
              />
            </label>
            <label>
              回复格式
              <Select
                label="回复格式"
                value={draft.response_format}
                disabled={busy}
                onChange={(response_format) =>
                  onChange({ ...draft, response_format })
                }
                options={["json_object", "json_schema", "none"].map(
                  (value) => ({ value, label: value }),
                )}
              />
            </label>
            <label>
              token 参数
              <Select
                label="token 参数"
                value={draft.token_parameter}
                disabled={busy}
                onChange={(token_parameter) =>
                  onChange({ ...draft, token_parameter })
                }
                options={["max_tokens", "max_completion_tokens"].map(
                  (value) => ({ value, label: value }),
                )}
              />
            </label>
            <label className="wide">
              密钥环境变量
              <input
                className="input mono"
                aria-label="密钥环境变量"
                value={draft.api_key_env}
                disabled={busy}
                onChange={(e) =>
                  onChange({ ...draft, api_key_env: e.target.value })
                }
              />
            </label>
          </div>
        </details>
        <div className="font-credit">
          中文字体：Noto Sans CJK SC · SIL Open Font License 1.1
          <br />
          字体随程序提供，使用时无需下载。
        </div>
      </div>
      <div className="settings-actions">
        <span className="check-status">{checkStatus}</span>
        <Button variant="ghost" disabled={busy} onClick={onApply}>
          应用设置
        </Button>
        <Button variant="outline" disabled={busy} onClick={onCheck}>
          <PlugZap size={14} />
          检查连接
        </Button>
        <Button disabled={busy} onClick={onSave}>
          <Save size={14} />
          保存配置
        </Button>
      </div>
    </div>
  );
}
