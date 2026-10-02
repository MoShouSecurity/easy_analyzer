import {
  render,
  screen,
  fireEvent,
  waitFor,
  cleanup,
  act,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import userEvent from "@testing-library/user-event";
import { App } from "../App";
import { DataTable } from "../components/DataTable";
import { Inspector, SourceInspector } from "../components/Inspector";
import { SettingsView } from "../components/SettingsView";
import capability from "../../../capabilities/main.json";
import type {
  Bootstrap,
  ViewRequest,
  ViewResponse,
  RecordSummary,
  DetailResponse,
} from "../types";
const mock = vi.hoisted(() => ({
  invoke: vi.fn(),
  event: vi.fn(),
  window: {
    onDragDropEvent: vi.fn(),
    onCloseRequested: vi.fn(),
    startDragging: vi.fn(),
    close: vi.fn(),
    destroy: vi.fn(),
    minimize: vi.fn(),
    toggleMaximize: vi.fn(),
  },
}));
vi.mock("@tauri-apps/api/core", () => ({ invoke: mock.invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen: mock.event }));
vi.mock("@tauri-apps/api/webviewWindow", () => ({
  getCurrentWebviewWindow: () => mock.window,
}));
const boot: Bootstrap = {
  preferences: {
    dark: false,
    inspector: true,
    inspector_width: 320,
    config_path: "/tmp/gui-config.toml",
    window_width: 1280,
    window_height: 720,
  },
  config: {
    base_url: "http://127.0.0.1:9999",
    model: "synthetic-model",
    api_key_configured: true,
    api_key_env: "",
    timeout_seconds: 10,
    batch_bytes: 8192,
    max_output_tokens: 1000,
    response_format: "json_object",
    token_parameter: "max_tokens",
  },
  config_loaded: true,
  config_error: null,
  session_id: 7,
  selection: { id: 11, count: 150, label: "日志 · 完整筛选" },
  busy: null,
  platform: "macos",
  elevated: null,
  elevation_error: null,
  live_processes: false,
  capture_dir: "/tmp/captured",
  inputs: [],
  qa: false,
  qa_ai: false,
};
const record: RecordSummary = {
  id: "evidence-one",
  source_id: "source-one",
  position: "line:1",
  timestamp: "2026-10-01T10:00:00Z",
  status: "parsed",
  data: {
    kind: "log",
    fields: { category: "login", fields: { user: "合成用户" } },
  },
  summary: "中文证据记录",
};
function response(r: ViewRequest): ViewResponse {
  return {
    session_id: 7,
    revision: r.revision,
    overview: {
      sources: 1,
      records: 150,
      logs: 150,
      processes: 0,
      packets: 0,
      flows: 0,
      local_findings: 0,
      ai_findings: 0,
      suspicious: 3,
      risks: [0, 0, 0, 0, 0],
      categories: ["login"],
      protocols: [],
      parse_counts: [150, 0, 0],
    },
    records:
      r.screen === "logs"
        ? { items: [record], total: 150, offset: r.filters.offset }
        : null,
    findings: { items: [], total: 0, offset: 0 },
    flows: null,
    process_rows: [],
    sources: {
      items: [
        {
          id: "source-one",
          path: "/tmp/中文.log",
          format: "text",
          sha256: "abc",
          bytes: 500,
        },
      ],
      total: 1,
      offset: 0,
    },
    record_sources: { "source-one": "/tmp/中文.log" },
    diagnostics: { items: [], total: 0, offset: 0 },
    runs: { items: [], total: 0, offset: 0 },
    outside: false,
    offset: r.filters.offset,
    selection: boot.selection,
  };
}
beforeEach(() => {
  Object.defineProperty(window, "innerWidth", {
    configurable: true,
    value: 1280,
  });
  vi.clearAllMocks();
  mock.event.mockResolvedValue(() => {});
  mock.window.onDragDropEvent.mockResolvedValue(() => {});
  mock.window.onCloseRequested.mockResolvedValue(() => {});
  mock.invoke.mockImplementation(async (command: string, args: any) => {
    if (command === "initialize") return structuredClone(boot);
    if (command === "get_view") {
      if (args.request.filters.regex && args.request.filters.text === "[")
        throw "非法正则表达式";
      return response(args.request);
    }
    if (command === "start_ai")
      return {
        task_id: 99,
        session_id: 7,
        epoch: 0,
        revision: 1,
        kind: "ai",
        status: "running",
        label: "AI",
        stage: null,
        completed: null,
        total: null,
        error: null,
        saved_paths: [],
      };
    return undefined;
  });
});
afterEach(cleanup);
describe("window closing", () => {
  function desktopClose() {
    const invoke = mock.invoke.getMockImplementation()!;
    mock.invoke.mockImplementation((command, args) =>
      command === "initialize"
        ? Promise.resolve({ ...boot, platform: "windows", elevated: false })
        : invoke(command, args),
    );
    // Reproduce the installed Tauri onCloseRequested contract: await the
    // handler, then destroy only when it did not prevent the close event.
    const requestClose = async () => {
      const handler = mock.window.onCloseRequested.mock.calls.at(-1)![0];
      const event = { preventDefault: vi.fn() };
      await handler(event);
      if (!event.preventDefault.mock.calls.length) {
        if (!capability.permissions.includes("core:window:allow-destroy"))
          throw new Error("window.destroy not allowed");
        await mock.window.destroy();
      }
      return event;
    };
    mock.window.close.mockImplementation(requestClose);
    return requestClose;
  }
  it("saves preferences and closes from the titlebar without another close event", async () => {
    desktopClose();
    render(<App />);
    await waitFor(() =>
      expect(mock.window.onCloseRequested).toHaveBeenCalled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "关闭窗口" }));
    await waitFor(() => expect(mock.window.destroy).toHaveBeenCalledOnce());
    expect(mock.window.close).toHaveBeenCalledOnce();
    expect(
      mock.invoke.mock.calls.filter(([c]) => c === "save_preferences"),
    ).toHaveLength(1);
  });
  it("also completes the operating system close request", async () => {
    const requestClose = desktopClose();
    render(<App />);
    await waitFor(() =>
      expect(mock.window.onCloseRequested).toHaveBeenCalled(),
    );
    await act(requestClose);
    expect(mock.window.destroy).toHaveBeenCalledOnce();
    expect(mock.window.close).not.toHaveBeenCalled();
  });
  it("allows retry after preferences fail and ignores repeated clicks while saving", async () => {
    desktopClose();
    const invoke = mock.invoke.getMockImplementation()!;
    let rejectSave!: (reason: string) => void;
    mock.invoke.mockImplementation((command, args) =>
      command === "save_preferences"
        ? new Promise<void>((_, reject) => {
            rejectSave = reject;
          })
        : invoke(command, args),
    );
    render(<App />);
    await waitFor(() =>
      expect(mock.window.onCloseRequested).toHaveBeenCalled(),
    );
    const close = screen.getByRole("button", { name: "关闭窗口" });
    fireEvent.click(close);
    fireEvent.click(close);
    expect(
      mock.invoke.mock.calls.filter(([c]) => c === "save_preferences"),
    ).toHaveLength(1);
    expect(mock.window.destroy).not.toHaveBeenCalled();
    await act(async () => rejectSave("无法写入"));
    await screen.findByText("偏好保存失败：无法写入");
    mock.invoke.mockImplementation(invoke);
    fireEvent.click(close);
    await waitFor(() => expect(mock.window.destroy).toHaveBeenCalledOnce());
  });
  it("keeps the window open while cancelling an active task to preserve results", async () => {
    const requestClose = desktopClose();
    const invoke = mock.invoke.getMockImplementation()!;
    mock.invoke.mockImplementation((command, args) =>
      command === "initialize"
        ? Promise.resolve({
            ...boot,
            platform: "windows",
            busy: {
              task_id: 99,
              session_id: 7,
              epoch: 0,
              revision: 1,
              kind: "ai",
              status: "running",
              label: "AI",
              stage: null,
              completed: null,
              total: null,
              error: null,
              saved_paths: [],
            },
          })
        : invoke(command, args),
    );
    render(<App />);
    await waitFor(() =>
      expect(mock.window.onCloseRequested).toHaveBeenCalled(),
    );
    await act(requestClose);
    fireEvent.click(
      await screen.findByRole("button", { name: "取消任务并保留结果" }),
    );
    await waitFor(() =>
      expect(mock.invoke).toHaveBeenCalledWith("cancel_task", { taskId: 99 }),
    );
    expect(mock.window.destroy).not.toHaveBeenCalled();
    expect(mock.invoke.mock.calls.some(([c]) => c === "save_preferences")).toBe(
      false,
    );
  });
});
describe("Windows UAC collection", () => {
  function windowsBoot(elevated = false) {
    return { ...boot, platform: "windows", elevated, live_processes: elevated };
  }
  it("requires an explicit click and cancellation preserves the current session", async () => {
    mock.invoke.mockImplementation(async (command: string, args: any) => {
      if (command === "initialize") return windowsBoot();
      if (command === "get_view") return response(args.request);
      if (command === "request_elevation") return "cancelled";
    });
    render(<App />);
    const button = await screen.findByRole("button", {
      name: "以管理员身份启动",
    });
    expect(
      mock.invoke.mock.calls.some(
        ([command]) => command === "request_elevation",
      ),
    ).toBe(false);
    fireEvent.click(button);
    await screen.findByText("已取消 UAC 授权，仍使用当前窗口");
    expect(button).toBeEnabled();
    expect(
      mock.invoke.mock.calls.some(([command]) =>
        ["reset_session", "start_import", "start_ai"].includes(command),
      ),
    ).toBe(false);
    expect(mock.window.close).not.toHaveBeenCalled();
    expect(screen.getByText("普通权限")).toBeInTheDocument();
  });
  it("keeps the old window open after an elevated window starts", async () => {
    mock.invoke.mockImplementation(async (command: string, args: any) => {
      if (command === "initialize") return windowsBoot();
      if (command === "get_view") return response(args.request);
      if (command === "request_elevation") return "launched";
    });
    render(<App />);
    fireEvent.click(
      await screen.findByRole("button", { name: "以管理员身份启动" }),
    );
    await screen.findByText(
      "管理员窗口已启动；原窗口和证据保留，请在新窗口开始本机采集",
    );
    expect(mock.window.close).not.toHaveBeenCalled();
    expect(screen.getByText("普通权限")).toBeInTheDocument();
  });
  it("shows elevated status without prompting again or collecting automatically", async () => {
    mock.invoke.mockImplementation(async (command: string, args: any) => {
      if (command === "initialize") return windowsBoot(true);
      if (command === "get_view") return response(args.request);
    });
    render(<App />);
    await screen.findByText("管理员权限");
    expect(
      screen.queryByRole("button", { name: "以管理员身份启动" }),
    ).toBeNull();
    expect(
      screen.getByRole("checkbox", { name: "采集本机进程" }),
    ).toBeChecked();
    expect(
      mock.invoke.mock.calls.some(([command]) =>
        ["request_elevation", "start_import", "start_ai"].includes(command),
      ),
    ).toBe(false);
  });
  it("re-enables the UAC button after a launch error without clearing evidence", async () => {
    mock.invoke.mockImplementation(async (command: string, args: any) => {
      if (command === "initialize") return windowsBoot();
      if (command === "get_view") return response(args.request);
      if (command === "request_elevation") throw "模拟启动失败";
    });
    render(<App />);
    const button = await screen.findByRole("button", {
      name: "以管理员身份启动",
    });
    fireEvent.click(button);
    await screen.findByText("无法启动管理员窗口：模拟启动失败");
    expect(button).toBeEnabled();
    expect(mock.window.close).not.toHaveBeenCalled();
    expect(
      mock.invoke.mock.calls.some(([command]) => command === "reset_session"),
    ).toBe(false);
  });
});
it("normal startup has no evidence, imports or automatic AI requests", async () => {
  mock.invoke.mockImplementation(async (c: string) =>
    c === "initialize"
      ? { ...boot, session_id: null, selection: { id: 0, count: 0, label: "" } }
      : undefined,
  );
  render(<App />);
  await screen.findByText("汇集离线证据，开始本地分析");
  await waitFor(() => expect(mock.window.onDragDropEvent).toHaveBeenCalled());
  expect(mock.invoke.mock.calls.map((v) => v[0])).toEqual(["initialize"]);
  expect(screen.getByRole("button", { name: "导出报告" })).toBeDisabled();
});
it("renders every table field, preserves backend total and requests next offset", () => {
  const onPage = vi.fn();
  render(
    <DataTable
      page={{ items: [record], total: 100000, offset: 0 }}
      columns={[
        { accessorKey: "timestamp", header: "时间" },
        { accessorKey: "source_id", header: "来源" },
        { accessorKey: "status", header: "状态" },
        { accessorKey: "summary", header: "摘要" },
        { accessorKey: "position", header: "位置" },
      ]}
      id={(v) => v.id}
      limit={100}
      onPage={onPage}
    />,
  );
  expect(screen.getAllByRole("cell")).toHaveLength(5);
  expect(screen.getByText("中文证据记录")).toBeInTheDocument();
  expect(screen.getByText("100,000 条 · 第 1 / 1000 页")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "下一页" }));
  expect(onPage).toHaveBeenCalledWith(100);
});
it("invalid regex retains previous valid records and scope; paging is sent to Rust", async () => {
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getByRole("button", { name: "日志证据" }));
  await screen.findByText("中文证据记录");
  fireEvent.click(screen.getByRole("button", { name: "下一页" }));
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith(
      "get_view",
      expect.objectContaining({
        request: expect.objectContaining({
          filters: expect.objectContaining({ offset: 100 }),
        }),
      }),
    ),
  );
  fireEvent.change(screen.getByRole("textbox", { name: "查询证据" }), {
    target: { value: "[" },
  });
  fireEvent.click(screen.getByRole("checkbox", { name: "正则" }));
  await screen.findByText("非法正则表达式");
  expect(screen.getByText("中文证据记录")).toBeInTheDocument();
  fireEvent.click(screen.getAllByRole("button", { name: "AI 分析" })[1]);
  await screen.findByText("synthetic-model");
  expect(
    mock.invoke.mock.calls.filter((v) => v[0] === "start_ai"),
  ).toHaveLength(0);
});
it("IME candidate confirmation does not submit an incomplete evidence query", async () => {
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getByRole("button", { name: "日志证据" }));
  await screen.findByText("中文证据记录");
  const input = screen.getByRole("textbox", { name: "查询证据" });
  const form = input.closest("form")!;
  const before = mock.invoke.mock.calls.filter(
    (v) => v[0] === "get_view",
  ).length;
  fireEvent.compositionStart(input);
  fireEvent.change(input, { target: { value: "中文核查" } });
  expect(fireEvent.keyDown(input, { key: "Enter", isComposing: true })).toBe(
    false,
  );
  fireEvent.submit(form);
  expect(
    mock.invoke.mock.calls.filter((v) => v[0] === "get_view"),
  ).toHaveLength(before);
  fireEvent.compositionEnd(input);
  expect(fireEvent.keyDown(input, { key: "Enter", keyCode: 229 })).toBe(false);
  fireEvent.submit(form);
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith(
      "get_view",
      expect.objectContaining({
        request: expect.objectContaining({
          filters: expect.objectContaining({ text: "中文核查" }),
        }),
      }),
    ),
  );
});
it("native dropped files populate the pending list without importing or sending AI", async () => {
  mock.invoke.mockImplementation(async (c: string) =>
    c === "initialize"
      ? { ...boot, session_id: null, selection: { id: 0, count: 0, label: "" } }
      : undefined,
  );
  render(<App />);
  await waitFor(() => expect(mock.window.onDragDropEvent).toHaveBeenCalled());
  const handler = mock.window.onDragDropEvent.mock.calls[0][0];
  await act(async () =>
    handler({
      payload: {
        type: "drop",
        paths: [
          "/tmp/中文证据.log",
          "/tmp/中文证据.log",
          "/tmp/network.pcapng",
        ],
      },
    }),
  );
  expect(screen.getAllByText("中文证据.log")).toHaveLength(1);
  expect(screen.getByText("network.pcapng")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "开始本地分析" })).toBeEnabled();
  expect(mock.invoke.mock.calls.map((v) => v[0])).toEqual(["initialize"]);
});
it("AI starts only explicitly and raw payload is opt-in", async () => {
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getAllByRole("button", { name: "AI 分析" })[1]);
  await screen.findByText("synthetic-model");
  const button = screen.getByRole("button", { name: "运行 AI 分析" });
  fireEvent.click(button);
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("start_ai", {
      request: {
        session_id: 7,
        scope: "suspicious",
        selection_id: null,
        include_payload: false,
      },
    }),
  );
});
it("raw evidence is displayed as text and cannot render HTML", async () => {
  const detail: DetailResponse = {
    session_id: 7,
    record: { ...record, raw: "<img src=x onerror=alert(1)> 中文原文" },
    source: null,
    related: [],
  };
  const { container } = render(
    <Inspector
      detail={detail}
      finding={null}
      loading={false}
      onJump={() => {}}
      onFinding={() => {}}
      onClose={() => {}}
    />,
  );
  await userEvent.click(screen.getByRole("tab", { name: "原文" }));
  expect(
    screen.getByText("<img src=x onerror=alert(1)> 中文原文"),
  ).toBeInTheDocument();
  expect(container.querySelector("img")).toBeNull();
});
it("existing keys are status-only; replacement remains masked and explicit", () => {
  const onChange = vi.fn();
  render(
    <SettingsView
      config={boot.config}
      draft={{ ...boot.config, key_action: "keep", key_value: "" }}
      onChange={onChange}
      path="/tmp/gui.toml"
      onPath={() => {}}
      busy={false}
      checkStatus="尚未检查"
      onPick={() => {}}
      onApply={() => {}}
      onSave={() => {}}
      onLoad={() => {}}
      onCheck={() => {}}
    />,
  );
  expect(screen.getByText("已配置")).toBeInTheDocument();
  const input = screen.getByLabelText("新的 API 密钥");
  expect(input).toHaveAttribute("type", "password");
  expect(input).toHaveValue("");
  fireEvent.change(input, { target: { value: "sk-synthetic" } });
  expect(onChange).toHaveBeenCalledWith(
    expect.objectContaining({
      key_action: "replace",
      key_value: "sk-synthetic",
    }),
  );
});
it("current-filter AI sends the full selection token and resets payload after each run", async () => {
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getByRole("button", { name: "日志证据" }));
  await screen.findByText("中文证据记录");
  fireEvent.click(screen.getAllByRole("button", { name: "AI 分析" })[1]);
  await screen.findByText("synthetic-model");
  fireEvent.click(screen.getByRole("button", { name: "当前筛选" }));
  expect(screen.getByText("150")).toBeInTheDocument();
  fireEvent.click(
    screen.getByRole("checkbox", { name: "本次包含原始包与载荷" }),
  );
  fireEvent.click(screen.getByRole("button", { name: "运行 AI 分析" }));
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("start_ai", {
      request: {
        session_id: 7,
        scope: "matches",
        selection_id: 11,
        include_payload: true,
      },
    }),
  );
  expect(
    screen.getByRole("checkbox", { name: "本次包含原始包与载荷" }),
  ).not.toBeChecked();
  await mock.event.mock.calls[0][1]({
    payload: {
      task_id: 99,
      session_id: 7,
      epoch: 0,
      revision: 1,
      kind: "ai",
      status: "partial",
      label: "AI",
      stage: null,
      completed: 1,
      total: null,
      error: "后续批次失败，已保留有效发现",
      saved_paths: [],
    },
  });
  await screen.findByText("后续批次失败，已保留有效发现");
  expect(
    screen.getByRole("checkbox", { name: "本次包含原始包与载荷" }),
  ).not.toBeChecked();
});
it("evidence references locate records and return restores the original finding", async () => {
  const original = mock.invoke.getMockImplementation()!;
  const finding = {
    id: "f-one",
    origin: "local:test",
    severity: "high",
    title: "合成发现",
    description: "仅用于测试",
    evidence_ids: ["evidence-one"],
    confidence: 0.8,
    recommendations: [],
  };
  mock.invoke.mockImplementation(async (c: string, args: any) => {
    if (c === "get_view") {
      const v = response(args.request);
      if (args.request.screen === "overview")
        v.findings = { items: [finding as any], total: 1, offset: 0 };
      return v;
    }
    if (c === "get_detail")
      return {
        session_id: 7,
        record: { ...record, raw: "合成原文" },
        source: null,
        related: [],
      };
    return original(c, args);
  });
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getByRole("button", { name: "分析概览" }));
  await screen.findByText("合成发现");
  fireEvent.click(screen.getByText("合成发现"));
  fireEvent.click(screen.getByRole("button", { name: "evidence-one" }));
  await screen.findByRole("button", { name: "返回原视图" });
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith(
      "get_view",
      expect.objectContaining({
        request: expect.objectContaining({
          screen: "logs",
          focus_id: "evidence-one",
          commit_selection: false,
        }),
      }),
    ),
  );
  fireEvent.click(screen.getByRole("button", { name: "返回原视图" }));
  await screen.findByRole("heading", { name: "合成发现" });
  expect(screen.getByRole("heading", { name: "分析概览" })).toBeInTheDocument();
});

it("source details preserve full paths and hashes despite compact table labels", () => {
  const source = {
    id: "source-demo",
    path: "/long/synthetic/path/中文.log",
    format: "text",
    bytes: 1024,
    sha256: "a".repeat(64),
  };
  render(<SourceInspector source={source} onClose={() => {}} />);
  expect(screen.getByText("中文.log")).toBeInTheDocument();
  expect(screen.getByText(source.path)).toBeInTheDocument();
  expect(screen.getByText(source.sha256)).toBeInTheDocument();
});
