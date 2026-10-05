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
    context_tokens: null,
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
    if (command === "prepare_ai")
      return {
        id: 42,
        session_id: 7,
        plan: {
          selected_records: 3,
          evidence_tokens: 300,
          prompt_tokens: 100,
          input_budget_tokens: null,
          context_tokens: null,
          evidence_batches: 1,
          summary_planned: false,
        },
      };
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
it("shows the local recap after partial AI failure as escaped text without sending again", async () => {
  const original = mock.invoke.getMockImplementation()!;
  const recap =
    "本地结果整理（不是新的 AI 关联推理）\n成功 2/3，失败证据批次：2\n<script>unsafe()</script>\n证据：evidence-one";
  mock.invoke.mockImplementation((command, args) => {
    if (command === "get_view") {
      const view = response(args.request);
      view.runs = {
        total: 1,
        offset: 0,
        items: [
          {
            index: 0,
            model: "synthetic-model",
            endpoint: "http://127.0.0.1:9999",
            batches: 4,
            completed: 3,
            analyzed: 100,
            selected: 150,
            include_payload: false,
            local_summary: recap,
          },
        ],
      };
      return Promise.resolve(view);
    }
    return original(command, args);
  });
  const { container } = render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getAllByRole("button", { name: "AI 分析" })[1]);
  await screen.findByText("本地结果整理 · 部分完成");
  expect(container.querySelector(".local-ai-summary pre")?.textContent).toBe(
    recap,
  );
  expect(container.querySelector(".local-ai-summary script")).toBeNull();
  expect(mock.invoke.mock.calls.some(([c]) => c === "start_ai")).toBe(false);
  fireEvent.click(screen.getByRole("button", { name: /运行历史/ }));
  fireEvent.click(screen.getByRole("button", { name: /#1\s*synthetic-model/ }));
  await waitFor(() =>
    expect(document.querySelectorAll(".local-ai-summary")).toHaveLength(2),
  );
});
describe("AI batch progress", () => {
  it("shows current/total batches and resets the count for each summary round", async () => {
    const task = {
      task_id: 99,
      session_id: 7,
      epoch: 0,
      revision: 1,
      kind: "ai",
      status: "running",
      label: "AI 分析",
      stage: "AI 批次",
      completed: 1,
      total: 7,
      error: null,
      saved_paths: [],
    };
    const invoke = mock.invoke.getMockImplementation()!;
    mock.invoke.mockImplementation((command, args) =>
      command === "initialize"
        ? Promise.resolve({ ...boot, busy: task })
        : invoke(command, args),
    );
    const { container } = render(<App />);
    await screen.findByText("AI 批次 · 1 / 7");
    const listener = mock.event.mock.calls.find(
      ([name]) => name === "analysis-task",
    )![1];
    await act(async () => listener({ payload: { ...task, completed: 7 } }));
    await screen.findByText("AI 批次 · 7 / 7");
    // The last batch is still awaiting its response, not 100% complete.
    expect(container.querySelector(".statusbar .progress-track")).toBeNull();
    await act(async () =>
      listener({
        payload: {
          ...task,
          stage: "跨批汇总（第 1 轮）",
          completed: 1,
          total: 3,
        },
      }),
    );
    await screen.findByText("跨批汇总（第 1 轮） · 1 / 3");
    await act(async () =>
      listener({
        payload: {
          ...task,
          stage: "跨批汇总（第 2 轮）",
          completed: 1,
          total: 1,
        },
      }),
    );
    await screen.findByText("跨批汇总（第 2 轮） · 1 / 1");
  });
});
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
    fireEvent.click(await screen.findByRole("button", { name: "导入分析" }));
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
    fireEvent.click(await screen.findByRole("button", { name: "导入分析" }));
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
    fireEvent.click(await screen.findByRole("button", { name: "导入分析" }));
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
    fireEvent.click(await screen.findByRole("button", { name: "导入分析" }));
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
  await screen.findByText("每次应急响应独立保存，继续已有项目或新建项目");
  await waitFor(() => expect(mock.window.onDragDropEvent).toHaveBeenCalled());
  expect(
    mock.invoke.mock.calls.some(([v]) =>
      ["start_import", "start_ai"].includes(v),
    ),
  ).toBe(false);
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
  expect(
    mock.invoke.mock.calls.some(([v]) =>
      ["start_import", "start_ai"].includes(v),
    ),
  ).toBe(false);
});
it("AI starts only explicitly and raw payload is opt-in", async () => {
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getAllByRole("button", { name: "AI 分析" })[1]);
  await screen.findByText("synthetic-model");
  const button = screen.getByRole("button", { name: "运行 AI 分析" });
  await waitFor(() => expect(button).toBeEnabled());
  fireEvent.click(button);
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("start_ai", {
      request: {
        session_id: 7,
        scope: "suspicious",
        selection_id: null,
        include_payload: false,
        plan_id: 42,
      },
    }),
  );
});
it("failed local planning blocks sending and offers a retry", async () => {
  const original = mock.invoke.getMockImplementation()!;
  mock.invoke.mockImplementation((c, args) =>
    c === "prepare_ai" ? Promise.reject("上下文预算不足") : original(c, args),
  );
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getAllByRole("button", { name: "AI 分析" })[1]);
  await screen.findByText("预览失败：上下文预算不足");
  expect(screen.getByRole("button", { name: "运行 AI 分析" })).toBeDisabled();
  expect(mock.invoke.mock.calls.some(([c]) => c === "start_ai")).toBe(false);
  mock.invoke.mockImplementation(original);
  fireEvent.click(screen.getByRole("button", { name: "重新计算" }));
  await screen.findByText("单次完整发送 · 字节兼容模式");
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "运行 AI 分析" })).toBeEnabled(),
  );
});
it("ignores stale previews and only sends the latest explicitly selected payload plan", async () => {
  const original = mock.invoke.getMockImplementation()!;
  const pending: { args: any; resolve: (v: any) => void }[] = [];
  mock.invoke.mockImplementation((c, args) =>
    c === "prepare_ai"
      ? new Promise((resolve) => pending.push({ args, resolve }))
      : original(c, args),
  );
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getAllByRole("button", { name: "AI 分析" })[1]);
  await waitFor(() => expect(pending).toHaveLength(1));
  fireEvent.click(
    screen.getByRole("checkbox", { name: "本次包含原始包与载荷" }),
  );
  await waitFor(() => expect(pending).toHaveLength(2));
  const preview = {
    id: 83,
    session_id: 7,
    plan: {
      selected_records: 3,
      evidence_tokens: 400,
      prompt_tokens: 100,
      input_budget_tokens: 700000,
      context_tokens: 1000000,
      evidence_batches: 2,
      summary_planned: true,
    },
  };
  await act(async () => pending[1].resolve(preview));
  await screen.findByText(/分为 2 个证据批次/);
  await act(async () =>
    pending[0].resolve({
      ...preview,
      id: 82,
      plan: { ...preview.plan, evidence_batches: 1 },
    }),
  );
  expect(screen.queryByText(/单次完整发送/)).not.toBeInTheDocument();
  expect(mock.invoke.mock.calls.some(([c]) => c === "start_ai")).toBe(false);
  expect(pending[1].args.request.include_payload).toBe(true);
  fireEvent.click(screen.getByRole("button", { name: "运行 AI 分析" }));
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("start_ai", {
      request: {
        session_id: 7,
        scope: "suspicious",
        selection_id: null,
        include_payload: true,
        plan_id: 83,
      },
    }),
  );
});
it("localizes nested Windows attributes while preserving their keys and values", () => {
  const key = "Event.System.Execution.#attributes.ThreadID";
  const detail: DetailResponse = {
    session_id: 7,
    record: {
      ...record,
      raw: `${key}=0042`,
      data: {
        kind: "log",
        fields: { category: "windows_event", fields: { [key]: "0042" } },
      },
    },
    source: null,
    related: [],
  };
  render(
    <Inspector
      detail={detail}
      finding={null}
      loading={false}
      onJump={() => {}}
      onFinding={() => {}}
      onClose={() => {}}
    />,
  );
  expect(screen.getByText("执行线程 ID")).toHaveAttribute("title", key);
  expect(screen.getByText("0042")).toBeInTheDocument();
  expect(detail.record.raw).toBe(`${key}=0042`);
  expect(detail.record.data).toMatchObject({
    fields: { fields: { [key]: "0042" } },
  });
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
  const runButton = screen.getByRole("button", { name: "运行 AI 分析" });
  await waitFor(() => expect(runButton).toBeEnabled());
  fireEvent.click(runButton);
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("start_ai", {
      request: {
        session_id: 7,
        scope: "matches",
        selection_id: 11,
        include_payload: true,
        plan_id: 42,
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

it("AI edits a full evidence selection locally and sends the new selection only explicitly", async () => {
  const original = mock.invoke.getMockImplementation()!;
  let selected = { id: 22, count: 250, label: "日志 · 关键词：合成组甲" };
  mock.invoke.mockImplementation((c, args) => {
    if (c === "initialize")
      return { ...boot, selection: { id: null, count: 0, label: "" } };
    if (
      c === "get_view" &&
      args.request.screen === "logs" &&
      args.request.filters.text === "合成组甲"
    )
      return {
        ...response(args.request),
        selection: selected,
        records: { items: [record], total: 250, offset: 0 },
      };
    if (c === "get_view" && args.request.screen === "ai")
      return { ...response(args.request), selection: selected };
    return original(c, args);
  });
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getAllByRole("button", { name: "AI 分析" })[1]);
  fireEvent.click(await screen.findByRole("button", { name: "编辑筛选" }));
  fireEvent.change(screen.getByRole("textbox", { name: "发送证据查询" }), {
    target: { value: "合成组甲" },
  });
  fireEvent.click(screen.getByRole("button", { name: "应用筛选" }));
  await waitFor(() =>
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
  );
  expect(mock.invoke).toHaveBeenCalledWith("get_view", {
    request: expect.objectContaining({
      screen: "logs",
      commit_selection: true,
      focus_id: null,
      filters: expect.objectContaining({
        text: "合成组甲",
        offset: 0,
        limit: 100,
      }),
    }),
  });
  expect(mock.invoke.mock.calls.some(([c]) => c === "start_ai")).toBe(false);
  expect(
    screen.queryByRole("combobox", { name: "发现来源" }),
  ).not.toBeInTheDocument();
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "运行 AI 分析" })).toBeEnabled(),
  );
  expect(screen.getByText("日志 · 关键词：合成组甲")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "运行 AI 分析" }));
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("start_ai", {
      request: expect.objectContaining({
        scope: "matches",
        selection_id: 22,
        include_payload: false,
      }),
    }),
  );
});

it("AI current selection has an editor even when no previous evidence selection exists", async () => {
  const original = mock.invoke.getMockImplementation()!;
  mock.invoke.mockImplementation((c, args) => {
    if (c === "initialize")
      return { ...boot, selection: { id: null, count: 0, label: "" } };
    if (c === "get_view")
      return {
        ...response(args.request),
        selection: { id: null, count: 0, label: "" },
      };
    return original(c, args);
  });
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getAllByRole("button", { name: "AI 分析" })[1]);
  fireEvent.click(await screen.findByRole("button", { name: "当前筛选" }));
  expect(
    screen.getByRole("dialog", { name: "筛选发送证据" }),
  ).toBeInTheDocument();
  expect(mock.invoke.mock.calls.some(([c]) => c === "start_ai")).toBe(false);
});

it("invalid AI filter keeps the previous selection and Chinese composition does not submit", async () => {
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getAllByRole("button", { name: "AI 分析" })[1]);
  fireEvent.click(await screen.findByRole("button", { name: "当前筛选" }));
  fireEvent.click(screen.getByRole("button", { name: "编辑筛选" }));
  const input = screen.getByRole("textbox", { name: "发送证据查询" });
  fireEvent.change(input, { target: { value: "[" } });
  fireEvent.click(screen.getByRole("checkbox", { name: "正则表达式" }));
  const before = mock.invoke.mock.calls.length;
  fireEvent.compositionStart(input);
  expect(
    fireEvent.keyDown(input, { key: "Enter", keyCode: 229, isComposing: true }),
  ).toBe(false);
  fireEvent.submit(input.closest("form")!);
  expect(mock.invoke.mock.calls.length).toBe(before);
  fireEvent.compositionEnd(input);
  fireEvent.click(screen.getByRole("button", { name: "应用筛选" }));
  await screen.findByRole("alert");
  expect(screen.getByRole("alert")).toHaveTextContent("保留上一次有效筛选");
  fireEvent.click(screen.getByRole("button", { name: "取消" }));
  await waitFor(() =>
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
  );
  expect(screen.getByText("日志 · 完整筛选")).toBeInTheDocument();
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "运行 AI 分析" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "运行 AI 分析" }));
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("start_ai", {
      request: expect.objectContaining({ scope: "matches", selection_id: 11 }),
    }),
  );
});

function dirtyProjectBoot(): Bootstrap {
  return {
    ...boot,
    project: {
      info: {
        id: "synthetic-project-id",
        name: "客户甲响应",
        client: "客户甲",
        response_start: "2026-10-05T09:00:00+08:00",
        response_end: null,
        location: "",
        responders: "",
        description: "",
        created_at: "2026-10-05T09:00:00+08:00",
        updated_at: "2026-10-05T09:00:00+08:00",
      },
      path: "/tmp/synthetic.eair",
      dirty: true,
      revision: 2,
    },
  };
}
it("protects dirty projects when switching and waits for a successful save", async () => {
  const original = mock.invoke.getMockImplementation()!;
  let fresh = dirtyProjectBoot();
  const job = {
    task_id: 123,
    session_id: 7,
    epoch: 0,
    revision: 2,
    kind: "project_save",
    status: "running",
    label: "保存项目",
    stage: null,
    completed: null,
    total: null,
    error: null,
    saved_paths: [],
  };
  mock.invoke.mockImplementation((cmd, args) =>
    cmd === "initialize"
      ? Promise.resolve(structuredClone(fresh))
      : cmd === "project_save"
        ? Promise.resolve(job)
        : original(cmd, args),
  );
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  fireEvent.click(screen.getAllByRole("button", { name: "新建项目" })[0]);
  await screen.findByText("项目有未保存的修改");
  fireEvent.click(screen.getByRole("button", { name: "保存并继续" }));
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("project_save", {
      sessionId: 7,
      path: "/tmp/synthetic.eair",
      overwrite: false,
    }),
  );
  expect(screen.queryByText("新建应急响应项目")).not.toBeInTheDocument();
  const listener = mock.event.mock.calls.find(
    ([name]) => name === "analysis-task",
  )![1];
  await act(async () =>
    listener({ payload: { ...job, status: "failed", error: "合成保存失败" } }),
  );
  expect(screen.getByText("项目有未保存的修改")).toBeInTheDocument();
  expect(screen.queryByText("新建应急响应项目")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "保存并继续" }));
  fresh = { ...fresh, project: { ...fresh.project!, dirty: false } };
  await act(async () =>
    listener({
      payload: {
        ...job,
        task_id: 124,
        status: "completed",
        saved_paths: ["/tmp/synthetic.eair"],
      },
    }),
  );
  await screen.findByText("新建应急响应项目");
});
it("prevents closing a dirty project until the user resolves unsaved changes", async () => {
  const original = mock.invoke.getMockImplementation()!;
  mock.invoke.mockImplementation((cmd, args) =>
    cmd === "initialize"
      ? Promise.resolve(dirtyProjectBoot())
      : original(cmd, args),
  );
  render(<App />);
  await waitFor(() => expect(mock.window.onCloseRequested).toHaveBeenCalled());
  const event = { preventDefault: vi.fn() };
  await act(async () =>
    mock.window.onCloseRequested.mock.calls.at(-1)![0](event),
  );
  expect(event.preventDefault).toHaveBeenCalled();
  await screen.findByText("项目有未保存的修改");
  expect(mock.window.destroy).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "放弃修改并继续" }));
  await waitFor(() => expect(mock.window.destroy).toHaveBeenCalledTimes(1));
});
