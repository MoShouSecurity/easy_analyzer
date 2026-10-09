import {
  render,
  screen,
  fireEvent,
  waitFor,
  cleanup,
  within,
} from "@testing-library/react";
import { afterEach, beforeEach, it, vi, expect } from "vitest";
import {
  ProjectHome,
  ProjectEditor,
  newProject,
} from "../components/ProjectView";
import { IocView } from "../components/IocView";
import type { ProjectEntry } from "../types";
const mock = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: mock.invoke }));
afterEach(cleanup);
beforeEach(() => mock.invoke.mockReset());
it("defaults the project name to the client and saves a blank name using the client", async () => {
  const save = vi.fn().mockResolvedValue(undefined);
  render(
    <ProjectEditor
      info={newProject()}
      busy={false}
      onClose={() => {}}
      onSave={save}
    />,
  );
  fireEvent.change(screen.getByLabelText("客户单位 *"), {
    target: { value: "合成客户甲" },
  });
  expect(screen.getByLabelText("项目名称")).toHaveValue("合成客户甲");
  fireEvent.change(screen.getByLabelText("客户单位 *"), {
    target: { value: "合成客户乙" },
  });
  expect(screen.getByLabelText("项目名称")).toHaveValue("合成客户乙");
  fireEvent.change(screen.getByLabelText("项目名称"), {
    target: { value: " " },
  });
  fireEvent.click(screen.getByRole("button", { name: "确认项目资料" }));
  await waitFor(() =>
    expect(save).toHaveBeenCalledWith(
      expect.objectContaining({
        name: "合成客户乙",
        client: "合成客户乙",
      }),
    ),
  );
});
it("preserves custom and existing project names when the client changes", () => {
  const { unmount } = render(
    <ProjectEditor
      info={newProject()}
      busy={false}
      onClose={() => {}}
      onSave={vi.fn()}
    />,
  );
  fireEvent.change(screen.getByLabelText("项目名称"), {
    target: { value: "自定义响应名称" },
  });
  fireEvent.change(screen.getByLabelText("客户单位 *"), {
    target: { value: "合成客户甲" },
  });
  expect(screen.getByLabelText("项目名称")).toHaveValue("自定义响应名称");
  unmount();
  render(
    <ProjectEditor
      info={{ ...newProject(), name: "合成客户甲", client: "合成客户甲" }}
      busy={false}
      onClose={() => {}}
      onSave={vi.fn()}
    />,
  );
  fireEvent.change(screen.getByLabelText("客户单位 *"), {
    target: { value: "合成客户乙" },
  });
  expect(screen.getByLabelText("项目名称")).toHaveValue("合成客户甲");
});
it("validates response times and preserves metadata until accepted", async () => {
  const save = vi.fn().mockRejectedValue("响应时间必须含时区");
  render(
    <ProjectEditor
      info={newProject()}
      busy={false}
      onClose={() => {}}
      onSave={save}
    />,
  );
  fireEvent.change(screen.getByLabelText("项目名称"), {
    target: { value: "合成项目" },
  });
  fireEvent.change(screen.getByLabelText("客户单位 *"), {
    target: { value: "合成客户" },
  });
  fireEvent.change(screen.getByLabelText("响应结束时间（含时区）"), {
    target: { value: "2000-01-01T00:00:00Z" },
  });
  fireEvent.click(screen.getByRole("button", { name: "确认项目资料" }));
  await screen.findByText("响应结束时间不能早于开始时间");
  expect(save).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText("响应结束时间（含时区）"), {
    target: { value: "" },
  });
  fireEvent.click(screen.getByRole("button", { name: "确认项目资料" }));
  await screen.findByText("响应时间必须含时区");
  expect(screen.getByLabelText("项目名称")).toHaveValue("合成项目");
});
it("searches project metadata and clearly identifies missing files", async () => {
  mock.invoke.mockResolvedValue([
    {
      info: { ...newProject(), name: "合成响应", client: "合成客户" },
      path: "/tmp/moved.eair",
      last_opened: "2026-10-05T10:00:00Z",
      missing: true,
    },
  ]);
  render(
    <ProjectHome
      busy={false}
      onNew={() => {}}
      onOpen={() => {}}
      onPick={() => {}}
      onError={() => {}}
    />,
  );
  await screen.findByText("项目文件缺失，请重新打开移动后的文件");
  expect(screen.getByRole("button", { name: "继续项目" })).toBeDisabled();
  fireEvent.change(screen.getByLabelText("项目搜索"), {
    target: { value: "合成" },
  });
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith(
      "project_list",
      expect.objectContaining({
        search: expect.objectContaining({ text: "合成" }),
      }),
    ),
  );
});
function projectEntry(name: string): ProjectEntry {
  return {
    info: { ...newProject(), name, client: `${name}客户` },
    path: `/tmp/${name}.eair`,
    last_opened: "2026-10-07T09:00:00+08:00",
    missing: false,
  };
}
const homeProps = {
  busy: false,
  onNew: () => {},
  onOpen: () => {},
  onPick: () => {},
  onError: () => {},
};
it("requires confirmation to remove only the selected catalog entry and refreshes the list", async () => {
  const a = projectEntry("合成响应甲");
  const b = projectEntry("合成响应乙");
  let entries = [a, b];
  mock.invoke.mockImplementation(async (command: string) => {
    if (command === "project_list") return entries;
    if (command === "project_remove") entries = [b];
  });
  render(<ProjectHome {...homeProps} />);
  const button = await screen.findByRole("button", {
    name: "从列表移除 合成响应甲",
  });
  fireEvent.click(button);
  const dialog = screen.getByRole("dialog", { name: "从列表移除项目" });
  expect(within(dialog).getByText(/保留 .eair 文件、证据和 IOC/)).toBeVisible();
  expect(within(dialog).getByText(a.path)).toBeVisible();
  fireEvent.click(within(dialog).getByRole("button", { name: "取消" }));
  expect(
    mock.invoke.mock.calls.some(([command]) => command === "project_remove"),
  ).toBe(false);
  expect(screen.getByText(a.info.name)).toBeVisible();
  fireEvent.click(button);
  fireEvent.click(screen.getByRole("button", { name: "确认移除" }));
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("project_remove", {
      id: a.info.id,
      path: a.path,
    }),
  );
  await waitFor(() =>
    expect(screen.queryByText(a.info.name)).not.toBeInTheDocument(),
  );
  expect(screen.getByText(b.info.name)).toBeVisible();
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  await screen.findByText("按最近打开排序 · 1 个项目");
  await waitFor(() =>
    expect(
      mock.invoke.mock.calls.filter(([command]) => command === "project_list"),
    ).toHaveLength(2),
  );
});
it("preserves the list and displays errors when removal fails", async () => {
  const entry = projectEntry("合成响应");
  mock.invoke.mockImplementation(async (command: string) => {
    if (command === "project_list") return [entry];
    if (command === "project_remove") throw new Error("项目目录不可用");
  });
  render(<ProjectHome {...homeProps} />);
  fireEvent.click(
    await screen.findByRole("button", { name: "从列表移除 合成响应" }),
  );
  fireEvent.click(screen.getByRole("button", { name: "确认移除" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("项目目录不可用");
  expect(screen.getByRole("button", { name: "确认移除" })).toBeEnabled();
  fireEvent.click(screen.getByRole("button", { name: "取消" }));
  expect(screen.getByText(entry.info.name)).toBeVisible();
});
it("allows missing entries to be removed and prevents duplicate requests while pending", async () => {
  const entry = { ...projectEntry("缺失项目"), missing: true };
  let finish!: () => void;
  let entries = [entry];
  mock.invoke.mockImplementation((command: string) => {
    if (command === "project_list") return Promise.resolve(entries);
    if (command === "project_remove")
      return new Promise<void>((resolve) => {
        finish = () => {
          entries = [];
          resolve();
        };
      });
  });
  const { rerender } = render(<ProjectHome {...homeProps} busy />);
  const remove = await screen.findByRole("button", {
    name: "从列表移除 缺失项目",
  });
  expect(remove).toBeDisabled();
  expect(screen.getByRole("button", { name: "继续项目" })).toBeDisabled();
  rerender(<ProjectHome {...homeProps} />);
  expect(remove).toBeEnabled();
  fireEvent.click(remove);
  fireEvent.click(screen.getByRole("button", { name: "确认移除" }));
  const pending = screen.getByRole("button", { name: "正在移除…" });
  expect(pending).toBeDisabled();
  fireEvent.click(pending);
  expect(screen.getByRole("button", { name: "取消" })).toBeDisabled();
  expect(
    mock.invoke.mock.calls.filter(([command]) => command === "project_remove"),
  ).toHaveLength(1);
  finish();
  await waitFor(() =>
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
  );
  await screen.findByText(/项目列表为空/);
});
it("mixes IOC paste and manual inputs and explicitly scans with exact domain policy", async () => {
  mock.invoke.mockImplementation(async (c: string) => {
    if (c === "get_ioc")
      return {
        status: { indicators: 1, records: 150, needs_rescan: true, run: null },
        indicators: { offset: 0, total: 1, items: [] },
        hits: { offset: 0, total: 0, items: [] },
      };
    if (c === "import_ioc")
      return { indicators: [], issues: [{ line: 2, message: "无效 IOC" }] };
    if (c === "start_ioc_scan") return { task_id: 1 };
  });
  const onTask = vi.fn(async (f: () => Promise<unknown>) => {
    await f();
  });
  render(
    <IocView
      sessionId={7}
      revision={1}
      busy={false}
      onTask={onTask}
      onJump={() => {}}
      onChanged={async () => {}}
      onError={() => {}}
    />,
  );
  await screen.findByText("有新增证据或清单变更尚未扫描，请主动重新扫描。");
  fireEvent.change(screen.getByLabelText("手动 IOC"), {
    target: { value: "2001:db8::1" },
  });
  fireEvent.click(screen.getByRole("button", { name: "手动添加" }));
  await screen.findByText("第 2 行：无效 IOC");
  expect(mock.invoke).toHaveBeenCalledWith(
    "import_ioc",
    expect.objectContaining({
      sessionId: 7,
      input: expect.objectContaining({ value: "2001:db8::1" }),
    }),
  );
  fireEvent.change(screen.getByLabelText("IOC 清单"), {
    target: { value: "type,value\ndomain,example.com" },
  });
  fireEvent.click(
    screen.getByRole("checkbox", { name: "CSV 格式（type,value，可选 note）" }),
  );
  fireEvent.click(screen.getByRole("button", { name: "追加粘贴清单" }));
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith(
      "import_ioc",
      expect.objectContaining({
        input: expect.objectContaining({ csv: true }),
      }),
    ),
  );
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "扫描当前项目" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("checkbox", { name: "域名包含子域名" }));
  fireEvent.click(screen.getByRole("button", { name: "扫描当前项目" }));
  await waitFor(() =>
    expect(mock.invoke).toHaveBeenCalledWith("start_ioc_scan", {
      sessionId: 7,
      includeSubdomains: false,
    }),
  );
});
