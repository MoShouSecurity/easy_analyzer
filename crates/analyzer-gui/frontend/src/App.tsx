import { version as appVersion } from "../package.json";
import {
  useState,
  useEffect,
  useRef,
  useCallback,
  type CSSProperties,
} from "react";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import {
  Upload,
  LayoutDashboard,
  FileText,
  GitFork,
  Network,
  Sparkles,
  Files,
  Settings2,
  Sun,
  Moon,
  ChevronRight,
  ChevronDown,
  Plus,
  Download,
  Search,
  PanelRight,
  ArrowLeft,
  X,
  LoaderCircle,
  ShieldCheck,
  CircleAlert,
  ArrowUpRight,
  Check,
  Minus,
  Square,
  Keyboard,
  FolderOpen,
} from "lucide-react";
import type { ColumnDef } from "@tanstack/react-table";
import { api } from "./lib/api";
import { basename, bytes, number } from "./lib/utils";
import {
  defaultFilters,
  evidenceScreen,
  screens,
  titles,
  statusLabel,
  severityLabel,
  type Screen,
  type Bootstrap,
  type ViewResponse,
  type Filters,
  type DetailResponse,
  type Finding,
  type RecordSummary,
  type Flow,
  type Source,
  type ConfigInput,
  type Preferences,
  type ImportRequest,
  type TaskMessage,
  type SelectionInfo,
  type Severity,
} from "./types";
import { Button } from "./components/ui/button";
import { Select } from "./components/ui/select";
import { Checkbox } from "./components/ui/checkbox";
import { Dialog } from "./components/ui/dialog";
import { Tooltip, TooltipProvider } from "./components/ui/tooltip";
import { Tabs } from "./components/ui/tabs";
import { DataTable } from "./components/DataTable";
import { Inspector, SourceInspector, Risk } from "./components/Inspector";
import { ImportView } from "./components/ImportView";
import { SettingsView } from "./components/SettingsView";
import { AiHistory } from "./components/AiHistory";
const icons = {
  import: Upload,
  overview: LayoutDashboard,
  logs: FileText,
  processes: GitFork,
  network: Network,
  ai: Sparkles,
  reports: Files,
  settings: Settings2,
};
const hints: Record<Screen, string> = {
  import: "汇集离线证据，开始本地分析",
  overview: "从发现追溯证据，核查每一条线索",
  logs: "完整集合查询 · 保留原始记录",
  processes: "按快照来源建立关系，识别孤儿与循环",
  network: "离线网络会话与数据包，保留完整会话统计",
  ai: "主动选择证据范围，核查已校验的结果",
  reports: "来源可追溯，导出保留完整证据",
  settings: "配置按需保存，连接检查由你主动发起",
};
const initialPreferences: Preferences = {
  dark: false,
  inspector: true,
  inspector_width: 320,
  config_path: "",
  window_width: 1280,
  window_height: 720,
};
const initialImport: ImportRequest = {
  paths: [],
  live: false,
  auto_logs: false,
  capture_dir: "",
  format: "auto",
  max_file_bytes: 536870912,
  max_records: 1000000,
  web_format: null,
};
const emptySelection: SelectionInfo = { id: 0, count: 0, label: "" };
const draftOf = (c: Bootstrap["config"]): ConfigInput => ({
  ...c,
  key_action: "keep",
  key_value: "",
});
const initialFilters = () =>
  Object.fromEntries(screens.map((s) => [s, defaultFilters()])) as Record<
    Screen,
    Filters
  >;
const statusText: Record<string, string> = {
  running: "处理中",
  cancelling: "正在取消，等待当前请求返回",
  completed: "已完成",
  partial: "部分完成",
  cancelled: "已取消，结果不完整",
  failed: "处理失败",
};
interface ScopeContext {
  screen: Screen;
  filters: Filters;
}
interface Bookmark {
  screen: Screen;
  filters: Record<Screen, Filters>;
  finding: Finding | null;
  detail: DetailResponse | null;
  selectedId: string | null;
  scopeContext: ScopeContext | null;
}
export function App() {
  const [boot, setBoot] = useState<Bootstrap | null>(null),
    [prefs, setPrefs] = useState(initialPreferences),
    [screen, setScreen] = useState<Screen>("import"),
    [filters, setFilters] = useState(initialFilters),
    [views, setViews] = useState<Partial<Record<Screen, ViewResponse>>>({}),
    [lastView, setLastView] = useState<ViewResponse | null>(null),
    [selection, setSelection] = useState(emptySelection),
    [loading, setLoading] = useState(false),
    [detailLoading, setDetailLoading] = useState(false),
    [detail, setDetail] = useState<DetailResponse | null>(null),
    [selectedSource, setSelectedSource] = useState<Source | null>(null),
    [finding, setFinding] = useState<Finding | null>(null),
    [selectedId, setSelectedId] = useState<string | null>(null),
    [focus, setFocus] = useState<string | null>(null),
    [drawer, setDrawer] = useState(false),
    [back, setBack] = useState<Bookmark[]>([]),
    [error, setError] = useState<string | null>(null),
    [notice, setNotice] = useState("就绪"),
    [task, setTask] = useState<TaskMessage | null>(null),
    [request, setRequest] = useState(initialImport),
    [dragging, setDragging] = useState(false),
    [elevationBusy, setElevationBusy] = useState(false),
    [scope, setScope] = useState("suspicious"),
    [payload, setPayload] = useState(false),
    [exportOpen, setExportOpen] = useState(false),
    [exportPath, setExportPath] = useState(""),
    [exportHtml, setExportHtml] = useState(true),
    [exportJson, setExportJson] = useState(false),
    [overwrite, setOverwrite] = useState(false),
    [newOpen, setNewOpen] = useState(false),
    [closeOpen, setCloseOpen] = useState(false),
    [draft, setDraft] = useState<ConfigInput | null>(null),
    [checkStatus, setCheckStatus] = useState("尚未检查"),
    [width, setWidth] = useState(window.innerWidth),
    [sourceOffset, setSourceOffset] = useState(0),
    [diagnosticOffset, setDiagnosticOffset] = useState(0),
    [runOffset, setRunOffset] = useState(0);
  const session = useRef<number | null>(null),
    viewRevision = useRef(0),
    detailRevision = useRef(0),
    scopeContext = useRef<ScopeContext | null>(null),
    ended = useRef(new Set<number>()),
    closing = useRef(false),
    composingQuery = useRef(false),
    lifecycle = useRef(0),
    taskRef = useRef<TaskMessage | null>(null),
    currentScreen = useRef(screen),
    currentFilters = useRef(filters),
    currentFocus = useRef(focus),
    prefsRef = useRef(prefs),
    requestRef = useRef(request),
    refreshRef = useRef<
      (
        s?: Screen,
        f?: Filters,
        focusId?: string | null,
        commit?: boolean,
      ) => Promise<void>
    >(async () => {}),
    qaAiStarted = useRef(false);
  currentScreen.current = screen;
  currentFilters.current = filters;
  currentFocus.current = focus;
  prefsRef.current = prefs;
  requestRef.current = request;
  taskRef.current = task;
  const data = views[screen],
    overview = data?.overview || lastView?.overview,
    active = filters[screen],
    hasSession = boot?.session_id !== null && !!boot,
    busy = !!task || elevationBusy,
    narrow = width < 1200,
    compact = width < 1024;
  const refresh = useCallback(
    async (
      next: Screen = currentScreen.current,
      filter: Filters = currentFilters.current[next],
      focusId: string | null = null,
      commit = true,
    ) => {
      const sid = session.current;
      if (sid === null) return;
      const revision = ++viewRevision.current;
      setLoading(true);
      try {
        const value = await api.view({
          session_id: sid,
          revision,
          screen: next,
          filters: filter,
          focus_id: focusId,
          commit_selection: commit,
          source_offset: sourceOffset,
          diagnostic_offset: diagnosticOffset,
          run_offset: runOffset,
        });
        if (
          revision !== viewRevision.current ||
          value.session_id !== session.current
        )
          return;
        setViews((v) => ({ ...v, [next]: value }));
        setLastView(value);
        setSelection(value.selection);
        if (evidenceScreen(next) && commit && !focusId)
          scopeContext.current = {
            screen: next,
            filters: structuredClone(filter),
          };
        if (value.offset !== filter.offset)
          setFilters((v) => ({
            ...v,
            [next]: { ...v[next], offset: value.offset },
          }));
        setError(null);
      } catch (e) {
        if (
          revision === viewRevision.current &&
          !String(e).includes("已忽略") &&
          !String(e).includes("已取消")
        )
          setError(String(e));
      } finally {
        if (revision === viewRevision.current) setLoading(false);
      }
    },
    [sourceOffset, diagnosticOffset, runOffset],
  );
  refreshRef.current = refresh;
  const launch = async (run: () => Promise<TaskMessage>) => {
    lifecycle.current++;
    setError(null);
    try {
      const value = await run();
      if (!ended.current.has(value.task_id)) setTask(value);
    } catch (e) {
      setError(String(e));
    }
  };
  const updatePreferences = async (value: Preferences) => {
    setPrefs(value);
    try {
      await api.preferences(value);
    } catch (e) {
      setError(`偏好保存失败：${String(e)}`);
    }
  };
  useEffect(() => {
    document.documentElement.classList.toggle("dark", prefs.dark);
  }, [prefs.dark]);
  useEffect(() => {
    const resize = () => setWidth(window.innerWidth);
    window.addEventListener("resize", resize);
    return () => window.removeEventListener("resize", resize);
  }, []);
  useEffect(() => {
    let disposed = false;
    let stopTask: (() => void) | undefined,
      stopDrop: (() => void) | undefined,
      stopClose: (() => void) | undefined;
    const initialize = async () => {
      try {
        stopTask = await listen<TaskMessage>("analysis-task", async (event) => {
          const value = event.payload;
          if (disposed) return;
          if (["running", "cancelling"].includes(value.status)) {
            if (!ended.current.has(value.task_id)) setTask(value);
            return;
          }
          ended.current.add(value.task_id);
          setTask((current) =>
            current?.task_id === value.task_id ? null : current,
          );
          setNotice(
            value.saved_paths.length
              ? `已保存：${value.saved_paths.join("、")}`
              : statusText[value.status] || value.status,
          );
          if (value.error) setError(value.error);
          if (value.kind === "config_check")
            setCheckStatus(value.error ? "连接失败" : "连接正常");
          const generation = lifecycle.current;
          const fresh = await api.initialize();
          if (disposed || generation !== lifecycle.current) return;
          const changed = fresh.session_id !== session.current;
          session.current = fresh.session_id;
          setBoot(fresh);
          setSelection(fresh.selection);
          setPrefs(fresh.preferences);
          if (value.kind.startsWith("config_")) setDraft(draftOf(fresh.config));
          if (changed) {
            viewRevision.current++;
            detailRevision.current++;
            setViews({});
            setFilters(initialFilters());
            setDetail(null);
            setFinding(null);
            setSelectedId(null);
            setSelectedSource(null);
            setFocus(null);
            setBack([]);
            scopeContext.current = null;
            setScreen("overview");
            await refreshRef.current("overview", defaultFilters(), null, false);
          } else if (fresh.session_id !== null) {
            await refreshRef.current(
              currentScreen.current,
              currentFilters.current[currentScreen.current],
              currentFocus.current,
              evidenceScreen(currentScreen.current) && !currentFocus.current,
            );
          }
          if (
            fresh.qa_ai &&
            !qaAiStarted.current &&
            value.kind === "import" &&
            fresh.session_id !== null
          ) {
            qaAiStarted.current = true;
            await launch(() =>
              api.ai(fresh.session_id!, "suspicious", null, false),
            );
          }
          if (value.error) setError(value.error);
        });
        const fresh = await api.initialize();
        if (disposed) return;
        setBoot(fresh);
        setPrefs(fresh.preferences);
        setDraft(draftOf(fresh.config));
        setSelection(fresh.selection);
        setTask(fresh.busy);
        session.current = fresh.session_id;
        setRequest((v) => ({
          ...v,
          capture_dir: fresh.capture_dir,
          paths: fresh.inputs,
          live: fresh.live_processes,
        }));
        if (fresh.config_error) setError(fresh.config_error);
        const win = getCurrentWebviewWindow();
        stopDrop = await win.onDragDropEvent(({ payload }) => {
          if (payload.type === "over" || payload.type === "enter")
            setDragging(true);
          else if (payload.type === "leave") setDragging(false);
          else if (payload.type === "drop") {
            setDragging(false);
            if (!taskRef.current) {
              setRequest((v) => ({
                ...v,
                paths: [...new Set([...v.paths, ...payload.paths])],
              }));
              setScreen("import");
            }
          }
        });
        stopClose = await win.onCloseRequested(async (event) => {
          if (closing.current) {
            event.preventDefault();
            return;
          }
          if (taskRef.current) {
            event.preventDefault();
            setCloseOpen(true);
          } else {
            closing.current = true;
            try {
              await api.preferences(prefsRef.current);
              // Tauri destroys the window after this awaited handler returns.
            } catch (e) {
              event.preventDefault();
              closing.current = false;
              setError(`偏好保存失败：${String(e)}`);
            }
          }
        });
        if (fresh.inputs.length)
          await launch(() =>
            api.import({
              ...initialImport,
              capture_dir: fresh.capture_dir,
              paths: fresh.inputs,
            }),
          );
      } catch (e) {
        if (!disposed) setError(`桌面接口初始化失败：${String(e)}`);
      }
    };
    void initialize();
    return () => {
      disposed = true;
      stopTask?.();
      stopDrop?.();
      stopClose?.();
    };
  }, []);
  useEffect(() => {
    if (session.current !== null)
      void refresh(screen, filters[screen], focus, focus === null);
  }, [screen, sourceOffset, diagnosticOffset, runOffset]);
  const navigate = (next: Screen) => {
    if (next === screen) return;
    detailRevision.current++;
    setScreen(next);
    setSelectedSource(null);
    setFocus(null);
    setDetail(null);
    setDetailLoading(false);
    setFinding(null);
    setSelectedId(null);
    setError(null);
    setDrawer(false);
  };
  const changeFilters = (patch: Partial<Filters>, reset = true) => {
    const updated = { ...active, ...patch, ...(reset ? { offset: 0 } : {}) };
    setFilters((v) => ({ ...v, [screen]: updated }));
    setFocus(null);
    void refresh(screen, updated, null, true);
  };
  const requestElevation = async () => {
    if (busy || boot?.platform !== "windows") return;
    setElevationBusy(true);
    setError(null);
    setNotice("等待 UAC 授权");
    try {
      const result = await api.elevate();
      setNotice(
        result === "launched"
          ? "管理员窗口已启动；原窗口和证据保留，请在新窗口开始本机采集"
          : result === "cancelled"
            ? "已取消 UAC 授权，仍使用当前窗口"
            : "当前窗口已具有管理员权限",
      );
    } catch (error) {
      setNotice("提权未完成，当前会话保留");
      setError(`无法启动管理员窗口：${String(error)}`);
    } finally {
      setElevationBusy(false);
    }
  };
  const pick = async (kind: string) => {
    try {
      const paths = await api.pick(kind);
      if (!paths.length) return;
      if (kind === "inputs") {
        setRequest((v) => ({
          ...v,
          paths: [...new Set([...v.paths, ...paths])],
        }));
        navigate("import");
      } else if (kind === "capture")
        setRequest((v) => ({ ...v, capture_dir: paths[0] }));
      else if (kind === "web")
        setRequest((v) => ({ ...v, web_format: paths[0] }));
      else if (kind === "config") {
        setPrefs((v) => ({ ...v, config_path: paths[0] }));
        await launch(() => api.config("load", paths[0]));
      } else if (kind === "export") {
        setExportPath(paths[0]);
        setOverwrite(false);
      }
    } catch (e) {
      setError(String(e));
    }
  };
  const selectRecord = async (id: string, jump = false) => {
    const sid = session.current;
    if (sid === null) return;
    if (jump)
      setBack((v) => [
        ...v,
        {
          screen,
          filters: structuredClone(filters),
          finding,
          detail,
          selectedId,
          scopeContext: scopeContext.current
            ? structuredClone(scopeContext.current)
            : null,
        },
      ]);
    const revision = ++detailRevision.current;
    setSelectedId(id);
    setFinding(null);
    setDetail(null);
    setDetailLoading(true);
    setDrawer(true);
    void updatePreferences({ ...prefsRef.current, inspector: true });
    try {
      const result = await api.detail(sid, id);
      if (revision !== detailRevision.current || sid !== session.current)
        return;
      setDetail(result);
      if (jump) {
        const next: Screen =
          result.record.data.kind === "log"
            ? "logs"
            : result.record.data.kind === "process"
              ? "processes"
              : "network";
        setScreen(next);
        setFocus(id);
        if (next === "network")
          setFilters((v) => ({
            ...v,
            network: { ...v.network, packets: true },
          }));
        await refresh(
          next,
          {
            ...filters[next],
            ...(next === "network" ? { packets: true } : {}),
          },
          id,
          false,
        );
      }
    } catch (e) {
      if (revision === detailRevision.current) setError(String(e));
    } finally {
      if (revision === detailRevision.current) setDetailLoading(false);
    }
  };
  const selectFinding = (value: Finding) => {
    detailRevision.current++;
    setDetailLoading(false);
    setFinding(value);
    setDetail(null);
    setSelectedId(null);
    setDrawer(true);
    void updatePreferences({ ...prefsRef.current, inspector: true });
  };
  const goBack = async () => {
    const previous = back.at(-1);
    if (!previous) return;
    detailRevision.current++;
    setBack((v) => v.slice(0, -1));
    setFilters(previous.filters);
    setScreen(previous.screen);
    setFocus(null);
    setFinding(previous.finding);
    setDetail(previous.detail);
    setSelectedId(previous.selectedId);
    scopeContext.current = previous.scopeContext;
    if (previous.scopeContext)
      await refresh(
        previous.scopeContext.screen,
        previous.scopeContext.filters,
        null,
        true,
      );
    await refresh(
      previous.screen,
      previous.filters[previous.screen],
      null,
      false,
    );
  };
  const applyConfig = async () => {
    if (!draft) return;
    const config = await api.applyConfig(draft);
    setBoot((v) => (v ? { ...v, config } : v));
    setDraft(draftOf(config));
    return config;
  };
  const configOperation = async (operation: string) => {
    try {
      if (operation !== "load") await applyConfig();
      await launch(() => api.config(operation, prefs.config_path));
      await api.preferences(prefs);
    } catch (e) {
      setError(String(e));
    }
  };
  const startAI = async () => {
    const sid = session.current;
    if (sid === null) return;
    const includePayload = payload;
    setPayload(false);
    await launch(() =>
      api.ai(
        sid,
        scope,
        scope === "matches" ? selection.id : null,
        includePayload,
      ),
    );
  };
  const reset = async () => {
    lifecycle.current++;
    try {
      await api.reset();
      session.current = null;
      viewRevision.current++;
      detailRevision.current++;
      setBoot((v) => (v ? { ...v, session_id: null } : v));
      setViews({});
      setSelectedSource(null);
      setLastView(null);
      setSelection(emptySelection);
      setFilters(initialFilters());
      setFinding(null);
      setDetail(null);
      setSelectedId(null);
      setFocus(null);
      setBack([]);
      scopeContext.current = null;
      setRequest((v) => ({ ...v, paths: [] }));
      setScreen("import");
      setNotice("就绪");
      setNewOpen(false);
    } catch (e) {
      setError(String(e));
    }
  };
  const doExport = async () => {
    const sid = session.current;
    if (sid === null) return;
    setError(null);
    try {
      lifecycle.current++;
      const job = await api.export(
        sid,
        selection.id || null,
        exportPath,
        exportHtml,
        exportJson,
        overwrite,
      );
      setExportOpen(false);
      setOverwrite(false);
      if (!ended.current.has(job.task_id)) setTask(job);
    } catch (e) {
      if (String(e).includes("已存在")) setOverwrite(true);
      else setError(String(e));
    }
  };
  const resizeInspector = (e: React.PointerEvent) => {
    e.currentTarget.setPointerCapture(e.pointerId);
    const start = e.clientX,
      original = prefs.inspector_width;
    const move = (event: PointerEvent) =>
      setPrefs((v) => ({
        ...v,
        inspector_width: Math.max(
          280,
          Math.min(440, original + start - event.clientX),
        ),
      }));
    const end = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", end);
      void api.preferences(prefsRef.current);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", end);
  };
  const findingsColumns: ColumnDef<Finding>[] = [
    {
      id: "risk",
      header: "风险",
      size: 72,
      cell: ({ row }) => <Risk finding={row.original} />,
    },
    {
      accessorKey: "title",
      header: "发现",
      cell: ({ row }) => (
        <span className="truncate table-primary" title={row.original.title}>
          {row.original.title}
        </span>
      ),
    },
    {
      id: "origin",
      header: "来源",
      size: 78,
      cell: ({ row }) => (
        <span className="origin-badge">
          {row.original.origin.startsWith("local:") ? "本地规则" : "AI"}
        </span>
      ),
    },
    {
      id: "evidence",
      header: "证据",
      size: 53,
      cell: ({ row }) => (
        <span className="mono table-muted">
          {row.original.evidence_ids.length}
        </span>
      ),
    },
    {
      id: "confidence",
      header: "置信度",
      size: 64,
      cell: ({ row }) => (
        <span className="table-muted">
          {Math.round(row.original.confidence * 100)}%
        </span>
      ),
    },
  ];
  const recordsColumns: ColumnDef<RecordSummary>[] = [
    {
      id: "time",
      header: screen === "processes" ? "PID / PPID" : "时间",
      size: screen === "processes" ? 85 : 115,
      cell: ({ row }) => {
        const r = row.original;
        return (
          <span className="mono truncate table-muted" title={r.timestamp || ""}>
            {r.data.kind === "process"
              ? `${r.data.fields.pid} / ${r.data.fields.parent_pid ?? "—"}`
              : r.timestamp?.slice(5, 19).replace("T", " ") || "未知"}
          </span>
        );
      },
    },
    {
      id: "source",
      header: screen === "processes" ? "快照来源" : "来源",
      size: 99,
      cell: ({ row }) => (
        <span
          className="truncate table-muted"
          title={data?.record_sources[row.original.source_id]}
        >
          {basename(
            data?.record_sources[row.original.source_id] ||
              row.original.source_id.slice(0, 8),
          )}
        </span>
      ),
    },
    {
      id: "kind",
      header:
        screen === "processes"
          ? "关系"
          : screen === "network"
            ? "协议"
            : "类别",
      size: screen === "network" ? 56 : 87,
      cell: ({ row }) => {
        const r = row.original;
        const node = data?.process_rows.find((n) => n.record_id === r.id);
        return r.data.kind === "process" ? (
          <span className="relation-tags">
            {node?.orphan && <span className="tag-warning">孤儿</span>}
            {node?.cyclic && <span className="tag-warning">循环</span>}
            {node?.context && <span>上下文</span>}
            {!node?.orphan && !node?.cyclic && !node?.context && (
              <span className="table-muted">正常</span>
            )}
          </span>
        ) : (
          <span
            className="truncate table-muted"
            title={
              r.data.kind === "log"
                ? r.data.fields.category
                : r.data.fields.protocol
            }
          >
            {r.data.kind === "log"
              ? r.data.fields.category
              : r.data.fields.protocol}
          </span>
        );
      },
    },
    {
      id: "summary",
      header:
        screen === "processes"
          ? "进程名称"
          : screen === "network"
            ? "端点 / 摘要"
            : "关键字段",
      cell: ({ row }) => {
        const r = row.original;
        const node = data?.process_rows.find((n) => n.record_id === r.id);
        return (
          <div
            className="process-name"
            style={
              r.data.kind === "process"
                ? { paddingLeft: Math.min(node?.depth || 0, 8) * 12 }
                : undefined
            }
          >
            {node?.has_children && (
              <button
                className="tree-toggle"
                aria-label={`${active.collapsed.includes(r.id) ? "展开" : "收起"} ${r.data.kind === "process" ? r.data.fields.name : ""}`}
                onClick={(e) => {
                  e.stopPropagation();
                  changeFilters({
                    collapsed: active.collapsed.includes(r.id)
                      ? active.collapsed.filter((id) => id !== r.id)
                      : [...active.collapsed, r.id],
                  });
                }}
              >
                {active.collapsed.includes(r.id) ? (
                  <ChevronRight size={12} />
                ) : (
                  <ChevronDown size={12} />
                )}
              </button>
            )}
            <span
              className="truncate table-primary"
              title={r.data.kind === "process" ? r.data.fields.name : r.summary}
            >
              {r.data.kind === "process"
                ? r.data.fields.name
                : r.data.kind === "log" &&
                    !Object.keys(r.data.fields.fields).length
                  ? "点击查看原始记录"
                  : r.summary}
            </span>
          </div>
        );
      },
    },
    {
      id: "status",
      header: screen === "network" ? "字节" : "状态",
      size: 66,
      cell: ({ row }) =>
        row.original.data.kind === "packet" ? (
          <span className="mono table-muted">
            {bytes(row.original.data.fields.original_bytes)}
          </span>
        ) : (
          <span className={`parse-status parse-${row.original.status}`}>
            {statusLabel[row.original.status]}
          </span>
        ),
    },
  ];
  const flowColumns: ColumnDef<Flow>[] = [
    {
      accessorKey: "endpoint_a",
      header: "端点 A",
      cell: ({ row }) => (
        <span
          className="mono truncate table-primary"
          title={row.original.endpoint_a}
        >
          {row.original.endpoint_a}
        </span>
      ),
    },
    {
      accessorKey: "endpoint_b",
      header: "端点 B",
      cell: ({ row }) => (
        <span className="mono truncate" title={row.original.endpoint_b}>
          {row.original.endpoint_b}
        </span>
      ),
    },
    { accessorKey: "protocol", header: "协议", size: 64 },
    {
      id: "packets",
      header: "命中 / 全部包",
      size: 110,
      cell: ({ row }) => (
        <span className="mono">
          {row.original.matched_packets} / {row.original.packets}
        </span>
      ),
    },
    {
      id: "bytes",
      header: "字节",
      size: 74,
      cell: ({ row }) => (
        <span className="mono table-muted">{bytes(row.original.bytes)}</span>
      ),
    },
  ];
  const sourceColumns: ColumnDef<Source>[] = [
    {
      accessorKey: "path",
      header: "来源路径",
      cell: ({ row }) => (
        <span className="truncate mono" title={row.original.path}>
          {basename(row.original.path)}
        </span>
      ),
    },
    {
      accessorKey: "format",
      header: "格式",
      size: 76,
      cell: ({ row }) => (
        <span className="small-badge">{row.original.format}</span>
      ),
    },
    {
      id: "size",
      header: "大小",
      size: 80,
      cell: ({ row }) => (
        <span className="mono table-muted">{bytes(row.original.bytes)}</span>
      ),
    },
    {
      accessorKey: "sha256",
      header: "SHA-256",
      size: 128,
      cell: ({ row }) => (
        <span className="mono truncate table-muted" title={row.original.sha256}>
          {row.original.sha256}
        </span>
      ),
    },
  ];
  const riskControls = (
    <div className="filter-row">
      <Select
        label="风险级别"
        value={active.severity || ""}
        onChange={(v) => changeFilters({ severity: (v as Severity) || null })}
        options={[
          { value: "", label: "全部风险" },
          ...Object.entries(severityLabel).map(([value, label]) => ({
            value,
            label,
          })),
        ]}
      />
      <Select
        label="发现来源"
        value={active.origin}
        onChange={(v) => changeFilters({ origin: v || "all" })}
        options={[
          { value: "all", label: "全部发现" },
          { value: "local", label: "本地规则" },
          { value: "ai", label: "AI 发现" },
        ]}
      />
      <span className="filter-count">
        {number(data?.findings?.total || 0)} 项发现
      </span>
    </div>
  );
  const findingsTable = (
    <DataTable
      page={data?.findings || null}
      columns={findingsColumns}
      id={(v) => v.id}
      selected={finding?.id}
      onSelect={selectFinding}
      loading={loading}
      empty={hasSession ? "当前筛选没有发现" : "导入证据后展示分析结果"}
      limit={active.limit}
      onPage={(offset) => changeFilters({ offset }, false)}
      onSize={(limit) => changeFilters({ limit })}
    />
  );
  const closeInspector = () => {
    setDrawer(false);
    void updatePreferences({ ...prefs, inspector: false });
  };
  const inspector =
    screen === "reports" && selectedSource ? (
      <SourceInspector source={selectedSource} onClose={closeInspector} />
    ) : (
      <Inspector
        finding={finding}
        detail={detail}
        loading={detailLoading}
        onJump={(id) => void selectRecord(id, true)}
        onFinding={selectFinding}
        onClose={closeInspector}
      />
    );
  const aiCount =
    scope === "matches"
      ? selection.count
      : scope === "all"
        ? overview?.records || 0
        : overview?.suspicious || 0;
  return (
    <TooltipProvider>
      <div
        className={`application ${boot?.platform === "macos" ? "macos" : ""}`}
        style={
          { "--inspector-width": `${prefs.inspector_width}px` } as CSSProperties
        }
      >
        <header
          className="toolbar"
          onMouseDown={(event) => {
            if (
              event.button === 0 &&
              !(event.target as HTMLElement).closest("button,input,select")
            ) {
              void getCurrentWebviewWindow().startDragging();
            }
          }}
        >
          <div className="brand">
            <span className="brand-mark">
              <i />
              <i />
              <i />
            </span>
            <strong>Analyzer</strong>
          </div>
          <div className="toolbar-session">
            <span className="session-symbol">
              <Files size={13} />
            </span>
            <span>{hasSession ? "证据分析会话" : "新分析"}</span>
            <ChevronRight size={12} />
            <span className="toolbar-current">{titles[screen]}</span>
            {hasSession && (
              <span className="session-badge">
                <span className="status-dot" />
                本地会话
              </span>
            )}
          </div>
          <div className="toolbar-actions">
            <Button
              variant="ghost"
              disabled={busy}
              onClick={() =>
                hasSession ? setNewOpen(true) : navigate("import")
              }
            >
              <Plus size={14} />
              <span>新建分析</span>
            </Button>
            <Button
              variant="ghost"
              disabled={!hasSession}
              onClick={() => navigate("ai")}
            >
              <Sparkles size={14} />
              <span>AI 分析</span>
            </Button>
            <Button
              variant="secondary"
              disabled={!hasSession || busy || loading}
              onClick={() => {
                setExportOpen(true);
                setOverwrite(false);
              }}
            >
              <Download size={14} />
              <span>导出报告</span>
            </Button>
          </div>
          {boot?.platform !== "macos" && (
            <div className="window-actions">
              <Button
                variant="ghost"
                size="icon"
                aria-label="最小化"
                onClick={() => void getCurrentWebviewWindow().minimize()}
              >
                <Minus size={13} />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                aria-label="最大化"
                onClick={() => void getCurrentWebviewWindow().toggleMaximize()}
              >
                <Square size={11} />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                aria-label="关闭窗口"
                onClick={() =>
                  void getCurrentWebviewWindow()
                    .close()
                    .catch((e) => setError(`关闭窗口失败：${String(e)}`))
                }
              >
                <X size={14} />
              </Button>
            </div>
          )}
        </header>
        <div className="workbench">
          <aside className="sidebar">
            <div className="sidebar-section">工作台</div>
            {screens
              .filter((s) => s !== "settings")
              .map((s, i) => {
                const Icon = icons[s];
                return (
                  <div key={s}>
                    {i === 2 && <div className="sidebar-section">证据</div>}
                    {i === 5 && (
                      <div className="sidebar-section">分析与输出</div>
                    )}
                    <Tooltip text={titles[s]}>
                      <button
                        className={`nav-item ${screen === s ? "active" : ""}`}
                        aria-label={titles[s]}
                        aria-current={screen === s ? "page" : undefined}
                        onClick={() => navigate(s)}
                      >
                        <Icon size={16} strokeWidth={1.7} />
                        <span>{titles[s]}</span>
                        {s === "overview" && overview && (
                          <small>
                            {overview.local_findings + overview.ai_findings}
                          </small>
                        )}
                      </button>
                    </Tooltip>
                  </div>
                );
              })}
            <div className="sidebar-bottom">
              {hasSession && (
                <div className="sidebar-session">
                  <span className="session-symbol">
                    <Files size={14} />
                  </span>
                  <div>
                    <strong>{number(overview?.records || 0)} 条证据</strong>
                    <span>{overview?.sources || 0} 个来源 · 内存会话</span>
                  </div>
                </div>
              )}
              <Tooltip text="设置">
                <button
                  className={`nav-item ${screen === "settings" ? "active" : ""}`}
                  onClick={() => navigate("settings")}
                  aria-label="设置"
                >
                  <Settings2 size={16} />
                  <span>设置</span>
                </button>
              </Tooltip>
              <Tooltip text={prefs.dark ? "切换浅色主题" : "切换深色主题"}>
                <button
                  className="nav-item theme-toggle"
                  aria-label={prefs.dark ? "切换浅色主题" : "切换深色主题"}
                  onClick={() =>
                    void updatePreferences({ ...prefs, dark: !prefs.dark })
                  }
                >
                  {prefs.dark ? <Sun size={16} /> : <Moon size={16} />}
                  <span>{prefs.dark ? "浅色主题" : "深色主题"}</span>
                </button>
              </Tooltip>
              <div className="sidebar-version">
                Easy Analyzer <span>{appVersion}</span>
              </div>
            </div>
          </aside>
          <main className="workspace">
            <div className="page-heading">
              <div>
                <div className="title-line">
                  {back.length > 0 && (
                    <Button
                      variant="ghost"
                      size="icon"
                      aria-label="返回原视图"
                      onClick={() => void goBack()}
                    >
                      <ArrowLeft size={16} />
                    </Button>
                  )}
                  <h1>{titles[screen]}</h1>
                  {loading && <LoaderCircle size={14} className="spin muted" />}
                </div>
                <p>{hints[screen]}</p>
              </div>
              <Tooltip
                text={
                  narrow
                    ? "打开证据详情"
                    : prefs.inspector
                      ? "收起详情"
                      : "展开详情"
                }
              >
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label="切换详情"
                  onClick={() =>
                    narrow
                      ? setDrawer(true)
                      : void updatePreferences({
                          ...prefs,
                          inspector: !prefs.inspector,
                        })
                  }
                >
                  <PanelRight size={17} />
                </Button>
              </Tooltip>
            </div>
            {error && (
              <div className="error-banner">
                <CircleAlert size={14} />
                <span>{error}</span>
                <button aria-label="关闭错误" onClick={() => setError(null)}>
                  <X size={13} />
                </button>
              </div>
            )}
            <div className="page-body">
              {screen === "import" && (
                <ImportView
                  request={request}
                  onChange={setRequest}
                  busy={busy}
                  platform={boot?.platform || "macos"}
                  elevated={boot?.elevated ?? null}
                  elevationError={boot?.elevation_error ?? null}
                  elevationBusy={elevationBusy}
                  onElevate={() => void requestElevation()}
                  onPick={(k) => void pick(k)}
                  onStart={() => void launch(() => api.import(request))}
                  dragging={dragging}
                />
              )}
              {screen === "overview" && (
                <>
                  <div className="statistics">
                    {[
                      {
                        label: "证据来源",
                        value: overview?.sources || 0,
                        sub: "独立来源",
                        icon: Files,
                      },
                      {
                        label: "证据记录",
                        value: overview?.records || 0,
                        sub: "完整证据集合",
                        icon: FileText,
                      },
                      {
                        label: "本地发现",
                        value: overview?.local_findings || 0,
                        sub: "规则分析",
                        icon: ShieldCheck,
                      },
                      {
                        label: "AI 发现",
                        value: overview?.ai_findings || 0,
                        sub: "已通过校验",
                        icon: Sparkles,
                      },
                    ].map((item) => (
                      <div key={item.label}>
                        <span>
                          <item.icon size={13} />
                          {item.label}
                        </span>
                        <strong>{number(item.value)}</strong>
                        <small>{item.sub}</small>
                      </div>
                    ))}
                  </div>
                  <div className="table-section-heading">
                    <span>待核查发现</span>
                    <small>按风险级别排列</small>
                  </div>
                  {riskControls}
                  {findingsTable}
                </>
              )}
              {evidenceScreen(screen) && (
                <>
                  <form
                    className="search-row"
                    onSubmit={(e) => {
                      e.preventDefault();
                      if (composingQuery.current) return;
                      changeFilters({});
                    }}
                  >
                    <div className="search-input">
                      <Search size={15} />
                      <input
                        aria-label="查询证据"
                        placeholder="搜索关键词或输入正则表达式…"
                        value={active.text}
                        onCompositionStart={() => {
                          composingQuery.current = true;
                        }}
                        onCompositionEnd={() => {
                          composingQuery.current = false;
                        }}
                        onKeyDown={(e) => {
                          // WebKit may report keyCode 229 while committing an IME candidate.
                          if (
                            e.key === "Enter" &&
                            (composingQuery.current ||
                              e.nativeEvent.isComposing ||
                              e.nativeEvent.keyCode === 229)
                          )
                            e.preventDefault();
                        }}
                        onChange={(e) =>
                          setFilters((v) => ({
                            ...v,
                            [screen]: { ...v[screen], text: e.target.value },
                          }))
                        }
                      />
                      <span className="search-key">
                        <Keyboard size={12} />↵
                      </span>
                    </div>
                    <Button
                      variant="secondary"
                      type="submit"
                      disabled={!hasSession || loading}
                    >
                      查询
                    </Button>
                    <Button
                      variant="ghost"
                      type="button"
                      onClick={() => {
                        const f = defaultFilters();
                        setFilters((v) => ({ ...v, [screen]: f }));
                        setFocus(null);
                        void refresh(screen, f);
                      }}
                    >
                      重置
                    </Button>
                  </form>
                  <div className="filter-row evidence-filters">
                    <Checkbox
                      label="正则"
                      checked={active.regex}
                      onChange={(regex) => changeFilters({ regex })}
                    />
                    <Checkbox
                      label="仅本地可疑"
                      checked={active.suspicious}
                      onChange={(suspicious) => changeFilters({ suspicious })}
                    />
                    <span className="filter-separator" />
                    <Select
                      label="证据来源"
                      value={active.source || ""}
                      onChange={(source) =>
                        changeFilters({ source: source || null })
                      }
                      options={[
                        { value: "", label: "全部来源" },
                        ...(data?.sources.items || []).map((s) => ({
                          value: s.id,
                          label: basename(s.path),
                        })),
                        ...(active.source &&
                        !data?.sources.items.some((s) => s.id === active.source)
                          ? [{ value: active.source, label: "指定来源" }]
                          : []),
                      ]}
                    />
                    {screen === "logs" && (
                      <Select
                        label="日志类别"
                        value={active.category || ""}
                        onChange={(category) =>
                          changeFilters({ category: category || null })
                        }
                        options={[
                          { value: "", label: "全部类别" },
                          ...(overview?.categories || []).map((value) => ({
                            value,
                            label: value,
                          })),
                        ]}
                      />
                    )}
                    <Select
                      label="解析状态"
                      value={active.status || ""}
                      onChange={(status) =>
                        changeFilters({
                          status: (status as Filters["status"]) || null,
                        })
                      }
                      options={[
                        { value: "", label: "全部状态" },
                        ...Object.entries(statusLabel).map(
                          ([value, label]) => ({ value, label }),
                        ),
                      ]}
                    />
                    {screen === "network" && (
                      <Select
                        label="协议"
                        value={active.protocol || ""}
                        onChange={(protocol) =>
                          changeFilters({ protocol: protocol || null })
                        }
                        options={[
                          { value: "", label: "全部协议" },
                          ...(overview?.protocols || []).map((value) => ({
                            value,
                            label: value,
                          })),
                        ]}
                      />
                    )}
                  </div>
                  {data && data.sources.total > 100 && (
                    <div className="source-filter-pager">
                      <span>
                        来源 {sourceOffset + 1}–
                        {Math.min(sourceOffset + 100, data.sources.total)} /{" "}
                        {data.sources.total}
                      </span>
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={!sourceOffset}
                        onClick={() =>
                          setSourceOffset(Math.max(0, sourceOffset - 100))
                        }
                      >
                        上一组
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={sourceOffset + 100 >= data.sources.total}
                        onClick={() => setSourceOffset(sourceOffset + 100)}
                      >
                        下一组
                      </Button>
                    </div>
                  )}
                  {screen === "processes" && (
                    <div className="view-mode">
                      <Tabs
                        value={active.tree ? "tree" : "list"}
                        onChange={(v) => changeFilters({ tree: v === "tree" })}
                        items={[
                          { value: "tree", label: "进程树" },
                          { value: "list", label: "列表" },
                        ]}
                      />
                      <span>快照来源独立分组 · 祖先仅作为上下文</span>
                    </div>
                  )}
                  {screen === "network" && (
                    <div className="view-mode">
                      <Tabs
                        value={active.packets ? "packets" : "flows"}
                        onChange={(v) =>
                          changeFilters({
                            packets: v === "packets",
                            flow: null,
                          })
                        }
                        items={[
                          { value: "flows", label: "网络会话" },
                          { value: "packets", label: "数据包" },
                        ]}
                      />
                      <span>
                        {active.flow !== null
                          ? `会话 #${active.flow + 1} · 筛选交集`
                          : "会话统计为完整包数与字节数"}
                      </span>
                      {active.flow !== null && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => changeFilters({ flow: null })}
                        >
                          全部包
                        </Button>
                      )}
                    </div>
                  )}
                  {data?.outside && (
                    <div className="focus-banner">
                      <ArrowUpRight size={13} />
                      已定位筛选外证据，返回后恢复原视图。
                    </div>
                  )}
                  {screen === "network" && !active.packets ? (
                    <DataTable
                      page={data?.flows || null}
                      columns={flowColumns}
                      id={(v) => String(v.key)}
                      loading={loading}
                      onSelect={(f) =>
                        changeFilters({ flow: f.key, packets: true })
                      }
                      onPage={(offset) => changeFilters({ offset }, false)}
                      onSize={(limit) => changeFilters({ limit })}
                      limit={active.limit}
                    />
                  ) : (
                    <DataTable
                      page={data?.records || null}
                      columns={recordsColumns}
                      id={(v) => v.id}
                      selected={selectedId}
                      onSelect={(r) => void selectRecord(r.id)}
                      loading={loading}
                      onPage={(offset) => changeFilters({ offset }, false)}
                      onSize={(limit) => changeFilters({ limit })}
                      limit={active.limit}
                      empty={
                        hasSession
                          ? "没有匹配的证据，请调整筛选"
                          : "先导入证据，随后在这里查询和核查"
                      }
                    />
                  )}
                </>
              )}
              {screen === "ai" && (
                <>
                  <div className="ai-scope-row">
                    <span className="section-label-text">证据范围</span>
                    <div className="segmented">
                      {[
                        { value: "suspicious", label: "本地可疑项" },
                        { value: "matches", label: "当前筛选" },
                        { value: "all", label: "全部证据" },
                      ].map((s) => (
                        <button
                          key={s.value}
                          disabled={
                            busy || (s.value === "matches" && !selection.id)
                          }
                          className={scope === s.value ? "active" : ""}
                          onClick={() => setScope(s.value)}
                        >
                          {scope === s.value && <Check size={12} />} {s.label}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div className="ai-summary">
                    <div className="ai-summary-main">
                      <span className="ai-symbol">
                        <Sparkles size={18} />
                      </span>
                      <div>
                        <strong>
                          {number(aiCount)} <small>条证据</small>
                        </strong>
                        <p title={scope === "matches" ? selection.label : ""}>
                          {scope === "matches"
                            ? selection.label
                            : scope === "suspicious"
                              ? "本地规则命中的完整证据集合"
                              : "当前会话的全部证据"}
                        </p>
                      </div>
                      <Button
                        disabled={
                          !hasSession ||
                          busy ||
                          loading ||
                          !aiCount ||
                          !boot?.config_loaded
                        }
                        onClick={() => void startAI()}
                      >
                        <Sparkles size={14} />
                        运行 AI 分析
                      </Button>
                    </div>
                    <div className="ai-service">
                      <span>
                        模型 <strong>{boot?.config.model || "尚未配置"}</strong>
                      </span>
                      <span className="truncate" title={boot?.config.base_url}>
                        服务{" "}
                        <strong>{boot?.config.base_url || "尚未配置"}</strong>
                      </span>
                      <button onClick={() => navigate("settings")}>
                        配置
                        <ArrowUpRight size={11} />
                      </button>
                    </div>
                  </div>
                  <div className="ai-privacy">
                    <Checkbox
                      label="本次包含原始包与载荷"
                      checked={payload}
                      disabled={busy}
                      onChange={setPayload}
                    />
                    <span>
                      <CircleAlert size={12} />
                      证据不会自动脱敏
                    </span>
                  </div>
                  {!boot?.config_loaded && (
                    <div className="muted text-small">
                      请先在设置页加载或保存配置。
                    </div>
                  )}
                  {hasSession && (
                    <AiHistory
                      key={boot!.session_id}
                      runs={data?.runs}
                      sessionId={boot!.session_id!}
                      onOffset={setRunOffset}
                      onError={setError}
                    />
                  )}
                  <div className="table-section-heading">
                    <span>有效发现</span>
                    <small>仅展示通过回复与证据校验的结果</small>
                  </div>
                  {riskControls}
                  {findingsTable}
                </>
              )}
              {screen === "reports" && (
                <>
                  <div className="report-summary">
                    <div>
                      <span className="report-icon">
                        <Files size={20} />
                      </span>
                      <div>
                        <strong>完整证据报告</strong>
                        <p>
                          {overview?.sources || 0} 个来源 ·{" "}
                          {number(overview?.records || 0)} 条证据 ·{" "}
                          {number(
                            (overview?.local_findings || 0) +
                              (overview?.ai_findings || 0),
                          )}{" "}
                          项发现
                        </p>
                      </div>
                    </div>
                    <Button
                      variant="secondary"
                      disabled={!hasSession || busy || loading}
                      onClick={() => setExportOpen(true)}
                    >
                      <Download size={14} />
                      导出报告
                    </Button>
                  </div>
                  <div className="table-section-heading">
                    <span>证据来源</span>
                    <small>原始文件哈希 · SHA-256</small>
                  </div>
                  <div className="sources-table">
                    <DataTable
                      page={data?.sources || null}
                      columns={sourceColumns}
                      id={(v) => v.id}
                      selected={selectedSource?.id}
                      onSelect={(source) => {
                        setSelectedSource(source);
                        setDrawer(true);
                        void updatePreferences({
                          ...prefsRef.current,
                          inspector: true,
                        });
                      }}
                      empty="尚未导入来源"
                    />
                  </div>
                  <div className="group-pager">
                    <span>
                      {data
                        ? `${sourceOffset + 1}–${Math.min(sourceOffset + 100, data.sources.total)} / ${data.sources.total} 个来源`
                        : "0 个来源"}
                    </span>
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={!sourceOffset}
                      onClick={() =>
                        setSourceOffset(Math.max(0, sourceOffset - 100))
                      }
                    >
                      上一组
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={
                        !data || sourceOffset + 100 >= data.sources.total
                      }
                      onClick={() => setSourceOffset(sourceOffset + 100)}
                    >
                      下一组
                    </Button>
                  </div>
                  <div className="table-section-heading">
                    <span>
                      诊断 <small>{data?.diagnostics.total || 0}</small>
                    </span>
                    <small>保留未完成范围与解析问题</small>
                  </div>
                  <div className="diagnostic-list">
                    {data?.diagnostics.items.map((d, i) => (
                      <div
                        key={i}
                        className={`diagnostic diagnostic-${d.level}`}
                      >
                        <CircleAlert size={13} />
                        <span className="diagnostic-source" title={d.source}>
                          {basename(d.source)}
                        </span>
                        <span title={d.message}>{d.message}</span>
                      </div>
                    ))}
                    {!data?.diagnostics.items.length && (
                      <div className="diagnostic-empty">
                        <ShieldCheck size={17} />
                        没有诊断
                      </div>
                    )}
                  </div>
                  <div className="group-pager">
                    <span>{data?.diagnostics.total || 0} 条诊断</span>
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={!diagnosticOffset}
                      onClick={() =>
                        setDiagnosticOffset(Math.max(0, diagnosticOffset - 50))
                      }
                    >
                      上一组
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={
                        !data || diagnosticOffset + 50 >= data.diagnostics.total
                      }
                      onClick={() => setDiagnosticOffset(diagnosticOffset + 50)}
                    >
                      下一组
                    </Button>
                  </div>
                </>
              )}
              {screen === "settings" && draft && boot && (
                <SettingsView
                  config={boot.config}
                  draft={draft}
                  onChange={setDraft}
                  path={prefs.config_path}
                  onPath={(config_path) =>
                    setPrefs((v) => ({ ...v, config_path }))
                  }
                  busy={busy}
                  checkStatus={checkStatus}
                  onPick={() => void pick("config")}
                  onApply={() =>
                    void applyConfig()
                      .then(() => setNotice("设置已应用，尚未保存"))
                      .catch((e) => setError(String(e)))
                  }
                  onSave={() => void configOperation("save")}
                  onLoad={() => void configOperation("load")}
                  onCheck={() => void configOperation("check")}
                />
              )}
            </div>
          </main>
          {!narrow && prefs.inspector && (
            <aside className="inspector">
              <div
                className="inspector-resize"
                onPointerDown={resizeInspector}
              />
              {inspector}
            </aside>
          )}
        </div>
        <footer className="statusbar">
          <div>
            {task ? (
              <>
                <LoaderCircle size={12} className="spin" />
                <span>
                  {task.status === "cancelling"
                    ? statusText.cancelling
                    : task.label}
                </span>
                {task.stage && (
                  <span className="status-muted">
                    {task.stage}
                    {task.completed !== null
                      ? ` · ${number(task.completed)}${task.total !== null ? ` / ${number(task.total)}` : ""}`
                      : ""}
                  </span>
                )}
                {task.total !== null && task.total > 0 && (
                  <span className="progress-track">
                    <i
                      style={{
                        width: `${Math.min(100, ((task.completed || 0) / task.total) * 100)}%`,
                      }}
                    />
                  </span>
                )}
                <button onClick={() => void api.cancel(task.task_id)}>
                  取消
                </button>
              </>
            ) : (
              <>
                {elevationBusy ? (
                  <LoaderCircle size={12} className="spin" />
                ) : (
                  <span className="status-dot" />
                )}
                <span className="status-notice" title={notice}>
                  {notice}
                </span>
                {hasSession && (
                  <>
                    <span className="status-separator" />
                    <span className="status-muted">
                      {number(overview?.records || 0)} 条证据
                    </span>
                    <button onClick={() => navigate("reports")}>
                      {lastView?.diagnostics.total || 0} 条诊断
                    </button>
                  </>
                )}
              </>
            )}
          </div>
          <span className="status-muted">
            本地工作台
            <span className="status-separator" />
            内存会话
          </span>
        </footer>
        <Dialog
          drawer
          open={narrow && drawer}
          onOpenChange={setDrawer}
          title="证据详情"
        >
          {inspector}
        </Dialog>
        <Dialog
          open={exportOpen}
          onOpenChange={setExportOpen}
          title="导出报告"
          description="保留完整证据与发现，不受当前筛选或分页裁剪。"
        >
          <div className="export-options">
            <Checkbox
              label="HTML 报告"
              checked={exportHtml}
              onChange={setExportHtml}
            />
            <Checkbox
              label="JSON 数据"
              checked={exportJson}
              onChange={setExportJson}
            />
          </div>
          <label className="form-field">
            导出路径
            <div className="input-action">
              <input
                className="input mono"
                aria-label="导出路径"
                value={exportPath}
                onChange={(e) => {
                  setExportPath(e.target.value);
                  setOverwrite(false);
                }}
                placeholder="选择报告保存位置"
              />
              <Button
                variant="outline"
                size="icon"
                aria-label="选择导出路径"
                onClick={() => void pick("export")}
              >
                <FolderOpen size={15} />
              </Button>
            </div>
          </label>
          {overwrite && (
            <div className="warning-note">
              同名报告已存在。再次点击将覆盖报告；证据与配置路径仍受保护。
            </div>
          )}
          <div className="dialog-actions">
            <Button variant="ghost" onClick={() => setExportOpen(false)}>
              取消
            </Button>
            <Button
              disabled={
                busy ||
                loading ||
                (!exportHtml && !exportJson) ||
                !exportPath.trim()
              }
              onClick={() => void doExport()}
            >
              <Download size={14} />
              {overwrite ? "确认覆盖并导出" : "导出完整报告"}
            </Button>
          </div>
        </Dialog>
        <Dialog
          open={newOpen}
          onOpenChange={setNewOpen}
          title="新建分析"
          description="当前会话仅保存在内存中。建议先导出需要保留的报告。"
        >
          <div className="dialog-actions">
            <Button variant="ghost" onClick={() => setNewOpen(false)}>
              返回当前会话
            </Button>
            <Button onClick={() => void reset()}>新建空会话</Button>
          </div>
        </Dialog>
        <Dialog
          open={closeOpen}
          onOpenChange={setCloseOpen}
          title="任务仍在运行"
          description="取消会保留有效结果；已发送的请求需要等待返回或超时。"
        >
          <div className="dialog-actions">
            <Button variant="ghost" onClick={() => setCloseOpen(false)}>
              继续等待
            </Button>
            <Button
              onClick={() => {
                if (task) void api.cancel(task.task_id);
                setCloseOpen(false);
              }}
            >
              取消任务并保留结果
            </Button>
          </div>
        </Dialog>
      </div>
    </TooltipProvider>
  );
}
