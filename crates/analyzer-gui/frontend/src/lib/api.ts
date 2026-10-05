import { invoke } from "@tauri-apps/api/core";
import type {
  Bootstrap,
  ProjectInfo,
  ProjectStatus,
  ProjectEntry,
  IocInput,
  IocImport,
  IocView,
  Screen,
  Filters,
  ViewRequest,
  ViewResponse,
  DetailResponse,
  ImportRequest,
  TaskMessage,
  ConfigInput,
  PublicConfig,
  Preferences,
  AiBatch,
  Page,
  AiPreview,
} from "../types";
export const api = {
  projects: (search: {
    text: string;
    client: string;
    from: string | null;
    until: string | null;
  }) => invoke<ProjectEntry[]>("project_list", { search }),
  createProject: (info: ProjectInfo) =>
    invoke<TaskMessage>("project_create", { info }),
  openProject: (path: string) => invoke<TaskMessage>("project_open", { path }),
  saveProject: (sessionId: number, path: string, overwrite: boolean) =>
    invoke<TaskMessage>("project_save", { sessionId, path, overwrite }),
  editProject: (sessionId: number, info: ProjectInfo) =>
    invoke<ProjectStatus>("project_edit", { sessionId, info }),
  note: (sessionId: number, record: string, text: string) =>
    invoke<ProjectStatus>("project_note", { sessionId, record, text }),
  projectFilters: (sessionId: number, filters: Record<Screen, Filters>) =>
    invoke<ProjectStatus>("project_filters", { sessionId, filters }),
  importIoc: (sessionId: number, input: IocInput) =>
    invoke<IocImport>("import_ioc", { sessionId, input }),
  ioc: (sessionId: number, offset: number, hitOffset: number) =>
    invoke<IocView>("get_ioc", { sessionId, offset, hitOffset }),
  iocNote: (sessionId: number, id: string, note: string) =>
    invoke<ProjectStatus>("ioc_note", { sessionId, id, note }),
  scanIoc: (sessionId: number, includeSubdomains: boolean) =>
    invoke<TaskMessage>("start_ioc_scan", { sessionId, includeSubdomains }),

  findingRefs: (sessionId: number, id: string, offset: number) =>
    invoke<Page<string>>("finding_references", { sessionId, id, offset }),
  initialize: () => invoke<Bootstrap>("initialize"),
  elevate: () =>
    invoke<"launched" | "cancelled" | "already_elevated">("request_elevation"),
  view: (request: ViewRequest) => invoke<ViewResponse>("get_view", { request }),
  detail: (sessionId: number, id: string) =>
    invoke<DetailResponse>("get_detail", { sessionId, id }),
  batches: (sessionId: number, run: number, offset: number) =>
    invoke<Page<AiBatch>>("get_ai_batches", { sessionId, run, offset }),
  import: (request: ImportRequest) =>
    invoke<TaskMessage>("start_import", { request }),
  cancel: (taskId: number) => invoke<void>("cancel_task", { taskId }),
  reset: () => invoke<void>("reset_session"),
  applyConfig: (config: ConfigInput) =>
    invoke<PublicConfig>("apply_config", { config }),
  config: (operation: string, path: string) =>
    invoke<TaskMessage>("config_operation", { operation, path }),
  previewAi: (
    sessionId: number,
    scope: string,
    selectionId: number | null,
    includePayload: boolean,
  ) =>
    invoke<AiPreview>("prepare_ai", {
      request: {
        session_id: sessionId,
        scope,
        selection_id: selectionId,
        include_payload: includePayload,
      },
    }),
  ai: (
    sessionId: number,
    scope: string,
    selectionId: number | null,
    includePayload: boolean,
    planId: number,
  ) =>
    invoke<TaskMessage>("start_ai", {
      request: {
        session_id: sessionId,
        scope,
        selection_id: selectionId,
        include_payload: includePayload,
        plan_id: planId,
      },
    }),
  export: (
    sessionId: number,
    selectionId: number | null,
    path: string,
    html: boolean,
    json: boolean,
    overwrite: boolean,
  ) =>
    invoke<TaskMessage>("start_export", {
      request: {
        session_id: sessionId,
        selection_id: selectionId,
        path,
        html,
        json,
        overwrite,
      },
    }),
  pick: (kind: string) => invoke<string[]>("pick_paths", { kind }),
  preferences: (preferences: Preferences) =>
    invoke<void>("save_preferences", { preferences }),
};
