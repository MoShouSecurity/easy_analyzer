import { invoke } from "@tauri-apps/api/core";
import type {
  Bootstrap,
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
} from "../types";
export const api = {
  initialize: () => invoke<Bootstrap>("initialize"),
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
  ai: (
    sessionId: number,
    scope: string,
    selectionId: number | null,
    includePayload: boolean,
  ) =>
    invoke<TaskMessage>("start_ai", {
      request: {
        session_id: sessionId,
        scope,
        selection_id: selectionId,
        include_payload: includePayload,
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
