import { describe, expect, it } from "vitest";
import { logFieldLabel } from "./field-labels";

describe("Windows event field labels", () => {
  it.each([
    ["Execution.#attributes.ThreadID", "执行线程 ID"],
    ["Execution.#attributes.ProcessID", "执行进程 ID"],
    ["Provider.#attributes.Name", "事件提供程序"],
    ["Provider.#attributes.Guid", "提供程序 GUID"],
    ["Provider.#attributes.EventSourceName", "事件来源名称"],
    ["TimeCreated.#attributes.SystemTime", "记录时间"],
    ["Correlation.#attributes.ActivityID", "活动 ID"],
    ["Correlation.#attributes.RelatedActivityID", "关联活动 ID"],
    ["Security.#attributes.UserID", "用户 SID"],
    ["EventID.#attributes.Qualifiers", "事件限定符"],
  ])("localizes actual EVTX XML attribute path %s", (field, label) => {
    expect(logFieldLabel(`Event.System.${field}`)).toBe(label);
    expect(logFieldLabel(`System.${field}`)).toBe(label);
  });

  it("accepts plain and older attribute paths and text nodes", () => {
    for (const field of [
      "Execution.ThreadID",
      "Execution._attributes.ThreadID",
      "Execution_attributes.ThreadID",
    ]) {
      expect(logFieldLabel(`Event.System.${field}`)).toBe("执行线程 ID");
    }
    expect(logFieldLabel("Event.System.EventID.#text")).toBe("事件 ID");
    expect(logFieldLabel("Event.EventData.FailureReason.#text")).toBe(
      "失败原因",
    );
  });

  it("retains unknown names and fields outside the Windows event namespaces", () => {
    for (const field of [
      "Event.System.Execution.#attributes.UnknownAttribute",
      "Event.System.Unknown.#attributes.ThreadID",
      "Event.EventData.Unknown.#text",
      "custom.Execution.#attributes.ThreadID",
      "__proto__",
    ]) {
      expect(logFieldLabel(field)).toBe(field);
    }
  });
});
