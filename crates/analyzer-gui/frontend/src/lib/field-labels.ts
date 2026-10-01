// Display labels only. Original field keys and values remain in the evidence model.
const eventDataLabels: Record<string, string> = {
  AuthenticationPackageName: "身份验证包名称",
  FailureReason: "失败原因",
  IpAddress: "IP 地址",
  IpPort: "网络端口",
  KeyLength: "密钥长度",
  LmPackageName: "NTLM 包名称",
  LogonProcessName: "登录进程名称",
  LogonType: "登录类型",
  ProcessId: "进程 ID",
  ProcessName: "进程名称",
  Status: "状态码",
  SubStatus: "子状态码",
  SubjectUserSid: "主体用户 SID",
  SubjectUserName: "主体用户名",
  SubjectDomainName: "主体域名称",
  SubjectLogonId: "主体登录 ID",
  TargetUserSid: "目标用户 SID",
  TargetUserName: "目标用户名",
  TargetDomainName: "目标域名称",
  TargetLogonId: "目标登录 ID",
  TargetLinkedLogonId: "关联目标登录 ID",
  WorkstationName: "工作站名称",
  LogonGuid: "登录 GUID",
  TransmittedServices: "传递的服务",
  RestrictedAdminMode: "受限管理模式",
  VirtualAccount: "虚拟账户",
  ElevatedToken: "提升的令牌",
  ImpersonationLevel: "模拟级别",
  NewProcessId: "新进程 ID",
  NewProcessName: "新进程名称",
  ParentProcessName: "父进程名称",
  CommandLine: "命令行",
  TokenElevationType: "令牌提升类型",
  MandatoryLabel: "完整性标签",
  PrivilegeList: "权限列表",
  ObjectServer: "对象服务器",
  ObjectType: "对象类型",
  ObjectName: "对象名称",
  HandleId: "句柄 ID",
  AccessList: "访问权限列表",
  AccessMask: "访问掩码",
  ServiceName: "服务名称",
  ServiceFileName: "服务文件名称",
  ServiceType: "服务类型",
  ServiceStartType: "服务启动类型",
  ServiceAccount: "服务账户",
  TaskName: "任务名称",
  TaskContent: "任务内容",
  TaskContentNew: "新任务内容",
  SourceAddress: "源地址",
  SourcePort: "源端口",
  DestAddress: "目标地址",
  DestPort: "目标端口",
  Protocol: "协议",
  Application: "应用程序",
};

const systemLabels: Record<string, string> = {
  "Provider.Name": "事件提供程序",
  "Provider.Guid": "提供程序 GUID",
  "Provider.EventSourceName": "事件来源名称",
  EventID: "事件 ID",
  "EventID.Qualifiers": "事件限定符",
  Version: "事件版本",
  Level: "事件级别",
  Task: "任务类别",
  Opcode: "操作代码",
  Keywords: "关键词",
  "TimeCreated.SystemTime": "记录时间",
  EventRecordID: "事件记录 ID",
  "Correlation.ActivityID": "活动 ID",
  "Correlation.RelatedActivityID": "关联活动 ID",
  "Execution.ProcessID": "执行进程 ID",
  "Execution.ThreadID": "执行线程 ID",
  Channel: "日志通道",
  Computer: "计算机名称",
  "Security.UserID": "用户 SID",
};

const commonLabels: Record<string, string> = {
  event_id: "事件 ID",
  user: "用户",
  client_ip: "客户端 IP 地址",
  host: "主机",
  action: "操作",
};

function lookup(labels: Record<string, string>, key: string) {
  return Object.hasOwn(labels, key) ? labels[key] : undefined;
}

export function logFieldLabel(key: string): string {
  const normalized = key.replace(/\.#text$/, "");
  for (const prefix of ["Event.EventData.", "EventData."]) {
    if (normalized.startsWith(prefix)) {
      return lookup(eventDataLabels, normalized.slice(prefix.length)) ?? key;
    }
  }
  for (const prefix of ["Event.System.", "System."]) {
    if (normalized.startsWith(prefix)) {
      const field = normalized
        .slice(prefix.length)
        .replace(/_attributes\./g, ".");
      return lookup(systemLabels, field) ?? key;
    }
  }
  return lookup(commonLabels, key) ?? key;
}
