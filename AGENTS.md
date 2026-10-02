# 项目约定

## 架构

- 依赖方向为 `analyzer-cli / 未来 analyzer-gui → analyzer-app → analyzer-core`。CLI 不直接依赖 core；共享模型通过 app 的导出接口访问。
- 分析编排、范围选择、会话、配置保存与导出校验放在 app；解析器、规则、AI 协议和报告编码放在 core。前端负责参数/控件、标准输入输出及进度展示。
- app/core 不依赖 CLI 或 GUI 框架、不打印终端；新增耗时循环接入执行上下文。任务取消保留有效证据、有效 AI 结果和未完成诊断。
- 保持报告 schema 和已有 core 公开入口兼容；GUI 使用会话分页与后台任务，不复制整套 CLI 流程。

## Git 与发布

- 日常修改只提交源码；用户要求同步 GitHub 时推送分支，不创建或推送发布标签，也不手动启动发布 Actions。
- 只有用户明确要求“打包成 tag”时，才创建并推送 `vX.Y.Z` 发布标签。版本不明确时先确认；标签必须指向已提交的发布源码，并与 `Cargo.toml`、`Cargo.lock` 中的项目版本一致，更新 `CHANGELOG.md`。
- 发布标签推送后，由 `.github/workflows/ci.yml` 自动构建并发布正式 Releases，等待 Actions 结果后报告成功或失败。不要在普通更新中触发此流程。
- Releases 附件仅包含 Windows x64、Linux x64、macOS ARM64 各自的 CLI 与 GUI，共六个附件及 `SHA256SUMS`，其中 macOS GUI 为未压缩的 DMG，内含 `Easy Analyzer.app`（`easy-analyzer-gui-macos-arm64.dmg`），其余为独立程序；文件名明确包含 `-cli-` / `-gui-`。不发布 macOS Intel 版，不上传文档、样本、配置或其他压缩包。
- 不覆盖已发布版本；修改后用新的版本标签发布。

## 本地文件

- `dist/` 保留最新程序，不按版本新建目录；更新程序时保留用户的 `config.toml`、报告和案件文件。
- 密钥、本地配置、真实日志、案件数据和构建产物不得纳入 Git。
