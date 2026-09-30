# 项目约定

## Git 与发布

- 日常修改只提交源码；用户要求同步 GitHub 时推送分支，不创建或推送发布标签，也不手动启动发布 Actions。
- 只有用户明确要求“打包成 tag”时，才创建并推送 `vX.Y.Z` 发布标签。版本不明确时先确认；标签必须指向已提交的发布源码，并与 `Cargo.toml`、`Cargo.lock` 中的项目版本一致，更新 `CHANGELOG.md`。
- 发布标签推送后，由 `.github/workflows/ci.yml` 自动构建并发布正式 Releases，等待 Actions 结果后报告成功或失败。不要在普通更新中触发此流程。
- Releases 附件仅包含 Windows x64、Linux x64、macOS ARM64 的三个独立程序及 `SHA256SUMS`；不发布 macOS Intel 版，不上传文档、样本、配置或压缩包。
- 不覆盖已发布版本；修改后用新的版本标签发布。

## 本地文件

- `dist/` 保留最新程序，不按版本新建目录；更新程序时保留用户的 `config.toml`、报告和案件文件。
- 密钥、本地配置、真实日志、案件数据和构建产物不得纳入 Git。
