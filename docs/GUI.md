# 桌面 GUI 使用与构建

## macOS ARM64 使用

打开新版 `dist/Easy Analyzer.app`；独立程序为 `dist/easy-analyzer-gui`。八页双主题真实截图入口为 `dist/gui-linear-720p/index.html`，已完成与尚需人工复核的验收见 [验证记录](GUI_VALIDATION.md)。程序以本地 ad-hoc 签名交付，未进行 Apple 公证。正常启动为空会话，退出后不保存证据；需要保留时主动导出 HTML/JSON。窗口默认 1280×720，最小 960×600。

先在导入页选择或拖入文件，可混合 EVTX、文本登录/Web 日志、进程 JSON、PCAP/PCAPNG；点击“开始本地分析”。设置页可加载已有 CLI 配置，或选择用户应用数据目录下的新配置并主动保存。本机进程采集在导入页明确显示采集保存目录；macOS 本机日志加载不可用，可导入离线日志。

证据查询作用于整个集合。表格默认每页 100 条；日志来源、类别、解析状态、网络协议与本地可疑筛选取交集。非法正则不会清除上一有效查询。进程树按来源独立建立关系，祖先仅作上下文；网络会话显示完整统计及筛选命中包数。点击发现引用跳转，返回入口恢复视图。

AI 仅主动点击“运行 AI 分析”发送。默认建议本地可疑项；“当前筛选”指最近一次有效的日志/进程/数据包筛选，覆盖所有页。开始时固定范围与设置。数据不会自动脱敏；原始包与载荷每次须主动勾选。取消正在发送的请求需等待返回或超时，已经校验的发现保留。运行历史的原始回复按批次分页，默认折叠。

导出始终包含完整证据，并保留有效 `query_matches`，不受当前页限制。路径由应用层校验，不允许覆盖证据/配置。已有报告须主动确认覆盖。新建分析会清空内存会话；进行中的任务须先取消并等待完成。

用户应用数据目录由 Tauri 提供，macOS 通常为 `~/Library/Application Support/com.easyanalyzer.gui/`。偏好只保存主题、详情尺寸/开关、窗口尺寸和配置路径。密钥在 Rust 端保留，前端只得到是否配置；主动保存配置时沿用原子写入与 Unix 0600 权限。GUI 不自动读取仓库中的用户案件或发送 AI。

## 开发

安装 Rust 1.95+、Node.js 22.12+（本轮 Node 24）和 Tauri 平台依赖：[官方前置要求](https://v2.tauri.app/start/prerequisites/)。macOS 需要 Xcode Command Line Tools；Linux 需要 GTK/WebKitGTK，Windows 需要 MSVC 与 WebView2。本轮只交付 macOS ARM64，其他平台状态见验证记录。

```sh
npm --prefix crates/analyzer-gui/frontend ci
npm --prefix crates/analyzer-gui/frontend run build
cargo run -p analyzer-gui --locked
# 带 Vite 热更新的原生窗口
npm --prefix crates/analyzer-gui/frontend run tauri -- dev
```

运行静态构建前必须生成 frontend/dist。`cargo run` 直接使用嵌入资源；单独浏览 Vite 页面无法调用桌面接口。GUI crate 不是 workspace 默认构建成员，普通 `cargo build` 仍构建 CLI；标签 CI 显式构建 CLI 和 GUI。

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
npm --prefix crates/analyzer-gui/frontend run typecheck
npm --prefix crates/analyzer-gui/frontend test
npm --prefix crates/analyzer-gui/frontend run build
bash scripts/package_gui_macos.sh --stage
# 验证暂存应用后，可常规打包安装到 dist；保留 config、报告、案件和 CLI
bash scripts/package_gui_macos.sh
```

打包脚本先构建至 `dist/tauri-build/Easy Analyzer.app`，检查版本、ARM64 和签名，再安装到 dist。已有独立 GUI 与 .app 先备份至 dist/backups；源码迁移前的快照也在该目录。

## CI 与下载

v1.1.0 标签使用原 CLI 发布流程。从 v1.1.1 标签起同时构建 Windows x64、Linux x64、macOS ARM64 的 CLI 和 GUI，附件名称分别为 `easy-analyzer-cli-<平台>`、`easy-analyzer-gui-<平台>`（Windows 加 `.exe`）。六个独立程序统一由 `SHA256SUMS` 校验；不发布截图、配置、样本或压缩包，macOS `.app` 使用上述本地打包脚本生成。

CI 安装 Node 24 与平台构建依赖，通过前端格式检查、测试和类型/生产构建后，将静态资源嵌入 GUI。Rust workspace、Cargo.lock、Tauri 与 npm 的版本都必须匹配标签。各平台执行两个程序的 `--version`；macOS 另外验证 ARM64 与 ad-hoc 签名。合并附件时拒绝缺失程序、空文件或额外文件，发布前核对精确的六程序加校验文件清单。重跑只允许补全草稿，不能覆盖已发布版本。

Linux/macOS 下载后需 `chmod +x` 再运行。Windows GUI 需要 Microsoft Edge WebView2 Runtime。Linux GUI 需要桌面环境与 GTK 3/WebKitGTK 4.1，Ubuntu 22.04 可安装 `libwebkit2gtk-4.1-0`；构建依赖遵循 [Tauri 官方前置要求](https://v2.tauri.app/start/prerequisites/)。macOS GUI 要求 13.0+，CLI 要求 11.0+。CI 构建与版本检查不代表所有桌面交互已实机验收，各平台状态仍按验证记录说明。

## 合成验收

使用仓库合成 fixtures 或自行生成的数据，不使用真实案件。模拟服务只监听回环地址：

```sh
python3 scripts/gui_mock_ai.py --config /tmp/gui-mock.toml
# 在另一个终端启动；--qa 不保存偏好，--qa-ai 只允许回环模拟服务
cargo run -p analyzer-gui --locked -- --qa --qa-ai --config /tmp/gui-mock.toml \
  --input tests/fixtures/auth.log --input tests/fixtures/processes.json \
  --input tests/fixtures/sample.pcapng
# 窄窗口验收加入 --narrow
```

测试中的 AI 调用仅到本机模拟服务。`--temporary` 不保存偏好；`--input` 可重复指定明确导入文件。没有参数时不自动导入或发送 AI。
