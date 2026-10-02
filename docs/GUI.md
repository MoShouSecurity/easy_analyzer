# 桌面 GUI 使用与构建

## macOS ARM64 使用

打开新版 `dist/Easy Analyzer.app`；独立程序为 `dist/easy-analyzer-gui`。八页双主题真实截图入口为 `dist/gui-linear-720p/index.html`，已完成与尚需人工复核的验收见 [验证记录](GUI_VALIDATION.md)。程序以本地 ad-hoc 签名交付，未进行 Apple 公证。正常启动为空会话，退出后不保存证据；需要保留时主动导出 HTML/JSON。窗口默认 1280×720，最小 960×600。

先在导入页选择或拖入文件，可混合 EVTX、文本登录/Web 日志、进程 JSON、PCAP/PCAPNG；点击“开始本地分析”。设置页可加载已有 CLI 配置，或选择用户应用数据目录下的新配置并主动保存。本机进程采集在导入页明确显示采集保存目录；macOS 本机日志加载不可用，可导入离线日志。

Windows 导入页显示当前进程令牌的“普通权限 / 管理员权限”。点击“以管理员身份启动”后，通过系统 UAC 授权打开新的管理员窗口；取消或启动失败时保留原窗口、筛选和内存证据。新窗口不继承原会话，预选“采集本机进程”，仍需主动点击“开始本地分析”，不会自动采集或调用 AI。管理员窗口使用独立 WebView 数据目录，偏好保持临时，避免与原窗口争用；配置保存、报告导出仍由用户主动操作。

采集期间尝试启用 SeDebugPrivilege，完成、出错或取消后恢复原有权限状态。不能启用时继续采集可读信息，并在诊断中显示原因及缺失字段数量。提升权限有助于读取更多进程的路径、命令行和账户，但受保护进程、内核进程或已退出进程仍可能缺失信息。[Microsoft 进程访问说明](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)。CLI 在管理员终端运行进程采集时复用同一权限策略。

证据查询作用于整个集合。表格默认每页 100 条；日志来源、类别、解析状态、网络协议与本地可疑筛选取交集。非法正则不会清除上一有效查询。进程树按来源独立建立关系，祖先仅作上下文；网络会话显示完整统计及筛选命中包数。点击发现引用跳转，返回入口恢复视图。

AI 仅主动点击“运行 AI 分析”发送。默认建议本地可疑项；“当前筛选”指最近一次有效的日志/进程/数据包筛选，覆盖所有页。开始时固定范围与设置。数据不会自动脱敏；原始包与载荷每次须主动勾选。取消正在发送的请求需等待返回或超时，已经校验的发现保留。运行历史的原始回复按批次分页，默认折叠。

在设置页的“发送规划”选择“自动：按模型上下文预算”，填写所选模型/API 的实际 token 上限（1M 为 1000000），应用或保存后生效。工具预留输出上限和 20% 安全余量，并计算提示词开销；证据能装下时单次完整发送，超出预算才按完整记录分批，单条超限会提示，不截断证据。AI 页会先显示完整范围的记录数、证据及提示的 token 估算、证据批次数和是否需要跨批汇总；本地计算不会调用服务，预览完成前不能发送。修改模型、范围或载荷会重新计算，运行只使用本次预览固定的配置及证据。

Token 使用通用保守估算（ASCII 每两字节约一个 token，其他 UTF-8 字节每字节约一个），不是 DeepSeek/GLM 的精确分词结果，也不会仅凭模型名自动认定其上下文容量。服务方实际计数和限制为准。未设置 `context_tokens` 的旧配置继续按默认 96 KiB 字节预算分批；CLI 可以在配置文件中主动设置该字段启用同一规划与汇总能力。

个别证据批次失败后会继续处理其余批次；任务保持“部分完成”，记录失败范围，失败回复不会进入发现或总结。上下文模式的多批分析完成后，会汇总成功回复中已校验发现与模型保留的中性关联线索，按账号、主机、IP、时间及来源关联；汇总输入不是完整原始日志，不能保证覆盖模型未提取的线索。过大的汇总分组归并，最多四轮；汇总分组失败后仍处理其他分组，已经校验的输入线索保留到后续轮次，最多四轮；整轮没有成功回复时停止进一步汇总。超限、不收敛、服务失败或取消会保留有效发现和原始回复，并显示未完成诊断。部分失败或取消时，AI 页及对应运行历史提供“本地结果整理”：显示成功/失败/未执行范围、已校验发现与中性线索摘录及证据引用，明确没有完成新的 AI 关联推理。内容较多时展示部分摘录，完整发现及回复仍保留。没有成功回复时明确说明无法形成内容总结。这份整理作为诊断随 HTML/JSON 导出，不改变报告 schema，也不会添加伪造的 AI 发现。底部状态栏显示“AI 批次 · 当前 / 总数”；汇总阶段显示轮次及该轮“当前 / 总数”，每轮从 1 开始。重试不递增批次；最后一批等待响应时仍显示活动指示，不显示完成百分比；历史中的批次数包含汇总请求阶段，已分析记录数只计算原始证据一次。

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

打包脚本先构建至 `dist/tauri-build/Easy Analyzer.app`，检查版本、ARM64 和签名，再安装到 dist。同时生成 `dist/tauri-build/easy-analyzer-gui-macos-arm64.dmg`。CI 与本地脚本共用 `scripts/bundle_gui_macos.sh` 封装应用信息、图标、许可证和签名。已有独立 GUI 与 .app 先备份至 dist/backups；源码迁移前的快照也在该目录。

## CI 与下载

v1.1.0 标签使用原 CLI 发布流程。从 v1.1.1 标签起同时构建 Windows x64、Linux x64、macOS ARM64 的 CLI 和 GUI，附件名称分别为 `easy-analyzer-cli-<平台>`、`easy-analyzer-gui-<平台>`（Windows 加 `.exe`）。v1.1.1 至 v1.3.0 发布六个独立程序。从 v1.3.1 起，macOS GUI 改为 `easy-analyzer-gui-macos-arm64.dmg`，打开后为 `Easy Analyzer.app`；其余五个附件保持独立程序。`SHA256SUMS` 校验六个附件（macOS GUI 校验 DMG 本身），不发布截图、配置、样本或其他压缩包。

CI 安装 Node 24 与平台构建依赖，通过前端格式检查、测试和类型/生产构建后，将静态资源嵌入 GUI。Rust workspace、Cargo.lock、Tauri 与 npm 的版本都必须匹配标签。各平台执行两个程序的 `--version`；macOS 另外验证 ARM64 与 ad-hoc 签名。合并附件时拒绝缺失程序、空文件或额外文件，发布前核对精确的六附件加校验文件清单；macOS GUI 磁盘映像包含 `.app` 与“应用程序”安装链接，应用包内只包含程序、应用信息、图标、许可证和签名，挂载后验证 ARM64、签名与真实程序版本。重跑只允许补全草稿，不能覆盖已发布版本。

Linux 程序和 macOS CLI 下载后需 `chmod +x` 再运行。macOS GUI 打开 `.dmg`，将 `Easy Analyzer.app` 拖入“应用程序”后打开，无需手动设置执行权限。Windows GUI 需要 Microsoft Edge WebView2 Runtime。Linux GUI 需要桌面环境与 GTK 3/WebKitGTK 4.1，Ubuntu 22.04 可安装 `libwebkit2gtk-4.1-0`；构建依赖遵循 [Tauri 官方前置要求](https://v2.tauri.app/start/prerequisites/)。macOS GUI 要求 13.0+，CLI 要求 11.0+。CI 构建与版本检查不代表所有桌面交互已实机验收，各平台状态仍按验证记录说明。

## AI 页的证据筛选与结果阅读

点击“编辑筛选”可直接选择日志、进程或网络数据包，并组合关键词/正则、来源、类别或协议、解析状态和本地可疑项。应用后使用完整匹配集合，不受每页 50/100/200 条限制；非法正则不替换有效范围，0 条时无法运行 AI。尚无有效范围时，点击“当前筛选”也会打开编辑器。已有网络会话限制会保留，可在弹窗中移除。

AI 页的有效发现由 Rust 按 AI 来源过滤后分页，风险筛选仍覆盖完整 AI 结果；本地发现保留在分析概览和完整报告中。运行历史通过结果区按钮打开独立弹窗，按需读取批次和原始回复；预算详情及部分失败后的本地整理默认折叠。上方设置和下方结果独立滚动，给发现表保留阅读空间。

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


## 应用图标

当前图标来自 easy 系列设计库的 Easy Analyzer 产品资产，标准及小尺寸 SVG 母版保存在 `crates/analyzer-gui/icons/easy-family/`。Tauri 与 macOS 打包均引用该目录；GUI 标识和浏览器预览图标同步使用小尺寸母版。运行 `bash scripts/generate_gui_icons.sh` 可离线再生成多尺寸 PNG、七帧 ICO 和 ICNS，构建不依赖共享库的本机路径。详见该目录的 README。旧版图标保留。
