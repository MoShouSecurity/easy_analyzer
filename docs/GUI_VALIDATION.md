# Tauri GUI 验证记录

日期：2026-10-01。主机：macOS ARM64（macOS 27.0.1），Rust 1.97.1、Node.js 24.15.0。GUI 锁定 Tauri 2.12.1、React 19.3、TypeScript 7、Vite 8；实际版本见 Cargo.lock 与 frontend/package-lock.json。数据均为合成样本；AI 测试只调用回环模拟服务，不发送真实案件。

## 已完成的自动验证

- Rust 格式检查、全工作区 Clippy（`-D warnings`）、63 项工作区测试通过。
- 前端格式检查、TypeScript 检查、11 项 Vitest/React Testing Library 测试、生产构建通过。npm audit 无已知漏洞。
- macOS ARM64 release 构建通过；暂存 `.app` 与独立程序的版本和架构校验通过，ad-hoc 签名验证通过。
- workspace 默认成员仍为 core/app/CLI；GUI 只依赖 app，共享 core 模型由 app 导出。CLI 与现有发布流程未修改。

| 范围 | 验证证据 |
| --- | --- |
| 混合输入、损坏和超限 | app services 测试，保留有效来源与诊断；CLI/core fixtures 回归 |
| 10 万条分页 | app views 合成 100,000 条，50,000 条匹配，末页 100 条；取消查询不替换有效结果 |
| 筛选/非法正则 | GUI Rust/React 测试保留上一次有效范围与表格；50 条页对应完整 175 条选择；来源/类别/状态/协议全集合筛选 |
| 进程关系 | app services 覆盖跨来源重复 PID、孤儿/循环；GUI 测试证明祖先和折叠不会扩大 AI 范围 |
| 网络筛选 | app views 验证关联包交集及完整会话统计；GUI DTO 列表不传载荷/原文，完整记录按需取 |
| 引用与返回 | GUI Rust 筛选外临时定位、返回、旧会话/修订号拒绝；React 引用跳转与恢复发现 |
| AI 范围/载荷 | app AI tests 覆盖全部/当前选择/本地可疑、PCAP 默认无载荷、显式载荷；React 验证选择 token、主动发送、每次清空载荷选项 |
| AI 回复/部分失败/取消 | 本机模拟服务验证引用校验、重试、已接受结果保留、请求返回后取消后续批次、同会话写入串行 |
| 配置与导出 | app tests 原子保存失败保留原文件、0600、隐藏密钥、完整 HTML/JSON、重复路径/证据/配置/符号链接保护 |
| 文本呈现 | React 测试原始证据中的 HTML 按文本显示；密钥只返回状态，替换输入为 password |
| 启动行为 | React 测试普通空会话不触发导入或 AI；CLI 参数可显式指定合成验收输入 |

自动测试不是全部桌面验收的替代品。

## 已完成的原生运行检查

最终 release 程序的独立验收副本以 1280×720 实际启动，导入 5 个合成来源（登录/Web 日志、进程 JSON、EVTX、PCAPNG），保留 335 条证据、13 项本地发现。回环模拟 AI 服务完成 16 批、分析 282 条本地可疑证据，产生 16 项已校验发现；25 条诊断保留了故意损坏的 Web 输入等问题。

- 八页×双主题共 16 张真实 1280×720 PNG 已保存至 `dist/gui-linear-720p/light/` 与 `dark/`，逐页检查并验证像素尺寸。浅深配对使用相同会话、选择和数据，图片未经缩放或合成。
- 960×600 下八页×双主题另有 16 张检查截图位于 `narrow/`。导航收为图标栏、详情改为可关闭的抽屉，表格分页、导入主操作及设置保存/连接按钮均可见。设置滚动与长证据抽屉独立滚动正常。
- 原生文件对话框实际逐个选择 5 个合成文件，关闭或返回不会自动发送 AI。macOS 本机日志加载禁用；采集保存目录可见。
- 中文完整字符串“中文核查”输入、查询空集合及 AI 当前筛选空集合禁止发送已核对；非法正则 `[` 保留先前 302 条有效结果。输入法确认候选词的回车保护另有自动测试覆盖，包括 WebKit keyCode 229。
- 进程树、孤儿/循环标记、完整路径/命令行、网络会话关联包、HTTP 元数据、原始记录标签均已实际操作。筛选仅匹配孤儿后跳转到筛选外进程，返回恢复发现和完整有效筛选，AI 当前筛选仍为原来的 1 条。
- 来源表显示文件名，点击来源展示完整路径、字节数、SHA-256 与来源编号；实际双主题检查通过。
- GUI 导出 HTML/JSON 在当前筛选仅有 2 条网络证据时仍保留全部 335 条记录、5 个来源、29 项发现、1 次 AI 运行及 25 条诊断，`query_matches` 为 2 条。验收报告位于 `checks/full-evidence-report.*`。
- 设置页主动检查本机模拟服务显示“连接正常”；保存独立验收配置后修改未保存模型，再加载恢复原值，Unix 0600 权限通过。没有修改用户配置。
- 系统窗口缩放正常；最小化、恢复、关闭/退出进行了操作。自动工具对关闭后的应用可能重新启动，所以窗口关闭后持久化偏好的完整人工复核仍单独保留。

截图入口为 `dist/gui-linear-720p/index.html`，清单与校验值为 `manifest.json`、`SHA256SUMS`。最终 720p 截图使用与交付程序内容段一致的 release 验收副本；身份核对记录为 `checks/build-identity.json`。窄窗口截图使用同样布局、数据模型与样式的版本，后续输入法事件保护未改变布局。

## 尚需人工复核的交互

- 中文输入法真实候选词组合、确认与切换：完整中文文本输入和事件测试已通过，自动输入不等同于系统输入法实机组合验证。
- Finder 跨窗口原生文件拖放：事件处理及去重/不自动分析的测试已通过，但桌面自动工具数次拖放没有可靠地产生文件接收结果，不能将其记为原生拖放通过。
- 窗口关闭后偏好保存的人工复核。系统缩放与桌面布局已验证。

上述项目不作为已完成验收。新版 macOS ARM64 程序与 `.app` 已完成自动回归、主要原生流程及双主题视觉验证，更新至 `dist/easy-analyzer-gui` 和 `dist/Easy Analyzer.app`；旧 GUI 与迁移前源码快照保留在 `dist/backups/`。配置、报告、案件和 CLI 保留。本次交付为本地 ad-hoc 签名，未进行 Apple 公证。

## 平台状态

| 平台 | 状态 |
| --- | --- |
| macOS ARM64 当前主机 | 构建、签名、自动回归、主要原生流程及 32 张运行截图通过；上列交互仍需人工复核 |
| macOS 13 最低版本 | 打包声明最低版本 13，未在 macOS 13 实机验证 |
| Windows x64 | 本轮未构建/运行；需 MSVC/WebView2 与平台独立验证 |
| Linux x64 | 本轮未构建/运行；需 GTK/WebKitGTK 与平台独立验证 |

迁移前未提交源码的本地快照：`dist/backups/pre-tauri-source-20261001-093430.tar.gz` 和对应 patch。迁移阶段未提交或发布。随后准备 v1.1.0 发布：源码、依赖锁与文档随标签提交，正式 Releases 仍仅发布三个平台 CLI 与 SHA256SUMS。上述截图采集于发布前 1.0.0 GUI，v1.1.0 更新版本标识，验收限制保持不变。

## 后续 CLI / GUI 发布流程调整（2026-10-01）

标签工作流已改为显式构建三平台 CLI 与 GUI，附件名称使用 `-cli-` / `-gui-` 区分，六个程序加 `SHA256SUMS`。这项调整从 v1.1.1 标签生效，不修改 v1.1.0 标签或已发布附件。

- 本地 actionlint 工作流检查、所有内嵌 Bash 语法检查和差异格式检查通过。
- 新增发布校验 8 项测试通过：覆盖六程序清单、缺失 GUI、额外配置/报告/样本/目录、空程序、校验文件软链接、标签与 Rust/GUI/锁文件版本漂移。
- 前端格式检查、11 项测试、TypeScript 与 Vite 生产构建通过。
- v1.1.1 发布前通过 Rust 格式检查、workspace Clippy（警告视为错误）及全部 63 项 Rust 测试。AI 测试使用本机回环模拟服务，并显式恢复接收连接的阻塞模式，消除 macOS 偶发读取失败。
- 按 CI 参数本地构建 macOS ARM64 的 CLI 和 GUI release 程序，通过暂存独立程序的版本、ARM64 和 ad-hoc 签名检查；Mach-O 最低系统版本分别为 CLI 11.0、GUI 13.0。未替换 dist 中的用户程序或数据。
- Windows/Linux 原生 GUI 构建、Windows GUI 子系统下的版本输出检查与远端发布流程尚未执行，待后续新标签 Actions 验证。上述桌面交互验收限制保持不变。

## Windows UAC 与进程权限补充（2026-10-02，未发布源码）

- 导入页显示实际令牌提权状态；仅主动点击“以管理员身份启动”才调用 Windows UAC。新窗口为空会话并预选本机进程采集，原窗口和证据保留，不自动采集或调用 AI。管理员与普通窗口使用独立 WebView 数据目录。
- 进程采集尝试启用 `SeDebugPrivilege`，完成、失败或取消后恢复原有权限属性；启用失败仍保留可读取进程及诊断。缺失路径、命令行、用户字段提供汇总提示。该能力由 core 实现、app 导出，CLI 与 GUI 共享。
- macOS 主机上 Rust 格式检查、workspace Clippy（警告视为错误）、63 项工作区测试通过；前端格式、15 项测试、类型检查与生产构建通过。新增 React 测试覆盖主动点击、取消授权、启动成功保留原窗口、已提权不重复请求和启动失败恢复按钮。
- `x86_64-pc-windows-gnu` 完整 GUI 交叉检查与 core/app/GUI 全目标 Clippy 通过，包括两项 Windows 专属权限测试的编译。Windows MSVC 交叉检查因当前 macOS 主机缺少 Windows C SDK 头文件无法完成，不记为通过。
- Windows 专属权限测试覆盖采集开始前取消不修改令牌，以及具备调试权限时恢复原属性；本轮只交叉编译，未在 Windows 上运行这些测试。
- 使用合成 Windows bootstrap 的浏览器预览核查导入页双主题在 1280×720 和 960×600 下的布局。小窗口展开高级选项时内容可滚动，开始分析操作始终可见。4 张截图保存在 `dist/uac-check/`；这些是前端合成预览，不是 Windows 原生 UAC 运行截图。
- 尚需 Windows 实机验证：普通账户批准/取消 UAC、已提权启动、两窗口并存、中文/空格程序路径、实际增加的可读字段、调试权限恢复以及受保护进程诊断。提权不保证所有进程字段均可读取。

本轮没有提交、推送或发布，也未替换 dist 中的程序、配置、报告或案件。历史发布和桌面验收记录保留。

## Parallels Windows 11 首轮实机准备（2026-10-02）

- Windows 11 专业版 ARM64，系统 build 26200.9457；WebView2 154.0.4258.48。当前测试为 x64 程序在 ARM64 Windows 兼容运行，不代替 Windows x64 硬件或 CI MSVC 发布程序验收。
- 当前源码已构建 `x86_64-pc-windows-gnu` debug GUI/CLI，并复制至 `C:\Users\Public\Easy Analyzer UAC 测试 20261002-a1`；独立测试 GUI 文件名为 `easy-analyzer-gui-uac-test.exe`，GNU 构建所需的 `WebView2Loader.dll` 一并复制。桌面新增“Easy Analyzer 新版 UAC 测试”快捷方式，使用临时会话与独立配置路径。没有覆盖老版本或操作其正在运行的案件/AI 会话。
- GUI、CLI 与首次测试程序的 Windows 文件 SHA-256 和 Mac 构建一致；构建身份清单位于 `dist/uac-check/windows-build-identity.json`。
- Windows core 全部 17 项测试实机通过，包括调试权限恢复与开始前取消。执行账户是 Parallels 来宾命令的 SYSTEM，不能据此声称普通账户提权、UAC 授权/取消或 GUI 双窗口通过。
- 首次跨机器回归有 1 项测试因内嵌的 Mac 编译目录无法访问样本而失败；现改为编译时嵌入同一合成日志，Windows 17 项重跑全部通过，macOS 对应单项测试通过。产品解析逻辑未改变。
- Mac 当前锁定，界面操作工具两次明确报告无法自动解锁。用户解锁后继续普通桌面账户测试：启动新 GUI、取消/批准 UAC、双窗口并存、普通/管理员采集字段对比和证据保留。上述 UAC 与 GUI 项目本轮仍未完成。没有修改 PowerShell 执行策略、UAC 设置或虚拟机隔离设置。

## Mac 解锁后的 Windows GUI 检查（2026-10-02）

- 原有电脑操作工具能读取 Parallels 画面和外层菜单，来宾内部未可靠接收到自动鼠标/文本输入。用户随后明确授权 `prlctl` 和 Windows UI Automation，后续控件操作使用 Windows UIA，限定本轮新版测试进程。
- 新 GUI 从独立中文、带空格目录启动成功，启动为空会话、不自动导入或调用 AI；管理员权限标签可见，不展示重复提权按钮。两个测试窗口可同时运行，但不能据此把普通/管理员并存的 UAC 场景记为通过。
- 通过真实 GUI 仅勾选本机进程并开始本地分析，保留 1 个来源、179 条进程记录。通过真实导出弹窗选择仅 JSON、设置独立路径，成功导出完整 179 条记录、5 条诊断和 0 次 AI 运行。原始进程报告留在 Windows 独立测试目录，Mac 只保存字段统计，不复制原始命令行或账户数据。
- 缺失字段统计为路径 4 项、命令行 17 项、账户 2 项；汇总诊断与导出数据一致，没有调试权限启用失败诊断。该结果说明管理员采集和缺失字段诊断正常，不能声称已经验证提权后的读取增量。
- 真实原生窗口截图保存为 `dist/uac-check/windows-native-admin.png`。本机 Windows 缩放为 200%，逻辑客户区为 1280×720，带窗口边界的原始截图为 2586×1455；没有缩放或合成。最初终端遮挡的截屏未用于验收，最终通过原生窗口渲染读取后核对 179 条记录、1 个来源、0 项 AI 发现。
- 读取真实进程令牌：普通 Explorer 桌面、直接启动和 Explorer 启动的两份测试 GUI 均为 `TokenIsElevated=1`、`TokenElevationTypeDefault=1`，并非一份普通令牌、一份管理员令牌。注册策略为 EnableLUA=1、ConsentPromptBehaviorAdmin=5、PromptOnSecureDesktop=1；没有修改任何策略或账户。UAC 策略变更可能尚需重启生效，这是依据当前配置与令牌状态作出的推断，并未确认此前操作历史。微软说明管理员审批模式的变更需重启：[策略说明](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj852217%28v%3Dws.11%29)。
- 重启 Windows 的方式已向用户提出，当前等待选择；不会擅自重启虚拟机或关闭其他 Windows 程序。授权/取消 UAC、普通到管理员的窗口并存、读取字段增量仍待新会话验证。

## Windows 关闭窗口修复（2026-10-02，未发布源码）

- 已在此前新版空测试窗口中通过 Windows UIA 点击“关闭窗口”复现：窗口及进程仍然存在。Tauri 的 `onCloseRequested` 会等待前端处理完成，再调用 `destroy`；原 capabilities 只允许 `close`，未授予 `core:window:allow-destroy`。
- 补齐仅限主窗口的销毁权限；前端等待偏好保存后让 Tauri 完成关闭，移除再次发起 `close` 的递归流程。重复关闭请求在保存期间被拦截，保存失败保留窗口并可重试，运行中的任务仍提示取消并保留结果。
- 前端全部 19 项测试、格式检查、TypeScript 检查与生产构建通过。新增 4 项回归覆盖标题栏关闭、系统关闭、保存失败重试及连续点击、运行中取消保留结果；测试按本地 Tauri API 的真实关闭事件约定模拟，并检查实际 capabilities 中的销毁权限。
- Rust 格式及 diff 检查、macOS 与 Windows GNU 的 GUI 全目标 Clippy、GUI 6 项 Rust 测试，以及 Windows GNU debug GUI 构建通过。
- 新程序独立复制至 `C:\Users\Public\Easy Analyzer 关闭测试 20261002-b1\easy-analyzer-gui-close-test.exe`；两端 SHA-256 均为 `7e9cfd46455f0b8aeb85381e04a987039ce19f8e487341cc0b6467d5352475eb`，构建与测试身份记录在 `dist/uac-check/windows-close-build-identity.json`。
- Windows 原生验证：新空窗口 PID 11252 通过真实标题栏“关闭窗口”按钮退出，随后确认进程消失；另一新窗口 PID 9276 导入 2 条合成日志完成后通过系统 `WindowPattern.Close` 退出，随后确认进程消失。均为同一已核对哈希的程序，不是浏览器预览。
- 本轮创建的桌面“Easy Analyzer 新版 UAC 测试”快捷方式现已指向关闭修复后的程序；没有覆盖旧版本、用户配置或报告。先前已经运行的测试窗口不会自动更新，需从快捷方式重新启动。
- 测试环境仍为 Windows 11 ARM64 中运行 x64 GNU debug 程序，尚未验证 Windows x64 硬件上的 MSVC 发布程序。UAC 授权/取消及提权前后字段增量仍等待此前提出的 Windows 重启选择。本轮没有提交、推送或发布。

## v1.2.0 发布源码检查（2026-10-02）

- Rust workspace、Cargo.lock、Tauri 配置与 npm 清单/锁文件版本统一为 1.2.0；侧栏版本直接读取前端清单，避免独立硬编码。发布源码校验与 8 项附件校验脚本测试通过。
- 前端格式、19 项测试、TypeScript 检查与生产构建通过；Rust 格式、diff、workspace 全目标 Clippy（警告视为错误）与工作区全部 63 项测试（含 GUI 和文档测试）通过。
- 标签 CI 保持自动构建 Windows x64 MSVC、Linux x64 和 macOS ARM64 的 CLI/GUI，共六个独立程序及 SHA256SUMS。CI 构建结果不代表 Windows/Linux 桌面交互已完成验收；此前记录的实际 UAC 授权、取消及权限增量限制仍然有效。
