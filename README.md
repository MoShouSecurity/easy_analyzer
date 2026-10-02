# Easy Analyzer

Rust 开发的应急响应分析工具，提供 CLI 和原生桌面 GUI，可在 macOS 上分析 Windows、Linux 的离线日志。CLI 支持 Windows/Linux x64 和 macOS Apple Silicon（arm64）；GUI 当前已在 macOS ARM64 验证。

## 主要功能

- **日志分析**：支持 Windows EVTX、Linux utmp/wtmp/btmp、SSH 登录日志，以及 Apache/Nginx 访问和错误日志；自定义格式可读取 `LogFormat` / `log_format` 定义。
- **可疑项筛查**：默认启用 53 项日志规则，按高危、中危、低危展示，覆盖登录异常、账号与权限变更、审计异常和常见 Web 攻击特征；支持关键词和正则查询。
- **进程分析**：采集本机进程或导入 JSON 快照，查看名称、路径、命令行、父子关系和可疑进程。
- **流量分析**：导入 PCAP/PCAPNG，查看网络端点、协议、会话及 HTTP/DNS/TLS 元数据。
- **AI 分析**：接入自定义 OpenAI 兼容服务，将解析后的证据整理为文本，按日志、进程或流量场景自动生成提示词，返回严重度、说明、证据引用、置信度和建议。
- **导入与报告**：支持多个文件、标准输入和 Windows/Linux 本机常见日志路径加载；终端默认显示简洁摘要，可导出保留完整证据的 JSON、HTML 报告。

## CLI 命令

| 命令 | 功能 |
| --- | --- |
| `logs` | 分析日志、查询关键词、筛查可疑项 |
| `processes` | 采集本机进程或分析进程快照 |
| `pcap` | 分析离线 PCAP/PCAPNG 文件 |
| `analyze` | 自动识别并混合分析日志、进程快照和抓包文件 |
| `config` | 创建、查看和检查 AI 配置 |

## 常用示例

以下示例使用 `./easy-analyzer`，Windows 下对应 `easy-analyzer.exe`。

```sh
# 一键筛查可疑日志，默认只显示重要信息
./easy-analyzer logs cases/Security.evtx -s

# 查询关键词；添加 -r 使用正则表达式
./easy-analyzer logs cases/access.log -q '.env'

# 读取 Apache/Nginx 自定义日志格式
./easy-analyzer logs cases/access.log -W nginx-format.conf

# 自动加载当前 Windows/Linux 主机的常见日志
./easy-analyzer logs -l

# 采集本机进程并查看进程树
./easy-analyzer processes -t

# 分析离线抓包文件
./easy-analyzer pcap cases/capture.pcapng

# 混合导入，并导出完整报告
./easy-analyzer analyze cases/wtmp cases/processes.json cases/capture.pcap -j reports/case.json -H reports/case.html

# 管道输入日志
cat cases/auth.log | ./easy-analyzer logs - -f text
```

### 常用参数

所有长参数都有单字母短选项，区分大小写；完整参数和示例可用 `./easy-analyzer <命令> -h` 查看。

| 参数 | 用途 |
| --- | --- |
| `-s` | 显示默认规则命中的可疑记录 |
| `-q TEXT` / `-r` | 关键词查询 / 启用正则；与 `-s` 同用时取交集 |
| `-n N` | 终端记录显示数量，默认 50；`-n 0` 显示全部 |
| `-R` | 显示发现详情、证据引用及原始记录 |
| `-j PATH` / `-H PATH` | 导出完整 JSON / HTML 报告 |
| `-o html` / `-O PATH` | 保存 HTML 报告 / 指定主输出路径；省略路径时自动生成 `report.html`，已有文件时另取名称 |
| `-a` / `-S SCOPE` | 启用 AI / 指定发送范围：`all`、`matches`、`suspicious` |
| `-P` | PCAP 的 AI 分析额外发送原始包及载荷 |

## AI 配置

运行 `./easy-analyzer config init` 在当前工作目录创建 `config.toml`，默认使用 [DeepSeek 官方服务](https://api-docs.deepseek.com/) 的 `deepseek-flash` 模型。在文件中填写 `api_key = "你的密钥"` 即可持久保存，使用 `-c settings.toml` 可指定其他文件。

```sh
# 检查 AI 服务连接
./easy-analyzer config check

# 仅将本地规则命中的可疑日志发送给 AI
./easy-analyzer logs cases/Security.evtx -a -S suspicious
```

其他服务可修改配置中的 `base_url`、`model` 和 `api_key`。默认请求超时为 300 秒，每批证据文本上限 96 KiB（`batch_bytes = 98304`，不含提示词和传输编码），输出 token 上限 65536，使用 `json_object` 和 `max_tokens`；`config show` 隐藏密钥。

`-n` 只控制终端显示数量；AI 默认分析全部记录，可用 `-S suspicious` 仅分析可疑项，或配合查询使用 `-S matches`。

终端中启用 `-a` 后显示分析动画、当前批次和耗时，结束后提示完成或失败；动画写入标准错误，重定向标准错误时自动关闭。

AI 输入是本地解析后带证据编号的文本，通过 Chat Completions 接口发送。system 提示词根据 Windows 事件、Linux 登录/SSH、Web、进程、网络及混合场景自动组合；结果会校验证据编号和 JSON 结构。

AI 回复未通过 JSON 或证据校验时，当前批次最多重试两次；仍失败则记录缺失范围，跳过失败批次并继续分析其他批次；上下文模式仍汇总成功回复。若汇总自身失败，生成明确标注的本地结果整理，保留已校验发现、中性线索与证据引用，不新增模型推断。HTML 报告单列 AI 发现、完成范围及各批原始回复，JSON 报告在 `findings` 和 `ai_runs` 中保存这些内容；未通过校验的回复不作为结论。重试会再次调用 API。

仅指定 `-a` 时发送证据，所选数据不会自动脱敏；PCAP 默认发送解析摘要，添加 `-P` 才发送原始包和载荷。

## 使用说明

终端默认按风险级别汇总发现，显示关键字段和重点建议；`-n` 限制各区显示数量，`-R` 展开详情。HTML 提供响应式概览、重点发现和折叠详情，证据按来源分组，点击引用自动定位；JSON 顶部的 `summary` 提供风险概览，其余字段保留完整记录、发现及 AI 回复。导出后提示保存位置，来源或 AI 失败时保留已完成结果并显示诊断。规则命中是待核查线索，不代表攻击已成功。

macOS 请手动导入离线日志，`-l` 仅适用于 Windows/Linux；utmp/wtmp/btmp 支持 Linux glibc x64 常见布局。当前不支持实时抓包、TCP 重组或 TLS 解密。

Ctrl+C 可请求取消分析，保留已完成证据并尝试输出报告；已发送的 AI 请求等待返回或超时，再停止后续批次。

更多说明：[默认日志规则](docs/DEFAULT_RULES.md) · [macOS 使用指南](docs/MACOS.md)

## 架构

`analyzer-cli / analyzer-gui → analyzer-app → analyzer-core`：前端负责交互，应用层统一分析流程、会话、分页、任务和配置/导出，核心负责解析、规则、AI 与报告编码，详见[架构与接口](docs/ARCHITECTURE.md)。

## 现代桌面 GUI

采用 Tauri 2、React、TypeScript、Tailwind CSS 和 shadcn/ui，沿用 Rust 分析层。以 1280×720 桌面窗口设计，提供导入、概览、日志、进程、网络、AI、报告与来源、设置八页，以及浅色/深色主题。正常启动为空会话；统计来自实际分析结果。详情可收起，窄窗口使用详情抽屉和图标导航。

```sh
# 首次安装前端依赖并生成静态资源
npm --prefix crates/analyzer-gui/frontend ci
npm --prefix crates/analyzer-gui/frontend run build
cargo run -p analyzer-gui --locked
# macOS ARM64 本地打包，保留 dist 中已有配置和报告
bash scripts/package_gui_macos.sh
open "dist/Easy Analyzer.app"
```

GUI 使用后台任务进行导入、筛选、关系构建、AI、配置和导出。AI 默认建议本地可疑项，只有主动点击才发送；当前筛选覆盖完整集合，原始包/载荷每次主动勾选。报告保留完整证据，不受界面分页限制。

AI 设置支持按模型实际上下文上限自动规划，发送前预览完整记录数、保守 token 估算和批次数；预算内单次发送，超出才分批，并汇总跨批关联线索。旧配置保留原字节分批方式，使用方法与估算限制见 GUI 说明。

详见[GUI 使用与构建说明](docs/GUI.md)、[720p 布局](docs/GUI_DESIGN.md)和[GUI 验证记录](docs/GUI_VALIDATION.md)。八页双主题的 16 张真实 1280×720 截图入口为 `dist/gui-linear-720p/index.html`，另附 960×600 双主题检查截图（仍需人工复核的交互见验证记录）；图片和程序不纳入源码。标签发布流程同时构建 CLI 和 GUI；从 v1.1.1 标签起采用新版流程，v1.1.0 附件保持原样。

## 构建

安装 Rust 1.95+、C/C++ 构建工具和 CMake 后，运行 `cargo build --release --locked`，程序生成在 `target/release/`。workspace 默认成员仍为 core/app/CLI；GUI 需显式选择 `-p analyzer-gui`。

日常提交和分支推送不触发 GitHub Actions。只有明确要求“打包成 tag”时，才创建并推送 `vX.Y.Z` 发布标签；Actions 自动构建三平台的 CLI 和 GUI、生成并校验 SHA-256，然后发布到 Releases。标签版本必须与 Rust workspace、Cargo.lock、Tauri 配置和 npm 版本一致。

[Releases](https://github.com/MoShouSecurity/easy_analyzer/releases) 的后续新版本附件包含以下六个独立程序及 `SHA256SUMS`，不附文档、样本、配置或压缩包：

| 平台 | CLI（命令行） | GUI（图形界面） |
| --- | --- | --- |
| Windows x64 | `easy-analyzer-cli-windows-x64.exe` | `easy-analyzer-gui-windows-x64.exe` |
| Linux x64 | `easy-analyzer-cli-linux-x64` | `easy-analyzer-gui-linux-x64` |
| macOS ARM64 | `easy-analyzer-cli-macos-arm64` | `easy-analyzer-gui-macos-arm64` |

Linux/macOS 下载后需 `chmod +x`。macOS CLI 支持 11.0+、GUI 支持 13.0+，使用 ad-hoc 签名，未公证；GUI `.app` 仍可本地打包。Windows GUI 需要 WebView2 Runtime；Linux GUI 需要桌面环境与 GTK 3/WebKitGTK 4.1 运行库，Ubuntu 22.04 可安装 `libwebkit2gtk-4.1-0`。Windows/Linux GUI 的实际运行验证状态见[验证记录](docs/GUI_VALIDATION.md)。
