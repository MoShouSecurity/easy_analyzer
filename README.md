# Easy Analyzer

Rust 应急响应分析 CLI，支持 Windows/Linux x64 和 macOS Apple Silicon（arm64）。日志、进程和 PCAP 在本地解析，只有显式指定 `--ai` 才调用自定义 OpenAI 兼容服务。GUI 属于下一阶段，共享核心已经独立为库。

## 构建与运行

需要 Rust 1.95+、C/C++ 构建工具和 CMake（TLS 依赖使用 AWS-LC）。Windows 建议使用 MSVC 工具链；Linux 发布基线为 Ubuntu 22.04 x64，其他发行版可本机编译。Cargo.lock 纳入 Git。

```sh
cargo build --release --locked
cargo run -- analyze tests/fixtures/auth.log tests/fixtures/processes.json tests/fixtures/sample.pcap
```

发布包包含 `samples` 合成样本，可运行 `easy-analyzer analyze samples/auth.log samples/processes.json samples/sample.pcap` 查看效果。

Windows 可执行文件为 `target/release/easy-analyzer.exe`；Linux/macOS 为 `target/release/easy-analyzer`。macOS 发布包为 arm64 二进制，使用方式见 [macOS 指南](docs/MACOS.md)；开发者可运行 `bash tools/package-macos.sh`，直接生成 `dist/easy-analyzer-<版本>-macos-arm64/` 程序目录（需要 `aarch64-apple-darwin` Rust target和 Xcode 命令行工具）。

## 输入和分析

先选择命令，再查看对应帮助。`-h` 和 `--help` 都包含参数分组、输入说明与示例。

| 要做的事 | 命令 |
| --- | --- |
| 分析日志 | `logs` |
| 采集当前主机进程，或导入进程 JSON 快照 | `processes` |
| 分析已有 PCAP/PCAPNG | `pcap` |
| 自动识别文件，混合多种证据或同时采集进程 | `analyze` |
| 创建、查看或检查 AI 配置 | `config` |

```sh
easy-analyzer -h
easy-analyzer logs -h
easy-analyzer processes -h
easy-analyzer pcap -h
easy-analyzer config -h
```

各命令只接受对应模块的参数。`logs --format` 限定为日志格式；`processes` 固定读取进程 JSON，`pcap` 固定读取抓包文件。需要同时导入日志和采集进程时使用 `analyze --live-processes`。`--include-payload` 仅适用于 `pcap/analyze` 的 AI 分析。`--ai-scope matches` 必须同时提供 `--query` 或 `--suspicious`。

```sh
# 多种证据混合导入，自动识别并分类
easy-analyzer analyze cases/Security.evtx cases/wtmp cases/access.log cases/processes.json cases/capture.pcap

# 日志本地规则会自动运行；--suspicious 显示规则引用的记录
easy-analyzer logs cases/Security.evtx --suspicious
easy-analyzer logs cases/auth.log --query 'Failed password'
easy-analyzer logs cases/access.log --query 'union.*select|\.env|\.git' --regex

# 本机常见路径；Windows 导出的 EVTX 保留在 cases/captured
easy-analyzer logs --auto-load

# 手工输入、粘贴或管道输入（Windows PowerShell 可通过 Get-Content 管道输入）
 cat cases/auth.log | easy-analyzer logs - --format text

# 进程：无文件参数时采集本机；可导入快照并查看父子关系
easy-analyzer processes --tree
easy-analyzer processes cases/processes.json --tree

# PCAP 和 PCAPNG 离线分析
easy-analyzer pcap cases/capture.pcapng

# 完整 JSON 与独立 HTML；终端默认最多展示 50 条记录
easy-analyzer analyze cases/access.log --json-out reports/case.json --html-out reports/case.html
easy-analyzer logs cases/auth.log --output json > reports/auth.json
easy-analyzer processes --limit 0
```

支持显式 `--format auto|evtx|utmp|wtmp|btmp|web|text|processes|pcap`。自动识别主要依据魔数、文件名称和文本样本；登录二进制文件没有魔数，未知文件名需明确 `--format`。JSON 文件默认作为进程快照；JSON Web 日志请使用 `--format web --web-format-file`。

单文件默认上限 512 MiB、100 万条记录，可用 `--max-file-mb` 和 `--max-records` 调整。达到上限会报错，不会静默截断。当前数据集保存在内存中，输入和 JSON/HTML 原始证据会占用额外内存；超大案件建议分文件处理。

输入文件保持原状；禁止报告输出路径覆盖已导入的证据或配置。某个来源或 AI 分析失败时，其他已成功加载的来源仍输出报告，进程退出码为 1，并在 `diagnostics` 记录原因。退出码 0 表示任务完成，2 表示命令用法错误。单条无法解析的记录保留原始内容并标记状态。

## Apache/Nginx 自定义格式

`--web-format` 接收实际格式字符串或完整的服务格式定义；`--web-format-file` 从文件读取定义。支持 Apache common/combined、Nginx 常见访问日志，以及常见 Apache/Nginx error 日志。

```sh
easy-analyzer logs cases/access.log --format web --web-format 'LogFormat "%h %l %u %t \"%r\" %>s %b" common'
easy-analyzer logs tests/fixtures/custom.log --web-format-file tests/fixtures/custom-format.conf
```

Nginx 支持 `$name`、`${name}` 和分段引号定义，并保留额外变量；支持 `escape=json` 字符串转义。Apache 支持 `%h/%a/%l/%u/%t/%r/%s/%>s/%b/%B/%m/%U/%q/%D/%T/%v/%V/%p/%H` 及常见带 `{...}` 的 header/cookie/environment 指令。未支持的 Apache 指令会报错，避免猜测字段。error 日志和传统 syslog 中不含时区/年份的时间原样保留，不擅自补入案件时间。

## 本机采集与进程快照

Linux 常见来源包括 `/run/utmp`、`/var/log/{wtmp,btmp,auth.log,secure}`，以及 nginx/apache2/httpd 常见日志。仅使用 journald 的主机可先 `journalctl -o short-iso` 导出再导入。压缩日志需先解压。

Windows 本机加载通过 `wevtutil epl` 导出 Security、System、Application 和 PowerShell Operational 日志。Security 通常需要管理员权限；不会自动提权。导出文件保留在 `--evidence-dir`，权限不足或通道不可用会显示诊断。

macOS 可导入 Windows EVTX、Linux glibc x64 utmp/wtmp/btmp、SSH 和 Apache/Nginx 日志、进程快照及 PCAP/PCAPNG，使用与其他平台相同的解析器；可以采集 macOS 本机进程。`logs --auto-load` 仅适用于在 Windows/Linux 主机上运行，macOS 请显式选择已复制来的文件；当前不采集 macOS Unified Log，也不通过 SSH 自动读取远程日志。

进程采集包含 PID、父 PID、名称、可执行路径、命令行、账号 ID、启动时间和状态。权限不足、内核进程或瞬间退出可能导致部分字段缺失。进程快照接受如下 JSON 数组，也支持从本软件报告重新导入进程记录（保留原快照分组，来源哈希指向所导入的报告文件）：

```json
[
  {"pid": 100, "parent_pid": 1, "name": "demo", "path": "/usr/bin/demo", "command": ["demo"], "user": "1000"}
]
```

每次采集是一次快照，不持续监控进程；PID 关系按来源区分，避免混合多台主机的进程。

## AI 配置与调用

```sh
easy-analyzer config init
easy-analyzer --config config.toml config init
```

编辑配置的 `base_url`、`model` 和必要的兼容选项。密钥从 `api_key_env` 指定的环境变量读取，配置文件不存储密钥；不需要认证的本地服务可以不设置变量。

```toml
base_url = "http://127.0.0.1:11434/v1"
model = "your-model"
api_key_env = "EASY_ANALYZER_API_KEY"
timeout_seconds = 120
batch_bytes = 24000
max_output_tokens = 4096
response_format = "json_object" # json_schema / none 也可用
token_parameter = "max_tokens" # 部分模型需 max_completion_tokens
```

默认配置位于 Linux/macOS `$XDG_CONFIG_HOME/easy-analyzer/config.toml` 或 `~/.config/easy-analyzer/config.toml`；Windows 位于 `%APPDATA%/easy-analyzer/config.toml`。用全局 `--config` 指定其他路径。

```sh
easy-analyzer config show
easy-analyzer config check
easy-analyzer logs cases/Security.evtx --ai
easy-analyzer logs cases/access.log --query '\.env' --regex --ai --ai-scope matches
easy-analyzer analyze cases/auth.log --ai --ai-scope suspicious
easy-analyzer pcap cases/capture.pcap --ai
easy-analyzer pcap cases/capture.pcap --ai --include-payload
```

`--ai` 直接向指定服务发送所选数据，不弹出确认、不自动脱敏。`--ai-scope all` 默认分析全部已加载记录；`matches` 分析查询/可疑项筛选后的记录；`suspicious` 分析本地规则引用的记录。PCAP 默认只发送每个包的解析摘要（端点、协议、HTTP/DNS 元数据等），`--include-payload` 才包含原始包和载荷十六进制。

证据按 `batch_bytes` 分批提交，结果经结构与证据 ID 校验后汇总、去重；字节预算不是模型 token 计数，应根据服务上下文调整。单条记录过大时会报错，不裁剪证据。任一批次失败时不把部分 AI 结果标成完整结论，本地结果仍可使用。`config check` 会发出一个无证据的小请求，可能产生服务费用。

采用 Chat Completions 协议。JSON 模式仍由本地校验字段类型、严重度、置信度和证据 ID；兼容服务支持时可配置 `json_schema`。[官方结构化输出文档](https://developers.openai.com/api/docs/guides/structured-outputs)。

## 规则、证据和已知边界

内置规则覆盖重复失败登录（5 分钟内至少 5 次；无完整时间时至少 10 次）、失败后成功登录、远程 root 登录、Windows 清除日志事件、常见 Web 利用/探测特征、临时目录进程、编码/下载执行命令及 Office 启动脚本解释器。规则输出的是待核查线索，不判断利用已成功。

证据 ID 由来源路径/内容哈希和原始位置构成；记录包含源 ID、行号/字节偏移/事件 ID、时间、原始内容和解析状态。EVTX 的 `raw` 是解析后的事件 JSON，二进制登录日志和网络包的 `raw` 是十六进制。完整原始文件由来源路径和 SHA256 引用。JSON 报告 schema_version 为 1。

Linux utmp/wtmp/btmp 使用 glibc x64 常见的 384 字节、小端布局；BSD、大端及其他 ABI 不在本版范围。PCAP 支持常见 Ethernet、VLAN、raw IP 和 Linux cooked 链路，IPv4/IPv6、TCP/UDP/ICMP，并提取单包 HTTP/DNS/TLS 元数据。不进行 TCP 重组、TLS 解密或完整应用层会话还原；不支持的链路保留原包并诊断。实时抓包及 GUI 属于后续阶段。

## 开发与 Git

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

`tests/fixtures` 全部是由 `tools/generate-fixtures.py` 生成的合成证据，使用示例地址和账号，可纳入 Git。`.gitignore` 排除 `target`、`cases`、`evidence`、`reports`、本地配置和环境变量文件；真实案件请放在这些目录。源码、Cargo.lock、合成样本和 CI 配置应提交。

GitHub Actions 在 Windows 2022、Ubuntu 22.04 和 macOS arm64 上运行测试、构建和本机进程采集；Windows 额外验证本机 System 日志导出。macOS arm64 发布包也可由本地打包脚本生成。版本标签 `v*` 触发构建并保存包含 README/LICENSE 的发布压缩包，发布任务必须先通过相同测试。需要配置 Git remote 并推送后工作流才会执行。

共享库 `crates/analyzer-core` 提供输入识别、采集、规则、AI、报告和证据类型；`crates/analyzer-cli` 只负责命令和输出协调。后续全 Rust GUI 通过 `ingest_bytes` 支持粘贴/拖放，复用同一份分析结果及配置；日志/进程页面、设置和 AI 按钮在下一阶段实现。
