# Easy Analyzer

Rust 开发的应急响应分析 CLI，支持 Windows/Linux x64 和 macOS Apple Silicon（arm64），可在 macOS 上分析 Windows、Linux 的离线日志。

## 主要功能

- **日志分析**：支持 Windows EVTX、Linux utmp/wtmp/btmp、SSH 登录日志，以及 Apache/Nginx 访问和错误日志；自定义格式可读取 `LogFormat` / `log_format` 定义。
- **可疑项筛查**：默认启用 53 项日志规则，按高危、中危、低危展示，覆盖登录异常、账号与权限变更、审计异常和常见 Web 攻击特征；支持关键词和正则查询。
- **进程分析**：采集本机进程或导入 JSON 快照，查看名称、路径、命令行、父子关系和可疑进程。
- **流量分析**：导入 PCAP/PCAPNG，查看网络端点、协议、会话及 HTTP/DNS/TLS 元数据。
- **AI 分析**：接入自定义 OpenAI 兼容服务，按全部数据、筛选结果或可疑项分批分析，返回严重度、说明、证据引用、置信度和建议。
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
| `-a` / `-S SCOPE` | 启用 AI / 指定发送范围：`all`、`matches`、`suspicious` |
| `-P` | PCAP 的 AI 分析额外发送原始包及载荷 |

## AI 配置

运行 `./easy-analyzer config init` 在当前工作目录创建 `config.toml`，默认使用 [DeepSeek 官方服务](https://api-docs.deepseek.com/) 的 `deepseek-flash` 模型；默认从当前目录读取配置，使用 `-c settings.toml` 可指定其他文件。

```sh
# 在当前终端设置 DeepSeek 密钥（macOS/Linux）
export DEEPSEEK_API_KEY='你的密钥'

# 检查 AI 服务连接
./easy-analyzer config check

# 仅将本地规则命中的可疑日志发送给 AI
./easy-analyzer logs cases/Security.evtx -a -S suspicious
```

其他服务可修改配置中的 `base_url`、`model` 和 `api_key_env`。默认请求超时为 300 秒，每批证据上限 24000 字节，输出 token 上限 65536，使用 `json_object` 和 `max_tokens`。

仅指定 `-a` 时发送证据，所选数据不会自动脱敏；PCAP 默认发送解析摘要，添加 `-P` 才发送原始包和载荷。

## 使用说明

终端默认按风险级别汇总发现，并显示关键字段；`-R` 展开详情，JSON/HTML 始终保留完整记录和发现。规则命中是待核查线索，不代表攻击已成功。

macOS 请手动导入离线日志，`-l` 仅适用于 Windows/Linux；utmp/wtmp/btmp 支持 Linux glibc x64 常见布局。当前不支持实时抓包、TCP 重组或 TLS 解密，GUI 后续开发。

更多说明：[默认日志规则](docs/DEFAULT_RULES.md) · [macOS 使用指南](docs/MACOS.md)

## 构建

安装 Rust 1.95+、C/C++ 构建工具和 CMake 后，运行 `cargo build --release --locked`，程序生成在 `target/release/`。
