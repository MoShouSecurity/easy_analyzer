# 当前验证记录

2026-09-30，在 macOS ARM64 开发环境完成以下验证。

## 0.1.2 参数错误提示

- 复现不带输入运行 `analyze` 和 `logs` 的报错，必填项、用法标题及帮助提示均为中文。
- 核对未知命令/选项、遗漏参数值、非法格式/输出类型、无效数字值及依赖条件不足的诊断；错误写入 stderr，退出码为 2。
- 保留原始命令、选项名称、参数值、合法值列表和拼写建议；正常帮助/版本仍写入 stdout，退出码为 0。
- 现有 32 项回归测试及 Clippy 检查通过；发布仅生成 macOS arm64 原始程序目录。

## 0.1.1 CLI 帮助调整

- 顶层、四个分析命令、config 及三个配置子命令的 `-h` / `--help` 内容一致，包含中文用法说明；分析命令提供参数分组和示例，config 提供配置步骤。
- 11 种缺少输入、无关选项或依赖条件不足的用法正确返回退出码 2。四个分析入口与本机进程采集可执行。
- `cargo test --workspace --locked --offline` 的现有 32 项测试全部通过；格式检查和 Clippy 检查通过。
- 0.1.1 发布包仅提供 macOS arm64；Windows/Linux 交叉构建记录属于下方的 0.1.0 验证。

## 0.1.0 基线验证

- `cargo clippy --workspace --all-targets --offline -- -D warnings` 通过。
- `cargo test --workspace --locked --offline`：32 项测试全部通过，包括合成 EVTX、Linux 登录记录、混合来源、PCAP/PCAPNG 大小端、时间精度、进程树及报告导入分组、CLI 管道/输出、AI 本地 HTTP 模拟服务、超时/错误响应与载荷选择。新增 CLI 回归用例验证当前主机混合导入 Windows/Linux 日志，保留全部 25 条原始记录。
- Windows x64 GNU 和 Linux x64 GNU release 交叉构建成功；检查确认分别为 PE32+ x86-64 和 ELF x86-64。Windows 没有额外的 MinGW 运行库 DLL 依赖；Linux 二进制引用的最高 GLIBC 符号版本为 2.28。
- 本机进程采集测试覆盖当前测试进程；它证明共享采集接口在开发主机可运行，不代表 Windows/Linux 原生采集已验证。
- 生成完整的合成案件 JSON、HTML 和终端报告，位于被 Git 忽略的 `reports/demo.*`。HTML 的内容转义、证据链接结构和独立文档结构有测试覆盖。
- macOS arm64 release 构建成功；`LC_BUILD_VERSION` 部署目标为 11.0，SDK 为 27.0。依赖检查仅发现系统库/框架，无 Homebrew 动态库依赖。包中的二进制临时签名经 `codesign --verify --strict` 校验通过，没有 Apple 开发者签名/公证。
- 在 macOS 27.0.1 ARM64 主机上原生执行压缩包中解出的程序，通过 EVTX、三种 Linux 登录二进制日志、SSH/Web 日志、自定义 Nginx 格式、PCAP/PCAPNG 和本机进程采集检查。未在较旧 macOS 上执行。
- macOS ZIP 完整性、解包后的可执行权限、arm64 架构和签名均已检查。随包 `演示.command` 成功输出 19 条合成记录及 JSON/HTML 报告。

Windows/Linux 的原生执行、本机日志权限和 Windows 原生 `wevtutil` 路径尚未在真实目标系统运行。已提供 Windows/Linux/macOS GitHub Actions；仓库目前没有配置远程地址，工作流尚未执行。发布前应在目标平台通过该工作流并使用目标主机样本检查权限差异。

浏览器策略阻止直接打开本地 `file:` 报告，未进行浏览器截图与视觉检查；没有通过其他方式绕过该限制。

GUI 和实时抓包属于后续阶段，本次交付为 CLI 与共享 Rust 核心。实际第三方 AI 服务尚未连接；兼容性测试使用本地模拟服务，不使用真实密钥或案件数据。
