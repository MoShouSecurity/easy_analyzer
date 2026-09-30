# 当前验证记录

2026-09-30，在 macOS ARM64 开发环境完成以下验证：

- `cargo clippy --workspace --all-targets --offline -- -D warnings` 通过。
- `cargo test --workspace --locked --offline`：31 项测试全部通过，包括合成 EVTX、Linux 登录记录、混合来源、PCAP/PCAPNG 大小端、时间精度、进程树及报告导入分组、CLI 管道/输出、AI 本地 HTTP 模拟服务、超时/错误响应与载荷选择。
- Windows x64 GNU 和 Linux x64 GNU release 交叉构建成功；检查确认分别为 PE32+ x86-64 和 ELF x86-64。Windows 没有额外的 MinGW 运行库 DLL 依赖；Linux 二进制引用的最高 GLIBC 符号版本为 2.28。
- 本机进程采集测试覆盖当前测试进程；它证明共享采集接口在开发主机可运行，不代表 Windows/Linux 原生采集已验证。
- 生成完整的合成案件 JSON、HTML 和终端报告，位于被 Git 忽略的 `reports/demo.*`。HTML 的内容转义、证据链接结构和独立文档结构有测试覆盖。

Windows/Linux 的原生执行、本机日志权限和 Windows 原生 `wevtutil` 路径尚未在真实目标系统运行。已提供双平台 GitHub Actions；仓库目前没有配置远程地址，工作流尚未执行。发布前应在这两个平台通过该工作流并使用目标主机样本检查权限差异。

浏览器策略阻止直接打开本地 `file:` 报告，未进行浏览器截图与视觉检查；没有通过其他方式绕过该限制。

GUI 和实时抓包属于后续阶段，本次交付为 CLI 与共享 Rust 核心。实际第三方 AI 服务尚未连接；兼容性测试使用本地模拟服务，不使用真实密钥或案件数据。
