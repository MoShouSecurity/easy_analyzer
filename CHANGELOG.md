# 更新记录

## 0.1.1 — 2026-09-30

- 重新组织 CLI 帮助：明确命令选择，按输入、查询、AI、报告和限制分组，补充示例及配置步骤。
- `-h` 与 `--help` 提供相同说明。
- 拆分各命令的参数：日志格式仅在 logs/analyze 指定；Web 格式与自动日志加载用于 logs/analyze；采集进程加入混合分析使用 analyze 的 `--live-processes`；PCAP 载荷发送用于 pcap/analyze。
- 缺少文件/采集来源、不适用的参数及 AI matches 缺少筛选条件，在参数解析时提示错误并返回退出码 2。
- macOS 发布包为 Apple Silicon arm64，使用现有共享分析核心。

## 0.1.0 — 2026-09-30

- 首版 Rust CLI：日志、进程、PCAP 分析，本地规则和查询，OpenAI 兼容 AI，终端/JSON/HTML 报告。
- Git 管理、合成样本及 Windows/Linux/macOS 构建配置。
