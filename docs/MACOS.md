# macOS 使用指南

这是 CLI 版本。包中的 `easy-analyzer` 适用于 Apple Silicon（arm64），构建部署目标为 macOS 11.0；实际运行验证的平台见 `VALIDATION.md`。

## 在程序目录中运行

本地打包后，最新程序直接位于项目的 `dist/`，不含版本子目录。先在终端进入 `dist/`，再运行：

```sh
./easy-analyzer -h
./easy-analyzer analyze samples/synthetic.evtx samples/sample.wtmp samples/auth.log samples/access.log -j reports/demo.json -H reports/demo.html
```

也可以双击包中的 `演示.command`，运行上述合成样本并生成报告。报告不含真实案件数据。可用浏览器打开 `reports/demo.html` 查看结果。

## 分析 Windows/Linux 证据

先从目标主机复制日志到 Mac，再在 Mac 上运行：

```sh
./easy-analyzer logs /path/to/Security.evtx -s
./easy-analyzer logs /path/to/Security.evtx -s -R
./easy-analyzer logs /path/to/wtmp /path/to/btmp
./easy-analyzer logs /path/to/auth.log -s
./easy-analyzer logs /path/to/auth.log -q 'Failed password'
./easy-analyzer logs /path/to/access.log -q 'union.*select|\.env' -r
./easy-analyzer logs /path/to/access.log -W /path/to/nginx-format.conf
./easy-analyzer pcap /path/to/capture.pcapng
./easy-analyzer processes /path/to/processes.json -t
```

EVTX 不需要 Windows 环境；Linux 登录二进制日志支持 glibc x64 常见的 384 字节小端布局。与当前 Mac 的 CPU 架构无关。不同布局的 BSD/macOS utmp 不在解析范围内。未知名称的登录文件可加 `--format wtmp` 等参数。

日志默认运行高危、中危、低危规则，`-s` 一键查询全部命中；规则清单见 [默认日志规则](DEFAULT_RULES.md)。

CLI 默认将发现按风险分组显示命中数量和规则名称，每条记录仅显示一行风险级别和关键字段，隐藏逐条的来源/位置、已解析状态和时间记录头。`-R` / `--raw` 显示发现解释、置信度、规则 ID、证据引用、记录头和原始记录。`-n 0` 展示全部摘要，`-R -n 0` 展示全部详情。JSON/HTML 报告始终保留完整证据。

使用 `-o html` 会自动在当前目录保存 `report.html`，已有文件时另取名称；`-O 3.html` 可指定保存路径。终端会提示报告位置及具体失败原因。

采集当前 Mac 的进程：

```sh
./easy-analyzer processes -t
```

`logs --auto-load` 要在 Windows/Linux 目标主机上运行。macOS 版目前不自动采集 Unified Log、不远程采集日志、不实时抓包。

## AI

```sh
./easy-analyzer config init
# 编辑当前目录的 config.toml，填写 api_key = "你的密钥"
# 默认使用 DeepSeek deepseek-flash
./easy-analyzer logs /path/to/Security.evtx -a -S suspicious
```

默认在当前工作目录创建和读取 `config.toml`；从 `dist/` 运行时配置就在 `dist/config.toml`，密钥填写到 `api_key` 后持久保存，也可用 `-c` 指定其他位置。AI 仅在显式调用时发送所选数据。配置和 CLI 选项详见包中的 `README.md`。

AI 默认分析全部记录，`-n` 只限制终端显示数量；仅分析可疑项请加 `-S suspicious`。默认每批证据上限为 65536 字节，单条证据超过上限时会提示所需大小，可调整 `batch_bytes`。

## 发布包信息

`BUILD_INFO.txt` 记录构建目标和 Git 提交。本地打包脚本直接输出包含程序、说明和合成样本的目录。二进制使用本地临时签名，未进行 Apple 开发者签名或公证。
