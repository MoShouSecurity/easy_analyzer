# macOS 使用指南

这是 CLI 版本。包中的 `easy-analyzer` 适用于 Apple Silicon（arm64），构建部署目标为 macOS 11.0；实际运行验证的平台见 `VALIDATION.md`。

## 在程序目录中运行

在终端进入程序目录；从压缩包取得程序时先解压：

```sh
./easy-analyzer -h
./easy-analyzer analyze samples/synthetic.evtx samples/sample.wtmp samples/auth.log samples/access.log -j reports/demo.json -H reports/demo.html
```

也可以双击包中的 `演示.command`，运行上述合成样本并生成报告。报告不含真实案件数据。可用浏览器打开 `reports/demo.html` 查看结果。

## 分析 Windows/Linux 证据

先从目标主机复制日志到 Mac，再在 Mac 上运行：

```sh
./easy-analyzer logs /path/to/Security.evtx -s
./easy-analyzer logs /path/to/wtmp /path/to/btmp
./easy-analyzer logs /path/to/auth.log -q 'Failed password'
./easy-analyzer logs /path/to/access.log -q 'union.*select|\.env' -r
./easy-analyzer logs /path/to/access.log -W /path/to/nginx-format.conf
./easy-analyzer pcap /path/to/capture.pcapng
./easy-analyzer processes /path/to/processes.json -t
```

EVTX 不需要 Windows 环境；Linux 登录二进制日志支持 glibc x64 常见的 384 字节小端布局。与当前 Mac 的 CPU 架构无关。不同布局的 BSD/macOS utmp 不在解析范围内。未知名称的登录文件可加 `--format wtmp` 等参数。

采集当前 Mac 的进程：

```sh
./easy-analyzer processes -t
```

`logs --auto-load` 要在 Windows/Linux 目标主机上运行。macOS 版目前不自动采集 Unified Log、不远程采集日志、不实时抓包。

## AI

```sh
./easy-analyzer config init
# 编辑 ~/.config/easy-analyzer/config.toml 中的服务地址和模型
export EASY_ANALYZER_API_KEY='your-key'
./easy-analyzer logs /path/to/Security.evtx -a -S suspicious
```

AI 仅在显式调用时发送所选数据。配置和 CLI 选项详见包中的 `README.md`。

## 发布包信息

`BUILD_INFO.txt` 记录构建目标和 Git 提交。本地打包脚本直接输出包含程序、说明和合成样本的目录。二进制使用本地临时签名，未进行 Apple 开发者签名或公证。
