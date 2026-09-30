# 合成测试证据

所有样本均由仓库中的 `tools/generate-fixtures.py` 生成，账号、域名和地址为演示值，不包含真实主机记录。

- `synthetic.evtx`：构造的 EVTX/BinXML，含 6 次失败及 1 次成功登录；`empty.evtx` 是有效的空文件头，`malformed.evtx` 为截断头。
- `sample.utmp/wtmp/btmp`：384 字节 Linux 小端记录。
- `sample.pcap/pcapng`：构造的 Ethernet/IPv4/TCP/HTTP 包，PCAPNG 含大小端两个 section；`truncated.pcap` 缺少末尾数据。
- `auth.log/access.log/custom.log`：文本登录、访问日志及自定义格式；`custom-format.conf` 定义解析格式。
- `processes.json`：三个合成进程，用于父子关系、临时目录与编码命令规则。

修改生成器后运行 `python3 tools/generate-fixtures.py` 更新样本，再运行 Rust 测试。
