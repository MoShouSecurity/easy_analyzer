# 应急响应项目与 IOC

一次应急响应是一个项目；同一客户的另一次响应新建项目。同一项目可以持续多天，追加多个主机的证据。必填客户单位、响应开始时间；项目名称默认使用客户单位，可手动修改，留空时使用客户单位。开始时间默认本地当前时间，结束时间不得早于开始时间。时间使用带偏移量的 RFC 3339，创建/更新与响应起止时间分别保存。

## 使用

GUI 首页新建、搜索或继续项目。工作台顶部显示项目及客户，点击名称可修改资料。导入向当前项目追加；相同来源 ID 不重复写入，来源 ID 包含来源身份和内容信息，内容变化成为新来源。不会仅凭相同内容哈希跨主机合并。备注、AI 历史、IOC 和筛选条件随项目保存。新增证据使 AI 预览过期，保留原 IOC 命中并提示需主动扫描。

保存与另存为均保留 UUID，新建生成新的 UUID。另存为更新目录中的路径，原文件保留。文件移动后重新打开，目录更新路径；缺失文件明确提示。未保存时切换或关闭提供保存、返回及放弃本次修改选择。

```sh
easy-analyzer project create response.eair --name "客户甲响应" --client "客户甲" \
  --response-start "2026-10-05T09:00:00+08:00" --location "现场" --responders "工程师甲"
easy-analyzer project import response.eair host-a/auth.log host-b/auth.log
easy-analyzer project edit response.eair --response-end "2026-10-07T18:00:00+08:00"
easy-analyzer project note response.eair --record EVIDENCE_ID --text "现场核查备注"
easy-analyzer project open response.eair -q "192.0.2.10" -H report.html
easy-analyzer project list --search "客户甲" --from 2026-10-01 --until 2026-10-31

# --project 追加到工作数据库；同时指定 --save-project 才写回项目文件
easy-analyzer analyze host-c/auth.log --project response.eair --save-project response.eair

# 原直接分析仍可用；保存新项目必须提供客户，名称和开始时间可选
easy-analyzer analyze auth.log --save-project new.eair --client "客户乙"
```

CLI `project import` 自动保存此次显式操作，`project open` 只读打开，不重新解析或自动调用 AI。`--project` 操作会在私有工作副本中进行，未指定 `--save-project` 时原文件不改变。CLI 显式查询条件在保存时保留，续办时恢复；GUI 各页面筛选分别保存。

## IOC

GUI 支持 TXT/CSV 文件、粘贴和手动添加，三种入口共用校验及去重。TXT 每行一个 IOC；CSV 可转义逗号、引号及多行说明，列名为 `type,value` 和可选 `note`：

```csv
type,value,note
ip,192.0.2.10,示例地址
ip,2001:db8::1,示例 IPv6
domain,example.com,"示例说明，含逗号"
url,https://example.com/a?q=1,示例 URL
```

无效条目提示位置，其余有效条目继续导入；没有有效条目则保留原清单。域名默认包含子域名，按标签边界匹配；IP 按完整地址匹配。URL 规范化协议、主机与默认端口，忽略片段，路径和查询参数必须一致。首版不支持哈希、CIDR、通配符或联网查询。

```sh
easy-analyzer project import response.eair auth.log \
  --ioc indicators.txt --ioc indicators.csv --ioc-value 192.0.2.10 \
  --ioc-value https://example.com/a?q=1 --ioc-exact-domain
easy-analyzer project open response.eair --ioc-stdin < indicators.txt
# 保存粘贴/标准输入与扫描结果
easy-analyzer project open response.eair --ioc-stdin --ioc-stdin-csv \
  --save-project response.eair < indicators.csv
```

证据与 IOC 不能同时占用标准输入。扫描解析字段、日志原文、进程命令及网络/HTTP/DNS 元数据，排除二进制日志原文、包十六进制原文和载荷。命中保存 IOC、说明、证据 ID、实际值和位置，进入本地可疑筛选及报告，均为待核查线索。重复扫描逐记录替换结果；取消保留已完成记录的新命中及未访问记录的早先有效命中，覆盖提示说明最新扫描是否完成。

## 存储与架构

每个 `.eair` 是一个独立 SQLite 文件，应用标识 `0x45414952`、项目 schema 版本 `1`。SQLite 使用 `rusqlite` 的 bundled 特性随程序编译；core 不依赖数据库。参考 [SQLite 应用文件格式](https://www.sqlite.org/appfileformat.html) 和 [Backup API](https://www.sqlite.org/backup.html)。

- `analyzer-app` 的 `ProjectService` 管理工作数据库、资料、追加、保存和验证；`ProjectCatalog` 管理资料/路径/最近打开时间；`IocService` 管理清单与扫描任务。
- 来源、记录、发现及引用、网络会话及引用、AI 运行及批次、备注、筛选条件、IOC 及命中分表保存。记录 ID、来源、类别、解析状态、协议及关系有索引。记录/查询结果页使用序号游标，关系及报告使用分批游标；文本与正则维持原匹配语义，集合保存于工作表。
- 初次导入逐来源解析、执行规则、写入并释放，保留单来源限制。规则提供来源游标接口，AI 规划逐批读取并冻结到私有磁盘批次，HTML/JSON 编码通过 core 的 `ReportCursor` 输出；常用项目打开、页面、筛选、IOC 和导出路径不调用完整报告兼容物化入口。进程树仍需要进程节点集合，旧 `with_report`/core 公共入口保留原行为。
- 工作副本位于私有临时目录。手动保存以 Backup API 生成目标目录内临时快照，清除运行时集合，关闭旁文件、同步并原子替换。取消或替换失败保留原目标。打开校验标识、版本、完整结构/索引、数据库及外键、AI 证据引用，不重新解析。
- 输出路径保护覆盖原证据、配置、IOC 和项目；保存识别原文件 UUID/修订变化。项目没有 AI 配置密钥字段。项目目录仅保存基本资料、路径和最近打开时间，没有证据表；默认位于应用数据目录，可用 `EASY_ANALYZER_DATA_DIR` 指定隔离目录。
- GUI 后台任务绑定会话和修订，切换清除旧选择/预览；旧任务结果拒绝写入新项目。HTML 显示项目名称、客户及响应时间，JSON 沿用现有报告 schema，完整项目资料和备注留在数据库。

## 验证记录（2026-10-05）

Rust workspace 88 项测试（含文档测试）和 GUI 前端 44 项测试通过；覆盖跨客户会话隔离、同客户独立 UUID、多天追加、重复来源/内容变化、原输入移除后恢复、目录重定位、保存取消与外部修改、路径保护、元数据/筛选/备注、AI 过期预览、IOC 三入口/转义/无效行/边界/重复与取消覆盖。前端覆盖保存成功后继续、保存失败留在原项目和未保存关闭提示。

macOS ARM64 原生 GUI 使用合成客户：创建项目、导入 `auth.log`、粘贴含无效行的 IOC、完成扫描、保存项目；CLI 打开恢复证据/IOC 并写备注，移动后 GUI 提示缺失、重新定位，并显示 CLI 备注。Windows/Linux 桌面交互未实机验证。SQLite 已完成 macOS ARM64、Linux x64 GNU 和 Windows x64 GNU 编译检查；正式 Windows MSVC 编译仍需 Windows SDK/Visual Studio 工具链，当前 macOS 环境缺少该工具链，不能以 GNU 检查替代 MSVC 验证。现有发布 CI 的三个原生 runner 将构建 bundled SQLite；本次没有运行发布 Actions。

### 大项目合成测量

macOS ARM64、本地 SSD、Rust release；每条日志约 1 KiB，每来源 25,000 条，每 10,000 条一条 IOC。分别在独立进程测量初次解析/保存和打开后续办，`/usr/bin/time -l` 记录 RSS 峰值。无真实客户数据，无 AI 网络调用。

| 项目 | 十万条 | 百万条 |
|---|---:|---:|
| `.eair` 文件大小 | 248,496,128 B | 2,488,332,288 B |
| 初次解析及导入 | 3.790 s | 38.167 s |
| 保存快照 | 0.261 s | 2.198 s |
| 初次处理峰值 RSS | 184.1 MiB | 944.6 MiB |
| 打开（最后一轮） | 1.561 s | 13.447 s |
| 末页 100 条 | 0.002 s | 0.021 s |
| 文本筛选 | 0.061 s | 0.595 s |
| 正则筛选 | 0.060 s | 0.601 s |
| IOC 全项目扫描 | 0.764 s | 7.474 s |
| JSON 流式导出 | 0.322 s | 2.884 s |
| HTML 流式导出 | 0.490 s | 4.519 s |
| 续办峰值 RSS | 26.1 MiB | 26.0 MiB |

打开包含全文件校验及私有副本复制，明显受磁盘缓存/系统 I/O 影响；此前分别为 0.369 s 和 3.169–3.679 s，表中保留最后一轮结果，不承诺固定延迟。初次处理峰值随总量增长，不能据续办结果宣称初次导入也只需 26 MiB；当前逐来源释放、源内解析仍保留记录，尚未证实初次 RSS 恒定。合成文本结果也不能替代 EVTX/PCAP、密集 IOC 命中或长 AI 历史的大规模测量。

可复现命令（输出仅为自建合成项目；外部路径不得覆盖已有项目）：

```sh
cargo build --release --locked -p analyzer-app --example project_benchmark
/usr/bin/time -l target/release/examples/project_benchmark 100000 1024 import /tmp/synthetic-100k.eair
/usr/bin/time -l target/release/examples/project_benchmark 100000 1024 resume /tmp/synthetic-100k.eair
/usr/bin/time -l target/release/examples/project_benchmark 1000000 1024 import /tmp/synthetic-1m.eair
/usr/bin/time -l target/release/examples/project_benchmark 1000000 1024 resume /tmp/synthetic-1m.eair
```

本地文件与手动保存为首版边界，不含客户联系人、合同/收费、多人协作、云同步、自动保存或核查状态。
