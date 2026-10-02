# Easy Analyzer · easy 系列图标

采用共享 `easy_ico` 设计库 v1.1.0（2026-10-02）的 Easy Analyzer 资产：碧绿 `#00B89C` 圆角底板、白色大写 E 右倾 12°、深海蓝功能区与三根递增柱形。透明边距保留，应用按钮与风险配色不随身份色改变。

- `icon.svg`：标准几何母版，48 px 及以上使用。
- `icon-micro.svg`：32 px 及以下的光学校正版，字形与符号加粗。
- `icon.ico`：Windows 程序/快捷方式，含 16、24、32、48、64、128、256 px 七个 RGBA 帧；前三帧独立采用 micro 母版。
- `icon.icns`：macOS 应用包，包含普通和 Retina 尺寸。
- `icon.png`：512 px；另含 16 至 1024 px 的九个尺寸 PNG。
- `128x128@2x.png`：256 px PNG 的 Tauri Retina 别名。
- `SHA256SUMS`：本目录所有图形资产的内容校验值。

素材来源：共享库的 `masters/easy-analyzer.svg`、`masters/easy-analyzer-micro.svg` 及 `exports/easy-analyzer/`。导入后的文件自包含，构建不要求该共享库存在、不读外部绝对路径。

从仓库根目录运行 `bash scripts/generate_gui_icons.sh` 可从本目录 SVG 重新生成。脚本使用已安装的 Tauri CLI 和 Python 标准库，不调用图片模型、不联网；同时同步 GUI 的 `frontend/public/easy-analyzer.svg`。PNG、ICO、ICNS 已逐帧解码验证，与共享库成品一致。

Tauri 配置和 macOS 自定义打包脚本均引用本目录。父目录及 `icons/easy-analyzer/` 的旧图标保留，不再用于当前构建。重新打包并启动后，系统和 GUI 才使用新的标识。
