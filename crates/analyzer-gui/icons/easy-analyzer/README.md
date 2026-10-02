# Easy Analyzer 图标

深蓝圆角底、青色盾牌和白色分析波形，表达安全证据分析。图形不含文字，三平台使用相同视觉设计；圆角外为透明背景。

| 平台 / 用途 | 文件 |
| --- | --- |
| Windows 应用、快捷方式 | `icon.ico`，内含 16、24、32、48、64、256 px |
| macOS 应用包 | `icon.icns`，包含普通及 Retina 尺寸 |
| Linux 桌面、启动器 | `icon.png`（512 px），以及 32、64、128、256 px PNG |
| Windows Store | `Square*Logo.png`、`StoreLogo.png` |
| 原始母图 | `source.png`（1254 × 1254，RGBA） |

本目录保留此前的蓝色盾牌图标及生成记录，当前构建已改用 `../easy-family/`。父目录的更早图标也保留；Windows/Linux 实际桌面显示需在对应平台构建后验证。

当前 `scripts/generate_gui_icons.sh` 从 `../easy-family/` 的 SVG 母版生成 easy 系列图标；本目录的母图与成品作为历史设计素材保留。

## 母图生成记录

使用 Codex 内置 imagegen 生成，开启透明背景。提示词如下：

```text
Use case: logo-brand. Create one polished desktop application icon for Easy Analyzer, an offline cybersecurity incident-response evidence analysis tool for logs, processes, and network traffic. A single bold shield symbol with a simple rising analysis pulse / waveform integrated into its negative space. Elegant minimal geometric design, deep midnight navy rounded-square tile, vivid turquoise shield and crisp near-white pulse. Subtle restrained dimensionality and fine edge highlights, strong silhouette, broad shapes that remain recognizable at 16x16 and 32x32. Square front-facing centered composition. The rounded-square tile fills roughly 86 percent of the canvas with a consistent transparent margin around it, no perspective. Shield occupies most of tile with generous internal spacing. No letters, no text, no digits, no magnifying glass, no padlock, no tiny circuitry, no watermark, no mockup, no extra icons. Transparent pixels outside the rounded-square tile. Production-ready 1024x1024 or larger square application icon.
```
