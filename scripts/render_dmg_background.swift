// Render both Finder background resolutions using macOS fonts and the app icon.
import AppKit

guard CommandLine.arguments.count == 3,
      let icon = NSImage(contentsOfFile: CommandLine.arguments[2]) else {
    fatalError("Usage: swift render_dmg_background.swift <output directory> <app icon>")
}
let output = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)

func color(_ hex: UInt32) -> NSColor {
    NSColor(srgbRed: CGFloat((hex >> 16) & 255) / 255,
            green: CGFloat((hex >> 8) & 255) / 255,
            blue: CGFloat(hex & 255) / 255, alpha: 1)
}

func rounded(_ rect: NSRect, radius: CGFloat, fill: NSColor, stroke: NSColor? = nil) {
    let path = NSBezierPath(roundedRect: rect, xRadius: radius, yRadius: radius)
    fill.setFill()
    path.fill()
    if let stroke {
        stroke.setStroke()
        path.lineWidth = 1
        path.stroke()
    }
}

func text(_ value: String, in rect: NSRect, size: CGFloat,
          weight: NSFont.Weight = .regular, tint: UInt32 = 0x172C43,
          centered: Bool = false) {
    let paragraph = NSMutableParagraphStyle()
    paragraph.alignment = centered ? .center : .left
    (value as NSString).draw(in: rect, withAttributes: [
        .font: NSFont.systemFont(ofSize: size, weight: weight),
        .foregroundColor: color(tint), .paragraphStyle: paragraph,
    ])
}

for scale in [1, 2] {
    // Explicit pixels keep output independent of the build host's display scale.
    guard let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil,
        pixelsWide: 760 * scale, pixelsHigh: 480 * scale, bitsPerSample: 8,
        samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
        colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
        let context = NSGraphicsContext(bitmapImageRep: bitmap) else {
        fatalError("Cannot allocate Finder background")
    }
    NSGraphicsContext.saveGraphicsState()
    context.cgContext.translateBy(x: 0, y: CGFloat(480 * scale))
    context.cgContext.scaleBy(x: CGFloat(scale), y: -CGFloat(scale))
    NSGraphicsContext.current = NSGraphicsContext(cgContext: context.cgContext, flipped: true)

    color(0xF5F8F7).setFill()
    NSRect(x: 0, y: 0, width: 760, height: 480).fill()
    // Quiet brand accent; keep the installation targets clear and readable.
    NSGradient(starting: color(0xEBF7F2), ending: color(0xF5F8F7))!
        .draw(in: NSRect(x: 0, y: 0, width: 760, height: 124), angle: 0)
    icon.draw(in: NSRect(x: 44, y: 38, width: 50, height: 50),
              from: .zero, operation: .sourceOver, fraction: 1,
              respectFlipped: true, hints: nil)
    text("Easy Analyzer", in: NSRect(x: 108, y: 38, width: 360, height: 36),
         size: 27, weight: .semibold)
    text("应急响应 · 证据分析 · IOC 匹配", in: NSRect(x: 109, y: 77, width: 380, height: 22),
         size: 13, tint: 0x64756F)
    rounded(NSRect(x: 548, y: 49, width: 164, height: 30), radius: 15,
            fill: color(0xE3F2EC))
    text("macOS · Apple Silicon", in: NSRect(x: 548, y: 56, width: 164, height: 18),
         size: 11, weight: .medium, tint: 0x277561, centered: true)

    text("将 Easy Analyzer 拖入「应用程序」", in: NSRect(x: 40, y: 145, width: 680, height: 32),
         size: 21, weight: .medium, centered: true)
    text("拖拽一次，完成安装", in: NSRect(x: 40, y: 183, width: 680, height: 24),
         size: 13, tint: 0x718179, centered: true)

    for x in [130, 490] {
        rounded(NSRect(x: x, y: 227, width: 140, height: 140), radius: 30,
                fill: .white, stroke: color(0xE1EAE5))
    }
    // Finder supplies the real, draggable icons above these two wells.
    let arrow = NSBezierPath()
    arrow.move(to: NSPoint(x: 339, y: 284))
    arrow.line(to: NSPoint(x: 416, y: 284))
    arrow.move(to: NSPoint(x: 404, y: 272))
    arrow.line(to: NSPoint(x: 416, y: 284))
    arrow.line(to: NSPoint(x: 404, y: 296))
    arrow.lineWidth = 3
    arrow.lineCapStyle = .round
    arrow.lineJoinStyle = .round
    color(0x00A88C).setStroke()
    arrow.stroke()

    text("01  拖动应用", in: NSRect(x: 100, y: 386, width: 200, height: 20),
         size: 12, weight: .medium, tint: 0x708178, centered: true)
    text("02  完成安装", in: NSRect(x: 460, y: 386, width: 200, height: 20),
         size: 12, weight: .medium, tint: 0x708178, centered: true)
    color(0xE0E8E3).setFill()
    NSRect(x: 44, y: 423, width: 672, height: 1).fill()
    text("安装后，从「应用程序」或启动台打开。  ·  macOS 13.0 及以上",
         in: NSRect(x: 40, y: 443, width: 680, height: 21),
         size: 12, tint: 0x7C8982, centered: true)

    NSGraphicsContext.restoreGraphicsState()
    guard let png = bitmap.representation(using: .png, properties: [:]) else {
        fatalError("Cannot render Finder background")
    }
    try png.write(to: output.appendingPathComponent(scale == 1 ? "background.png" : "background@2x.png"))
}
