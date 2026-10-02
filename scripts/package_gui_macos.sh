#!/usr/bin/env bash
set -euo pipefail
gui_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$gui_root"
gui_mode="${1:-install}"
if [[ "$gui_mode" != "--stage" && "$gui_mode" != "install" ]]; then
  echo "Usage: $0 [--stage]" >&2; exit 2
fi
npm --prefix crates/analyzer-gui/frontend ci --ignore-scripts
npm --prefix crates/analyzer-gui/frontend run build
MACOSX_DEPLOYMENT_TARGET=13.0 cargo build -p analyzer-gui --release --locked --target aarch64-apple-darwin
gui_version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)"
gui_stage="$gui_root/dist/tauri-build"
gui_bundle="$gui_stage/Easy Analyzer.app"
mkdir -p "$gui_bundle/Contents/MacOS" "$gui_bundle/Contents/Resources"
cp target/aarch64-apple-darwin/release/easy-analyzer-gui "$gui_bundle/Contents/MacOS/easy-analyzer-gui"
cp crates/analyzer-gui/assets/OFL.txt "$gui_bundle/Contents/Resources/OFL.txt"
cp crates/analyzer-gui/icons/easy-family/icon.icns "$gui_bundle/Contents/Resources/icon.icns"
cp LICENSE "$gui_bundle/Contents/Resources/LICENSE"
cat > "$gui_bundle/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>Easy Analyzer</string>
<key>CFBundleDisplayName</key><string>Easy Analyzer</string>
<key>CFBundleIdentifier</key><string>com.easyanalyzer.gui</string>
<key>CFBundleExecutable</key><string>easy-analyzer-gui</string>
<key>CFBundleIconFile</key><string>icon.icns</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$gui_version</string>
<key>CFBundleVersion</key><string>$gui_version</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
<key>NSRequiresAquaSystemAppearance</key><false/>
</dict></plist>
PLIST
codesign --force --sign - --timestamp=none "$gui_bundle"
codesign --verify --strict "$gui_bundle"
lipo "$gui_bundle/Contents/MacOS/easy-analyzer-gui" -verify_arch arm64
cp "$gui_bundle/Contents/MacOS/easy-analyzer-gui" "$gui_stage/easy-analyzer-gui"
# A standalone executable needs its own signature, without the bundle Info.plist slot.
codesign --force --sign - --timestamp=none "$gui_stage/easy-analyzer-gui"
codesign --verify --strict "$gui_stage/easy-analyzer-gui"
test "$("$gui_bundle/Contents/MacOS/easy-analyzer-gui" --version)" = "easy-analyzer-gui $gui_version (Tauri)"
if [[ "$gui_mode" != "--stage" ]]; then
  mkdir -p dist
  gui_backup_stamp="$(date +%Y%m%d-%H%M%S)"
  if [[ -f dist/easy-analyzer-gui ]]; then
    mkdir -p dist/backups
    cp dist/easy-analyzer-gui "dist/backups/easy-analyzer-gui-pre-install-$gui_backup_stamp"
  fi
  if [[ -d "dist/Easy Analyzer.app" ]]; then
    mkdir -p dist/backups
    ditto "$gui_root/dist/Easy Analyzer.app" "$gui_root/dist/backups/Easy Analyzer-pre-install-$gui_backup_stamp.app"
  fi
  # Only replace the GUI; user config, reports and case files are not touched.
  cp "$gui_stage/easy-analyzer-gui" dist/easy-analyzer-gui
  ditto "$gui_bundle" "$gui_root/dist/Easy Analyzer.app"
  codesign --verify --strict "$gui_root/dist/Easy Analyzer.app"
fi
(cd "$gui_stage" && shasum -a 256 easy-analyzer-gui > SHA256SUMS)
echo "GUI: $gui_bundle"
