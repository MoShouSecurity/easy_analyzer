#!/usr/bin/env bash
# Build an app bundle from the already-built GUI; shared by CI and local packaging.
set -euo pipefail
if [[ $# != 2 ]]; then
  echo "Usage: $0 <GUI executable> <new Easy Analyzer.app path>" >&2; exit 2
fi
gui_root="$(cd "$(dirname "$0")/.." && pwd)"
gui_program="$1"
gui_bundle="$2"
if [[ "$(uname -s)" != Darwin || "$(basename "$gui_bundle")" != "Easy Analyzer.app" ]]; then
  echo "Expected macOS and an Easy Analyzer.app destination" >&2; exit 2
fi
if [[ -e "$gui_bundle" || -L "$gui_bundle" ]]; then
  echo "App destination must be new; refusing to overwrite it" >&2; exit 2
fi
test "$(lipo -archs "$gui_program")" = arm64
gui_version="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$gui_root/crates/analyzer-gui/tauri.conf.json")"
test "$("$gui_program" --version)" = "easy-analyzer-gui $gui_version (Tauri)"
mkdir -p "$gui_bundle/Contents/MacOS" "$gui_bundle/Contents/Resources"
cp "$gui_program" "$gui_bundle/Contents/MacOS/easy-analyzer-gui"
chmod 755 "$gui_bundle/Contents/MacOS/easy-analyzer-gui"
cp "$gui_root/crates/analyzer-gui/assets/OFL.txt" "$gui_bundle/Contents/Resources/OFL.txt"
cp "$gui_root/crates/analyzer-gui/icons/easy-family/icon.icns" "$gui_bundle/Contents/Resources/icon.icns"
cp "$gui_root/LICENSE" "$gui_bundle/Contents/Resources/LICENSE"
python3 - "$gui_root/crates/analyzer-gui/tauri.conf.json" "$gui_bundle/Contents/Info.plist" <<'PY'
import json, plistlib, sys
with open(sys.argv[1], encoding="utf-8") as source:
    config = json.load(source)
info = {
    "CFBundleName": config["productName"], "CFBundleDisplayName": config["productName"],
    "CFBundleIdentifier": config["identifier"], "CFBundleExecutable": "easy-analyzer-gui",
    "CFBundleIconFile": "icon.icns", "CFBundlePackageType": "APPL",
    "CFBundleShortVersionString": config["version"], "CFBundleVersion": config["version"],
    "LSMinimumSystemVersion": config["bundle"]["macOS"]["minimumSystemVersion"],
    "NSHighResolutionCapable": True, "NSRequiresAquaSystemAppearance": False,
}
with open(sys.argv[2], "wb") as dest:
    plistlib.dump(info, dest)
PY
codesign --force --sign - --timestamp=none "$gui_bundle"
codesign --verify --strict "$gui_bundle"
test "$("$gui_bundle/Contents/MacOS/easy-analyzer-gui" --version)" = "easy-analyzer-gui $gui_version (Tauri)"
echo "Bundle: $gui_bundle"
