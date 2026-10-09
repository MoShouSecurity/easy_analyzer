#!/usr/bin/env bash
# Use a read-only, uncompressed disk image so the downloaded app keeps its bundle.
set -euo pipefail
if [[ $# != 2 || "$(uname -s)" != Darwin ]]; then
  echo "Usage (macOS): $0 <Easy Analyzer.app> <new .dmg path>" >&2; exit 2
fi
gui_bundle="$1"
gui_image="$2"
if [[ ! -d "$gui_bundle" || "$(basename "$gui_bundle")" != "Easy Analyzer.app" || -e "$gui_image" || -L "$gui_image" ]]; then
  echo "Expected an app bundle and a new disk image destination" >&2; exit 2
fi
gui_root="$(cd "$(dirname "$0")/.." && pwd)"
gui_source="$(mktemp -d "${TMPDIR:-/tmp/}easy-analyzer-dmg.XXXXXX")"
gui_mounted=false
gui_cleanup() {
  if [[ "$gui_mounted" == true ]]; then
    hdiutil detach "$gui_source/mount" || hdiutil detach -force "$gui_source/mount" || return
  fi
  rm -rf "$gui_source"
}
trap gui_cleanup EXIT
# Isolate build dependencies and lock every wheel. No Finder/AppleScript access is
# needed: the saved window layout is written directly, including in CI.
python3 -m venv "$gui_source/tools"
"$gui_source/tools/bin/python" -m pip install --disable-pip-version-check \
  --require-hashes --only-binary=:all: -r "$gui_root/scripts/dmg-requirements.txt"
xcrun swift -module-cache-path "$gui_source/swift-cache" \
  "$gui_root/scripts/render_dmg_background.swift" "$gui_source/artwork" \
  "$gui_bundle/Contents/Resources/icon.icns"
mkdir "$gui_source/contents" "$gui_source/mount"
ditto --norsrc --noextattr "$gui_bundle" "$gui_source/contents/Easy Analyzer.app"
ln -s /Applications "$gui_source/contents/Applications"
tiffutil -cathidpicheck "$gui_source/artwork/background.png" \
  "$gui_source/artwork/background@2x.png" -out "$gui_source/contents/.background.tiff"
hdiutil create -srcfolder "$gui_source/contents" -volname "Easy Analyzer" \
  -fs HFS+ -format UDRW -nospotlight "$gui_source/working.dmg"
hdiutil attach -nobrowse -noautoopen -owners on -mountpoint "$gui_source/mount" "$gui_source/working.dmg"
gui_mounted=true
"$gui_source/tools/bin/python" "$gui_root/scripts/write_dmg_layout.py" "$gui_source/mount"
# Flush the layout before detaching and converting to the delivery format.
sync
hdiutil detach "$gui_source/mount"
gui_mounted=false
hdiutil convert "$gui_source/working.dmg" -format UDRO -o "$gui_image"
echo "Uncompressed DMG: $gui_image"
