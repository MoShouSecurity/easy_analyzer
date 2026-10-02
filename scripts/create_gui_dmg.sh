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
gui_source="$(mktemp -d "${TMPDIR:-/tmp/}easy-analyzer-dmg.XXXXXX")"
trap 'rm -rf "$gui_source"' EXIT
ditto --norsrc --noextattr "$gui_bundle" "$gui_source/Easy Analyzer.app"
ln -s /Applications "$gui_source/Applications"
hdiutil create -srcfolder "$gui_source" -volname "Easy Analyzer" -fs HFS+ -format UDRO -nospotlight "$gui_image"
echo "Uncompressed DMG: $gui_image"
