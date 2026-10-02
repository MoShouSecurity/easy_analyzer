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
# Assemble in a new directory so CI and local packaging seal the same resources.
gui_fresh="$(mktemp -d "${TMPDIR:-/tmp/}easy-analyzer-gui.XXXXXX")"
trap 'rm -rf "$gui_fresh"' EXIT
bash scripts/bundle_gui_macos.sh target/aarch64-apple-darwin/release/easy-analyzer-gui "$gui_fresh/Easy Analyzer.app"
mkdir -p "$gui_stage"
ditto "$gui_fresh/Easy Analyzer.app" "$gui_bundle"
gui_image="$gui_fresh/easy-analyzer-gui-macos-arm64.dmg"
bash scripts/create_gui_dmg.sh "$gui_fresh/Easy Analyzer.app" "$gui_image"
python3 scripts/release_assets.py verify-app-image "$gui_image" "$gui_version"
cp "$gui_image" "$gui_stage/easy-analyzer-gui-macos-arm64.dmg"
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
(cd "$gui_stage" && shasum -a 256 easy-analyzer-gui easy-analyzer-gui-macos-arm64.dmg > SHA256SUMS)
echo "GUI: $gui_bundle"
