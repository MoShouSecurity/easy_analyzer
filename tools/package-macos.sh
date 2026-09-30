#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"
if [[ "$(uname -s)" != Darwin ]]; then
  echo 'This script requires macOS and Xcode command line tools.' >&2
  exit 1
fi

VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)"
PACKAGE_NAME="easy-analyzer-${VERSION}-macos-arm64"
BUILD_ROOT="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
if [[ "$BUILD_ROOT" != /* ]]; then BUILD_ROOT="$PROJECT_ROOT/$BUILD_ROOT"; fi

export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-11.0}"
cargo build --release --locked --target aarch64-apple-darwin

# Build in a fresh directory so old packaging files never enter a new archive.
mkdir -p "$PROJECT_ROOT/dist"
STAGING="$(mktemp -d "$PROJECT_ROOT/dist/.macos-package.XXXXXX")"
trap 'rm -rf "$STAGING"' EXIT
STAGED_PACKAGE="$STAGING/$PACKAGE_NAME"
mkdir -p "$STAGED_PACKAGE/docs"
cp "$BUILD_ROOT/aarch64-apple-darwin/release/easy-analyzer" "$STAGED_PACKAGE/easy-analyzer"
chmod 755 "$STAGED_PACKAGE/easy-analyzer"
codesign --force --sign - "$STAGED_PACKAGE/easy-analyzer"
codesign --verify --strict "$STAGED_PACKAGE/easy-analyzer"
lipo "$STAGED_PACKAGE/easy-analyzer" -verify_arch arm64
cp README.md LICENSE "$STAGED_PACKAGE/"
cp docs/MACOS.md docs/VALIDATION.md "$STAGED_PACKAGE/docs/"
cp docs/MACOS.md "$STAGED_PACKAGE/开始使用.md"
cp -R tests/fixtures "$STAGED_PACKAGE/samples"
cp tools/macos-demo.command "$STAGED_PACKAGE/演示.command"
chmod 755 "$STAGED_PACKAGE/演示.command"
{
  echo "version=$VERSION"
  echo "git_commit=$(git rev-parse HEAD)"
  echo "architectures=arm64"
  echo "deployment_target=$MACOSX_DEPLOYMENT_TARGET"
  echo "code_signing=ad-hoc (not notarized)"
  if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
    echo "source_worktree=modified"
  else
    echo "source_worktree=clean"
  fi
} > "$STAGED_PACKAGE/BUILD_INFO.txt"

# Python preserves executable permissions and creates a portable UTF-8 ZIP.
python3 - "$STAGED_PACKAGE" "$PROJECT_ROOT/dist/$PACKAGE_NAME.zip" <<'PY'
import pathlib
import sys
import zipfile

root, archive = map(pathlib.Path, sys.argv[1:])
with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as out:
    for path in sorted(root.rglob('*')):
        if path.is_file():
            out.write(path, pathlib.Path(root.name) / path.relative_to(root))
PY
tar -czf "$PROJECT_ROOT/dist/$PACKAGE_NAME.tar.gz" -C "$STAGING" "$PACKAGE_NAME"
(
  cd "$PROJECT_ROOT/dist"
  shasum -a 256 "$PACKAGE_NAME.zip" > "$PACKAGE_NAME.zip.sha256"
  shasum -a 256 "$PACKAGE_NAME.tar.gz" > "$PACKAGE_NAME.tar.gz.sha256"
)
echo "Created dist/$PACKAGE_NAME.zip and .tar.gz"
