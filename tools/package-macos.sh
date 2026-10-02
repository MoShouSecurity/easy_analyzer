#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"
if [[ "$(uname -s)" != Darwin ]]; then
  echo 'This script requires macOS and Xcode command line tools.' >&2
  exit 1
fi

VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)"
PACKAGE_DIR="$PROJECT_ROOT/dist"
BUILD_ROOT="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
if [[ "$BUILD_ROOT" != /* ]]; then BUILD_ROOT="$PROJECT_ROOT/$BUILD_ROOT"; fi

export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-11.0}"
cargo build --release --locked --target aarch64-apple-darwin

# Stage generated files separately, then copy them into the program directory.
mkdir -p "$PROJECT_ROOT/dist"
STAGING="$(mktemp -d "$PROJECT_ROOT/dist/.macos-package.XXXXXX")"
trap 'rm -rf "$STAGING"' EXIT
STAGED_PACKAGE="$STAGING/package"
mkdir -p "$STAGED_PACKAGE"
cp "$BUILD_ROOT/aarch64-apple-darwin/release/easy-analyzer" "$STAGED_PACKAGE/easy-analyzer"
chmod 755 "$STAGED_PACKAGE/easy-analyzer"
codesign --force --sign - "$STAGED_PACKAGE/easy-analyzer"
codesign --verify --strict "$STAGED_PACKAGE/easy-analyzer"
lipo "$STAGED_PACKAGE/easy-analyzer" -verify_arch arm64
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

mkdir -p "$PACKAGE_DIR"
cp -R "$STAGED_PACKAGE/." "$PACKAGE_DIR/"
echo "Created program directory: $PACKAGE_DIR"
