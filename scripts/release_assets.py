"""Validate release versions and the exact CLI/GUI asset set (Python 3.11+)."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib


PLATFORMS = {"linux-x64": "", "windows-x64": ".exe", "macos-arm64": ""}


def asset_names(platform=None):
    platforms = [platform] if platform else PLATFORMS
    return [
        f"easy-analyzer-{kind}-{name}{PLATFORMS[name]}"
        for name in platforms
        for kind in ("cli", "gui")
    ]


def validate_source(root, tag):
    if not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        raise ValueError(f"Invalid release tag: {tag}")
    version = tag[1:]
    workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]
    if workspace["package"]["version"] != version:
        raise ValueError("Release tag differs from workspace version")
    lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
    packages = {p["name"]: p["version"] for p in lock["package"] if "source" not in p}
    for member in workspace["members"]:
        package = tomllib.loads((root / member / "Cargo.toml").read_text(encoding="utf-8"))["package"]
        declared = package["version"]
        if declared != {"workspace": True} and declared != version:
            raise ValueError(f"Version mismatch in {member}")
        if packages.get(package["name"]) != version:
            raise ValueError(f"Version mismatch in Cargo.lock: {package['name']}")
    gui = root / "crates/analyzer-gui"
    for path in ("tauri.conf.json", "frontend/package.json", "frontend/package-lock.json"):
        data = json.loads((gui / path).read_text(encoding="utf-8"))
        if data["version"] != version:
            raise ValueError(f"GUI version mismatch: {path}")
        if path.endswith("package-lock.json") and data["packages"][""]["version"] != version:
            raise ValueError("GUI npm root package version mismatch")


def verify_programs(directory, platform, version):
    # Capture explicit pipes, including Windows GUI-subsystem programs without a console.
    for name, kind in zip(asset_names(platform), ("cli", "gui")):
        result = subprocess.run(
            [str((directory / name).resolve()), "--version"],
            capture_output=True, text=True, check=True, timeout=30,
        )
        expected = f"easy-analyzer {version}" if kind == "cli" else f"easy-analyzer-gui {version} (Tauri)"
        if result.stdout.strip() != expected:
            raise ValueError(f"Unexpected {kind} program version: {result.stdout!r}")


def checksum_manifest(directory):
    names = asset_names()
    entries = {p.name for p in directory.iterdir()}
    # Re-running locally may replace a manifest, but no other file or folder is allowed.
    if entries - {"SHA256SUMS"} != set(names):
        raise ValueError(f"Expected exactly six CLI/GUI programs, found: {sorted(entries)}")
    manifest = directory / "SHA256SUMS"
    if manifest.is_symlink() or (manifest.exists() and not manifest.is_file()):
        raise ValueError("Invalid checksum manifest")
    lines = []
    for name in names:
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"Invalid release program: {name}")
        with path.open("rb") as program:
            digest = hashlib.file_digest(program, "sha256").hexdigest()
        lines.append(f"{digest}  {name}\n")
    manifest.write_text("".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    source = commands.add_parser("validate-source")
    source.add_argument("tag")
    source.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    programs = commands.add_parser("verify-programs")
    programs.add_argument("directory", type=Path)
    programs.add_argument("platform", choices=PLATFORMS)
    programs.add_argument("version")
    checksums = commands.add_parser("checksums")
    checksums.add_argument("directory", type=Path)
    commands.add_parser("names")
    args = parser.parse_args()
    if args.command == "validate-source":
        validate_source(args.root, args.tag)
    elif args.command == "verify-programs":
        verify_programs(args.directory, args.platform, args.version)
    elif args.command == "checksums":
        checksum_manifest(args.directory)
    else:
        print("\n".join(asset_names() + ["SHA256SUMS"]))


if __name__ == "__main__":
    main()
