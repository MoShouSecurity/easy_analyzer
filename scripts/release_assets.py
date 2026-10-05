"""Validate release versions and the exact CLI/GUI asset set (Python 3.11+)."""

import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import sys
import tempfile
import tomllib


PLATFORMS = {"linux-x64": "", "windows-x64": ".exe", "macos-arm64": ""}
APP_NAME = "Easy Analyzer.app"
APP_FILES = {
    "Contents/Info.plist", "Contents/MacOS/easy-analyzer-gui",
    "Contents/Resources/icon.icns", "Contents/Resources/LICENSE",
    "Contents/Resources/OFL.txt", "Contents/_CodeSignature/CodeResources",
}


def asset_names(platform=None):
    platforms = [platform] if platform else PLATFORMS
    return [
        f"easy-analyzer-{kind}-{name}{'.dmg' if name == 'macos-arm64' and kind == 'gui' else PLATFORMS[name]}"
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


def validate_app_bundle(bundle, version):
    """Reject missing resources, extra data, links and mismatched bundle metadata."""
    if bundle.name != APP_NAME or bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("Invalid macOS app bundle")
    expected = {bundle / name for name in APP_FILES}
    directories = {parent for path in expected for parent in path.parents if parent != bundle and bundle in parent.parents}
    entries = list(bundle.rglob("*"))
    if any(path.is_symlink() for path in entries):
        raise ValueError("App bundle contains a symlink")
    if set(entries) != expected | directories:
        raise ValueError("App bundle must contain exactly the executable, app metadata, icon, licenses and signature")
    if any(not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size == 0 for path in expected):
        raise ValueError("Invalid app bundle file")
    program = bundle / "Contents/MacOS/easy-analyzer-gui"
    # Windows test hosts do not preserve Unix execution modes; macOS verification does.
    if sys.platform != "win32" and not program.stat().st_mode & 0o111:
        raise ValueError("App executable has no execute permission")
    with program.open("rb") as executable:
        if executable.read(8) != b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01":
            raise ValueError("App executable must be macOS ARM64")
    try:
        with (bundle / "Contents/Info.plist").open("rb") as source:
            info = plistlib.load(source)
        required = {
            "CFBundleName": "Easy Analyzer", "CFBundleIdentifier": "com.easyanalyzer.gui",
            "CFBundleExecutable": "easy-analyzer-gui", "CFBundleIconFile": "icon.icns",
            "CFBundlePackageType": "APPL", "LSMinimumSystemVersion": "13.0",
            "CFBundleShortVersionString": version, "CFBundleVersion": version,
        }
        if any(info.get(key) != value for key, value in required.items()):
            raise ValueError("App metadata differs from release version or identity")
    except (plistlib.InvalidFileException, TypeError, AttributeError) as error:
        raise ValueError("Invalid app metadata") from error


def validate_image_file(path):
    # UDIF images end with a 512-byte 'koly' trailer; reject a renamed raw executable.
    if path.is_symlink() or not path.is_file() or path.stat().st_size < 512:
        raise ValueError("Invalid macOS disk image")
    with path.open("rb") as image:
        image.seek(-512, 2)
        if image.read(4) != b"koly":
            raise ValueError("Expected a macOS UDIF disk image")


def validate_image_contents(mount):
    # Permit only the installer artwork/layout in addition to the deliverable.
    # Do not broaden this to arbitrary hidden files or directories.
    layout = {".DS_Store", ".background.tiff"}
    bookkeeping = {".Trashes", ".fseventsd", ".Spotlight-V100", ".HFS+ Private Directory Data\r", "HFS+ Private Data"}
    names = {entry.name for entry in mount.iterdir()}
    if names - {APP_NAME, "Applications"} - layout - bookkeeping:
        raise ValueError("Unexpected files in macOS disk image")
    if names & layout:
        if not layout <= names:
            raise ValueError("Incomplete macOS installer layout")
        for name in layout:
            path = mount / name
            if path.is_symlink() or not path.is_file() or not 8 <= path.stat().st_size <= 8 * 1024 * 1024:
                raise ValueError("Invalid macOS installer resource")
            with path.open("rb") as source:
                header = source.read(8)
            if name == ".DS_Store" and header != b"\x00\x00\x00\x01Bud1":
                raise ValueError("Invalid Finder layout")
            if name == ".background.tiff" and header[:4] not in (b"II*\x00", b"MM\x00*"):
                raise ValueError("Invalid Finder background")
    applications = mount / "Applications"
    if not applications.is_symlink() or str(applications.readlink()) != "/Applications":
        raise ValueError("Disk image must include the Applications installation link")


def verify_app_image(path, version):
    validate_image_file(path)
    result = subprocess.run(["hdiutil", "imageinfo", "-plist", str(path.resolve())], capture_output=True, check=True, timeout=60)
    if plistlib.loads(result.stdout).get("Format") != "UDRO":
        raise ValueError("macOS GUI must be an uncompressed read-only disk image (UDRO)")
    with tempfile.TemporaryDirectory(prefix="easy-analyzer-image-check-") as temporary:
        mount = Path(temporary) / "mount"
        mount.mkdir()
        subprocess.run(["hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", str(mount), str(path.resolve())], check=True, capture_output=True, timeout=60)
        try:
            validate_image_contents(mount)
            bundle = mount / APP_NAME
            validate_app_bundle(bundle, version)
            subprocess.run(["codesign", "--verify", "--strict", str(bundle)], check=True, timeout=30)
            verify_program_version(bundle / "Contents/MacOS/easy-analyzer-gui", "gui", version)
        finally:
            subprocess.run(["hdiutil", "detach", str(mount)], check=True, capture_output=True, timeout=60)


def verify_program_version(path, kind, version):
    result = subprocess.run(
        [str(path.resolve()), "--version"],
        capture_output=True, text=True, check=True, timeout=30,
    )
    expected = f"easy-analyzer {version}" if kind == "cli" else f"easy-analyzer-gui {version} (Tauri)"
    if result.stdout.strip() != expected:
        raise ValueError(f"Unexpected {kind} program version: {result.stdout!r}")


def verify_programs(directory, platform, version):
    # Capture explicit pipes, including Windows GUI-subsystem programs without a console.
    for name, kind in zip(asset_names(platform), ("cli", "gui")):
        path = directory / name
        if platform != "macos-arm64" or kind != "gui":
            verify_program_version(path, kind, version)
            continue
        verify_app_image(path, version)


def checksum_manifest(directory):
    names = asset_names()
    entries = {p.name for p in directory.iterdir()}
    # Re-running locally may replace a manifest, but no other file or folder is allowed.
    if entries - {"SHA256SUMS"} != set(names):
        raise ValueError(f"Expected exactly six CLI/GUI assets, found: {sorted(entries)}")
    manifest = directory / "SHA256SUMS"
    if manifest.is_symlink() or (manifest.exists() and not manifest.is_file()):
        raise ValueError("Invalid checksum manifest")
    lines = []
    for name in names:
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"Invalid release program: {name}")
        if name.endswith(".dmg"):
            validate_image_file(path)
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
    app = commands.add_parser("verify-app-image")
    app.add_argument("image", type=Path)
    app.add_argument("version")
    commands.add_parser("names")
    args = parser.parse_args()
    if args.command == "validate-source":
        validate_source(args.root, args.tag)
    elif args.command == "verify-programs":
        verify_programs(args.directory, args.platform, args.version)
    elif args.command == "checksums":
        checksum_manifest(args.directory)
    elif args.command == "verify-app-image":
        verify_app_image(args.image, args.version)
    else:
        print("\n".join(asset_names() + ["SHA256SUMS"]))


if __name__ == "__main__":
    main()
