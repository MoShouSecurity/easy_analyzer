"""Build the Windows x64 GUI installer without publishing a release."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def run(command, directory, env):
    subprocess.run(command, cwd=directory, env=env, check=True)


def atomic_copy(source, target):
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise ValueError(f"Invalid installer destination: {target}")
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as temporary:
        name = Path(temporary.name)
        try:
            with source.open("rb") as incoming:
                shutil.copyfileobj(incoming, temporary)
            temporary.flush()
            os.fsync(temporary.fileno())
        except BaseException:
            name.unlink(missing_ok=True)
            raise
    try:
        name.replace(target)
    finally:
        name.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=["x86_64-pc-windows-msvc", "x86_64-pc-windows-gnu"],
                        default="x86_64-pc-windows-msvc")
    parser.add_argument("--bundle-only", action="store_true", help="Package an already built GUI")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    gui = root / "crates/analyzer-gui"
    frontend = gui / "frontend"
    env = os.environ.copy()
    node = shutil.which("node")
    npm = shutil.which("npm")
    if not node or not npm:
        raise SystemExit("Node.js and npm are required")
    if not args.bundle_only:
        npm_command = [npm, "ci", "--ignore-scripts"]
        if os.name == "nt" and Path(npm).suffix.lower() == ".cmd":
            npm_command = ["cmd.exe", "/d", "/c", *npm_command]
        run(npm_command, frontend, env)
    cli = frontend / "node_modules/@tauri-apps/cli/tauri.js"
    if not cli.is_file():
        raise SystemExit("Install frontend dependencies before packaging")
    if args.target.endswith("-gnu") and os.name != "nt":
        for name, value in {
            "CC_x86_64_pc_windows_gnu": "x86_64-w64-mingw32-gcc",
            "CXX_x86_64_pc_windows_gnu": "x86_64-w64-mingw32-g++",
            "AR_x86_64_pc_windows_gnu": "x86_64-w64-mingw32-ar",
            "CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER": "x86_64-w64-mingw32-gcc",
        }.items():
            env.setdefault(name, value)
    command = [node, str(cli), "bundle" if args.bundle_only else "build",
               "--target", args.target, "--ci"]
    if not args.bundle_only:
        command += ["--", "--locked"]
    run(command, gui, env)
    config = json.loads((gui / "tauri.conf.json").read_text(encoding="utf-8"))
    source = root / "target" / args.target / "release/bundle/nsis" / (
        f"{config['productName']}_{config['version']}_x64-setup.exe"
    )
    if not source.is_file() or source.stat().st_size == 0:
        raise SystemExit("Tauri did not generate the expected installer")
    dist = root / "dist"
    dist.mkdir(exist_ok=True)
    target = dist / "easy-analyzer-gui-windows-x64-setup.exe"
    atomic_copy(source, target)
    with target.open("rb") as installer:
        digest = hashlib.file_digest(installer, "sha256").hexdigest()
    # Keep this installer checksum separate from any existing release manifest.
    checksum = dist / "easy-analyzer-gui-windows-x64-setup.exe.sha256"
    with tempfile.TemporaryDirectory(dir=dist) as temporary:
        manifest = Path(temporary) / "checksum"
        manifest.write_text(f"{digest}  {target.name}\n", encoding="utf-8")
        atomic_copy(manifest, checksum)
    print(f"Windows installer: {target}")
    print(f"SHA-256: {digest}")


if __name__ == "__main__":
    main()
