"""Regression checks for release exclusions, completeness and version consistency."""

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from release_assets import asset_names, checksum_manifest, validate_source


class AssetsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        for name in asset_names():
            (self.directory / name).write_bytes(name.encode())

    def test_manifest_covers_both_interfaces_on_each_platform(self):
        checksum_manifest(self.directory)
        lines = (self.directory / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 6)
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(digest, hashlib.sha256(name.encode()).hexdigest())
        self.assertEqual(
            {line.split("  ")[1] for line in lines},
            {
                "easy-analyzer-cli-linux-x64", "easy-analyzer-gui-linux-x64",
                "easy-analyzer-cli-windows-x64.exe", "easy-analyzer-gui-windows-x64.exe",
                "easy-analyzer-cli-macos-arm64", "easy-analyzer-gui-macos-arm64",
            },
        )
        checksum_manifest(self.directory)  # Retry permits replacing the checksum file.

    def test_missing_gui_aborts_before_manifest(self):
        (self.directory / "easy-analyzer-gui-windows-x64.exe").unlink()
        with self.assertRaises(ValueError):
            checksum_manifest(self.directory)
        self.assertFalse((self.directory / "SHA256SUMS").exists())

    def test_excludes_configs_reports_samples_and_directories(self):
        for name in ("config.toml", "report.html", "case.evtx", "Easy Analyzer.app"):
            with self.subTest(name=name):
                extra = self.directory / name
                if name.endswith(".app"):
                    extra.mkdir()
                else:
                    extra.write_text("not a release program", encoding="utf-8")
                with self.assertRaises(ValueError):
                    checksum_manifest(self.directory)
                if extra.is_dir():
                    extra.rmdir()
                else:
                    extra.unlink()

    def test_rejects_empty_program(self):
        (self.directory / "easy-analyzer-gui-linux-x64").write_bytes(b"")
        with self.assertRaises(ValueError):
            checksum_manifest(self.directory)

    def test_rejects_symlink_manifest_without_overwriting_target(self):
        target = self.directory / "easy-analyzer-cli-linux-x64"
        original = target.read_bytes()
        try:
            (self.directory / "SHA256SUMS").symlink_to(target)
        except OSError:
            self.skipTest("This runner cannot create symlinks")
        with self.assertRaises(ValueError):
            checksum_manifest(self.directory)
        self.assertEqual(target.read_bytes(), original)


class VersionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        source = Path(__file__).resolve().parents[1]
        files = ["Cargo.toml", "Cargo.lock", "crates/analyzer-gui/tauri.conf.json"]
        files += [f"crates/{crate}/Cargo.toml" for crate in (
            "analyzer-app", "analyzer-core", "analyzer-cli", "analyzer-gui",
        )]
        files += [f"crates/analyzer-gui/frontend/{name}" for name in (
            "package.json", "package-lock.json",
        )]
        for name in files:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / name, target)
        self.version = json.loads((self.root / "crates/analyzer-gui/tauri.conf.json").read_text(encoding="utf-8"))["version"]

    def test_consistent_source(self):
        validate_source(self.root, f"v{self.version}")

    def test_invalid_or_mismatched_tag(self):
        for tag in ("main", f"v{self.version}-rc1", "v999.0.0"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                validate_source(self.root, tag)

    def test_rejects_gui_or_lock_version_drift(self):
        paths = [
            "Cargo.lock", "crates/analyzer-gui/tauri.conf.json",
            "crates/analyzer-gui/frontend/package.json", "crates/analyzer-gui/frontend/package-lock.json",
        ]
        for name in paths:
            with self.subTest(name=name):
                target = self.root / name
                original = target.read_text(encoding="utf-8")
                target.write_text(original.replace(self.version, "999.0.0", 1), encoding="utf-8")
                with self.assertRaises(ValueError):
                    validate_source(self.root, f"v{self.version}")
                target.write_text(original, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
