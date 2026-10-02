"""Regression checks for release exclusions, completeness and version consistency."""

import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import tempfile
import unittest
from unittest.mock import patch

from release_assets import APP_FILES, APP_NAME, asset_names, checksum_manifest, validate_app_bundle, validate_source, verify_app_image


class AssetsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        for name in asset_names():
            data = name.encode() if not name.endswith(".dmg") else b"image" + b"koly" + bytes(508)
            (self.directory / name).write_bytes(data)

    def test_manifest_covers_both_interfaces_on_each_platform(self):
        checksum_manifest(self.directory)
        lines = (self.directory / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 6)
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(digest, hashlib.sha256((self.directory / name).read_bytes()).hexdigest())
        self.assertEqual(
            {line.split("  ")[1] for line in lines},
            {
                "easy-analyzer-cli-linux-x64", "easy-analyzer-gui-linux-x64",
                "easy-analyzer-cli-windows-x64.exe", "easy-analyzer-gui-windows-x64.exe",
                "easy-analyzer-cli-macos-arm64", "easy-analyzer-gui-macos-arm64.dmg",
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

    def test_rejects_renamed_raw_gui_and_old_asset_before_manifest(self):
        image = self.directory / "easy-analyzer-gui-macos-arm64.dmg"
        image.write_bytes(b"raw program, not a disk image" * 50)
        with self.assertRaises(ValueError):
            checksum_manifest(self.directory)
        self.assertFalse((self.directory / "SHA256SUMS").exists())
        image.unlink()
        (self.directory / "easy-analyzer-gui-macos-arm64").write_bytes(b"old standalone GUI")
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


class AppBundleTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.bundle = self.directory / APP_NAME
        self.version = "1.3.1"
        for name in APP_FILES:
            path = self.bundle / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"declared resource")
        self.program = self.bundle / "Contents/MacOS/easy-analyzer-gui"
        self.program.write_bytes(b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01" + b"synthetic executable")
        self.program.chmod(0o755)
        self.info_path = self.bundle / "Contents/Info.plist"
        self.info = {
            "CFBundleName": "Easy Analyzer", "CFBundleIdentifier": "com.easyanalyzer.gui",
            "CFBundleExecutable": "easy-analyzer-gui", "CFBundleIconFile": "icon.icns",
            "CFBundlePackageType": "APPL", "LSMinimumSystemVersion": "13.0",
            "CFBundleShortVersionString": self.version, "CFBundleVersion": self.version,
        }
        self.info_path.write_bytes(plistlib.dumps(self.info))

    def test_complete_app_is_valid(self):
        validate_app_bundle(self.bundle, self.version)

    def test_missing_icon_and_extra_config_are_rejected(self):
        icon = self.bundle / "Contents/Resources/icon.icns"
        data = icon.read_bytes()
        icon.unlink()
        with self.assertRaises(ValueError):
            validate_app_bundle(self.bundle, self.version)
        icon.write_bytes(data)
        (self.bundle / "Contents/Resources/config.toml").write_text("private config", encoding="utf-8")
        with self.assertRaises(ValueError):
            validate_app_bundle(self.bundle, self.version)

    def test_wrong_version_identity_and_executable_are_rejected(self):
        for key, value in (("CFBundleVersion", "1.3.0"), ("CFBundleIdentifier", "other.app"), ("CFBundleIconFile", "missing.icns")):
            with self.subTest(key=key):
                changed = dict(self.info, **{key: value})
                self.info_path.write_bytes(plistlib.dumps(changed))
                with self.assertRaises(ValueError):
                    validate_app_bundle(self.bundle, self.version)
        self.info_path.write_bytes(plistlib.dumps(self.info))
        self.program.write_bytes(b"Intel or unrelated executable")
        with self.assertRaises(ValueError):
            validate_app_bundle(self.bundle, self.version)

    def test_image_rejects_compressed_format_before_mounting(self):
        image = self.directory / "app.dmg"
        image.write_bytes(b"image" + b"koly" + bytes(508))
        with patch("release_assets.subprocess.run") as run:
            run.return_value.stdout = plistlib.dumps({"Format": "UDZO"})
            with self.assertRaisesRegex(ValueError, "uncompressed"):
                verify_app_image(image, self.version)
            self.assertEqual(run.call_count, 1)

    def test_image_detaches_after_validation_failure(self):
        image = self.directory / "app.dmg"
        image.write_bytes(b"image" + b"koly" + bytes(508))
        with patch("release_assets.subprocess.run") as run:
            run.return_value.stdout = plistlib.dumps({"Format": "UDRO"})
            with self.assertRaises(ValueError):
                verify_app_image(image, self.version)
            self.assertEqual(run.call_args_list[-1].args[0][:2], ["hdiutil", "detach"])


if __name__ == "__main__":
    unittest.main()
