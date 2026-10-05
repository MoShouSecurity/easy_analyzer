"""Regression checks for release exclusions, completeness and version consistency."""

import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch

from release_assets import APP_FILES, APP_NAME, asset_names, checksum_manifest, macos_bundle_versions, source_info, validate_app_bundle, validate_image_contents, validate_installer_file, validate_source, verify_app_image


def synthetic_installer():
    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 64)
    data[64:68] = b"PE\0\0"
    struct.pack_into("<H", data, 68, 0x14c)
    data[256:272] = b"\xef\xbe\xad\xdeNullsoftInst"
    return data


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

    def test_preview_manifest_uses_installer_and_rejects_extra_portable_gui(self):
        portable = self.directory / "easy-analyzer-gui-windows-x64.exe"
        installer = self.directory / "easy-analyzer-gui-windows-x64-setup.exe"
        installer.write_bytes(synthetic_installer())
        with self.assertRaises(ValueError):
            checksum_manifest(self.directory, preview=True)
        portable.unlink()
        checksum_manifest(self.directory, preview=True)
        lines = (self.directory / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(lines), 6)
        self.assertEqual({line.split("  ")[1] for line in lines}, set(asset_names(preview=True)))
        self.assertTrue(any(installer.name in line for line in lines))
        with self.assertRaises(ValueError):
            checksum_manifest(self.directory)  # Stable assets remain portable programs.

    def test_installer_requires_pe_and_nsis_without_executing_it(self):
        installer = self.directory / "setup.exe"
        with patch("release_assets.subprocess.run") as run:
            installer.write_bytes(synthetic_installer())
            validate_installer_file(installer)
            for offset, replacement in [(0, b"XX"), (64, b"BAD!"), (68, b"\x64\xaa"), (256, b"not an installer")]:
                with self.subTest(offset=offset):
                    changed = synthetic_installer()
                    changed[offset:offset + len(replacement)] = replacement
                    installer.write_bytes(changed)
                    with self.assertRaises(ValueError):
                        validate_installer_file(installer)
            run.assert_not_called()


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

    def set_version(self, version):
        for path in self.root.rglob("*"):
            if path.is_file():
                path.write_text(path.read_text(encoding="utf-8").replace(self.version, version), encoding="utf-8")

    def test_preview_source_and_branch_never_publish_without_a_tag(self):
        self.set_version("1.4.0-preview.1")
        validate_source(self.root, "v1.4.0-preview.1")
        self.assertEqual(source_info(self.root, "refs/heads/codex/incident-projects-ioc"), {
            "version": "1.4.0-preview.1", "preview": "true", "publish": "false",
        })
        self.assertEqual(source_info(self.root, "refs/tags/v1.4.0-preview.1")["publish"], "true")
        for tag in ("v1.4.0", "v1.4.0-preview.2", "v1.4.0-preview.0", "v1.4.0-preview.01", "v1.4.0-preview.256", "v1.4.0-rc.1"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                source_info(self.root, f"refs/tags/{tag}")

    def test_stable_source_keeps_the_stable_channel(self):
        self.set_version("1.4.0")
        self.assertEqual(source_info(self.root, "refs/tags/v1.4.0"), {
            "version": "1.4.0", "preview": "false", "publish": "true",
        })
        self.assertEqual(source_info(self.root, "refs/heads/codex/incident-projects-ioc")["publish"], "false")

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

    def test_preview_bundle_uses_apple_version_fields(self):
        short, build = macos_bundle_versions("1.4.0-preview.1")
        self.assertEqual((short, build), ("1.4.0", "1.4.0d1"))
        self.info.update(CFBundleShortVersionString=short, CFBundleVersion=build)
        self.info_path.write_bytes(plistlib.dumps(self.info))
        validate_app_bundle(self.bundle, "1.4.0-preview.1")
        with self.assertRaises(ValueError):
            macos_bundle_versions("1.4.0-preview.256")

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


class InstallerContentsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.mount = Path(self.temp.name)
        (self.mount / APP_NAME).mkdir()
        try:
            (self.mount / "Applications").symlink_to("/Applications")
        except OSError:
            self.skipTest("This runner cannot create symlinks")
        (self.mount / ".DS_Store").write_bytes(b"\x00\x00\x00\x01Bud1")
        (self.mount / ".background.tiff").write_bytes(b"II*\x00" + bytes(8))

    def test_installer_layout_is_allowed_but_hidden_customer_data_is_rejected(self):
        validate_image_contents(self.mount)
        (self.mount / ".customer.eair").write_bytes(b"private project")
        with self.assertRaisesRegex(ValueError, "Unexpected"):
            validate_image_contents(self.mount)

    def test_layout_resources_cannot_be_missing_links_directories_or_unrelated_data(self):
        background = self.mount / ".background.tiff"
        background.unlink()
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            validate_image_contents(self.mount)
        background.mkdir()
        with self.assertRaisesRegex(ValueError, "resource"):
            validate_image_contents(self.mount)
        background.rmdir()
        background.symlink_to(self.mount / ".DS_Store")
        with self.assertRaisesRegex(ValueError, "resource"):
            validate_image_contents(self.mount)
        background.unlink()
        background.write_bytes(b"unrelated private data")
        with self.assertRaisesRegex(ValueError, "background"):
            validate_image_contents(self.mount)


if __name__ == "__main__":
    unittest.main()
