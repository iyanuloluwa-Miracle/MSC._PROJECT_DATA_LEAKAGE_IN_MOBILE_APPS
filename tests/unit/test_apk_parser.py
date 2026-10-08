"""Unit tests for APKParser using mocks and synthetic zip archives."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from data_leak_detector.analysis.apk_parser import APKParser
from data_leak_detector.core.exceptions import APKParsingError, InvalidAPKError
from data_leak_detector.core.models import ParsedAPKData


class TestAPKParser(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _create_synthetic_zip(self, filenames: list[str], content: bytes = b"dummy") -> Path:
        zip_path = self.temp_path / "test_synthetic.apk"
        with zipfile.ZipFile(zip_path, "w") as zf:
            for fname in filenames:
                zf.writestr(fname, content)
        return zip_path

    def test_nonexistent_file_raises_invalid_apk_error(self) -> None:
        fake_path = self.temp_path / "nonexistent.apk"
        parser = APKParser(fake_path)
        with self.assertRaises(InvalidAPKError) as ctx:
            parser.validate_file()
        self.assertIn("does not exist", str(ctx.exception))

    def test_directory_path_raises_invalid_apk_error(self) -> None:
        parser = APKParser(self.temp_path)
        with self.assertRaises(InvalidAPKError) as ctx:
            parser.validate_file()
        self.assertIn("not a regular file", str(ctx.exception))

    def test_non_zip_file_raises_invalid_apk_error(self) -> None:
        text_file = self.temp_path / "not_an_apk.apk"
        text_file.write_text("Hello plain text")
        parser = APKParser(text_file)
        with self.assertRaises(InvalidAPKError) as ctx:
            parser.validate_file()
        self.assertIn("not a valid ZIP/APK archive", str(ctx.exception))

    def test_zip_without_android_indicators_raises_invalid_apk_error(self) -> None:
        # A valid zip, but missing AndroidManifest.xml and classes.dex
        zip_path = self._create_synthetic_zip(["notes.txt", "image.png"])
        parser = APKParser(zip_path)
        with self.assertRaises(InvalidAPKError) as ctx:
            parser.validate_file()
        self.assertIn("lacks Android package indicators", str(ctx.exception))

    def test_calculate_sha256(self) -> None:
        test_file = self.temp_path / "dummy_bytes.apk"
        payload = b"Android static leak detector test payload"
        test_file.write_bytes(payload)
        expected_sha = hashlib.sha256(payload).hexdigest()

        parser = APKParser(test_file)
        self.assertEqual(parser.calculate_sha256(), expected_sha)

    @patch("data_leak_detector.analysis.apk_parser.APKParser._load_androguard_apk")
    def test_parse_with_mocked_androguard(self, mock_load_apk: MagicMock) -> None:
        # Create a synthetic archive with AndroidManifest.xml
        zip_path = self._create_synthetic_zip(["AndroidManifest.xml", "classes.dex"])
        
        # Configure mock AndroGuard APK object
        mock_apk = MagicMock()
        mock_apk.get_package.return_value = "com.mock.app"
        mock_apk.get_app_name.return_value = "Mock App"
        mock_apk.get_androidversion_name.return_value = "2.4.0"
        mock_apk.get_androidversion_code.return_value = "240"
        mock_apk.get_min_sdk_version.return_value = "26"
        mock_apk.get_target_sdk_version.return_value = "34"
        mock_apk.get_permissions.return_value = [
            "android.permission.INTERNET",
            "android.permission.ACCESS_FINE_LOCATION",
        ]
        mock_apk.get_declared_permissions.return_value = ["com.mock.app.CUSTOM_PERM"]
        mock_apk.get_activities.return_value = ["com.mock.app.MainActivity"]
        mock_apk.get_services.return_value = ["com.mock.app.SyncService"]
        mock_apk.get_receivers.return_value = ["com.mock.app.BootReceiver"]
        mock_apk.get_providers.return_value = []
        mock_apk.get_features.return_value = ["android.hardware.camera"]
        mock_apk.get_libraries.return_value = ["androidx.core"]
        mock_apk.get_attribute_value.side_effect = lambda tag, attr: {
            ("application", "allowBackup"): "true",
            ("application", "debuggable"): "false",
            ("application", "usesCleartextTraffic"): "true",
        }.get((tag, attr))
        mock_apk.get_android_manifest_xml.return_value = None

        mock_load_apk.return_value = mock_apk

        parser = APKParser(zip_path)
        parsed = parser.parse()

        self.assertIsInstance(parsed, ParsedAPKData)
        self.assertEqual(parsed.metadata.package_name, "com.mock.app")
        self.assertEqual(parsed.metadata.app_name, "Mock App")
        self.assertEqual(parsed.metadata.version_name, "2.4.0")
        self.assertEqual(parsed.metadata.min_sdk, "26")
        self.assertEqual(parsed.metadata.target_sdk, "34")
        self.assertEqual(len(parsed.permissions), 2)
        self.assertIn("android.permission.INTERNET", parsed.permissions)
        self.assertEqual(parsed.activities, ["com.mock.app.MainActivity"])
        self.assertEqual(parsed.services, ["com.mock.app.SyncService"])
        self.assertEqual(parsed.receivers, ["com.mock.app.BootReceiver"])
        self.assertEqual(parsed.features, ["android.hardware.camera"])

        # Check manifest data
        self.assertIsNotNone(parsed.manifest_info)
        self.assertTrue(parsed.manifest_info.allow_backup)
        self.assertFalse(parsed.manifest_info.debuggable)
        self.assertTrue(parsed.manifest_info.uses_cleartext_traffic)

    @patch("data_leak_detector.analysis.apk_parser.APKParser._load_androguard_apk")
    def test_parse_handles_androguard_exception_gracefully(self, mock_load_apk: MagicMock) -> None:
        zip_path = self._create_synthetic_zip(["AndroidManifest.xml"])
        mock_load_apk.side_effect = APKParsingError("AndroGuard failed to unpack DEX")

        parser = APKParser(zip_path)
        with self.assertRaises(APKParsingError) as ctx:
            parser.parse()
        self.assertIn("AndroGuard failed to unpack DEX", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
