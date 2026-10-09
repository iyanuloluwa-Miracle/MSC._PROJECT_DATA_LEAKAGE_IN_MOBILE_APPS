"""Integration tests for APKParser using real APK specified via TEST_APK_PATH."""

from __future__ import annotations

import os
import unittest
from pathlib import Path

from data_leak_detector.analysis.apk_parser import APKParser
from data_leak_detector.core.models import ParsedAPKData


class TestAPKIntegration(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("TEST_APK_PATH"),
        "Optional real-device integration test: requires TEST_APK_PATH environment variable.",
    )
    def test_real_apk_parsing(self) -> None:
        """Integration test against an actual APK supplied via TEST_APK_PATH."""
        apk_env = os.environ.get("TEST_APK_PATH")
        if not apk_env:
            return

        apk_path = Path(apk_env)
        if not apk_path.exists():
            self.fail(f"TEST_APK_PATH points to non-existent file: {apk_path}")

        parser = APKParser(apk_path)
        result = parser.parse()

        self.assertIsInstance(result, ParsedAPKData)
        self.assertTrue(result.is_valid_apk)
        self.assertTrue(result.metadata.package_name)
        self.assertGreater(result.metadata.file_size, 0)
        self.assertEqual(len(result.metadata.sha256), 64)


if __name__ == "__main__":
    unittest.main()
