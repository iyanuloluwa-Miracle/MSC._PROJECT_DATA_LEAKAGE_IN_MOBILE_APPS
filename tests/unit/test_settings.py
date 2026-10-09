"""Unit tests for configuration persistence, settings management, and defaults."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from data_leak_detector.core.config import AppConfig


class TestSettings(unittest.TestCase):
    """Test suite covering AppConfig persistence, validation, and defaults."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_dir = Path(self.temp_dir.name)
        self.config_file = self.config_dir / "config.json"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_default_config_initialization(self) -> None:
        """Verify initial default configuration values and limits."""
        config = AppConfig()
        self.assertEqual(config.max_apk_size_bytes, 209_715_200)  # 200MB
        self.assertEqual(config.max_extracted_file_count, 10_000)
        self.assertEqual(config.max_extracted_size_bytes, 524_288_000)  # 500MB
        self.assertEqual(config.max_scanned_file_size_bytes, 5_242_880)  # 5MB
        self.assertEqual(config.subprocess_timeout_seconds, 120)
        self.assertFalse(config.high_contrast_mode)
        self.assertEqual(config.theme, "dark")
        self.assertTrue(config.is_rule_enabled("NET-001"))

    def test_save_and_load_disk_persistence(self) -> None:
        """Verify saving and re-loading modified settings preserves values accurately."""
        config = AppConfig(
            jadx_path=Path("/opt/jadx/bin/jadx"),
            apktool_path=Path("/opt/apktool/apktool"),
            output_dir=self.config_dir / "custom_reports",
            high_contrast_mode=True,
            subprocess_timeout_seconds=45,
            max_apk_size_bytes=50_000_000,
            disabled_rules=["CRYPTO-001", "SECRET-002"],
        )

        saved_path = config.save_to_disk(self.config_file)
        self.assertTrue(saved_path.exists())

        loaded = AppConfig.load_from_disk(self.config_file)
        self.assertEqual(loaded.jadx_path, Path("/opt/jadx/bin/jadx"))
        self.assertEqual(loaded.apktool_path, Path("/opt/apktool/apktool"))
        self.assertEqual(loaded.output_dir, self.config_dir / "custom_reports")
        self.assertTrue(loaded.high_contrast_mode)
        self.assertEqual(loaded.subprocess_timeout_seconds, 45)
        self.assertEqual(loaded.max_apk_size_bytes, 50_000_000)
        self.assertFalse(loaded.is_rule_enabled("CRYPTO-001"))
        self.assertFalse(loaded.is_rule_enabled("SECRET-002"))
        self.assertTrue(loaded.is_rule_enabled("NET-001"))

    def test_load_from_missing_file_returns_defaults(self) -> None:
        """Loading from non-existent file returns default configuration safely."""
        missing_path = self.config_dir / "non_existent.json"
        config = AppConfig.load_from_disk(missing_path)
        self.assertIsInstance(config, AppConfig)
        self.assertEqual(config.subprocess_timeout_seconds, 120)

    def test_load_from_corrupted_json_returns_defaults(self) -> None:
        """Loading from invalid JSON file recovers gracefully with default settings."""
        corrupted_path = self.config_dir / "corrupted.json"
        corrupted_path.write_text("{invalid_json: true, unterminated", encoding="utf-8")

        config = AppConfig.load_from_disk(corrupted_path)
        self.assertIsInstance(config, AppConfig)
        self.assertEqual(config.subprocess_timeout_seconds, 120)

    def test_rule_toggle_enable_disable(self) -> None:
        """Verify rule enable, disable, and query helpers."""
        config = AppConfig()
        self.assertTrue(config.is_rule_enabled("SEC-001"))

        config.set_rule_enabled("SEC-001", False)
        self.assertFalse(config.is_rule_enabled("SEC-001"))
        self.assertIn("SEC-001", config.disabled_rules)

        config.set_rule_enabled("SEC-001", True)
        self.assertTrue(config.is_rule_enabled("SEC-001"))
        self.assertNotIn("SEC-001", config.disabled_rules)

    def test_reset_to_defaults(self) -> None:
        """Verify reset_to_defaults restores initial state."""
        config = AppConfig(
            high_contrast_mode=True,
            subprocess_timeout_seconds=300,
            disabled_rules=["RULE-1", "RULE-2"],
        )
        config.reset_to_defaults()
        self.assertFalse(config.high_contrast_mode)
        self.assertEqual(config.subprocess_timeout_seconds, 120)
        self.assertEqual(len(config.disabled_rules), 0)


if __name__ == "__main__":
    unittest.main()
