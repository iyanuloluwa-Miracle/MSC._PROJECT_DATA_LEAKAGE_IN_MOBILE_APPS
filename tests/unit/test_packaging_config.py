"""Tests for standalone distribution configuration, resource resolution, and packaging spec."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from data_leak_detector.core.config import AppConfig
from data_leak_detector.core.logging_config import setup_logging


import unittest


class PackagingConfigTests(unittest.TestCase):
    """Test suite for standalone packaging and resource resolution."""

    def test_bundled_resources_exist_and_are_valid_json(self) -> None:
        """Verify that all three mandated distribution resources exist and parse as valid JSON."""
        root_dir = Path(__file__).resolve().parent.parent.parent
        resources_dir = root_dir / "resources"

        required_files = [
            "permission_metadata.json",
            "sdk_patterns.json",
            "tracking_patterns.json",
        ]

        for filename in required_files:
            filepath = resources_dir / filename
            self.assertTrue(filepath.exists(), f"Mandatory resource file '{filename}' missing")
            self.assertTrue(filepath.is_file())

            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.assertIsNotNone(data)
                self.assertGreater(len(data), 0)

    def test_frozen_resource_resolution_with_meipass(self) -> None:
        """Verify AppConfig resolves resources_dir correctly when sys.frozen and _MEIPASS are set."""
        with tempfile.TemporaryDirectory() as tmp_bundle:
            bundle_path = Path(tmp_bundle)
            bundle_res = bundle_path / "resources"
            bundle_res.mkdir()

            with patch.object(sys, "frozen", True, create=True), \
                 patch.object(sys, "_MEIPASS", str(bundle_path), create=True):
                config = AppConfig()
                self.assertEqual(config.resources_dir, bundle_res)
                self.assertTrue(config.temp_dir.exists())
                self.assertIn("MobileDataLeakDetector_temp", str(config.temp_dir))

    def test_frozen_resource_resolution_fallback_to_executable_dir(self) -> None:
        """Verify AppConfig falls back to executable parent folder if _MEIPASS is missing."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            fake_bin_dir = Path(tmp_dir) / "bin"
            fake_bin_dir.mkdir()
            fake_exe = fake_bin_dir / "data_leak_detector.exe"
            fake_exe.touch()

            fake_res = fake_bin_dir / "resources"
            fake_res.mkdir()

            with patch.object(sys, "frozen", True, create=True), \
                 patch.object(sys, "executable", str(fake_exe)), \
                 patch.object(sys, "_MEIPASS", "", create=True):
                config = AppConfig()
                self.assertEqual(config.resources_dir, fake_res)

    def test_logging_setup_with_none_stderr(self) -> None:
        """Verify logging setup handles windowed GUI mode without throwing AttributeError."""
        with patch.object(sys, "stderr", None), \
             patch.object(sys, "stdout", None):
            setup_logging()

    def test_spec_file_contains_required_packaging_rules(self) -> None:
        """Verify data_leak_detector.spec contains mandated bundle definitions and console=False."""
        root_dir = Path(__file__).resolve().parent.parent.parent
        spec_path = root_dir / "data_leak_detector.spec"
        self.assertTrue(spec_path.exists(), "data_leak_detector.spec not found in project root")

        spec_content = spec_path.read_text(encoding="utf-8")
        self.assertIn("permission_metadata.json", spec_content)
        self.assertIn("sdk_patterns.json", spec_content)
        self.assertIn("tracking_patterns.json", spec_content)
        self.assertIn("console=False", spec_content)
        self.assertIn("COLLECT", spec_content)
