"""End-to-end integration tests that do not require external APK downloads.

Constructs synthetic APK packages and validates the complete pipeline:
Validation -> Static Parsing -> Rule Execution -> Risk Scoring -> Database Persistence -> Reporting.
"""

from __future__ import annotations

import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from data_leak_detector.analysis.engine import AnalysisEngine
from data_leak_detector.core.config import AppConfig
from data_leak_detector.core.models import (
    ApplicationMetadata,
    ComponentDetail,
    ManifestData,
    ParsedAPKData,
)
from data_leak_detector.reporting.report_generator import ReportGenerator
from data_leak_detector.storage.database import DatabaseManager


class TestEndToEndPipeline(unittest.TestCase):
    """Integration test suite executing the entire static scan lifecycle."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir.name)
        self.db_path = self.work_dir / "test_integration.sqlite3"
        self.reports_dir = self.work_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _create_synthetic_apk(self) -> Path:
        """Create a valid synthetic APK package with manifest, dex bytecode, and resources."""
        apk_path = self.work_dir / "synthetic_sample.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr(
                "AndroidManifest.xml",
                b'<manifest package="com.example.synthetic">\n'
                b'    <application android:debuggable="true">\n'
                b'        <activity android:name=".MainActivity" android:exported="true"/>\n'
                b'    </application>\n'
                b'</manifest>\n',
            )
            zf.writestr(
                "classes.dex",
                b"dex\n035\x00"
                b"Lcom/example/synthetic/Secret;\x00"
                b"AIzaSyD-FakeTestingKey-NotRealKey1234567\x00"
                b"http://insecure-api.synthetic-leak.com/data\x00",
            )
            zf.writestr(
                "res/raw/config.json",
                b'{"endpoint": "http://api.synthetic.org/v1", "backup_token": "AKIAIOSFODNN7EXAMPLE"}',
            )
        return apk_path

    def test_complete_static_analysis_pipeline_run(self) -> None:
        """Execute full pipeline: Engine -> Scorer -> DB -> Multi-format Reporting."""
        apk_path = self._create_synthetic_apk()
        config = AppConfig(output_dir=self.reports_dir)

        # Mock AndroGuard APK extraction to avoid binary AXML decoding issues in synthetic file
        mock_parsed = ParsedAPKData(
            metadata=ApplicationMetadata(
                filename=apk_path.name,
                sha256="c" * 64,
                file_size=apk_path.stat().st_size,
                package_name="com.example.synthetic",
                file_path=apk_path,
                app_name="SyntheticApp",
                version_name="1.0.0",
                version_code=1,
                min_sdk=21,
                target_sdk=33,
                analyzed_at=datetime.now(timezone.utc),
            ),
            permissions=[
                "android.permission.INTERNET",
                "android.permission.ACCESS_FINE_LOCATION",
            ],
            manifest_info=ManifestData(
                package_name="com.example.synthetic",
                app_name="SyntheticApp",
                debuggable=True,
                allow_backup=True,
                uses_cleartext_traffic=True,
                components=[
                    ComponentDetail(
                        component_type="activity",
                        name="com.example.synthetic.MainActivity",
                        exported=True,
                    )
                ],
            ),
            is_valid_apk=True,
        )

        engine = AnalysisEngine(config=config)
        with patch.object(engine, "_create_apk_parser") as mock_create:
            mock_parser_instance = MagicMock()
            mock_parser_instance.parse.return_value = mock_parsed
            mock_create.return_value = mock_parser_instance

            # 1. Run AnalysisEngine
            result = engine.analyze(apk_path)

            self.assertIsNotNone(result)
            self.assertEqual(result.application.package_name, "com.example.synthetic")
            self.assertGreater(result.overall_risk_score, 0)
            self.assertGreater(len(result.findings), 0)
            self.assertGreater(result.metrics.files_examined, 0)
            self.assertGreater(result.metrics.rules_executed, 0)

            # 2. Persist in local SQLite database
            db = DatabaseManager(self.db_path)
            db.initialize_schema()
            analysis_id = db.save_result(result)
            self.assertEqual(analysis_id, result.analysis_id)

            # Query database
            saved_record = db.get_result(analysis_id)
            self.assertIsNotNone(saved_record)
            self.assertEqual(saved_record.analysis_id, result.analysis_id)
            self.assertEqual(saved_record.application.package_name, "com.example.synthetic")

            by_hash = db.find_by_hash("c" * 64)
            self.assertEqual(len(by_hash), 1)
            self.assertEqual(by_hash[0]["id"], result.analysis_id)

            # 3. Generate Reports across all 3 formats (HTML, PDF, Text)
            report_gen = ReportGenerator(result)
            reports = report_gen.generate_all(
                output_dir=self.reports_dir,
                base_filename="integration_report",
            )

            self.assertTrue(reports["html"].exists())
            self.assertTrue(reports["pdf"].exists())
            self.assertTrue(reports["txt"].exists())

            # Verify contents of generated reports
            html_content = reports["html"].read_text(encoding="utf-8")
            self.assertIn("SyntheticApp", html_content)
            self.assertIn(result.analysis_id, html_content)
            # Secrets must be redacted
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", html_content)

            txt_content = reports["txt"].read_text(encoding="utf-8")
            self.assertIn("com.example.synthetic", txt_content)
            self.assertIn(result.analysis_id, txt_content)
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", txt_content)

            # Verify PDF exists and has size
            self.assertGreater(reports["pdf"].stat().st_size, 1024)

            db.close()


if __name__ == "__main__":
    unittest.main()
