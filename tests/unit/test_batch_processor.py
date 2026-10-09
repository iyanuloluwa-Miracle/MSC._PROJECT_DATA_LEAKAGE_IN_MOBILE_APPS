"""Unit tests for BatchProcessor and queue logic decoupled from Tkinter."""

from __future__ import annotations

import csv
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

from data_leak_detector.analysis.batch_processor import (
    BatchItem,
    BatchItemStatus,
    BatchProcessor,
    export_batch_summary_csv,
)
from data_leak_detector.analysis.engine import AnalysisEngine
from data_leak_detector.core.exceptions import AnalysisCancelledError
from data_leak_detector.core.models import (
    AnalysisMetrics,
    AnalysisResult,
    ApplicationMetadata,
    Confidence,
    FindingCategory,
    RiskRating,
    SecurityFinding,
    Severity,
)


def _make_dummy_result(pkg: str = "com.test.app", score: float = 45.0, rating: RiskRating = RiskRating.MEDIUM) -> AnalysisResult:
    """Helper creating minimal dummy AnalysisResult for batch testing."""
    now = datetime.now(timezone.utc)
    app = ApplicationMetadata(
        filename=f"{pkg}.apk",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_size=10240,
        package_name=pkg,
    )
    findings = [
        SecurityFinding(
            rule_id="CRIT-001",
            title="Critical Hardcoded Secret",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=FindingCategory.HARDCODED_SECRET,
            description="Fake secret description",
            evidence="TOP_SECRET_API_KEY_DO_NOT_LEAK",
        ),
        SecurityFinding(
            rule_id="HI-001",
            title="High Cleartext Network",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=FindingCategory.NETWORK_INDICATOR,
            description="Cleartext HTTP",
            evidence="http://insecure.example.com",
        ),
    ]
    metrics = AnalysisMetrics(
        started_at=now,
        completed_at=now,
        duration_seconds=3.5,
        files_examined=5,
        rules_executed=10,
    )
    return AnalysisResult(
        analysis_id="SCAN-TEST-001",
        application=app,
        overall_risk_score=score,
        risk_rating=rating,
        metrics=metrics,
        findings=findings,
    )


class TestBatchProcessor(unittest.TestCase):
    """Test suite for BatchProcessor queue management, execution, and CSV export."""

    def setUp(self) -> None:
        self.mock_engine = MagicMock(spec=AnalysisEngine)
        self.processor = BatchProcessor(engine=self.mock_engine, max_concurrent=1)

    def test_queue_lifecycle_and_sequential_execution(self) -> None:
        """Verify queueing multiple items, sequential processing, and status transitions."""
        res1 = _make_dummy_result(pkg="com.app.one", score=75.0, rating=RiskRating.HIGH)
        res2 = _make_dummy_result(pkg="com.app.two", score=20.0, rating=RiskRating.LOW)
        self.mock_engine.analyze_apk.side_effect = [res1, res2]

        item1 = self.processor.add_apk("test_app1.apk")
        item2 = self.processor.add_apk("test_app2.apk")

        self.assertEqual(len(self.processor.items), 2)
        self.assertEqual(item1.status, BatchItemStatus.WAITING)
        self.assertEqual(item2.status, BatchItemStatus.WAITING)
        self.assertIsNone(item1.risk_score)

        observed_statuses: list[tuple[str, BatchItemStatus]] = []

        def _callback(item: BatchItem) -> None:
            observed_statuses.append((item.filename, item.status))

        # Process all queued items
        completed_items = self.processor.process_all(item_callback=_callback)

        self.assertEqual(len(completed_items), 2)
        self.assertEqual(item1.status, BatchItemStatus.COMPLETE)
        self.assertEqual(item2.status, BatchItemStatus.COMPLETE)
        self.assertEqual(item1.risk_score, 75.0)
        self.assertEqual(item1.risk_rating, "HIGH")
        self.assertEqual(item2.risk_score, 20.0)
        self.assertEqual(item2.risk_rating, "LOW")
        self.assertEqual(item1.package_name, "com.app.one")
        self.assertEqual(item2.package_name, "com.app.two")

        # Verify engine was called in sequential FIFO order
        self.assertEqual(self.mock_engine.analyze_apk.call_count, 2)
        calls = self.mock_engine.analyze_apk.call_args_list
        self.assertEqual(calls[0].kwargs["apk_path"], Path("test_app1.apk"))
        self.assertEqual(calls[1].kwargs["apk_path"], Path("test_app2.apk"))

    def test_fault_containment_on_failed_apk(self) -> None:
        """Verify when an APK analysis fails, it is marked Failed, and subsequent APKs continue."""
        res2 = _make_dummy_result(pkg="com.app.two", score=15.0, rating=RiskRating.MINIMAL)
        self.mock_engine.analyze_apk.side_effect = [
            RuntimeError("Corrupt dex file structure"),
            res2,
        ]

        self.processor.add_apk("broken.apk")
        self.processor.add_apk("valid.apk")

        completed_items = self.processor.process_all()

        self.assertEqual(completed_items[0].status, BatchItemStatus.FAILED)
        self.assertIn("Corrupt dex", completed_items[0].error_message or "")
        self.assertIsNone(completed_items[0].risk_score)

        # Second item must still complete successfully
        self.assertEqual(completed_items[1].status, BatchItemStatus.COMPLETE)
        self.assertEqual(completed_items[1].package_name, "com.app.two")
        self.assertEqual(completed_items[1].risk_score, 15.0)

    def test_cancellation_of_item_and_all(self) -> None:
        """Verify cancellation of individual items and cancel_all."""
        item1 = self.processor.add_apk("app1.apk")
        item2 = self.processor.add_apk("app2.apk")
        item3 = self.processor.add_apk("app3.apk")

        # Cancel item 1 before running
        self.processor.cancel_item(item1.id)
        self.assertEqual(item1.status, BatchItemStatus.CANCELLED)

        # Cancel all
        self.processor.cancel_all()
        self.assertEqual(item2.status, BatchItemStatus.CANCELLED)
        self.assertEqual(item3.status, BatchItemStatus.CANCELLED)

        # Running process_all on cancelled items should not invoke engine
        self.processor.process_all()
        self.mock_engine.analyze_apk.assert_not_called()

    def test_cancellation_during_analysis(self) -> None:
        """Verify cooperative cancellation raised during analysis transitions item to Cancelled."""
        self.mock_engine.analyze_apk.side_effect = AnalysisCancelledError("User stopped scan")
        self.processor.add_apk("running_app.apk")

        items = self.processor.process_all()
        self.assertEqual(items[0].status, BatchItemStatus.CANCELLED)

    def test_export_batch_summary_csv_contents_and_redaction(self) -> None:
        """Verify CSV export contains all required fields and ZERO sensitive evidence."""
        res = _make_dummy_result(pkg="com.secure.test", score=88.0, rating=RiskRating.CRITICAL)
        item1 = BatchItem(
            apk_path=Path("secure_app.apk"),
            status=BatchItemStatus.COMPLETE,
            result=res,
        )
        item2 = BatchItem(
            apk_path=Path("failed_app.apk"),
            status=BatchItemStatus.FAILED,
            error_message="Invalid zip",
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            csv_path = Path(tmp_dir) / "batch_report.csv"
            export_batch_summary_csv([item1, item2], csv_path)

            self.assertTrue(csv_path.exists())

            with open(csv_path, mode="r", encoding="utf-8") as f:
                reader = csv.reader(f)
                rows = list(reader)

            # Check Headers
            headers = rows[0]
            expected_headers = [
                "filename",
                "package",
                "SHA-256",
                "analysis timestamp",
                "risk score",
                "risk rating",
                "critical count",
                "high count",
                "medium count",
                "low count",
                "analysis duration",
            ]
            self.assertEqual(headers, expected_headers)

            # Check Row 1 (Complete)
            row1 = rows[1]
            self.assertEqual(row1[0], "secure_app.apk")
            self.assertEqual(row1[1], "com.secure.test")
            self.assertTrue(len(row1[2]) > 10)  # SHA-256
            self.assertTrue(len(row1[3]) > 0)   # timestamp
            self.assertEqual(row1[4], "88.0")   # risk score
            self.assertEqual(row1[5], "CRITICAL")  # risk rating
            self.assertEqual(row1[6], "1")      # critical count
            self.assertEqual(row1[7], "1")      # high count
            self.assertEqual(row1[8], "0")      # medium count
            self.assertEqual(row1[9], "0")      # low count
            self.assertEqual(row1[10], "3.50s") # duration

            # Check Row 2 (Failed)
            row2 = rows[2]
            self.assertEqual(row2[0], "failed_app.apk")
            self.assertEqual(row2[1], "")       # package
            self.assertEqual(row2[4], "")       # risk score

            # CRITICAL REQUIREMENT: Verify sensitive evidence was NOT written to CSV
            file_text = csv_path.read_text(encoding="utf-8")
            self.assertNotIn("TOP_SECRET_API_KEY_DO_NOT_LEAK", file_text)
            self.assertNotIn("Fake secret description", file_text)

    def test_queue_manipulation_methods(self) -> None:
        """Verify adding lists of APKs, removing by ID, and clearing queue."""
        added = self.processor.add_apks(["a.apk", "b.apk", "c.apk"])
        self.assertEqual(len(added), 3)
        self.assertEqual(len(self.processor.items), 3)

        removed = self.processor.remove_item(added[1].id)
        self.assertTrue(removed)
        self.assertEqual(len(self.processor.items), 2)
        self.assertEqual([i.filename for i in self.processor.items], ["a.apk", "c.apk"])

        self.processor.clear()
        self.assertEqual(len(self.processor.items), 0)


if __name__ == "__main__":
    unittest.main()
