"""Unit tests for the dissertation evaluation harness (scripts/evaluate.py)."""

from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts.evaluate import (
    calculate_confusion_metrics,
    calculate_timing_statistics,
    evaluate_directory,
    load_ground_truth,
    match_ground_truth_for_apk,
)
from data_leak_detector.core.models import (
    AnalysisMetrics,
    AnalysisResult,
    ApplicationMetadata,
    Confidence,
    FindingCategory,
    PermissionFinding,
    RiskRating,
    SecurityFinding,
    Severity,
)


class TestEvaluationHarness(unittest.TestCase):
    """Test suite verifying metric calculations, ground-truth matching, and serialization."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_timing_statistics_empty(self) -> None:
        """Verify empty duration list returns None/0 defaults."""
        stats = calculate_timing_statistics([])
        self.assertIsNone(stats["mean_analysis_time_seconds"])
        self.assertIsNone(stats["median_analysis_time_seconds"])
        self.assertIsNone(stats["minimum_analysis_time_seconds"])
        self.assertIsNone(stats["maximum_analysis_time_seconds"])
        self.assertEqual(stats["total_analysis_time_seconds"], 0.0)

    def test_timing_statistics_valid(self) -> None:
        """Verify mean, median, min, max, and total durations on sample timings."""
        durations = [1.2, 2.4, 0.6, 3.8, 2.0]
        stats = calculate_timing_statistics(durations)
        self.assertEqual(stats["minimum_analysis_time_seconds"], 0.6)
        self.assertEqual(stats["maximum_analysis_time_seconds"], 3.8)
        self.assertEqual(stats["median_analysis_time_seconds"], 2.0)
        self.assertEqual(stats["mean_analysis_time_seconds"], 2.0)
        self.assertEqual(stats["total_analysis_time_seconds"], 10.0)

    def test_confusion_metrics_perfect_score(self) -> None:
        """When detected rules match ground truth exactly, precision, recall, and F1 are 1.0."""
        metrics = calculate_confusion_metrics(true_positives=4, false_positives=0, false_negatives=0)
        self.assertEqual(metrics["precision"], 1.0)
        self.assertEqual(metrics["recall"], 1.0)
        self.assertEqual(metrics["f1_score"], 1.0)

    def test_confusion_metrics_partial_score(self) -> None:
        """Verify arithmetic for mixed true positives, false positives, and false negatives."""
        # TP = 3, FP = 1 (precision = 3/4 = 0.75), FN = 1 (recall = 3/4 = 0.75) -> F1 = 0.75
        metrics = calculate_confusion_metrics(true_positives=3, false_positives=1, false_negatives=1)
        self.assertEqual(metrics["precision"], 0.75)
        self.assertEqual(metrics["recall"], 0.75)
        self.assertEqual(metrics["f1_score"], 0.75)

    def test_confusion_metrics_division_by_zero_safeguards(self) -> None:
        """Verify graceful 0/1 fallback when no findings exist or expected."""
        # 0 TP, 0 FP, 0 FN (both tool and ground truth found 0 flaws)
        zero_case = calculate_confusion_metrics(true_positives=0, false_positives=0, false_negatives=0)
        self.assertEqual(zero_case["precision"], 1.0)
        self.assertEqual(zero_case["recall"], 1.0)
        self.assertEqual(zero_case["f1_score"], 1.0)

        # 0 TP, 5 FP, 0 FN (hallucinated findings)
        fp_case = calculate_confusion_metrics(true_positives=0, false_positives=5, false_negatives=0)
        self.assertEqual(fp_case["precision"], 0.0)
        self.assertEqual(fp_case["recall"], 1.0)
        self.assertEqual(fp_case["f1_score"], 0.0)

        # 0 TP, 0 FP, 5 FN (missed all flaws)
        fn_case = calculate_confusion_metrics(true_positives=0, false_positives=0, false_negatives=5)
        self.assertEqual(fn_case["precision"], 1.0)
        self.assertEqual(fn_case["recall"], 0.0)
        self.assertEqual(fn_case["f1_score"], 0.0)

    def test_ground_truth_loading_and_matching(self) -> None:
        """Verify loading ground truth in dictionary and list representations."""
        gt_dict_path = self.work_dir / "gt_dict.json"
        gt_data = {
            "apks": {
                "sample.apk": {
                    "expected_rules": ["SEC-001", "NET-001"],
                },
                "a" * 64: {
                    "expected_rules": ["CRY-001"],
                },
            }
        }
        gt_dict_path.write_text(json.dumps(gt_data), encoding="utf-8")

        loaded = load_ground_truth(gt_dict_path)
        self.assertIn("sample.apk", loaded)
        self.assertIn("a" * 64, loaded)

        # Match by filename
        match1 = match_ground_truth_for_apk({"filename": "Sample.APK"}, loaded)
        self.assertIsNotNone(match1)
        self.assertEqual(match1["expected_rules"], ["SEC-001", "NET-001"])

        # Match by SHA-256 hash
        match2 = match_ground_truth_for_apk({"filename": "other.apk", "sha256": "A" * 64}, loaded)
        self.assertIsNotNone(match2)
        self.assertEqual(match2["expected_rules"], ["CRY-001"])

    def _create_dummy_apk(self, name: str) -> Path:
        apk_path = self.work_dir / name
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
        return apk_path

    def _create_mock_result(self, name: str, sha256: str) -> AnalysisResult:
        return AnalysisResult(
            analysis_id="test-scan-123",
            application=ApplicationMetadata(
                filename=name,
                sha256=sha256,
                file_size=1024,
                package_name="com.example.mock",
                file_path=Path(name),
                analyzed_at=datetime.now(timezone.utc),
            ),
            overall_risk_score=65.0,
            risk_rating=RiskRating.HIGH,
            metrics=AnalysisMetrics(
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
                duration_seconds=1.23,
                files_examined=5,
                rules_executed=10,
                warnings=[],
            ),
            permissions=[
                PermissionFinding(
                    permission="android.permission.CAMERA",
                    protection_level="dangerous",
                    risk_level=Severity.HIGH,
                    description="Camera permission",
                    reason="Grants hardware access",
                    is_sensitive_user_data=True,
                ),
            ],
            findings=[
                SecurityFinding(
                    rule_id="SEC-001",
                    title="Hardcoded API Key",
                    category=FindingCategory.HARDCODED_SECRET,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description="Secret leak",
                    evidence="AIzaSy...",
                ),
                SecurityFinding(
                    rule_id="NET-001",
                    title="Cleartext Traffic",
                    category=FindingCategory.NETWORK_INDICATOR,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description="Insecure HTTP",
                    evidence="http://example.com",
                ),
            ],
        )

    @patch("scripts.evaluate.AnalysisEngine")
    def test_evaluate_directory_without_ground_truth(self, mock_engine_cls: MagicMock) -> None:
        """Without ground truth, detection counts and timings are exported without accuracy claims."""
        self._create_dummy_apk("app1.apk")
        mock_engine = MagicMock()
        mock_engine.analyze_apk.return_value = self._create_mock_result("app1.apk", "b" * 64)
        mock_engine_cls.return_value = mock_engine

        out_dir = self.work_dir / "output_no_gt"
        results = evaluate_directory(
            apk_dir=self.work_dir,
            output_dir=out_dir,
            ground_truth_path=None,
        )

        self.assertIsNotNone(results)
        self.assertEqual(results["metadata"]["total_apks_evaluated"], 1)
        self.assertFalse(results["metadata"]["ground_truth_enabled"])
        self.assertIn("status", results["accuracy_evaluation"])
        self.assertIsNone(results["accuracy_evaluation"]["overall_precision"])

        # Check output files exist
        csv_path = out_dir / "evaluation_results.csv"
        json_path = out_dir / "evaluation_results.json"
        self.assertTrue(csv_path.exists())
        self.assertTrue(json_path.exists())

        # Validate CSV content
        csv_content = csv_path.read_text(encoding="utf-8")
        self.assertIn("filename,sha256,package", csv_content)
        self.assertIn("app1.apk", csv_content)
        self.assertIn("com.example.mock", csv_content)

    @patch("scripts.evaluate.AnalysisEngine")
    def test_evaluate_directory_with_ground_truth(self, mock_engine_cls: MagicMock) -> None:
        """With ground truth, TP/FP/FN/Precision/Recall/F1 are calculated empirically."""
        self._create_dummy_apk("app1.apk")
        mock_engine = MagicMock()
        mock_engine.analyze_apk.return_value = self._create_mock_result("app1.apk", "c" * 64)
        mock_engine_cls.return_value = mock_engine

        # Ground truth expects SEC-001 and NET-001 (mock tool also detected SEC-001 and NET-001 -> 100%)
        gt_path = self.work_dir / "ground_truth.json"
        gt_data = {
            "apks": {
                "app1.apk": {
                    "expected_rules": ["SEC-001", "NET-001"],
                }
            }
        }
        gt_path.write_text(json.dumps(gt_data), encoding="utf-8")

        out_dir = self.work_dir / "output_with_gt"
        results = evaluate_directory(
            apk_dir=self.work_dir,
            output_dir=out_dir,
            ground_truth_path=gt_path,
        )

        self.assertTrue(results["metadata"]["ground_truth_enabled"])
        acc = results["accuracy_evaluation"]
        self.assertEqual(acc["total_true_positives"], 2)
        self.assertEqual(acc["total_false_positives"], 0)
        self.assertEqual(acc["total_false_negatives"], 0)
        self.assertEqual(acc["overall_precision"], 1.0)
        self.assertEqual(acc["overall_recall"], 1.0)
        self.assertEqual(acc["overall_f1_score"], 1.0)

        # Check per-rule metrics
        self.assertIn("SEC-001", acc["per_rule_metrics"])
        self.assertEqual(acc["per_rule_metrics"]["SEC-001"]["precision"], 1.0)

        # Validate CSV includes TP/FP/FN/Precision columns
        csv_path = out_dir / "evaluation_results.csv"
        csv_content = csv_path.read_text(encoding="utf-8")
        self.assertIn("true_positives,false_positives,false_negatives", csv_content)


if __name__ == "__main__":
    unittest.main()
