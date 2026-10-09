"""Unit and integration tests for AnalysisEngine orchestration layer with heavy mocks."""

from __future__ import annotations

import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from data_leak_detector.analysis.engine import (
    AnalysisEngine,
    AnalysisStage,
    CancellationToken,
    ProgressUpdate,
)
from data_leak_detector.analysis.tool_adapters import ApktoolAdapter, JadxAdapter
from data_leak_detector.core.config import AppConfig
from data_leak_detector.core.exceptions import (
    AnalysisCancelledError,
    ExternalToolError,
    InvalidAPKError,
)
from data_leak_detector.core.models import (
    AnalysisResult,
    ApplicationMetadata,
    ComponentDetail,
    Confidence,
    FindingCategory,
    ManifestData,
    ParsedAPKData,
    RiskRating,
    SecurityFinding,
    Severity,
)
from data_leak_detector.rules.base import BaseRule
from data_leak_detector.rules.registry import RuleRegistry


class MockFlakyRule(BaseRule):
    """Rule that intentionally raises an exception to verify fault containment."""

    rule_id = "FLK-001"
    title = "Flaky Failure Rule"
    category = FindingCategory.MANIFEST_MISCONFIG
    default_severity = Severity.MEDIUM
    description = "Test rule that raises an exception."

    def evaluate(self, context: object) -> list[SecurityFinding]:
        raise RuntimeError("Simulated crash in rule evaluation")


class MockDuplicateFindingRule(BaseRule):
    """Rule that produces duplicate findings to test deduplication."""

    rule_id = "DUP-001"
    title = "Duplicate Indicator Rule"
    category = FindingCategory.STORAGE_INSECURITY
    default_severity = Severity.LOW
    description = "Emits duplicate findings for testing deduplication."

    def evaluate(self, context: object) -> list[SecurityFinding]:
        return [
            self.create_finding(
                title="Duplicate Issue",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description="Duplicate finding description",
                evidence="dummy_evidence",
                location="DummyFile.java:10",
            ),
            self.create_finding(
                title="Duplicate Issue",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description="Duplicate finding description",
                evidence="dummy_evidence",
                location="DummyFile.java:10",
            ),
        ]


class TestAnalysisEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

        # Create a valid synthetic APK zip with AndroidManifest.xml and classes.dex
        self.apk_path = self.temp_path / "sample_test.apk"
        with zipfile.ZipFile(self.apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest package='com.example.test'/>")
            zf.writestr("classes.dex", b"DEX\n035\x00dummy_bytecode_strings_here_http://tracker.example.com")
            zf.writestr("res/values/strings.xml", b"<resources><string name='api_key'>sample_dummy_key_123456789</string></resources>")


        # Create mock ParsedAPKData
        self.mock_metadata = ApplicationMetadata(
            filename=self.apk_path.name,
            sha256="a" * 64,
            file_size=1024,
            package_name="com.example.test",
            file_path=self.apk_path,
            app_name="TestApp",
            version_name="1.0.0",
            version_code=1,
            min_sdk=21,
            target_sdk=30,
        )
        self.mock_manifest = ManifestData(
            package_name="com.example.test",
            app_name="TestApp",
            target_sdk=30,
            debuggable=False,
            allow_backup=True,
            raw_xml="<manifest package='com.example.test'><application android:allowBackup='true'/></manifest>",
            components=[
                ComponentDetail(
                    component_type="activity",
                    name="com.example.test.MainActivity",
                    exported=True,
                    is_main_launcher=True,
                )
            ],
        )
        self.mock_parsed_apk = ParsedAPKData(
            metadata=self.mock_metadata,
            permissions=["android.permission.INTERNET", "android.permission.ACCESS_FINE_LOCATION"],
            activities=["com.example.test.MainActivity"],
            manifest_info=self.mock_manifest,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _create_engine_with_mock_parser(
        self,
        jadx_adapter: JadxAdapter | None = None,
        apktool_adapter: ApktoolAdapter | None = None,
        registry: RuleRegistry | None = None,
    ) -> AnalysisEngine:
        config = AppConfig(base_dir=self.temp_path)
        engine = AnalysisEngine(
            config=config,
            jadx_adapter=jadx_adapter,
            apktool_adapter=apktool_adapter,
            registry=registry,
        )

        mock_parser = MagicMock()
        mock_parser.validate_file.return_value = None
        mock_parser.calculate_sha256.return_value = "b" * 64
        mock_parser.parse.return_value = self.mock_parsed_apk

        engine._create_apk_parser = MagicMock(return_value=mock_parser)  # type: ignore[assignment]
        return engine

    def test_engine_has_zero_tkinter_dependency(self) -> None:
        """Verify AnalysisEngine does not import or depend directly on Tkinter."""
        import data_leak_detector.analysis.engine as eng
        self.assertNotIn("tkinter", sys.modules.get("data_leak_detector.analysis.engine", "").__doc__ or "")
        # Check imports in module attributes
        self.assertFalse(hasattr(eng, "tk"))
        self.assertFalse(hasattr(eng, "Tk"))
        self.assertFalse(hasattr(eng, "ttk"))

    def test_end_to_end_analysis_successful(self) -> None:
        """Verify full analysis workflow executes and returns populated AnalysisResult."""
        engine = self._create_engine_with_mock_parser()
        result = engine.analyze_apk(self.apk_path)

        self.assertIsInstance(result, AnalysisResult)
        self.assertEqual(result.application.package_name, "com.example.test")
        self.assertIsInstance(result.overall_risk_score, float)
        self.assertIsInstance(result.risk_rating, RiskRating)
        self.assertGreaterEqual(result.overall_risk_score, 0.0)
        self.assertLessEqual(result.overall_risk_score, 100.0)

        # Check metrics
        self.assertGreater(result.metrics.duration_seconds, 0)
        self.assertGreater(result.metrics.rules_executed, 0)
        self.assertGreater(result.metrics.files_examined, 0)
        self.assertIsInstance(result.metrics.warnings, list)

        # Check permissions and findings
        self.assertGreater(len(result.permissions), 0)
        self.assertIsInstance(result.findings, list)

    def test_all_twelve_progress_stages_emitted_in_order(self) -> None:
        """Verify that all 12 specified stages are emitted in the exact expected order."""
        engine = self._create_engine_with_mock_parser()
        stages_emitted: list[str] = []
        progress_values: list[float] = []

        def on_progress(frac: float, stage: str, msg: str = "") -> None:
            stages_emitted.append(stage)
            progress_values.append(frac)

        engine.analyze_apk(self.apk_path, progress_callback=on_progress)

        expected_stages = [
            AnalysisStage.VALIDATING.value,
            AnalysisStage.PARSING.value,
            AnalysisStage.DECOMPILING.value,
            AnalysisStage.ANALYZING_PERMISSIONS.value,
            AnalysisStage.SCANNING_MANIFEST.value,
            AnalysisStage.SCANNING_SECRETS.value,
            AnalysisStage.SCANNING_NETWORK.value,
            AnalysisStage.SCANNING_STORAGE.value,
            AnalysisStage.SCANNING_CRYPTO.value,
            AnalysisStage.SCANNING_SDKS.value,
            AnalysisStage.SCORING.value,
            AnalysisStage.COMPLETE.value,
        ]

        self.assertEqual(stages_emitted, expected_stages)
        # Check that progress is strictly non-decreasing
        for i in range(len(progress_values) - 1):
            self.assertLessEqual(progress_values[i], progress_values[i + 1])
        self.assertEqual(progress_values[-1], 1.0)

    def test_progress_callback_signatures_supported(self) -> None:
        """Verify callbacks with 1, 2, or 3 arguments are cleanly invoked."""
        engine = self._create_engine_with_mock_parser()

        # 1-arg: ProgressUpdate
        updates: list[ProgressUpdate] = []
        engine.analyze_apk(self.apk_path, progress_callback=lambda u: updates.append(u))
        self.assertEqual(len(updates), 12)
        self.assertEqual(updates[0].stage, AnalysisStage.VALIDATING)

        # 2-arg: (float, str)
        two_args: list[tuple[float, str]] = []
        engine.analyze_apk(self.apk_path, progress_callback=lambda f, s: two_args.append((f, s)))
        self.assertEqual(len(two_args), 12)
        self.assertEqual(two_args[0][1], "VALIDATING")

    def test_cancellation_via_token_raises_analysis_cancelled_error(self) -> None:
        """Verify cooperative cancellation via CancellationToken interrupts execution."""
        engine = self._create_engine_with_mock_parser()
        token = CancellationToken()

        stages_seen: list[str] = []

        def on_progress(frac: float, stage: str) -> None:
            stages_seen.append(stage)
            if stage == AnalysisStage.PARSING.value:
                token.cancel()

        with self.assertRaises(AnalysisCancelledError):
            engine.analyze_apk(
                self.apk_path,
                progress_callback=on_progress,
                cancellation_token=token,
            )

        # Analysis stopped before reaching scanning stages
        self.assertNotIn(AnalysisStage.SCANNING_SECRETS.value, stages_seen)
        self.assertNotIn(AnalysisStage.COMPLETE.value, stages_seen)

    def test_cancellation_via_callback(self) -> None:
        """Verify cancel_callback parameter stops analysis immediately."""
        engine = self._create_engine_with_mock_parser()
        call_count = 0

        def should_cancel() -> bool:
            nonlocal call_count
            call_count += 1
            return call_count >= 3  # Cancel on third check

        with self.assertRaises(AnalysisCancelledError):
            engine.analyze_apk(self.apk_path, cancel_callback=should_cancel)

    def test_cancellation_via_engine_method(self) -> None:
        """Verify calling engine.cancel() interrupts the scan."""
        engine = self._create_engine_with_mock_parser()

        def on_progress(frac: float, stage: str) -> None:
            if stage == AnalysisStage.DECOMPILING.value:
                engine.cancel()

        with self.assertRaises(AnalysisCancelledError):
            engine.analyze_apk(self.apk_path, progress_callback=on_progress)

    def test_optional_tool_failure_generates_warnings_not_crashes(self) -> None:
        """Verify that external tool errors (JADX, Apktool) record warnings and scan continues."""
        mock_jadx = MagicMock(spec=JadxAdapter)
        mock_jadx.is_available.return_value = True
        mock_jadx.run.side_effect = ExternalToolError("JADX timed out")

        mock_apktool = MagicMock(spec=ApktoolAdapter)
        mock_apktool.is_available.return_value = True
        mock_apktool.run.side_effect = ExternalToolError("Apktool syntax failure")

        engine = self._create_engine_with_mock_parser(
            jadx_adapter=mock_jadx,
            apktool_adapter=mock_apktool,
        )

        result = engine.analyze_apk(self.apk_path)
        self.assertIsInstance(result, AnalysisResult)

        # Warnings should record the tool failures
        warning_text = " ".join(result.metrics.warnings)
        self.assertIn("JADX", warning_text)
        self.assertIn("Apktool", warning_text)

    def test_nonexistent_apk_raises_invalid_apk_error(self) -> None:
        """Verify non-existent file path immediately raises InvalidAPKError."""
        engine = AnalysisEngine()
        nonexistent = self.temp_path / "does_not_exist.apk"

        with self.assertRaises(InvalidAPKError):
            engine.analyze_apk(nonexistent)

    def test_corrupted_apk_raises_invalid_apk_error(self) -> None:
        """Verify non-zip file raises InvalidAPKError."""
        corrupt_file = self.temp_path / "corrupt.apk"
        corrupt_file.write_text("Not a zip file")

        engine = AnalysisEngine()
        with self.assertRaises(InvalidAPKError):
            engine.analyze_apk(corrupt_file)

    def test_rule_exception_is_isolated_and_recorded_in_warnings(self) -> None:
        """Verify a broken rule does not crash the entire scan and records a warning."""
        registry = RuleRegistry()
        registry.register(MockFlakyRule())

        engine = self._create_engine_with_mock_parser(registry=registry)
        result = engine.analyze_apk(self.apk_path)

        self.assertIsInstance(result, AnalysisResult)
        warning_text = " ".join(result.metrics.warnings)
        self.assertIn("FLK-001", warning_text)

    def test_finding_deduplication(self) -> None:
        """Verify duplicate findings with identical attributes are deduplicated."""
        findings = [
            SecurityFinding(
                rule_id="DUP-001",
                title="Duplicate Issue",
                category=FindingCategory.STORAGE_INSECURITY,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description="Desc",
                evidence="secret_key_1",
                location="MainActivity.java:15",
            ),
            SecurityFinding(
                rule_id="DUP-001",
                title="Duplicate Issue",
                category=FindingCategory.STORAGE_INSECURITY,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description="Desc",
                evidence="secret_key_1",
                location="MainActivity.java:15",
            ),
            SecurityFinding(
                rule_id="DUP-001",
                title="Distinct Issue",
                category=FindingCategory.STORAGE_INSECURITY,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description="Desc",
                evidence="secret_key_2",
                location="MainActivity.java:25",
            ),
        ]

        deduped = AnalysisEngine.deduplicate_findings(findings)
        self.assertEqual(len(deduped), 2)
        self.assertEqual(deduped[0].evidence, "secret_key_1")
        self.assertEqual(deduped[1].evidence, "secret_key_2")

    def test_temporary_directories_cleaned_after_normal_run(self) -> None:
        """Verify temporary directories created during analysis are cleaned up."""
        created_temp_dirs: list[Path] = []
        original_mkdtemp = tempfile.mkdtemp

        def tracked_mkdtemp(*args: object, **kwargs: object) -> str:
            res = original_mkdtemp(*args, **kwargs)
            created_temp_dirs.append(Path(res))
            return res

        with patch("tempfile.mkdtemp", side_effect=tracked_mkdtemp):
            engine = self._create_engine_with_mock_parser()
            engine.analyze_apk(self.apk_path)

        self.assertGreater(len(created_temp_dirs), 0)
        for d in created_temp_dirs:
            self.assertFalse(d.exists(), f"Temporary directory {d} was not cleaned up!")

    def test_temporary_directories_cleaned_after_exception(self) -> None:
        """Verify temporary directories are cleaned even if an unhandled exception or cancellation occurs."""
        created_temp_dirs: list[Path] = []
        original_mkdtemp = tempfile.mkdtemp

        def tracked_mkdtemp(*args: object, **kwargs: object) -> str:
            res = original_mkdtemp(*args, **kwargs)
            created_temp_dirs.append(Path(res))
            return res

        with patch("tempfile.mkdtemp", side_effect=tracked_mkdtemp):
            engine = self._create_engine_with_mock_parser()

            # Trigger cancellation during decompilation
            def cancel_during_decomp(frac: float, stage: str) -> None:
                if stage == AnalysisStage.DECOMPILING.value:
                    engine.cancel()

            with self.assertRaises(AnalysisCancelledError):
                engine.analyze_apk(self.apk_path, progress_callback=cancel_during_decomp)

        self.assertGreater(len(created_temp_dirs), 0)
        for d in created_temp_dirs:
            self.assertFalse(d.exists(), f"Temporary directory {d} was not cleaned up on cancellation!")


if __name__ == "__main__":
    unittest.main()
