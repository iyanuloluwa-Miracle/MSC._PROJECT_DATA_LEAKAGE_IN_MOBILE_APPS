"""Comprehensive unit tests covering domain models, serialization, and validation."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from data_leak_detector.core.config import AppConfig
from data_leak_detector.core.logging_config import SensitiveDataFilter
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


class TestCoreModels(unittest.TestCase):
    def setUp(self) -> None:
        self.valid_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.now = datetime.now(timezone.utc)
        self.later = self.now + timedelta(seconds=12)

    def test_app_config_initialization(self) -> None:
        config = AppConfig()
        self.assertEqual(config.app_name, "Mobile Data Leak Detector")
        self.assertTrue(config.resources_dir.exists())

    def test_sensitive_data_filter_redaction(self) -> None:
        sample = "Found API key: AIzaSyD3x9ExampleKey1234567890abcdef and password=supersecret"
        redacted = SensitiveDataFilter.redact(sample)
        self.assertNotIn("AIzaSyD3x9ExampleKey1234567890abcdef", redacted)
        self.assertIn("[REDACTED_SECRET]", redacted)

    def test_application_metadata_construction_and_serialization(self) -> None:
        meta = ApplicationMetadata(
            filename="sample_app.apk",
            sha256=self.valid_sha256,
            file_size=1048576,
            package_name="com.example.testapp",
            file_path=Path("/tmp/sample_app.apk"),
            app_name="Test App",
            version_name="1.0.0",
            version_code=100,
            min_sdk=21,
            target_sdk=34,
            analyzed_at=self.now,
        )

        # Test to_dict
        d = meta.to_dict()
        self.assertEqual(d["filename"], "sample_app.apk")
        self.assertEqual(d["sha256"], self.valid_sha256)
        self.assertEqual(d["file_size"], 1048576)
        self.assertEqual(d["package_name"], "com.example.testapp")
        self.assertIsInstance(d["file_path"], str)
        self.assertEqual(d["app_name"], "Test App")
        self.assertEqual(d["min_sdk"], 21)

        # Test to_json & roundtrip
        json_str = meta.to_json()
        reconstructed = ApplicationMetadata.from_json(json_str)
        self.assertEqual(reconstructed.filename, meta.filename)
        self.assertEqual(reconstructed.sha256, meta.sha256)
        self.assertEqual(reconstructed.package_name, meta.package_name)
        self.assertEqual(reconstructed.file_size, meta.file_size)
        self.assertEqual(reconstructed.target_sdk, meta.target_sdk)
        self.assertIsInstance(reconstructed.file_path, Path)

    def test_application_metadata_optional_fields(self) -> None:
        meta = ApplicationMetadata(
            filename="minimal.apk",
            sha256=self.valid_sha256,
            file_size=500,
            package_name="com.minimal.app",
        )
        self.assertIsNone(meta.file_path)
        self.assertIsNone(meta.app_name)
        self.assertIsNone(meta.version_name)
        self.assertIsNone(meta.version_code)
        self.assertIsNone(meta.min_sdk)
        self.assertIsNone(meta.target_sdk)
        self.assertIsInstance(meta.analyzed_at, datetime)

        d = meta.to_dict()
        self.assertIsNone(d["file_path"])
        reconstructed = ApplicationMetadata.from_dict(d)
        self.assertIsNone(reconstructed.app_name)

    def test_application_metadata_validation(self) -> None:
        # Empty filename
        with self.assertRaises(ValueError):
            ApplicationMetadata(
                filename="",
                sha256=self.valid_sha256,
                file_size=100,
                package_name="com.example.app",
            )

        # Empty package name
        with self.assertRaises(ValueError):
            ApplicationMetadata(
                filename="app.apk",
                sha256=self.valid_sha256,
                file_size=100,
                package_name="   ",
            )

        # Negative file size
        with self.assertRaises(ValueError):
            ApplicationMetadata(
                filename="app.apk",
                sha256=self.valid_sha256,
                file_size=-1,
                package_name="com.example.app",
            )

        # Malformed SHA256
        with self.assertRaises(ValueError):
            ApplicationMetadata(
                filename="app.apk",
                sha256="not-a-valid-sha256",
                file_size=100,
                package_name="com.example.app",
            )

    def test_permission_finding_construction_and_serialization(self) -> None:
        perm = PermissionFinding(
            permission="android.permission.ACCESS_FINE_LOCATION",
            protection_level="dangerous",
            risk_level=Severity.HIGH,
            description="Allows precise location access",
            reason="Can be used for background user tracking",
            source="manifest",
            confidence=Confidence.HIGH,
        )
        d = perm.to_dict()
        self.assertEqual(d["permission"], "android.permission.ACCESS_FINE_LOCATION")
        self.assertEqual(d["risk_level"], "HIGH")
        self.assertEqual(d["confidence"], "HIGH")

        # Roundtrip JSON
        json_str = perm.to_json()
        recon = PermissionFinding.from_json(json_str)
        self.assertEqual(recon.permission, perm.permission)
        self.assertEqual(recon.risk_level, Severity.HIGH)
        self.assertEqual(recon.confidence, Confidence.HIGH)

    def test_permission_finding_validation(self) -> None:
        with self.assertRaises(ValueError):
            PermissionFinding(
                permission="",
                protection_level="dangerous",
                risk_level=Severity.HIGH,
                description="",
                reason="",
            )

        # Invalid severity string
        with self.assertRaises(ValueError):
            PermissionFinding(
                permission="android.permission.INTERNET",
                protection_level="normal",
                risk_level="SUPER_CRITICAL",  # type: ignore
                description="",
                reason="",
            )

    def test_security_finding_construction_and_serialization(self) -> None:
        finding = SecurityFinding(
            rule_id="NET-001",
            title="Cleartext Traffic Detected",
            category=FindingCategory.NETWORK_INDICATOR,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description="Cleartext HTTP endpoint found in DEX strings.",
            evidence="http://insecure-api.tracker.com/collect",
            location="com/example/api/ApiClient.smali:42",
            impact="Network eavesdropping may expose private user metadata.",
            remediation="Enforce HTTPS across all endpoints via Network Security Config.",
            owasp_reference="OWASP-M3: Insecure Communication",
            is_static_indicator=True,
        )

        d = finding.to_dict()
        self.assertEqual(d["rule_id"], "NET-001")
        self.assertEqual(d["category"], "NETWORK_INDICATOR")
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["confidence"], "MEDIUM")
        self.assertTrue(d["is_static_indicator"])

        # JSON Roundtrip
        json_str = finding.to_json()
        recon = SecurityFinding.from_json(json_str)
        self.assertEqual(recon.rule_id, finding.rule_id)
        self.assertEqual(recon.category, FindingCategory.NETWORK_INDICATOR)
        self.assertEqual(recon.severity, Severity.HIGH)
        self.assertEqual(recon.confidence, Confidence.MEDIUM)
        self.assertEqual(recon.owasp_reference, "OWASP-M3: Insecure Communication")

    def test_security_finding_optional_fields(self) -> None:
        finding = SecurityFinding(
            rule_id="SEC-001",
            title="Hardcoded Secret Indicator",
            category="CUSTOM_CATEGORY",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="Potential key detected",
            evidence="[REDACTED_SECRET]",
        )
        self.assertIsNone(finding.location)
        self.assertIsNone(finding.impact)
        self.assertIsNone(finding.remediation)
        self.assertIsNone(finding.owasp_reference)
        self.assertTrue(finding.is_static_indicator)

        recon = SecurityFinding.from_dict(finding.to_dict())
        self.assertEqual(recon.category, "CUSTOM_CATEGORY")

    def test_security_finding_validation(self) -> None:
        with self.assertRaises(ValueError):
            SecurityFinding(
                rule_id="",
                title="Title",
                category=FindingCategory.HARDCODED_SECRET,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="desc",
                evidence="ev",
            )

        with self.assertRaises(ValueError):
            SecurityFinding(
                rule_id="RULE-1",
                title="",
                category=FindingCategory.HARDCODED_SECRET,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="desc",
                evidence="ev",
            )

    def test_analysis_metrics_construction_and_validation(self) -> None:
        metrics = AnalysisMetrics(
            started_at=self.now,
            completed_at=self.later,
            duration_seconds=12.0,
            files_examined=150,
            rules_executed=18,
            warnings=["APK contains multi-dex structure."],
        )
        d = metrics.to_dict()
        self.assertEqual(d["duration_seconds"], 12.0)
        self.assertEqual(d["files_examined"], 150)
        self.assertEqual(d["rules_executed"], 18)
        self.assertEqual(len(d["warnings"]), 1)

        recon = AnalysisMetrics.from_dict(d)
        self.assertEqual(recon.duration_seconds, 12.0)
        self.assertEqual(recon.files_examined, 150)

        # Validation: duration < 0
        with self.assertRaises(ValueError):
            AnalysisMetrics(
                started_at=self.now,
                completed_at=self.later,
                duration_seconds=-5.0,
            )

        # Validation: completed_at before started_at
        with self.assertRaises(ValueError):
            AnalysisMetrics(
                started_at=self.later,
                completed_at=self.now,
                duration_seconds=1.0,
            )

    def test_analysis_result_construction_and_serialization(self) -> None:
        meta = ApplicationMetadata(
            filename="target.apk",
            sha256=self.valid_sha256,
            file_size=2048,
            package_name="com.secure.app",
        )
        metrics = AnalysisMetrics(
            started_at=self.now,
            completed_at=self.later,
            duration_seconds=12.0,
            files_examined=45,
            rules_executed=10,
        )
        perm = PermissionFinding(
            permission="android.permission.INTERNET",
            protection_level="normal",
            risk_level=Severity.LOW,
            description="Allows socket creation",
            reason="Exfiltration transport vector",
        )
        finding = SecurityFinding(
            rule_id="MAN-001",
            title="AllowBackup Enabled",
            category=FindingCategory.MANIFEST_MISCONFIG,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description="allowBackup is set to true",
            evidence="android:allowBackup=true",
        )

        result = AnalysisResult(
            analysis_id="scan-2026-0001",
            application=meta,
            overall_risk_score=42.5,
            risk_rating=RiskRating.MEDIUM,
            metrics=metrics,
            permissions=[perm],
            findings=[finding],
            analyzer_version="0.1.0",
        )

        d = result.to_dict()
        self.assertEqual(d["analysis_id"], "scan-2026-0001")
        self.assertEqual(d["overall_risk_score"], 42.5)
        self.assertEqual(d["risk_rating"], "MEDIUM")
        self.assertEqual(d["application"]["package_name"], "com.secure.app")
        self.assertEqual(len(d["permissions"]), 1)
        self.assertEqual(len(d["findings"]), 1)

        # Roundtrip JSON
        json_str = result.to_json()
        recon = AnalysisResult.from_json(json_str)
        self.assertEqual(recon.analysis_id, "scan-2026-0001")
        self.assertEqual(recon.overall_risk_score, 42.5)
        self.assertEqual(recon.risk_rating, RiskRating.MEDIUM)
        self.assertEqual(recon.application.package_name, "com.secure.app")
        self.assertEqual(len(recon.permissions), 1)
        self.assertEqual(recon.permissions[0].permission, "android.permission.INTERNET")
        self.assertEqual(len(recon.findings), 1)
        self.assertEqual(recon.findings[0].rule_id, "MAN-001")

    def test_analysis_result_validation(self) -> None:
        meta = ApplicationMetadata(
            filename="target.apk",
            sha256=self.valid_sha256,
            file_size=2048,
            package_name="com.secure.app",
        )
        metrics = AnalysisMetrics(
            started_at=self.now,
            completed_at=self.later,
            duration_seconds=12.0,
        )

        # Score > 100
        with self.assertRaises(ValueError):
            AnalysisResult(
                analysis_id="scan-1",
                application=meta,
                overall_risk_score=105.0,
                risk_rating=RiskRating.CRITICAL,
                metrics=metrics,
            )

        # Score < 0
        with self.assertRaises(ValueError):
            AnalysisResult(
                analysis_id="scan-1",
                application=meta,
                overall_risk_score=-0.5,
                risk_rating=RiskRating.LOW,
                metrics=metrics,
            )

        # Empty analysis_id
        with self.assertRaises(ValueError):
            AnalysisResult(
                analysis_id="",
                application=meta,
                overall_risk_score=50.0,
                risk_rating=RiskRating.MEDIUM,
                metrics=metrics,
            )

    def test_enums_serialization(self) -> None:
        self.assertEqual(Severity.CRITICAL.value, "CRITICAL")
        self.assertEqual(Severity.HIGH.value, "HIGH")
        self.assertEqual(Severity.MEDIUM.value, "MEDIUM")
        self.assertEqual(Severity.LOW.value, "LOW")
        self.assertEqual(Severity.INFO.value, "INFO")

        self.assertEqual(Confidence.HIGH.value, "HIGH")
        self.assertEqual(Confidence.MEDIUM.value, "MEDIUM")
        self.assertEqual(Confidence.LOW.value, "LOW")

        self.assertEqual(RiskRating.CRITICAL.value, "CRITICAL")
        self.assertEqual(RiskRating.HIGH.value, "HIGH")
        self.assertEqual(RiskRating.MEDIUM.value, "MEDIUM")
        self.assertEqual(RiskRating.LOW.value, "LOW")
        self.assertEqual(RiskRating.MINIMAL.value, "MINIMAL")


if __name__ == "__main__":
    unittest.main()
