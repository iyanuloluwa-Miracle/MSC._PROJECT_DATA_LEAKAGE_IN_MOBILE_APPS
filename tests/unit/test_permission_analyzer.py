"""Unit tests for PermissionAnalyzer covering sensitive families, classifications, and summaries."""

from __future__ import annotations

import unittest

from data_leak_detector.analysis.permission_analyzer import (
    PermissionAnalyser,
    PermissionAnalyzer,
)
from data_leak_detector.core.models import (
    ApplicationMetadata,
    ParsedAPKData,
    Severity,
)


class TestPermissionAnalyzer(unittest.TestCase):
    def setUp(self) -> None:
        self.analyzer = PermissionAnalyzer()

    def test_analyzer_alias_british_spelling(self) -> None:
        self.assertIs(PermissionAnalyser, PermissionAnalyzer)
        analyser_inst = PermissionAnalyser()
        self.assertIsInstance(analyser_inst, PermissionAnalyzer)

    def test_sensitive_user_data_permissions(self) -> None:
        perms = [
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_SMS",
            "android.permission.READ_CALL_LOG",
            "android.permission.READ_CALENDAR",
            "android.permission.READ_EXTERNAL_STORAGE",
        ]
        summary = self.analyzer.analyze(perms)

        self.assertEqual(summary.total_permissions, 8)
        self.assertEqual(summary.dangerous_permissions, 8)
        self.assertEqual(summary.unknown_custom_permissions, 0)
        self.assertEqual(summary.sensitive_user_data_permissions, 8)

        # Verify families are identified
        expected_families = {
            "location",
            "contacts",
            "camera",
            "microphone",
            "sms",
            "call_logs",
            "calendar",
            "storage",
        }
        self.assertTrue(expected_families.issubset(set(summary.sensitive_families)))

        # Verify human-readable user friendly descriptions exist
        for finding in summary.findings:
            self.assertTrue(finding.is_sensitive_user_data)
            self.assertIsNotNone(finding.user_friendly_description)
            self.assertGreater(len(finding.user_friendly_description or ""), 10)
            self.assertEqual(
                finding.classification, "Permission associated with sensitive user data"
            )

    def test_standard_normal_permissions(self) -> None:
        perms = [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.VIBRATE",
        ]
        summary = self.analyzer.analyze(perms)

        self.assertEqual(summary.total_permissions, 3)
        self.assertEqual(summary.normal_permissions, 3)
        self.assertEqual(summary.dangerous_permissions, 0)

        for finding in summary.findings:
            self.assertEqual(finding.protection_level, "normal")
            self.assertEqual(finding.classification, "Standard operational permission")
            self.assertFalse(finding.is_heuristic_warning)

    def test_signature_privileged_permission(self) -> None:
        perms = ["android.permission.READ_PRIVILEGED_PHONE_STATE"]
        summary = self.analyzer.analyze(perms)

        self.assertEqual(summary.total_permissions, 1)
        self.assertEqual(summary.signature_permissions, 1)
        finding = summary.findings[0]
        self.assertIn("signature", finding.protection_level)
        self.assertEqual(finding.risk_level, Severity.CRITICAL)
        self.assertTrue(finding.is_heuristic_warning)

    def test_custom_unknown_permissions(self) -> None:
        perms = [
            "com.example.app.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION",
            "org.custom.vendor.permission.HARDWARE_CONFIG",
        ]
        summary = self.analyzer.analyze(perms)

        self.assertEqual(summary.total_permissions, 2)
        self.assertEqual(summary.unknown_custom_permissions, 2)
        self.assertEqual(summary.dangerous_permissions, 0)

        for finding in summary.findings:
            self.assertEqual(finding.protection_level, "custom/unknown")
            self.assertEqual(finding.classification, "Custom/unknown permission")
            self.assertTrue(finding.is_heuristic_warning)
            self.assertIn("Custom permission", finding.user_friendly_description or "")

    def test_uncatalogued_standard_android_permission(self) -> None:
        # Standard AOSP permission not explicitly in our sensitive catalog
        perms = ["android.permission.SET_WALLPAPER"]
        summary = self.analyzer.analyze(perms)

        self.assertEqual(summary.total_permissions, 1)
        finding = summary.findings[0]
        self.assertEqual(finding.protection_level, "normal")
        self.assertEqual(finding.classification, "Standard operational permission")
        self.assertFalse(finding.is_heuristic_warning)

    def test_summary_metrics_with_mixed_permissions(self) -> None:
        perms = [
            "android.permission.INTERNET",                # normal
            "android.permission.ACCESS_FINE_LOCATION",    # dangerous, sensitive data
            "android.permission.CAMERA",                  # dangerous, sensitive data
            "android.permission.READ_PRIVILEGED_PHONE_STATE", # signature
            "com.custom.AUTH_TOKEN_ACCESS",              # unknown/custom
        ]
        summary = self.analyzer.analyze(perms)

        self.assertEqual(summary.total_permissions, 5)
        self.assertEqual(summary.normal_permissions, 1)
        self.assertEqual(summary.dangerous_permissions, 2)
        self.assertEqual(summary.signature_permissions, 1)
        self.assertEqual(summary.unknown_custom_permissions, 1)
        self.assertEqual(summary.sensitive_user_data_permissions, 3)

        # Check sorting: highest risk first
        self.assertEqual(summary.findings[0].risk_level, Severity.CRITICAL)

    def test_analyze_with_parsed_apk_data_object(self) -> None:
        meta = ApplicationMetadata(
            filename="app.apk",
            sha256="a" * 64,
            file_size=1024,
            package_name="com.test.app",
        )
        parsed_apk = ParsedAPKData(
            metadata=meta,
            permissions=["android.permission.CAMERA", "android.permission.VIBRATE"],
        )

        summary = self.analyzer.analyze(parsed_apk)
        self.assertEqual(summary.total_permissions, 2)
        self.assertEqual(summary.dangerous_permissions, 1)
        self.assertEqual(summary.normal_permissions, 1)

    def test_backwards_compatible_analyze_permissions_api(self) -> None:
        perms = ["android.permission.RECORD_AUDIO", "android.permission.INTERNET"]
        perm_findings, sec_findings = self.analyzer.analyze_permissions(perms)

        self.assertEqual(len(perm_findings), 2)
        self.assertEqual(len(sec_findings), 1)  # Only RECORD_AUDIO is HIGH risk
        self.assertEqual(sec_findings[0].title, "Sensitive Permission Declared: RECORD_AUDIO")
        self.assertEqual(sec_findings[0].severity, Severity.HIGH)


if __name__ == "__main__":
    unittest.main()
