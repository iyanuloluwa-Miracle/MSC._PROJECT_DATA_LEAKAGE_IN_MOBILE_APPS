"""Unit tests for ReportGenerator producing HTML, PDF, and plain text audit reports."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from data_leak_detector.core.exceptions import ReportGenerationError
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
from data_leak_detector.reporting.html_report import HTMLReportFormatter
from data_leak_detector.reporting.pdf_report import PDFReportFormatter
from data_leak_detector.reporting.report_generator import ReportGenerator
from data_leak_detector.reporting.text_report import (
    STATIC_ANALYSIS_DISCLAIMER,
    TextReportFormatter,
    sort_findings_by_severity,
)


class TestReportGenerator(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

        self.sample_sha256 = "1111222233334444555566667777888899990000aaaabbbbccccdddd11112222"
        self.sample_result = self._build_sample_result()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _build_sample_result(self) -> AnalysisResult:
        app_meta = ApplicationMetadata(
            filename="production_banking.apk",
            sha256=self.sample_sha256,
            file_size=12582912,
            package_name="com.bank.mobile",
            app_name="BankMobile Secure",
            version_name="3.4.1",
            version_code=104,
            min_sdk=24,
            target_sdk=34,
            analyzed_at=datetime(2026, 3, 20, 14, 30, 0, tzinfo=timezone.utc),
        )

        permissions = [
            PermissionFinding(
                permission="android.permission.INTERNET",
                protection_level="normal",
                risk_level=Severity.INFO,
                description="Allows application to open network sockets",
                reason="Standard networking",
                is_sensitive_user_data=False,
            ),
            PermissionFinding(
                permission="android.permission.ACCESS_FINE_LOCATION",
                protection_level="dangerous",
                risk_level=Severity.HIGH,
                family="location",
                description="Precise GPS location access",
                reason="Declared in manifest",
                is_sensitive_user_data=True,
            ),
            PermissionFinding(
                permission="android.permission.READ_CONTACTS",
                protection_level="dangerous",
                risk_level=Severity.HIGH,
                family="contacts",
                description="Read user address book",
                reason="Declared in manifest",
                is_sensitive_user_data=True,
            ),
        ]

        # Mixed severity findings to test ordering
        findings = [
            SecurityFinding(
                rule_id="NET-001",
                title="Cleartext HTTP Endpoint Detected",
                category=FindingCategory.NETWORK_INDICATOR,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description="Insecure HTTP communication URL found",
                evidence="http://api.bank.com/data",
                location="NetworkModule.java:88",
                impact="Cleartext transmission susceptible to eavesdropping",
                remediation="Migrate all endpoints to HTTPS",
                owasp_reference="OWASP-M3: Insecure Communication",
            ),
            SecurityFinding(
                rule_id="SEC-001",
                title="Hardcoded Production Master Key",
                category=FindingCategory.HARDCODED_SECRET,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                description="Hardcoded credential discovered in bytecode",
                evidence="AIzaSyAB********XYZ",
                location="CryptoHelper.java:23",
                impact="Permits unauthorized access to cloud resources",
                remediation="Store secrets externally in KeyStore",
                owasp_reference="OWASP-M9: Reverse Engineering",
            ),
            SecurityFinding(
                rule_id="CRY-001",
                title="DES Cipher Implementation",
                category=FindingCategory.CRYPTO_FLAW,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="Use of broken DES encryption algorithm",
                evidence="Cipher.getInstance(\"DES/CBC/PKCS5Padding\")",
                location="Vault.java:114",
                impact="Weak encryption can be cracked via brute force",
                remediation="Upgrade to AES-256-GCM",
                owasp_reference="OWASP-M5: Insufficient Cryptography",
            ),
            SecurityFinding(
                rule_id="STO-001",
                title="World-Readable SharedPreferences",
                category=FindingCategory.STORAGE_INSECURITY,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description="Legacy world-readable file mode enabled",
                evidence="MODE_WORLD_READABLE (1)",
                location="PrefsManager.java:34",
                impact="Local applications can read internal preference data",
                remediation="Use MODE_PRIVATE or EncryptedSharedPreferences",
                owasp_reference="OWASP-M2: Insecure Data Storage",
            ),
        ]

        metrics = AnalysisMetrics(
            started_at=datetime(2026, 3, 20, 14, 30, 0, tzinfo=timezone.utc),
            completed_at=datetime(2026, 3, 20, 14, 30, 8, tzinfo=timezone.utc),
            duration_seconds=8.25,
            files_examined=340,
            rules_executed=42,
            warnings=["JADX decompilation skipped."],
        )

        return AnalysisResult(
            analysis_id="bank-audit-uuid-1234",
            application=app_meta,
            overall_risk_score=78.5,
            risk_rating=RiskRating.HIGH,
            metrics=metrics,
            permissions=permissions,
            findings=findings,
            analyzer_version="0.1.0",
        )

    def test_sort_findings_by_severity(self) -> None:
        """Verify sorting puts Critical first, followed by High, Medium, Low, Info."""
        sorted_f = sort_findings_by_severity(self.sample_result.findings)
        severities = [f.severity for f in sorted_f]
        expected = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        self.assertEqual(severities, expected)

    def test_text_report_generation(self) -> None:
        """Verify plain text report contains all 18 required audit elements and correct order."""
        out_txt = self.temp_path / "report.txt"
        formatter = TextReportFormatter(self.sample_result)
        rendered_path = formatter.render(out_txt)

        self.assertTrue(rendered_path.exists())
        content = rendered_path.read_text(encoding="utf-8")

        # 1. Title
        self.assertIn("MOBILE APPLICATION STATIC SECURITY & PRIVACY AUDIT REPORT", content)
        # 2. Analysis ID
        self.assertIn("bank-audit-uuid-1234", content)
        # 3. Timestamp
        self.assertIn("2026-03-20", content)
        # 4. App metadata
        self.assertIn("BankMobile Secure", content)
        self.assertIn("com.bank.mobile", content)
        self.assertIn("3.4.1", content)
        # 5. SHA-256
        self.assertIn(self.sample_sha256, content)
        # 6. Duration
        self.assertIn("8.25 seconds", content)
        # 7. Risk score
        self.assertIn("78.5 / 100", content)
        # 8. Risk rating
        self.assertIn("HIGH", content)
        # 9. Executive summary
        self.assertIn("EXECUTIVE SUMMARY", content)
        # 10. Severity breakdown
        self.assertIn("CRITICAL:        1", content)
        self.assertIn("HIGH:            1", content)
        self.assertIn("MEDIUM:          1", content)
        self.assertIn("LOW:             1", content)
        # 11 & 12. Permissions
        self.assertIn("PERMISSION AUDIT", content)
        self.assertIn("android.permission.ACCESS_FINE_LOCATION", content)
        self.assertIn("location", content)
        # 13. Vulnerability findings
        self.assertIn("[CRITICAL] Finding #1: Hardcoded Production Master Key", content)
        self.assertIn("[HIGH] Finding #2: DES Cipher Implementation", content)
        self.assertIn("[MEDIUM] Finding #3: World-Readable SharedPreferences", content)
        self.assertIn("[LOW] Finding #4: Cleartext HTTP Endpoint Detected", content)
        # 14. Evidence
        self.assertIn("AIzaSyAB********XYZ", content)
        # 15. Impact
        self.assertIn("Permits unauthorized access to cloud resources", content)
        # 16. Remediation
        self.assertIn("Upgrade to AES-256-GCM", content)
        # 17. OWASP references
        self.assertIn("OWASP-M9", content)
        # 18. Disclaimer
        self.assertIn("STATIC ANALYSIS METHODOLOGY & LIMITATIONS DISCLAIMER", content)
        self.assertIn("The target APK was evaluated purely statically", content)
        self.assertIn("Absence Does Not Prove Security", content)
        self.assertIn("No Runtime Transmission Confirmation", content)

        # Verify ordering: Critical appears before High, High before Medium, Medium before Low
        pos_critical = content.find("[CRITICAL]")
        pos_high = content.find("[HIGH]")
        pos_medium = content.find("[MEDIUM]")
        pos_low = content.find("[LOW]")
        self.assertLess(pos_critical, pos_high)
        self.assertLess(pos_high, pos_medium)
        self.assertLess(pos_medium, pos_low)

    def test_html_report_generation(self) -> None:
        """Verify HTML report contains all required elements, escaped HTML, and valid structure."""
        out_html = self.temp_path / "report.html"
        formatter = HTMLReportFormatter(self.sample_result)
        rendered_path = formatter.render(out_html)

        self.assertTrue(rendered_path.exists())
        content = rendered_path.read_text(encoding="utf-8")

        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("Security Audit Report: com.bank.mobile", content)
        self.assertIn("bank-audit-uuid-1234", content)
        self.assertIn("BankMobile Secure", content)
        self.assertIn(self.sample_sha256, content)
        self.assertIn("78.5", content)
        self.assertIn("HIGH", content)
        self.assertIn("Critical: 1", content)
        self.assertIn("Hardcoded Production Master Key", content)
        self.assertIn("AIzaSyAB********XYZ", content)
        self.assertIn("OWASP-M9", content)
        self.assertIn("ACCESS_FINE_LOCATION", content)
        self.assertIn("Methodology & Limitations Disclaimer", content)

        # Ordering check
        crit_idx = content.find("pill-critical")
        high_idx = content.find("pill-high")
        self.assertLess(crit_idx, high_idx)

    def test_pdf_report_generation_via_reportlab(self) -> None:
        """Verify PDF report builds successfully using ReportLab and produces valid PDF file."""
        out_pdf = self.temp_path / "report.pdf"
        formatter = PDFReportFormatter(self.sample_result)
        rendered_path = formatter.render(out_pdf)

        self.assertTrue(rendered_path.exists())
        pdf_bytes = rendered_path.read_bytes()

        # PDF header magic bytes
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
        # PDF has substantial content
        self.assertGreater(len(pdf_bytes), 2000)

    def test_report_generator_generate_all(self) -> None:
        """Verify ReportGenerator.generate_all creates html, pdf, and txt reports simultaneously."""
        generator = ReportGenerator(self.sample_result)
        reports = generator.generate_all(self.temp_path, base_filename="custom_audit")

        self.assertIn("html", reports)
        self.assertIn("pdf", reports)
        self.assertIn("txt", reports)

        for key, p in reports.items():
            self.assertTrue(p.exists(), f"Report {key} at {p} does not exist!")
            self.assertGreater(p.stat().st_size, 0)

        self.assertEqual(reports["html"].suffix, ".html")
        self.assertEqual(reports["pdf"].suffix, ".pdf")
        self.assertEqual(reports["txt"].suffix, ".txt")

    def test_report_with_no_findings(self) -> None:
        """Verify clean APK with zero findings generates valid reports across all formats."""
        clean_result = self._build_sample_result()
        clean_result.findings = []
        clean_result.overall_risk_score = 0.0
        clean_result.risk_rating = RiskRating.MINIMAL

        generator = ReportGenerator(clean_result)
        reports = generator.generate_all(self.temp_path, base_filename="clean_app")

        for key, p in reports.items():
            self.assertTrue(p.exists())
            self.assertGreater(p.stat().st_size, 0)

        txt_content = reports["txt"].read_text(encoding="utf-8")
        self.assertIn("No security or privacy findings were detected", txt_content)
        self.assertIn("MINIMAL", txt_content)

    def test_secret_in_evidence_is_not_exposed(self) -> None:
        """Verify raw secret tokens never appear in plain text or HTML reports."""
        raw_secret_value = "super_secret_unmasked_token_xyz987"
        result_with_secret = self._build_sample_result()
        # Add finding that might contain raw secret in evidence
        result_with_secret.findings.append(
            SecurityFinding(
                rule_id="SEC-999",
                title="Unmasked Secret Test",
                category=FindingCategory.HARDCODED_SECRET,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="Testing secret masking",
                evidence=f"api_key = {raw_secret_value}",
                location="Config.java:12",
            )
        )

        generator = ReportGenerator(result_with_secret)
        txt_path = generator.generate_text(self.temp_path / "secret_test.txt")
        html_path = generator.generate_html(self.temp_path / "secret_test.html")

        txt_content = txt_path.read_text(encoding="utf-8")
        html_content = html_path.read_text(encoding="utf-8")

        # The raw secret string should have been redacted
        self.assertNotIn(raw_secret_value, txt_content)
        self.assertNotIn(raw_secret_value, html_content)


if __name__ == "__main__":
    unittest.main()
