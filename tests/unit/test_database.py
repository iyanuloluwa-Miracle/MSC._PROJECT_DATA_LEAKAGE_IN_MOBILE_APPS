"""Unit tests for SQLite DatabaseManager persistence, models, and security guarantees."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from data_leak_detector.core.exceptions import StorageError
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
from data_leak_detector.storage.database import (
    ApplicationRecord,
    DatabaseManager,
    get_default_database_path,
)


class TestDatabaseManager(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.db_path = self.temp_path / "test_history.sqlite3"
        self.manager = DatabaseManager(self.db_path)

    def tearDown(self) -> None:
        self.manager.close()
        self.temp_dir.cleanup()

    def _create_sample_result(
        self,
        analysis_id: str = "test-uuid-001",
        package_name: str = "com.example.secureapp",
        sha256: str = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        risk_score: float = 45.5,
        rating: RiskRating = RiskRating.MEDIUM,
    ) -> AnalysisResult:
        app_meta = ApplicationMetadata(
            filename="app_release.apk",
            sha256=sha256,
            file_size=5242880,
            package_name=package_name,
            app_name="SecureApp",
            version_name="2.1.0",
            version_code=42,
            min_sdk=21,
            target_sdk=33,
            analyzed_at=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        )

        permissions = [
            PermissionFinding(
                permission="android.permission.INTERNET",
                protection_level="normal",
                risk_level=Severity.INFO,
                description="Allows network access",
                reason="Declared in manifest",
                is_sensitive_user_data=False,
            ),
            PermissionFinding(
                permission="android.permission.ACCESS_FINE_LOCATION",
                protection_level="dangerous",
                risk_level=Severity.HIGH,
                family="location",
                description="Precise location access",
                reason="Declared in manifest",
                is_sensitive_user_data=True,
            ),
        ]

        findings = [
            SecurityFinding(
                rule_id="NET-001",
                title="Cleartext HTTP Endpoint",
                category=FindingCategory.NETWORK_INDICATOR,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description="Found unencrypted HTTP endpoint",
                evidence="http://insecure.example.com/api",
                location="ApiClient.java:45",
                impact="Data transmitted in cleartext",
                remediation="Use HTTPS exclusively",
                owasp_reference="OWASP-M3",
            ),
            SecurityFinding(
                rule_id="SEC-001",
                title="Hardcoded Google API Key",
                category=FindingCategory.HARDCODED_SECRET,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="Discovered API key",
                evidence="AIzaSyAB********XYZ",
                location="strings.xml",
                impact="May expose backend quota",
                remediation="Store secrets in KeyStore",
                owasp_reference="OWASP-M9",
            ),
        ]

        metrics = AnalysisMetrics(
            started_at=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            completed_at=datetime(2026, 1, 15, 10, 0, 5, tzinfo=timezone.utc),
            duration_seconds=5.0,
            files_examined=120,
            rules_executed=35,
            warnings=["Apktool decoding skipped."],
        )

        return AnalysisResult(
            analysis_id=analysis_id,
            application=app_meta,
            overall_risk_score=risk_score,
            risk_rating=rating,
            metrics=metrics,
            permissions=permissions,
            findings=findings,
            analyzer_version="0.1.0",
        )

    def test_schema_initialization_creates_all_tables_and_indices(self) -> None:
        """Verify applications, analysis_results, and findings tables exist with expected structure."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}

        expected_tables = {
            "applications",
            "analysis_results",
            "permission_findings",
            "security_findings",
        }
        self.assertTrue(expected_tables.issubset(tables))

        # Check applications columns
        cursor.execute("PRAGMA table_info(applications)")
        app_cols = {row[1] for row in cursor.fetchall()}
        self.assertTrue(
            {"id", "file_hash", "filename", "package_name", "version", "analysis_timestamp"}.issubset(
                app_cols
            )
        )

        # Check analysis_results columns
        cursor.execute("PRAGMA table_info(analysis_results)")
        res_cols = {row[1] for row in cursor.fetchall()}
        self.assertTrue(
            {
                "id",
                "application_id",
                "risk_score",
                "risk_rating",
                "duration",
                "analyzer_version",
                "created_at",
            }.issubset(res_cols)
        )

        conn.close()

    def test_save_and_get_result_roundtrip(self) -> None:
        """Verify saving and retrieving an AnalysisResult reconstructs all attributes."""
        result = self._create_sample_result()
        saved_id = self.manager.save_result(result)
        self.assertEqual(saved_id, result.analysis_id)

        fetched = self.manager.get_result(result.analysis_id)
        self.assertIsNotNone(fetched)
        assert fetched is not None

        self.assertEqual(fetched.analysis_id, result.analysis_id)
        self.assertEqual(fetched.application.package_name, result.application.package_name)
        self.assertEqual(fetched.application.sha256, result.application.sha256)
        self.assertEqual(fetched.overall_risk_score, result.overall_risk_score)
        self.assertEqual(fetched.risk_rating, result.risk_rating)
        self.assertEqual(len(fetched.permissions), 2)
        self.assertEqual(len(fetched.findings), 2)

        # Check individual finding details
        finding = fetched.findings[0]
        self.assertEqual(finding.rule_id, "NET-001")
        self.assertEqual(finding.evidence, "http://insecure.example.com/api")
        self.assertEqual(finding.confidence, Confidence.HIGH)

    def test_get_result_relational_fallback_when_json_is_null(self) -> None:
        """Verify relational tables can reconstruct AnalysisResult even if JSON cache is wiped."""
        result = self._create_sample_result()
        self.manager.save_result(result)

        # Wipe result_data_json in SQLite
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("UPDATE analysis_results SET result_data_json = NULL WHERE id = ?", (result.analysis_id,))
        conn.commit()
        conn.close()

        # Re-fetch via manager; should use relational fallback
        reconstructed = self.manager.get_result(result.analysis_id)
        self.assertIsNotNone(reconstructed)
        assert reconstructed is not None

        self.assertEqual(reconstructed.analysis_id, result.analysis_id)
        self.assertEqual(reconstructed.application.package_name, result.application.package_name)
        self.assertEqual(len(reconstructed.permissions), 2)
        self.assertEqual(len(reconstructed.findings), 2)
        self.assertEqual(reconstructed.overall_risk_score, 45.5)

    def test_get_nonexistent_result_returns_none(self) -> None:
        """Verify querying unknown ID returns None."""
        self.assertIsNone(self.manager.get_result("nonexistent-id-999"))

    def test_list_history_ordering_and_pagination(self) -> None:
        """Verify list_history returns summaries ordered descending with pagination."""
        r1 = self._create_sample_result(analysis_id="id-1", package_name="com.app.one")
        r2 = self._create_sample_result(analysis_id="id-2", package_name="com.app.two")
        r3 = self._create_sample_result(analysis_id="id-3", package_name="com.app.three")

        self.manager.save_result(r1)
        self.manager.save_result(r2)
        self.manager.save_result(r3)

        # Fetch first page of 2
        history_page1 = self.manager.list_history(limit=2, offset=0)
        self.assertEqual(len(history_page1), 2)

        # Check summary structure
        first = history_page1[0]
        self.assertIn("id", first)
        self.assertIn("application_id", first)
        self.assertIn("package_name", first)
        self.assertIn("risk_score", first)
        self.assertIn("findings_count", first)
        self.assertEqual(first["findings_count"], 2)
        self.assertEqual(first["permissions_count"], 2)

        # Fetch second page of 2
        history_page2 = self.manager.list_history(limit=2, offset=2)
        self.assertEqual(len(history_page2), 1)

    def test_find_by_hash(self) -> None:
        """Verify find_by_hash locates scans matching SHA-256 hash."""
        target_hash = "a" * 64
        other_hash = "b" * 64

        r1 = self._create_sample_result(analysis_id="h-1", sha256=target_hash)
        r2 = self._create_sample_result(analysis_id="h-2", sha256=other_hash)

        self.manager.save_result(r1)
        self.manager.save_result(r2)

        matches = self.manager.find_by_hash(target_hash)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["id"], "h-1")
        self.assertEqual(matches[0]["file_hash"], target_hash)

        # Non-existent hash
        no_matches = self.manager.find_by_hash("0000000000000000000000000000000000000000000000000000000000000000")
        self.assertEqual(len(no_matches), 0)

    def test_delete_result_cascades_and_removes_orphaned_application(self) -> None:
        """Verify delete_result cascades to findings and cleans application record."""
        res = self._create_sample_result()
        self.manager.save_result(res)

        self.assertIsNotNone(self.manager.get_result(res.analysis_id))
        deleted = self.manager.delete_result(res.analysis_id)
        self.assertTrue(deleted)

        # Should now be gone
        self.assertIsNone(self.manager.get_result(res.analysis_id))

        # Check relational tables are empty
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM permission_findings")
        self.assertEqual(cursor.fetchone()[0], 0)
        cursor.execute("SELECT COUNT(*) FROM security_findings")
        self.assertEqual(cursor.fetchone()[0], 0)
        cursor.execute("SELECT COUNT(*) FROM applications")
        self.assertEqual(cursor.fetchone()[0], 0)
        conn.close()

        # Deleting nonexistent returns False
        self.assertFalse(self.manager.delete_result("already-deleted"))

    def test_clear_history_removes_all_records(self) -> None:
        """Verify clear_history purges all tables and returns total count."""
        r1 = self._create_sample_result(analysis_id="c-1")
        r2 = self._create_sample_result(analysis_id="c-2")
        self.manager.save_result(r1)
        self.manager.save_result(r2)

        count = self.manager.clear_history()
        self.assertEqual(count, 2)
        self.assertEqual(len(self.manager.list_history()), 0)

    def test_sql_injection_resistance_via_parameterization(self) -> None:
        """Verify malicious metadata strings cannot perform SQL injection."""
        malicious_input = "'; DROP TABLE applications; --"
        res = self._create_sample_result(
            analysis_id="sqli-test",
            package_name=malicious_input,
        )

        saved_id = self.manager.save_result(res)
        self.assertEqual(saved_id, "sqli-test")

        # Table must still exist
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM applications")
        self.assertEqual(cursor.fetchone()[0], 1)
        conn.close()

        # find_by_hash with injection payload
        result = self.manager.find_by_hash(malicious_input)
        self.assertEqual(len(result), 0)

    def test_default_database_path_in_user_app_data_dir(self) -> None:
        """Verify default database path resides in user app data directory, not source repo."""
        default_path = get_default_database_path()
        self.assertTrue(default_path.is_absolute())
        self.assertEqual(default_path.name, "analysis_history.sqlite3")

        # Must not be inside current source directory
        repo_root = Path(__file__).resolve().parent.parent.parent
        self.assertFalse(
            repo_root in default_path.parents,
            f"Database should not be stored in repository root: {default_path}",
        )

    def test_no_binary_data_stored_in_tables(self) -> None:
        """Verify database schema contains zero BLOB columns."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall() if not row[0].startswith("sqlite_")]

        for tbl in tables:
            cursor.execute(f"PRAGMA table_info({tbl})")
            for col in cursor.fetchall():
                col_type = col[2].upper()
                self.assertNotIn("BLOB", col_type, f"Table {tbl} column {col[1]} has type {col_type}")

        conn.close()

    def test_in_memory_database_support(self) -> None:
        """Verify transient in-memory database works seamlessly."""
        with DatabaseManager(":memory:") as mem_mgr:
            res = self._create_sample_result(analysis_id="mem-1")
            mem_mgr.save_result(res)
            fetched = mem_mgr.get_result("mem-1")
            self.assertIsNotNone(fetched)
            assert fetched is not None
            self.assertEqual(fetched.analysis_id, "mem-1")

    def test_empty_sha256_raises_storage_error(self) -> None:
        """Verify saving a result with an invalid/empty SHA-256 raises StorageError."""
        res = self._create_sample_result()
        res.application.sha256 = ""
        with self.assertRaises(StorageError):
            self.manager.save_result(res)


if __name__ == "__main__":
    unittest.main()
