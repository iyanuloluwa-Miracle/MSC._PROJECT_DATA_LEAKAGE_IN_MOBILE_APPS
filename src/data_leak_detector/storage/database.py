"""Local SQLite persistence manager for static analysis history.

Provides relational and structured JSON storage for applications, scan results,
permission findings, and security findings using Python's standard sqlite3 module.

Guarantees:
- Local only: No remote database connectivity or telemetry.
- Zero binary storage: Never stores APK binary bytes in the database.
- Strict parameterization: Uses parameterized SQL exclusively to prevent injection.
- User data directory default: Persists databases in OS-standard application data directories.
- Automatic idempotent schema migration and initialization.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

from data_leak_detector.core.exceptions import DetectorError, StorageError
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


logger = logging.getLogger(__name__)


def get_default_database_path() -> Path:
    """Resolve database location within the operating system user application data directory."""
    app_folder_name = "MobileDataLeakDetector"
    if os.name == "nt":
        app_data = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        base_dir = Path(app_data) if app_data else Path.home() / "AppData" / "Local"
    else:
        xdg = os.environ.get("XDG_DATA_HOME")
        base_dir = Path(xdg) if xdg else Path.home() / ".local" / "share"

    target_dir = base_dir / app_folder_name
    target_dir.mkdir(parents=True, exist_ok=True)
    return target_dir / "analysis_history.sqlite3"


@dataclass
class ApplicationRecord:
    """Relational representation of an analyzed Android application package."""

    id: int | None
    file_hash: str
    filename: str
    package_name: str
    version: str | None
    analysis_timestamp: str
    app_name: str | None = None
    file_size: int = 0
    min_sdk: str | None = None
    target_sdk: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert record to dictionary."""
        return {
            "id": self.id,
            "file_hash": self.file_hash,
            "filename": self.filename,
            "package_name": self.package_name,
            "version": self.version,
            "analysis_timestamp": self.analysis_timestamp,
            "app_name": self.app_name,
            "file_size": self.file_size,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
        }


@dataclass
class AnalysisResultRecord:
    """Relational summary record for an executed analysis run."""

    id: str
    application_id: int
    risk_score: float
    risk_rating: str
    duration: float
    analyzer_version: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        """Convert record to dictionary."""
        return {
            "id": self.id,
            "application_id": self.application_id,
            "risk_score": self.risk_score,
            "risk_rating": self.risk_rating,
            "duration": self.duration,
            "analyzer_version": self.analyzer_version,
            "created_at": self.created_at,
        }


# Aliases for domain consistency
Application = ApplicationRecord
AnalysisResultEntry = AnalysisResultRecord


class DatabaseManager:
    """Manages local SQLite database operations for persisting and retrieving scan history."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        """Initialize database manager.
        
        Args:
            db_path: Optional explicit database path or ':memory:'. If None, defaults
                to the user application data directory.
        """
        if db_path is None:
            self.db_path = get_default_database_path()
        elif str(db_path) == ":memory:":
            self.db_path = Path(":memory:")
        else:
            self.db_path = Path(db_path)

        self._memory_conn: sqlite3.Connection | None = None
        if str(self.db_path) == ":memory:":
            self._memory_conn = sqlite3.connect(":memory:", timeout=30.0, check_same_thread=False)
            self._memory_conn.row_factory = sqlite3.Row
            self._memory_conn.execute("PRAGMA foreign_keys = ON;")
        else:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.initialize_schema()

    def close(self) -> None:
        """Close persistent database connection if in-memory."""
        if self._memory_conn is not None:
            try:
                self._memory_conn.close()
            except Exception:
                pass
            self._memory_conn = None

    def __enter__(self) -> DatabaseManager:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Contextual generator yielding an active SQLite connection with foreign keys enabled."""
        if self._memory_conn is not None:
            try:
                yield self._memory_conn
            except Exception as exc:
                self._memory_conn.rollback()
                if isinstance(exc, DetectorError):
                    raise
                raise StorageError(f"Database operation failed: {exc}") from exc
        else:
            conn = sqlite3.connect(str(self.db_path), timeout=30.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            try:
                yield conn
            except Exception as exc:
                conn.rollback()
                if isinstance(exc, DetectorError):
                    raise
                raise StorageError(f"Database operation failed: {exc}") from exc
            finally:
                conn.close()

    def initialize_schema(self) -> None:
        """Create application, analysis result, and finding tables if not present."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Applications table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS applications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_hash TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    version TEXT,
                    analysis_timestamp TEXT NOT NULL,
                    app_name TEXT,
                    file_size INTEGER DEFAULT 0,
                    min_sdk TEXT,
                    target_sdk TEXT
                );
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_applications_file_hash ON applications(file_hash);"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_applications_package_name ON applications(package_name);"
            )

            # 2. Analysis Results table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_results (
                    id TEXT PRIMARY KEY,
                    application_id INTEGER NOT NULL,
                    risk_score REAL NOT NULL,
                    risk_rating TEXT NOT NULL,
                    duration REAL NOT NULL,
                    analyzer_version TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    result_data_json TEXT,
                    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
                );
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_analysis_results_app_id ON analysis_results(application_id);"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_analysis_results_created_at ON analysis_results(created_at);"
            )

            # 3. Permission Findings table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS permission_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    result_id TEXT NOT NULL,
                    permission_name TEXT NOT NULL,
                    protection_level TEXT,
                    risk_level TEXT NOT NULL,
                    family TEXT,
                    description TEXT,
                    is_sensitive_user_data INTEGER DEFAULT 0,
                    FOREIGN KEY (result_id) REFERENCES analysis_results(id) ON DELETE CASCADE
                );
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_permission_findings_result_id ON permission_findings(result_id);"
            )

            # 4. Security Findings table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS security_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    result_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    description TEXT,
                    evidence TEXT,
                    location TEXT,
                    impact TEXT,
                    remediation TEXT,
                    owasp_reference TEXT,
                    is_static_indicator INTEGER DEFAULT 1,
                    FOREIGN KEY (result_id) REFERENCES analysis_results(id) ON DELETE CASCADE
                );
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_security_findings_result_id ON security_findings(result_id);"
            )

            conn.commit()

    def save_result(self, result: AnalysisResult) -> str:
        """Save analysis result and associated findings to local database.
        
        Args:
            result: Complete AnalysisResult model.

        Returns:
            The analysis record identifier (result.analysis_id).
        """
        if not isinstance(result, AnalysisResult):
            raise TypeError(f"Expected AnalysisResult instance, got {type(result).__name__}")

        app = result.application
        if not app.sha256:
            raise StorageError("Cannot save AnalysisResult with empty application SHA-256 hash.")

        version_str = app.version_name or (str(app.version_code) if app.version_code is not None else None)
        analyzed_at_str = (
            app.analyzed_at.isoformat()
            if isinstance(app.analyzed_at, datetime)
            else str(app.analyzed_at)
        )
        created_at_str = (
            result.metrics.completed_at.isoformat()
            if isinstance(result.metrics.completed_at, datetime)
            else datetime.now(timezone.utc).isoformat()
        )

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Insert Application entry
            cursor.execute(
                """
                INSERT INTO applications (
                    file_hash, filename, package_name, version, analysis_timestamp,
                    app_name, file_size, min_sdk, target_sdk
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    app.sha256,
                    app.filename,
                    app.package_name,
                    version_str,
                    analyzed_at_str,
                    app.app_name,
                    int(app.file_size),
                    str(app.min_sdk) if app.min_sdk is not None else None,
                    str(app.target_sdk) if app.target_sdk is not None else None,
                ),
            )
            app_id = cursor.lastrowid
            if app_id is None:
                raise StorageError("Failed to obtain generated application_id from database.")

            # 2. Insert AnalysisResult entry
            cursor.execute(
                """
                INSERT OR REPLACE INTO analysis_results (
                    id, application_id, risk_score, risk_rating, duration,
                    analyzer_version, created_at, result_data_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.analysis_id,
                    app_id,
                    float(result.overall_risk_score),
                    result.risk_rating.value if hasattr(result.risk_rating, "value") else str(result.risk_rating),
                    float(result.metrics.duration_seconds),
                    result.analyzer_version,
                    created_at_str,
                    result.to_json(),
                ),
            )

            # 3. Insert PermissionFindings relationally
            for perm in result.permissions:
                cursor.execute(
                    """
                    INSERT INTO permission_findings (
                        result_id, permission_name, protection_level, risk_level,
                        family, description, is_sensitive_user_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result.analysis_id,
                        getattr(perm, "permission", getattr(perm, "name", "")),
                        perm.protection_level,
                        perm.risk_level.value if hasattr(perm.risk_level, "value") else str(perm.risk_level),
                        perm.family,
                        perm.description,
                        1 if perm.is_sensitive_user_data else 0,
                    ),
                )

            # 4. Insert SecurityFindings relationally
            for finding in result.findings:
                cursor.execute(
                    """
                    INSERT INTO security_findings (
                        result_id, rule_id, title, category, severity, confidence,
                        description, evidence, location, impact, remediation,
                        owasp_reference, is_static_indicator
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result.analysis_id,
                        finding.rule_id,
                        finding.title,
                        finding.category.value if hasattr(finding.category, "value") else str(finding.category),
                        finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                        finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence),
                        finding.description,
                        finding.evidence,
                        finding.location,
                        finding.impact,
                        finding.remediation,
                        finding.owasp_reference,
                        1 if finding.is_static_indicator else 0,
                    ),
                )

            conn.commit()

        logger.info(f"Saved analysis result '{result.analysis_id}' for package '{app.package_name}'")
        return result.analysis_id

    def save_scan_result(self, result: AnalysisResult) -> str:
        """Alias for save_result for backwards compatibility."""
        return self.save_result(result)

    def get_result(self, result_id: str) -> AnalysisResult | None:
        """Retrieve full details of an analysis run by record ID.
        
        Args:
            result_id: Unique analysis identifier.
            
        Returns:
            Reconstructed AnalysisResult dataclass, or None if not found.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, application_id, risk_score, risk_rating, duration,
                       analyzer_version, created_at, result_data_json
                FROM analysis_results
                WHERE id = ?
                """,
                (str(result_id),),
            )
            row = cursor.fetchone()
            if not row:
                return None

            # First attempt: Lossless reconstruction from serialized JSON
            if row["result_data_json"]:
                try:
                    return AnalysisResult.from_json(row["result_data_json"])
                except Exception as exc:
                    logger.warning(
                        f"Failed reconstructing AnalysisResult from JSON for ID '{result_id}': {exc}. "
                        "Falling back to relational reconstruction."
                    )

            # Fallback: Relational table reconstruction
            return self._reconstruct_result_relationally(cursor, row)

    def get_scan_by_id(self, scan_id: str | int) -> AnalysisResult | None:
        """Alias for get_result for backwards compatibility."""
        return self.get_result(str(scan_id))

    def _reconstruct_result_relationally(
        self, cursor: sqlite3.Cursor, result_row: sqlite3.Row
    ) -> AnalysisResult:
        """Reconstruct AnalysisResult from relational database tables."""
        res_id = result_row["id"]
        app_id = result_row["application_id"]

        # Fetch Application
        cursor.execute("SELECT * FROM applications WHERE id = ?", (app_id,))
        app_row = cursor.fetchone()
        if not app_row:
            raise StorageError(f"Application record {app_id} missing for scan {res_id}")

        meta = ApplicationMetadata(
            filename=app_row["filename"],
            sha256=app_row["file_hash"],
            file_size=int(app_row["file_size"] or 0),
            package_name=app_row["package_name"],
            app_name=app_row["app_name"],
            version_name=app_row["version"],
            min_sdk=app_row["min_sdk"],
            target_sdk=app_row["target_sdk"],
            analyzed_at=datetime.fromisoformat(app_row["analysis_timestamp"].replace("Z", "+00:00")),
        )

        # Fetch Permission Findings
        cursor.execute("SELECT * FROM permission_findings WHERE result_id = ?", (res_id,))
        perm_rows = cursor.fetchall()
        permissions: list[PermissionFinding] = []
        for pr in perm_rows:
            permissions.append(
                PermissionFinding(
                    permission=pr["permission_name"],
                    protection_level=pr["protection_level"] or "normal",
                    risk_level=Severity(pr["risk_level"]),
                    family=pr["family"],
                    description=pr["description"] or "",
                    reason=pr["description"] or "Permission granted in manifest",
                    is_sensitive_user_data=bool(pr["is_sensitive_user_data"]),
                )
            )

        # Fetch Security Findings
        cursor.execute("SELECT * FROM security_findings WHERE result_id = ?", (res_id,))
        finding_rows = cursor.fetchall()
        findings: list[SecurityFinding] = []
        for fr in finding_rows:
            findings.append(
                SecurityFinding(
                    rule_id=fr["rule_id"],
                    title=fr["title"],
                    category=FindingCategory(fr["category"]),
                    severity=Severity(fr["severity"]),
                    confidence=Confidence(fr["confidence"]),
                    description=fr["description"] or "",
                    evidence=fr["evidence"] or "",
                    location=fr["location"],
                    impact=fr["impact"],
                    remediation=fr["remediation"],
                    owasp_reference=fr["owasp_reference"],
                    is_static_indicator=bool(fr["is_static_indicator"]),
                )
            )

        completed_dt = datetime.fromisoformat(result_row["created_at"].replace("Z", "+00:00"))
        metrics = AnalysisMetrics(
            started_at=completed_dt,
            completed_at=completed_dt,
            duration_seconds=float(result_row["duration"]),
            files_examined=0,
            rules_executed=len(findings),
            warnings=[],
        )

        return AnalysisResult(
            analysis_id=res_id,
            application=meta,
            overall_risk_score=float(result_row["risk_score"]),
            risk_rating=RiskRating(result_row["risk_rating"]),
            metrics=metrics,
            permissions=permissions,
            findings=findings,
            analyzer_version=result_row["analyzer_version"],
        )

    def list_history(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """Fetch historical scans for display in UI history view.
        
        Args:
            limit: Maximum number of scan records to return.
            offset: Record offset for pagination.
            
        Returns:
            List of summary dictionaries ordered chronologically descending.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT 
                    ar.id AS id,
                    ar.risk_score AS risk_score,
                    ar.risk_rating AS risk_rating,
                    ar.duration AS duration,
                    ar.analyzer_version AS analyzer_version,
                    ar.created_at AS created_at,
                    app.id AS application_id,
                    app.file_hash AS file_hash,
                    app.filename AS filename,
                    app.package_name AS package_name,
                    app.version AS version,
                    app.analysis_timestamp AS analysis_timestamp,
                    app.app_name AS app_name,
                    (SELECT COUNT(*) FROM security_findings sf WHERE sf.result_id = ar.id) AS findings_count,
                    (SELECT COUNT(*) FROM permission_findings pf WHERE pf.result_id = ar.id) AS permissions_count
                FROM analysis_results ar
                JOIN applications app ON ar.application_id = app.id
                ORDER BY ar.created_at DESC
                LIMIT ? OFFSET ?
                """,
                (max(1, limit), max(0, offset)),
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_recent_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        """Alias for list_history for backwards compatibility."""
        return self.list_history(limit=limit)

    def delete_result(self, result_id: str) -> bool:
        """Delete an analysis run and cascade-remove associated findings.
        
        Args:
            result_id: Identifier of the analysis record to delete.
            
        Returns:
            True if a record was removed, False if not found.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT application_id FROM analysis_results WHERE id = ?", (str(result_id),))
            row = cursor.fetchone()
            if not row:
                return False

            app_id = row["application_id"]
            cursor.execute("DELETE FROM analysis_results WHERE id = ?", (str(result_id),))

            # Clean up orphaned application record if no remaining analysis results reference it
            cursor.execute(
                "SELECT COUNT(*) AS cnt FROM analysis_results WHERE application_id = ?",
                (app_id,),
            )
            count_row = cursor.fetchone()
            if count_row and count_row["cnt"] == 0:
                cursor.execute("DELETE FROM applications WHERE id = ?", (app_id,))

            conn.commit()
            logger.info(f"Deleted analysis result '{result_id}'")
            return True

    def clear_history(self) -> int:
        """Delete all historical scans, findings, and applications.
        
        Returns:
            Total count of deleted analysis results.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) AS cnt FROM analysis_results")
            count_row = cursor.fetchone()
            total_deleted = count_row["cnt"] if count_row else 0

            cursor.execute("DELETE FROM security_findings")
            cursor.execute("DELETE FROM permission_findings")
            cursor.execute("DELETE FROM analysis_results")
            cursor.execute("DELETE FROM applications")

            conn.commit()
            logger.info(f"Cleared all analysis history ({total_deleted} scans removed)")
            return total_deleted

    def find_by_hash(self, file_hash: str) -> list[dict[str, Any]]:
        """Find historical scans for an application with a matching SHA-256 hash.
        
        Args:
            file_hash: Target SHA-256 hash string.
            
        Returns:
            List of matching scan summary dictionaries ordered chronologically descending.
        """
        clean_hash = str(file_hash).strip()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT 
                    ar.id AS id,
                    ar.risk_score AS risk_score,
                    ar.risk_rating AS risk_rating,
                    ar.duration AS duration,
                    ar.analyzer_version AS analyzer_version,
                    ar.created_at AS created_at,
                    app.id AS application_id,
                    app.file_hash AS file_hash,
                    app.filename AS filename,
                    app.package_name AS package_name,
                    app.version AS version,
                    app.analysis_timestamp AS analysis_timestamp,
                    app.app_name AS app_name,
                    (SELECT COUNT(*) FROM security_findings sf WHERE sf.result_id = ar.id) AS findings_count,
                    (SELECT COUNT(*) FROM permission_findings pf WHERE pf.result_id = ar.id) AS permissions_count
                FROM analysis_results ar
                JOIN applications app ON ar.application_id = app.id
                WHERE app.file_hash = ?
                ORDER BY ar.created_at DESC
                """,
                (clean_hash,),
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
