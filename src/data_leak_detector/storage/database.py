"""Local SQLite persistence manager for scan history."""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

from data_leak_detector.core.models import AnalysisResult


logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages local SQLite database operations for persisting and retrieving scan history."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)

    def initialize_schema(self) -> None:
        """Create scans and findings tables if not present."""
        raise NotImplementedError("Database schema initialization not yet implemented.")

    def save_scan_result(self, result: AnalysisResult) -> int:
        """Save analysis result to local database. Returns generated scan record ID."""
        raise NotImplementedError("save_scan_result not yet implemented.")

    def get_recent_scans(self, limit: int = 50) -> list[dict]:
        """Fetch historical scans for display in UI history view."""
        raise NotImplementedError("get_recent_scans not yet implemented.")

    def get_scan_by_id(self, scan_id: int) -> AnalysisResult | None:
        """Retrieve full details of a past scan by its record ID."""
        raise NotImplementedError("get_scan_by_id not yet implemented.")
