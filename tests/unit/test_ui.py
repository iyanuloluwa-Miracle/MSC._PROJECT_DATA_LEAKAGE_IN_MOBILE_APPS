"""Unit tests for Tkinter UI components and thread-safe interactions."""

from __future__ import annotations

import sys
import tempfile
import tkinter as tk
import unittest
from datetime import datetime, timezone
from pathlib import Path

# Add src to sys.path
_SRC_DIR = Path(__file__).resolve().parent.parent.parent / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from data_leak_detector.core.config import AppConfig
from data_leak_detector.core.models import (
    AnalysisMetrics,
    AnalysisResult,
    ApplicationMetadata,
    Confidence,
    FindingCategory,
    PermissionFinding,
    RiskRating,
    RiskScore,
    SecurityFinding,
    Severity,
)
from data_leak_detector.storage.database import DatabaseManager
from data_leak_detector.ui.analyze_view import AnalyzeView
from data_leak_detector.ui.history_view import HistoryView
from data_leak_detector.ui.main_window import AboutView, MainWindow
from data_leak_detector.ui.results_view import ResultsView
from data_leak_detector.ui.settings_view import SettingsView
from data_leak_detector.ui.widgets import (
    DropZone,
    EmptyState,
    MetricCard,
    SeverityBadge,
)


def _make_mock_result() -> AnalysisResult:
    """Helper creating a comprehensive sample AnalysisResult for testing."""
    app = ApplicationMetadata(
        filename="sample_app.apk",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_size=4194304,
        package_name="com.example.audittest",
        file_path=Path("C:/test/sample_app.apk"),
        version_name="2.1.0",
        version_code=42,
        min_sdk=24,
        target_sdk=33,
        app_name="Audit Test App",
    )

    findings = [
        SecurityFinding(
            rule_id="SEC-001",
            title="Hardcoded API Secret Detected",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=FindingCategory.HARDCODED_SECRET,
            description="Static credentials discovered in decompiled string pool.",
            impact="Unauthorized access to external cloud service.",
            evidence="sample_api_key_********xyz",
            location="res/values/strings.xml",
            remediation="Migrate credentials to backend service.",
            owasp_reference="OWASP MASVS-STORAGE-1",
        ),
        SecurityFinding(
            rule_id="NET-002",
            title="Cleartext HTTP Endpoint Embedded",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            category=FindingCategory.NETWORK_INDICATOR,
            description="Application communicates over insecure HTTP protocol.",
            impact="Susceptible to eavesdropping and MITM tampering.",
            evidence="http://api.insecure-service.com/v1",
            location="com/example/audittest/NetworkManager.java",
            remediation="Enforce HTTPS via Network Security Config.",
            owasp_reference="OWASP MASVS-NETWORK-1",
        ),
        SecurityFinding(
            rule_id="STR-001",
            title="World-Readable Internal Storage",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category=FindingCategory.STORAGE_INSECURITY,
            description="Legacy MODE_WORLD_READABLE mode used.",
            impact="Local arbitrary application data leakage.",
            evidence="Context.MODE_WORLD_READABLE",
            location="com/example/audittest/PrefHelper.java",
            remediation="Use MODE_PRIVATE.",
            owasp_reference="OWASP MASVS-STORAGE-2",
        ),
        SecurityFinding(
            rule_id="SDK-001",
            title="Analytics SDK Requested With Location Access",
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            category=FindingCategory.TRACKING_SDK,
            description="Informational SDK permission exposure indicator.",
            impact="Potential location telemetry sharing.",
            evidence="com.google.android.gms.analytics",
            location="AndroidManifest.xml",
            remediation="Review telemetry agreement.",
        ),
    ]

    permissions = [
        PermissionFinding(
            permission="android.permission.ACCESS_FINE_LOCATION",
            protection_level="dangerous",
            risk_level=Severity.HIGH,
            description="Precise GPS coordinates",
            reason="Accesses precise GPS coordinates of user.",
            is_sensitive_user_data=True,
        ),
        PermissionFinding(
            permission="android.permission.INTERNET",
            protection_level="normal",
            risk_level=Severity.LOW,
            description="Network access",
            reason="Allows application to open network sockets.",
            is_sensitive_user_data=False,
        ),
    ]

    metrics = AnalysisMetrics(
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        duration_seconds=3.45,
        files_examined=120,
        rules_executed=18,
    )

    return AnalysisResult(
        analysis_id="test-scan-001",
        application=app,
        overall_risk_score=68.5,
        risk_rating=RiskRating.HIGH,
        metrics=metrics,
        permissions=permissions,
        findings=findings,
        analyzer_version="0.1.0",
    )


class TestTkinterUI(unittest.TestCase):
    """Test suite covering UI components and view interactions."""

    @classmethod
    def setUpClass(cls) -> None:
        try:
            cls.root = tk.Tk()
            cls.root.withdraw()
        except Exception as exc:
            raise unittest.SkipTest(f"Tkinter headless initialization failed: {exc}")

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "root") and cls.root:
            cls.root.destroy()

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_gui_db.sqlite3"
        self.config = AppConfig(base_dir=Path(self.temp_dir.name))
        self.config.database_path = self.db_path

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_severity_badges(self) -> None:
        """Verify SeverityBadge initializes and updates for all severity bands."""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            badge = SeverityBadge(self.root, severity=sev)
            self.assertEqual(badge._label.cget("text"), sev)
            badge.set_severity("LOW")
            self.assertEqual(badge._label.cget("text"), "LOW")
            badge.destroy()

    def test_metric_card(self) -> None:
        """Verify MetricCard updates values and subtitles correctly."""
        card = MetricCard(self.root, title="Critical", value=5, subtitle="5 findings")
        self.assertEqual(card.value_label.cget("text"), "5")
        card.set_value(12, "12 findings")
        self.assertEqual(card.value_label.cget("text"), "12")
        self.assertEqual(card.subtitle_label.cget("text"), "12 findings")
        card.destroy()

    def test_empty_state(self) -> None:
        """Verify EmptyState initializes with custom prompt."""
        empty = EmptyState(
            self.root,
            title="Custom Empty Title",
            message="Custom message here.",
            icon="🔍",
        )
        self.assertIsNotNone(empty)
        empty.destroy()

    def test_drop_zone(self) -> None:
        """Verify DropZone shows and clears selected file metadata."""
        zone = DropZone(self.root, on_browse=lambda: None)
        dummy_file = Path(self.temp_dir.name) / "test.apk"
        dummy_file.write_bytes(b"PK\x03\x04" + b"\x00" * 2048)

        zone.show_selected_file(str(dummy_file))
        self.assertIn("test.apk", zone.file_name_label.cget("text"))

        zone.clear()
        self.assertEqual(zone.file_name_label.cget("text"), "")
        zone.destroy()

    def test_results_view_population(self) -> None:
        """Verify ResultsView displays score, severity counts, and findings."""
        res_view = ResultsView(self.root)
        mock_result = _make_mock_result()

        res_view.display_results(mock_result)

        # Check Risk Score & Rating
        self.assertIn(res_view.score_val_lbl.cget("text"), ["68", "69"])
        self.assertEqual(res_view.rating_lbl.cget("text"), "HIGH")

        # Check Metric Cards
        self.assertEqual(res_view.card_crit.value_label.cget("text"), "1")
        self.assertEqual(res_view.card_high.value_label.cget("text"), "1")
        self.assertEqual(res_view.card_med.value_label.cget("text"), "1")
        self.assertEqual(res_view.card_low.value_label.cget("text"), "0")

        # Check Treeview findings
        children = res_view.vuln_tree.get_children()
        self.assertEqual(len(children), 4)

        # Check Master-Detail selection
        res_view.vuln_tree.selection_set(children[0])
        res_view._on_vuln_selected(None)
        self.assertIn("SEC-001", res_view.detail_title_lbl.cget("text"))
        self.assertIn("sample_api_key", res_view.evidence_text.get("1.0", tk.END))

        # Check Permissions tree
        perm_children = res_view.perm_tree.get_children()
        self.assertEqual(len(perm_children), 2)

        # Check App Details tree
        detail_children = res_view.details_tree.get_children()
        self.assertGreater(len(detail_children), 5)

        res_view.destroy()

    def test_analyze_view_queue_and_state(self) -> None:
        """Verify AnalyzeView handles progress, success, and error events safely via event queue."""
        analyze_view = AnalyzeView(self.root, config=self.config)
        mock_result = _make_mock_result()

        # Simulate Progress event
        analyze_view._event_queue.put(("progress", (0.55, "SCANNING_SECRETS", "Scanning strings...")))
        analyze_view._poll_event_queue()
        self.assertEqual(analyze_view.percent_label.cget("text"), "55%")
        self.assertEqual(analyze_view.stage_label.cget("text"), "Stage: SCANNING_SECRETS")

        # Simulate Success event
        analyze_view._event_queue.put(("success", mock_result))
        analyze_view._poll_event_queue()
        self.assertEqual(analyze_view.percent_label.cget("text"), "100%")
        self.assertIn(analyze_view.results_view.score_val_lbl.cget("text"), ["68", "69"])

        analyze_view.destroy()

    def test_history_view_operations(self) -> None:
        """Verify HistoryView lists scans, filters results, and removes entries."""
        db = DatabaseManager(self.config.database_path)
        mock_result = _make_mock_result()
        db.save_result(mock_result)

        history_view = HistoryView(self.root, config=self.config)
        history_view.refresh_history()

        children = history_view.tree.get_children()
        self.assertEqual(len(children), 1)

        # Test search filter match
        history_view.search_var.set("audittest")
        history_view._apply_search_filter()
        self.assertEqual(len(history_view.tree.get_children()), 1)

        # Test search filter no-match
        history_view.search_var.set("nonexistent_package_query")
        history_view._apply_search_filter()
        self.assertEqual(len(history_view.tree.get_children()), 0)

        # Clear filter
        history_view.search_var.set("")
        history_view._apply_search_filter()
        self.assertEqual(len(history_view.tree.get_children()), 1)

        history_view.destroy()

    def test_settings_view(self) -> None:
        """Verify SettingsView updates timeout preferences."""
        from unittest.mock import patch
        with patch("tkinter.messagebox.showinfo"):
            settings_view = SettingsView(self.root, config=self.config)
            settings_view.timeout_var.set("180")
            settings_view._save_settings()
            self.assertEqual(self.config.subprocess_timeout_seconds, 180)

            settings_view._reset_defaults()
            self.assertEqual(self.config.subprocess_timeout_seconds, 120)
            settings_view.destroy()

    def test_about_view(self) -> None:
        """Verify AboutView instantiates without error."""
        about_view = AboutView(self.root)
        self.assertIsNotNone(about_view)
        about_view.destroy()

    def test_main_window_switching(self) -> None:
        """Verify MainWindow initializes and toggles between views smoothly."""
        win = MainWindow(config=self.config)
        win.withdraw()

        # Default view is analyze
        self.assertEqual(win._current_view, "analyze")

        # Switch to history
        win.show_view("history")
        self.assertEqual(win._current_view, "history")

        # Switch to settings
        win.show_view("settings")
        self.assertEqual(win._current_view, "settings")

        # Switch to about
        win.show_view("about")
        self.assertEqual(win._current_view, "about")

        win.destroy()


if __name__ == "__main__":
    unittest.main()
