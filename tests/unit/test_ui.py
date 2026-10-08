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
    ExpandableFindingCard,
    ExportToolbar,
    FilterBar,
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

        # Check Finding Card Widgets count
        self.assertEqual(len(res_view._finding_card_widgets), 4)

        # Check Treeview findings (compatibility)
        children = res_view.vuln_tree.get_children()
        self.assertEqual(len(children), 4)

        # Check Permissions tree (2 permissions)
        perm_children = res_view.perm_tree.get_children()
        self.assertEqual(len(perm_children), 2)

        # Check 5 columns in permission tree
        cols = res_view.perm_tree["columns"]
        self.assertEqual(
            list(cols),
            ["permission", "protection_level", "risk_level", "description", "reason"],
        )

        # Check App Details tree
        detail_children = res_view.details_tree.get_children()
        self.assertGreater(len(detail_children), 5)

        # Check Category Breakdown Labels
        self.assertIn("Secrets", res_view.cat_count_labels)
        self.assertIn("1 findings", res_view.cat_count_labels["Secrets"].cget("text"))

        res_view.destroy()

    def test_expandable_finding_card(self) -> None:
        """Verify ExpandableFindingCard displays summary, toggles details, and redacts evidence."""
        mock_result = _make_mock_result()
        finding = mock_result.findings[0]

        card = ExpandableFindingCard(self.root, finding=finding)

        # Check initial state: collapsed
        self.assertFalse(card.is_expanded)
        self.assertEqual(card.title_lbl.cget("text"), finding.title)
        self.assertIn("SEC-001", card.finding.rule_id)

        # Check plain-language explanation
        self.assertEqual(card.desc_lbl.cget("text"), finding.description)

        # Expand card
        card.expand()
        self.assertTrue(card.is_expanded)
        self.assertEqual(card.btn_toggle.cget("text"), "▲ Collapse")

        # Verify evidence is strictly sanitized
        self.assertIn("sample_api_key", card.sanitized_evidence)
        self.assertIn("********", card.sanitized_evidence)

        # Collapse card
        card.collapse()
        self.assertFalse(card.is_expanded)
        self.assertEqual(card.btn_toggle.cget("text"), "▼ Details")

        card.destroy()

    def test_filter_bar_and_category_filtering(self) -> None:
        """Verify Severity filter, Category filter, and search filter in ResultsView."""
        res_view = ResultsView(self.root)
        mock_result = _make_mock_result()
        res_view.display_results(mock_result)

        # Total findings initially
        self.assertEqual(len(res_view._finding_card_widgets), 4)

        # 1. Filter by Severity: CRITICAL
        res_view.filter_bar.sev_var.set("Critical")
        res_view._apply_finding_filters()
        self.assertEqual(len(res_view._finding_card_widgets), 1)

        # 2. Filter by Category: Network
        res_view.filter_bar.sev_var.set("All")
        res_view.filter_bar.cat_var.set("Network")
        res_view._apply_finding_filters()
        self.assertEqual(len(res_view._finding_card_widgets), 1)
        self.assertIn("Cleartext HTTP", res_view._finding_card_widgets[0].finding.title)

        # 3. Filter by Category: Secrets
        res_view.filter_bar.cat_var.set("Secrets")
        res_view._apply_finding_filters()
        self.assertEqual(len(res_view._finding_card_widgets), 1)
        self.assertIn("Hardcoded API Secret", res_view._finding_card_widgets[0].finding.title)

        # 4. Search filter: "Storage"
        res_view.filter_bar.cat_var.set("All")
        res_view.filter_bar.search_var.set("MODE_WORLD_READABLE")
        res_view._apply_finding_filters()
        self.assertEqual(len(res_view._finding_card_widgets), 1)
        self.assertIn("World-Readable", res_view._finding_card_widgets[0].finding.title)

        # 5. Reset filters
        res_view.filter_bar.reset_filters()
        self.assertEqual(len(res_view._finding_card_widgets), 4)

        # 6. Expand all and Collapse all
        res_view._expand_all_cards()
        self.assertTrue(all(c.is_expanded for c in res_view._finding_card_widgets))
        res_view._collapse_all_cards()
        self.assertTrue(all(not c.is_expanded for c in res_view._finding_card_widgets))

        res_view.destroy()

    def test_export_buttons_presence(self) -> None:
        """Verify Export PDF, Export HTML, and Export TXT buttons exist in ResultsView."""
        res_view = ResultsView(self.root)
        self.assertIsNotNone(res_view.btn_export_pdf)
        self.assertIsNotNone(res_view.btn_export_html)
        self.assertIsNotNone(res_view.btn_export_txt)
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
        """Verify HistoryView lists scans, columns, search by app/package, sort, open, delete, and clear."""
        from unittest.mock import patch

        db = DatabaseManager(self.config.database_path)
        mock_result = _make_mock_result()
        db.save_result(mock_result)

        inspected_results = []
        history_view = HistoryView(
            self.root,
            config=self.config,
            on_inspect_result=lambda res: inspected_results.append(res),
        )
        history_view.refresh_history()

        children = history_view.tree.get_children()
        self.assertEqual(len(children), 1)

        # Check column values: app_name, package_name, version, created_at, risk_score, risk_rating
        values = history_view.tree.item(children[0], "values")
        self.assertEqual(values[0], "Audit Test App")  # application name
        self.assertEqual(values[1], "com.example.audittest")  # package name
        self.assertEqual(values[2], "2.1.0")  # version
        self.assertTrue(len(values[3]) > 0)  # analysis date
        self.assertTrue("85" in values[4] or "100" in values[4])  # risk score
        self.assertEqual(values[5], "HIGH")  # risk rating

        # Test search by application name
        history_view.search_var.set("Audit Test")
        history_view._apply_search_filter()
        self.assertEqual(len(history_view.tree.get_children()), 1)

        # Test search by package name
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

        # Test sorting
        history_view.sort_var.set("Oldest First")
        history_view._apply_search_filter()
        self.assertEqual(len(history_view.tree.get_children()), 1)

        history_view.sort_var.set("Newest First")
        history_view._apply_search_filter()
        self.assertEqual(len(history_view.tree.get_children()), 1)

        # Test Open Previous Result
        history_view.tree.selection_set(children[0])
        history_view.open_previous_result()
        self.assertEqual(len(inspected_results), 1)
        self.assertEqual(inspected_results[0].application.package_name, "com.example.audittest")

        # Test Delete Result (with mocked confirmation)
        with patch("tkinter.messagebox.askyesno", return_value=True), patch("tkinter.messagebox.showinfo"):
            history_view.delete_result()
            self.assertEqual(len(history_view.tree.get_children()), 0)

        # Re-save and Test Clear History (with mocked confirmation)
        db.save_result(mock_result)
        history_view.refresh_history()
        self.assertEqual(len(history_view.tree.get_children()), 1)

        with patch("tkinter.messagebox.askyesno", return_value=True), patch("tkinter.messagebox.showinfo"):
            history_view.clear_history()
            self.assertEqual(len(history_view.tree.get_children()), 0)

        history_view.destroy()

    def test_settings_view(self) -> None:
        """Verify SettingsView updates preferences, diagnostic check, rule toggles, and reset."""
        from unittest.mock import patch
        with patch("tkinter.messagebox.showinfo"):
            settings_view = SettingsView(self.root, config=self.config)
            
            # Check Tools button execution
            settings_view.check_tools()
            self.assertTrue(hasattr(settings_view, "androguard_status_lbl"))
            self.assertTrue(hasattr(settings_view, "apktool_status_lbl"))
            self.assertTrue(hasattr(settings_view, "jadx_status_lbl"))
            self.assertTrue(hasattr(settings_view, "java_status_lbl"))

            # Update paths, preferences, and rules
            settings_view.timeout_var.set("180")
            settings_view.high_contrast_var.set(True)
            settings_view.report_fmt_var.set("HTML")
            settings_view.rule_manifest_var.set(False)
            settings_view.save_settings()

            self.assertEqual(self.config.subprocess_timeout_seconds, 180)
            self.assertTrue(self.config.high_contrast_mode)
            self.assertEqual(self.config.report_default_format, "HTML")
            self.assertFalse(self.config.enable_manifest_rules)

            # Test Reset Settings
            with patch("tkinter.messagebox.askyesno", return_value=True):
                settings_view.reset_settings()
                self.assertEqual(self.config.subprocess_timeout_seconds, 120)
                self.assertFalse(self.config.high_contrast_mode)
                self.assertEqual(self.config.report_default_format, "PDF")
                self.assertTrue(self.config.enable_manifest_rules)

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
