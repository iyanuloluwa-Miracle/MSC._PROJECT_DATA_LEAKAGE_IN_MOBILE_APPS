"""Tkinter / ttk desktop user interface components."""

from data_leak_detector.ui.analyze_view import AnalyzeView
from data_leak_detector.ui.history_view import HistoryView
from data_leak_detector.ui.main_window import MainWindow
from data_leak_detector.ui.results_view import ResultsView
from data_leak_detector.ui.settings_view import SettingsView
from data_leak_detector.ui.widgets import (
    CategoryBadge,
    ConfidenceBadge,
    DisclaimerBanner,
    DropZone,
    EmptyState,
    ExpandableFindingCard,
    ExportToolbar,
    FilterBar,
    MetricCard,
    ScrollableFrame,
    SeverityBadge,
    apply_custom_styles,
)

__all__ = [
    "MainWindow",
    "AnalyzeView",
    "ResultsView",
    "HistoryView",
    "SettingsView",
    "SeverityBadge",
    "ConfidenceBadge",
    "CategoryBadge",
    "MetricCard",
    "EmptyState",
    "DropZone",
    "ScrollableFrame",
    "ExpandableFindingCard",
    "FilterBar",
    "ExportToolbar",
    "DisclaimerBanner",
    "apply_custom_styles",
]
