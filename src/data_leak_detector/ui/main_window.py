"""Main Application Window with sidebar navigation, keyboard shortcuts, and view orchestration."""

from __future__ import annotations

import logging
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any

from data_leak_detector.core.config import AppConfig
from data_leak_detector.core.models import AnalysisResult
from data_leak_detector.ui.analyze_view import AnalyzeView
from data_leak_detector.ui.batch_view import BatchView
from data_leak_detector.ui.history_view import HistoryView
from data_leak_detector.ui.settings_view import SettingsView
from data_leak_detector.ui.widgets import (
    COLOR_ACCENT,
    COLOR_BG,
    COLOR_BORDER_LIGHT,
    COLOR_CARD_BG,
    COLOR_SIDEBAR_ACTIVE,
    COLOR_SIDEBAR_BG,
    COLOR_SIDEBAR_HOVER,
    COLOR_SIDEBAR_MUTED,
    COLOR_SIDEBAR_TEXT,
    COLOR_SUCCESS,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    FONT_BODY,
    FONT_BODY_BOLD,
    FONT_HEADING,
    FONT_SMALL,
    FONT_SUBHEADING,
    FONT_TITLE,
    apply_custom_styles,
)

logger = logging.getLogger(__name__)


class AboutView(ttk.Frame):
    """About view displaying academic research context, capabilities, and methodology."""

    def __init__(self, master: tk.Misc, *args, **kwargs) -> None:
        super().__init__(master, *args, **kwargs)

        container = tk.Frame(self, bg=COLOR_BG, padx=30, pady=24)
        container.pack(fill=tk.BOTH, expand=True)

        card = tk.Frame(
            container,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=28,
            pady=24,
        )
        card.pack(fill=tk.BOTH, expand=True)

        # Title & Subtitle
        tk.Label(
            card,
            text="Mobile Data Leak Detector",
            font=(FONT_TITLE[0], 18, "bold"),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill=tk.X)

        tk.Label(
            card,
            text="Academic Research Prototype • Version 0.1.0",
            font=FONT_SUBHEADING,
            bg=COLOR_CARD_BG,
            fg=COLOR_ACCENT,
            anchor="w",
        ).pack(fill=tk.X, pady=(2, 14))

        # Description
        desc_text = (
            "This software is an academic static analysis prototype designed to detect potential data leakage, "
            "credential exposure, and security weaknesses in compiled Android applications (.apk). "
            "It conducts thorough static analysis of AndroidManifest.xml, compiled DEX bytecode, and embedded "
            "resources without executing the application on a target device."
        )
        tk.Label(
            card,
            text=desc_text,
            font=FONT_BODY,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            wraplength=760,
            justify="left",
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 16))

        # Key Modules
        tk.Label(
            card,
            text="Core Research Capabilities:",
            font=FONT_HEADING,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 6))

        features = [
            "• Permission Overprivilege Auditing: Dangerous combinations (Location + Cellular State + Internet).",
            "• Secret & Token Redaction: Identifies API keys, tokens, and credentials with zero raw secrets displayed.",
            "• Network Communication Auditing: Cleartext HTTP, certificate bypasses, and embedded tracking domains.",
            "• Insecure Storage & Cryptography: External sensitive storage, hardcoded keys, ECB mode, and weak ciphers.",
            "• Third-Party SDK Profiling: Configurable tracking SDK detection and Permission Exposure modeling.",
            "• Transparent Weighted Risk Scoring: Explainable 0-100 heuristic scoring based on severity and confidence.",
            "• Multi-format Reporting: Publication-grade PDF (via ReportLab Platypus), standalone HTML, and Markdown.",
        ]
        for feat in features:
            tk.Label(
                card,
                text=feat,
                font=FONT_BODY,
                bg=COLOR_CARD_BG,
                fg=COLOR_TEXT_PRIMARY,
                anchor="w",
            ).pack(fill=tk.X, pady=2)

        # Academic Disclaimer
        disc_box = tk.Frame(card, bg="#f8fafc", padx=14, pady=12, highlightbackground=COLOR_BORDER_LIGHT, highlightthickness=1)
        disc_box.pack(fill=tk.X, pady=(18, 0))

        tk.Label(
            disc_box,
            text="Academic Methodology Notice:",
            font=FONT_BODY_BOLD,
            bg="#f8fafc",
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill=tk.X)

        disc_msg = (
            "Static analysis evaluates potential architectural vulnerabilities. The absence of findings does not "
            "guarantee an application is entirely secure, nor does static presence of an endpoint or SDK prove that "
            "sensitive data was actively transmitted at runtime. The risk score is a heuristic prioritisation metric "
            "and should not be interpreted as CVSS."
        )
        tk.Label(
            disc_box,
            text=disc_msg,
            font=FONT_SMALL,
            bg="#f8fafc",
            fg=COLOR_TEXT_MUTED,
            wraplength=730,
            justify="left",
            anchor="w",
        ).pack(fill=tk.X, pady=(4, 0))


class MainWindow(tk.Tk):
    """Primary application window hosting left sidebar and switchable view containers."""

    def __init__(self, config: AppConfig | None = None) -> None:
        super().__init__()
        self.app_config = config or AppConfig()

        self._init_window()
        self._init_styles()
        self._init_layout()
        self._bind_shortcuts()

    def _init_window(self) -> None:
        """Configure main window properties, title, and minimum dimensions."""
        self.title("Mobile Data Leak Detector - Academic Research Tool")
        self.geometry("1180x820")
        self.minsize(960, 640)
        self.configure(bg=COLOR_BG)

        # Protocol for clean window exit
        self.protocol("WM_DELETE_WINDOW", self._on_close_requested)

    def _init_styles(self) -> None:
        """Initialize custom ttk styling."""
        self.style = ttk.Style(self)
        apply_custom_styles(self.style)

    def _init_layout(self) -> None:
        """Construct sidebar and main content views."""
        # Main horizontal split: Sidebar on Left, Content on Right
        self.main_container = tk.Frame(self, bg=COLOR_BG)
        self.main_container.pack(fill=tk.BOTH, expand=True)

        # ---------------------------------------------------------------------
        # LEFT SIDEBAR
        # ---------------------------------------------------------------------
        self.sidebar = tk.Frame(
            self.main_container,
            bg=COLOR_SIDEBAR_BG,
            width=230,
        )
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.sidebar.pack_propagate(False)

        # App Brand Header
        brand_frame = tk.Frame(self.sidebar, bg=COLOR_SIDEBAR_BG, padx=18, pady=20)
        brand_frame.pack(fill=tk.X)

        brand_title = tk.Label(
            brand_frame,
            text="🛡 Leak Detector",
            font=(FONT_TITLE[0], 14, "bold"),
            bg=COLOR_SIDEBAR_BG,
            fg=COLOR_SIDEBAR_TEXT,
            anchor="w",
        )
        brand_title.pack(fill=tk.X)

        brand_sub = tk.Label(
            brand_frame,
            text="Android Security Audit",
            font=FONT_SMALL,
            bg=COLOR_SIDEBAR_BG,
            fg=COLOR_SIDEBAR_MUTED,
            anchor="w",
        )
        brand_sub.pack(fill=tk.X, pady=(2, 0))

        # Divider
        tk.Frame(self.sidebar, bg="#1e293b", height=1).pack(fill=tk.X, padx=12, pady=(0, 10))

        # Navigation Buttons Container
        self.nav_container = tk.Frame(self.sidebar, bg=COLOR_SIDEBAR_BG, padx=10)
        self.nav_container.pack(fill=tk.X)

        self._nav_buttons: dict[str, tk.Frame] = {}
        self._current_view = "analyze"

        # Create sidebar items
        self._create_sidebar_item("analyze", "📊 Dashboard / Analyze", "Ctrl+1")
        self._create_sidebar_item("batch", "📦 Batch Analysis", "Ctrl+2")
        self._create_sidebar_item("history", "📜 History", "Ctrl+3")
        self._create_sidebar_item("settings", "⚙ Settings", "Ctrl+4")
        self._create_sidebar_item("about", "ℹ About", "Ctrl+5")

        # Sidebar Footer
        footer_frame = tk.Frame(self.sidebar, bg=COLOR_SIDEBAR_BG, padx=16, pady=16)
        footer_frame.pack(side=tk.BOTTOM, fill=tk.X)

        tk.Frame(self.sidebar, bg="#1e293b", height=1).pack(side=tk.BOTTOM, fill=tk.X, padx=12)

        status_dot = tk.Label(
            footer_frame,
            text="● SQLite Connected",
            font=FONT_SMALL,
            bg=COLOR_SIDEBAR_BG,
            fg=COLOR_SUCCESS,
            anchor="w",
        )
        status_dot.pack(fill=tk.X)

        version_lbl = tk.Label(
            footer_frame,
            text="v0.1.0 • Academic Build",
            font=FONT_SMALL,
            bg=COLOR_SIDEBAR_BG,
            fg=COLOR_SIDEBAR_MUTED,
            anchor="w",
        )
        version_lbl.pack(fill=tk.X, pady=(2, 0))

        # ---------------------------------------------------------------------
        # MAIN CONTENT AREA
        # ---------------------------------------------------------------------
        self.content_area = tk.Frame(self.main_container, bg=COLOR_BG)
        self.content_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Initialize View Instances
        self.views: dict[str, ttk.Frame] = {}

        self.views["analyze"] = AnalyzeView(
            self.content_area,
            config=self.app_config,
            on_analysis_completed=self._on_scan_completed,
        )

        self.views["batch"] = BatchView(
            self.content_area,
            config=self.app_config,
            on_inspect_result=self._on_inspect_history_result,
        )

        self.views["history"] = HistoryView(
            self.content_area,
            config=self.app_config,
            on_inspect_result=self._on_inspect_history_result,
        )

        self.views["settings"] = SettingsView(
            self.content_area,
            config=self.app_config,
        )

        self.views["about"] = AboutView(
            self.content_area,
        )

        # Show default view: analyze
        self.show_view("analyze")

    def _create_sidebar_item(self, view_key: str, label_text: str, shortcut: str) -> None:
        """Create an interactive sidebar navigation item with hover and active states."""
        btn_frame = tk.Frame(
            self.nav_container,
            bg=COLOR_SIDEBAR_BG,
            padx=12,
            pady=10,
            cursor="hand2",
        )
        btn_frame.pack(fill=tk.X, pady=2)

        lbl = tk.Label(
            btn_frame,
            text=label_text,
            font=FONT_BODY_BOLD,
            bg=COLOR_SIDEBAR_BG,
            fg=COLOR_SIDEBAR_TEXT,
            anchor="w",
        )
        lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

        shortcut_lbl = tk.Label(
            btn_frame,
            text=shortcut,
            font=FONT_SMALL,
            bg=COLOR_SIDEBAR_BG,
            fg=COLOR_SIDEBAR_MUTED,
        )
        shortcut_lbl.pack(side=tk.RIGHT)

        # Event bindings
        def on_click(_event: Any, key: str = view_key) -> None:
            self.show_view(key)

        def on_enter(_event: Any, frame: tk.Frame = btn_frame, key: str = view_key) -> None:
            self._on_nav_enter(frame, key)

        def on_leave(_event: Any, frame: tk.Frame = btn_frame, key: str = view_key) -> None:
            self._on_nav_leave(frame, key)

        for widget in (btn_frame, lbl, shortcut_lbl):
            widget.bind("<Button-1>", on_click)
            widget.bind("<Enter>", on_enter)
            widget.bind("<Leave>", on_leave)

        self._nav_buttons[view_key] = btn_frame

    def _on_nav_enter(self, frame: tk.Frame, key: str) -> None:
        """Highlight sidebar button on mouse hover."""
        if self._current_view != key:
            frame.config(bg=COLOR_SIDEBAR_HOVER)
            for child in frame.winfo_children():
                if isinstance(child, tk.Label):
                    child.config(bg=COLOR_SIDEBAR_HOVER)

    def _on_nav_leave(self, frame: tk.Frame, key: str) -> None:
        """Restore sidebar button background on mouse leave."""
        if self._current_view != key:
            frame.config(bg=COLOR_SIDEBAR_BG)
            for child in frame.winfo_children():
                if isinstance(child, tk.Label):
                    child.config(bg=COLOR_SIDEBAR_BG)

    def show_view(self, view_key: str) -> None:
        """Switch active view in the main content container."""
        if view_key not in self.views:
            return

        self._current_view = view_key

        # Update sidebar active styling
        for key, frame in self._nav_buttons.items():
            if key == view_key:
                frame.config(bg=COLOR_SIDEBAR_ACTIVE)
                for child in frame.winfo_children():
                    if isinstance(child, tk.Label):
                        child.config(bg=COLOR_SIDEBAR_ACTIVE, fg="#ffffff")
            else:
                frame.config(bg=COLOR_SIDEBAR_BG)
                for child in frame.winfo_children():
                    if isinstance(child, tk.Label):
                        child.config(
                            bg=COLOR_SIDEBAR_BG,
                            fg=COLOR_SIDEBAR_TEXT if child.cget("text").startswith(("📊", "📦", "📜", "⚙", "ℹ")) else COLOR_SIDEBAR_MUTED,
                        )

        # Hide other views, show target view
        for key, view in self.views.items():
            if key == view_key:
                view.pack(fill=tk.BOTH, expand=True)
                # If switching to history, refresh items
                if key == "history" and hasattr(view, "refresh_history"):
                    view.refresh_history()
            else:
                view.pack_forget()

    # -------------------------------------------------------------------------
    # INTER-VIEW EVENT HANDLING
    # -------------------------------------------------------------------------
    def _on_scan_completed(self, result: AnalysisResult) -> None:
        """Callback triggered when static analysis completes in AnalyzeView."""
        logger.info("Scan completed for: %s", result.application.package_name)
        # History will automatically update on next view

    def _on_inspect_history_result(self, result: AnalysisResult) -> None:
        """Load an analysis result from history directly into the analyze view."""
        self.show_view("analyze")
        analyze_view: AnalyzeView = self.views["analyze"]  # type: ignore
        analyze_view.load_external_result(result)

    # -------------------------------------------------------------------------
    # KEYBOARD NAVIGATION SHORTCUTS
    # -------------------------------------------------------------------------
    def _bind_shortcuts(self) -> None:
        """Bind global keyboard shortcuts for seamless navigation."""
        self.bind("<Control-Key-1>", lambda e: self.show_view("analyze"))
        self.bind("<Control-Key-2>", lambda e: self.show_view("batch"))
        self.bind("<Control-Key-3>", lambda e: self.show_view("history"))
        self.bind("<Control-Key-4>", lambda e: self.show_view("settings"))
        self.bind("<Control-Key-5>", lambda e: self.show_view("about"))

        # Ctrl+O: Open file dialog
        self.bind("<Control-Key-o>", self._shortcut_open_file)
        self.bind("<Control-Key-O>", self._shortcut_open_file)

        # Ctrl+Enter or F5: Start analysis
        self.bind("<Control-Return>", self._shortcut_start_analysis)
        self.bind("<F5>", self._shortcut_start_analysis)

        # Escape: Cancel ongoing scan
        self.bind("<Escape>", self._shortcut_cancel_analysis)

    def _shortcut_open_file(self, event: Any = None) -> None:
        """Trigger file selection from keyboard shortcut."""
        self.show_view("analyze")
        analyze_view: AnalyzeView = self.views["analyze"]  # type: ignore
        analyze_view.browse_apk_file()

    def _shortcut_start_analysis(self, event: Any = None) -> None:
        """Trigger start analysis from keyboard shortcut."""
        if self._current_view == "analyze":
            analyze_view: AnalyzeView = self.views["analyze"]  # type: ignore
            analyze_view.start_analysis()

    def _shortcut_cancel_analysis(self, event: Any = None) -> None:
        """Trigger cancellation from keyboard shortcut."""
        if self._current_view == "analyze":
            analyze_view: AnalyzeView = self.views["analyze"]  # type: ignore
            if analyze_view._is_running:
                analyze_view.cancel_analysis()
        elif self._current_view == "batch":
            batch_view: Any = self.views.get("batch")
            if batch_view and batch_view.processor.is_running:
                batch_view.cancel_all()

    def _on_close_requested(self) -> None:
        """Handle window close event gracefully."""
        analyze_view: AnalyzeView = self.views.get("analyze")  # type: ignore
        batch_view: Any = self.views.get("batch")
        is_running = (analyze_view and analyze_view._is_running) or (
            batch_view and batch_view.processor.is_running
        )

        if is_running:
            confirm = messagebox.askyesno(
                "Analysis In Progress",
                "A static analysis scan is currently running.\nDo you want to cancel the scan and exit?",
            )
            if confirm:
                if analyze_view and analyze_view._is_running:
                    analyze_view.cancel_analysis()
                if batch_view and batch_view.processor.is_running:
                    batch_view.cancel_all()
                self.destroy()
        else:
            self.destroy()
