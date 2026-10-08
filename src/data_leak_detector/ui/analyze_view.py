"""Analyze View: File selector, background worker threading, progress indicators, and results display."""

from __future__ import annotations

import logging
import queue
import threading
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
import tkinter as tk
from typing import Any, Callable

from data_leak_detector.analysis.engine import AnalysisEngine, CancellationToken, ProgressUpdate
from data_leak_detector.core.config import AppConfig
from data_leak_detector.core.exceptions import AnalysisCancelledError
from data_leak_detector.core.models import AnalysisResult
from data_leak_detector.storage.database import DatabaseManager
from data_leak_detector.ui.results_view import ResultsView
from data_leak_detector.ui.widgets import (
    COLOR_ACCENT,
    COLOR_BG,
    COLOR_BORDER_LIGHT,
    COLOR_CARD_BG,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    FONT_BODY,
    FONT_BODY_BOLD,
    FONT_CODE,
    FONT_HEADING,
    FONT_SMALL,
    FONT_SUBHEADING,
    FONT_SUBTITLE,
    FONT_TITLE,
    DropZone,
    EmptyState,
)

logger = logging.getLogger(__name__)


class AnalyzeView(ttk.Frame):
    """Primary analysis view orchestrating APK selection, non-blocking scan, and result inspection."""

    def __init__(
        self,
        master: tk.Misc,
        config: AppConfig | None = None,
        on_analysis_completed: Callable[[AnalysisResult], None] | None = None,
        *args,
        **kwargs,
    ) -> None:
        super().__init__(master, *args, **kwargs)
        self.config = config or AppConfig()
        self.on_analysis_completed = on_analysis_completed

        self.selected_apk_path: Path | None = None
        self._cancellation_token: CancellationToken | None = None
        self._worker_thread: threading.Thread | None = None
        self._event_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._is_running = False

        self._init_layout()
        self._poll_event_queue()

    def _init_layout(self) -> None:
        """Create header, selection area, progress monitor, and results container."""
        # Top Header Area
        header_frame = tk.Frame(self, bg=COLOR_BG, padx=20, pady=16)
        header_frame.pack(fill=tk.X)

        title_lbl = tk.Label(
            header_frame,
            text="Mobile Data Leak Detector",
            font=FONT_TITLE,
            bg=COLOR_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        )
        title_lbl.pack(fill=tk.X)

        sub_lbl = tk.Label(
            header_frame,
            text="Analyze Android applications for potential privacy and data-leak risks.",
            font=FONT_SUBTITLE,
            bg=COLOR_BG,
            fg=COLOR_TEXT_MUTED,
            anchor="w",
        )
        sub_lbl.pack(fill=tk.X, pady=(2, 0))

        # APK Selection Area
        selection_container = tk.Frame(self, bg=COLOR_BG, padx=20, pady=6)
        selection_container.pack(fill=tk.X)

        self.drop_zone = DropZone(
            selection_container,
            on_browse=self.browse_apk_file,
            on_file_dropped=self.set_selected_apk,
        )
        self.drop_zone.pack(fill=tk.X)

        # Action Buttons Row (Analyze & Cancel)
        actions_frame = tk.Frame(self, bg=COLOR_BG, padx=20, pady=8)
        actions_frame.pack(fill=tk.X)

        self.btn_analyze = ttk.Button(
            actions_frame,
            text="▶ Start Static Analysis",
            style="Primary.TButton",
            command=self.start_analysis,
        )
        self.btn_analyze.pack(side=tk.LEFT, padx=(0, 10))

        self.btn_cancel = ttk.Button(
            actions_frame,
            text="⏹ Cancel",
            style="Danger.TButton",
            state=tk.DISABLED,
            command=self.cancel_analysis,
        )
        self.btn_cancel.pack(side=tk.LEFT, padx=(0, 10))

        self.btn_clear = ttk.Button(
            actions_frame,
            text="Clear Selection",
            style="Secondary.TButton",
            command=self.clear_selection,
        )
        self.btn_clear.pack(side=tk.LEFT)

        # Progress Area (Initially idle/hidden)
        self.progress_frame = tk.Frame(
            self,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=16,
            pady=10,
        )
        # Note: packed dynamically when analysis is started

        prog_top = tk.Frame(self.progress_frame, bg=COLOR_CARD_BG)
        prog_top.pack(fill=tk.X)

        self.stage_label = tk.Label(
            prog_top,
            text="Ready",
            font=FONT_BODY_BOLD,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        )
        self.stage_label.pack(side=tk.LEFT)

        self.percent_label = tk.Label(
            prog_top,
            text="0%",
            font=FONT_BODY_BOLD,
            bg=COLOR_CARD_BG,
            fg=COLOR_ACCENT,
            anchor="e",
        )
        self.percent_label.pack(side=tk.RIGHT)

        self.progress_bar = ttk.Progressbar(
            self.progress_frame,
            orient=tk.HORIZONTAL,
            mode="determinate",
            style="TProgressbar",
        )
        self.progress_bar.pack(fill=tk.X, pady=(6, 4))

        self.status_message = tk.Label(
            self.progress_frame,
            text="Waiting to launch scan...",
            font=FONT_SMALL,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_MUTED,
            anchor="w",
        )
        self.status_message.pack(fill=tk.X)

        # Results Area (Switchable container)
        self.results_container = tk.Frame(self, bg=COLOR_BG)
        self.results_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=(6, 12))

        # 1. Empty State
        self.empty_state = EmptyState(
            self.results_container,
            title="No Static Analysis Performed",
            message=(
                "Select an Android APK package using the Browse button above, then click "
                "'Start Static Analysis' to audit permissions, embedded credentials, and leakage indicators."
            ),
            icon="📱",
        )
        self.empty_state.pack(fill=tk.BOTH, expand=True)

        # 2. Loading State Frame
        self.loading_state = tk.Frame(self.results_container, bg=COLOR_CARD_BG, padx=24, pady=36)
        tk.Label(
            self.loading_state,
            text="⚡",
            font=(FONT_TITLE[0], 36),
            bg=COLOR_CARD_BG,
            fg=COLOR_ACCENT,
        ).pack(pady=(0, 10))

        tk.Label(
            self.loading_state,
            text="Static Vulnerability Analysis In Progress",
            font=FONT_HEADING,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(pady=(0, 4))

        self.loading_detail_lbl = tk.Label(
            self.loading_state,
            text="Decompiling bytecode and scanning resources for data leaks...",
            font=FONT_BODY,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_MUTED,
            wraplength=520,
            justify="center",
        )
        self.loading_detail_lbl.pack(pady=(0, 10))

        # 3. Results View
        self.results_view = ResultsView(self.results_container)

    # -------------------------------------------------------------------------
    # FILE SELECTION
    # -------------------------------------------------------------------------
    def browse_apk_file(self) -> None:
        """Open native file dialog to choose an APK package."""
        if self._is_running:
            return

        chosen = filedialog.askopenfilename(
            title="Select Target Android Package",
            filetypes=[
                ("Android Packages (*.apk)", "*.apk"),
                ("All Files (*.*)", "*.*"),
            ],
        )
        if chosen:
            self.set_selected_apk(chosen)

    def set_selected_apk(self, path_str: str) -> None:
        """Validate and set target APK file."""
        p = Path(path_str)
        if not p.exists() or not p.is_file():
            messagebox.showerror("Invalid File", f"The selected file does not exist:\n{path_str}")
            return

        if not p.name.lower().endswith(".apk"):
            resp = messagebox.askyesno(
                "Unusual Extension",
                f"The selected file '{p.name}' does not have an '.apk' extension.\nDo you want to proceed anyway?",
            )
            if not resp:
                return

        self.selected_apk_path = p
        self.drop_zone.show_selected_file(str(p))
        self.stage_label.config(text=f"Selected: {p.name}")
        self.status_message.config(text="File verified. Click 'Start Static Analysis' to begin.")

    def clear_selection(self) -> None:
        """Clear the current APK selection and restore empty state."""
        if self._is_running:
            return

        self.selected_apk_path = None
        self.drop_zone.clear()
        self.progress_frame.pack_forget()
        self._show_empty_state()

    # -------------------------------------------------------------------------
    # NON-BLOCKING BACKGROUND ANALYSIS
    # -------------------------------------------------------------------------
    def start_analysis(self) -> None:
        """Initiate background static analysis on the selected APK."""
        if self._is_running:
            return

        if not self.selected_apk_path:
            # If no APK selected, prompt user to browse
            self.browse_apk_file()
            if not self.selected_apk_path:
                return

        apk_path = self.selected_apk_path
        self._is_running = True
        self._cancellation_token = CancellationToken()

        # Update UI Controls state
        self.btn_analyze.config(state=tk.DISABLED)
        self.btn_cancel.config(state=tk.NORMAL)
        self.btn_clear.config(state=tk.DISABLED)
        self.drop_zone.browse_btn.config(state=tk.DISABLED)

        # Show progress frame
        self.progress_frame.pack(fill=tk.X, padx=20, pady=(0, 8), before=self.results_container)
        self.progress_bar.config(value=0)
        self.percent_label.config(text="0%")
        self.stage_label.config(text="Initializing Pipeline...")
        self.status_message.config(text="Preparing analysis engine...")

        # Switch to loading state in results container
        self._show_loading_state(f"Analyzing {apk_path.name}...")

        # Spawn background worker thread
        self._worker_thread = threading.Thread(
            target=self._worker_run,
            args=(apk_path, self._cancellation_token),
            name="StaticAnalysisWorker",
            daemon=True,
        )
        self._worker_thread.start()

    def cancel_analysis(self) -> None:
        """Request cooperative cancellation of the running scan."""
        if self._is_running and self._cancellation_token:
            self.btn_cancel.config(state=tk.DISABLED)
            self.status_message.config(text="Cancelling analysis... Cleaning temporary resources.")
            self._cancellation_token.cancel()

    def _worker_run(self, apk_path: Path, token: CancellationToken) -> None:
        """Worker thread entry point: executes static analysis without touching Tkinter widgets."""
        logger.info("Worker started static analysis on: %s", apk_path)

        def progress_listener(progress: float, stage: Any, message: str = "") -> None:
            stage_str = stage.value if hasattr(stage, "value") else str(stage)
            self._event_queue.put(("progress", (progress, stage_str, message)))

        try:
            engine = AnalysisEngine(config=self.config)
            result = engine.analyze_apk(
                apk_path=apk_path,
                progress_callback=progress_listener,
                cancellation_token=token,
            )

            # Auto-save scan result to local SQLite database
            try:
                db = DatabaseManager(self.config.database_path)
                db.save_result(result)
                logger.info("Successfully persisted analysis result to SQLite database.")
            except Exception as db_err:
                logger.warning("Could not persist result to SQLite database: %s", db_err)

            self._event_queue.put(("success", result))

        except AnalysisCancelledError as cancel_err:
            logger.info("Analysis cancelled: %s", cancel_err)
            self._event_queue.put(("cancelled", str(cancel_err)))

        except Exception as exc:
            logger.error("Analysis failed with exception: %s", exc, exc_info=True)
            self._event_queue.put(("error", str(exc)))

    # -------------------------------------------------------------------------
    # MAIN THREAD EVENT DISPATCHER (ZERO TKINTER CALLS FROM WORKER)
    # -------------------------------------------------------------------------
    def _poll_event_queue(self) -> None:
        """Check for messages from worker thread and safely update UI widgets."""
        try:
            while not self._event_queue.empty():
                event_type, payload = self._event_queue.get_nowait()
                if event_type == "progress":
                    progress, stage_str, message = payload
                    pct = int(progress * 100)
                    self.progress_bar.config(value=pct)
                    self.percent_label.config(text=f"{pct}%")
                    self.stage_label.config(text=f"Stage: {stage_str}")
                    if message:
                        self.status_message.config(text=message)
                        self.loading_detail_lbl.config(text=message)

                elif event_type == "success":
                    self._on_analysis_success(payload)

                elif event_type == "cancelled":
                    self._on_analysis_cancelled(payload)

                elif event_type == "error":
                    self._on_analysis_error(payload)

        except Exception as err:
            logger.error("Error processing queue event: %s", err)

        finally:
            # Poll every 50ms on main thread
            self.after(50, self._poll_event_queue)

    def _on_analysis_success(self, result: AnalysisResult) -> None:
        """Handle successful analysis completion on Tkinter main thread."""
        self._is_running = False
        self.btn_analyze.config(state=tk.NORMAL)
        self.btn_cancel.config(state=tk.DISABLED)
        self.btn_clear.config(state=tk.NORMAL)
        self.drop_zone.browse_btn.config(state=tk.NORMAL)

        self.progress_bar.config(value=100)
        self.percent_label.config(text="100%")
        self.stage_label.config(text="Scan Complete")
        duration = result.metrics.duration_seconds if hasattr(result, "metrics") and result.metrics else 0.0
        score = getattr(result, "overall_risk_score", getattr(getattr(result, "risk_score", None), "final_score", 0.0))
        rating = getattr(result, "risk_rating", getattr(getattr(result, "risk_score", None), "rating", "N/A"))
        if hasattr(rating, "value"):
            rating = rating.value
        self.status_message.config(
            text=f"Analyzed {result.application.package_name} in {duration:.2f}s. "
            f"Risk Score: {score:.0f}/100 ({rating})."
        )

        # Render results in ResultsView
        self._show_results_view(result)

        # Notify parent if registered
        if self.on_analysis_completed:
            self.on_analysis_completed(result)

    def _on_analysis_cancelled(self, message: str) -> None:
        """Handle analysis cancellation on Tkinter main thread."""
        self._is_running = False
        self.btn_analyze.config(state=tk.NORMAL)
        self.btn_cancel.config(state=tk.DISABLED)
        self.btn_clear.config(state=tk.NORMAL)
        self.drop_zone.browse_btn.config(state=tk.NORMAL)

        self.stage_label.config(text="Analysis Cancelled")
        self.status_message.config(text="Static analysis was interrupted by user.")
        self._show_empty_state()
        messagebox.showinfo("Analysis Cancelled", "Static audit was cancelled. Temporary files were cleaned up.")

    def _on_analysis_error(self, error_message: str) -> None:
        """Handle analysis failure on Tkinter main thread."""
        self._is_running = False
        self.btn_analyze.config(state=tk.NORMAL)
        self.btn_cancel.config(state=tk.DISABLED)
        self.btn_clear.config(state=tk.NORMAL)
        self.drop_zone.browse_btn.config(state=tk.NORMAL)

        self.stage_label.config(text="Scan Failed")
        self.status_message.config(text=f"Error: {error_message}")
        self._show_empty_state()

        messagebox.showerror(
            "Analysis Error",
            f"An error occurred during static analysis:\n\n{error_message}",
        )

    # -------------------------------------------------------------------------
    # CONTAINER STATE SWITCHING
    # -------------------------------------------------------------------------
    def _show_empty_state(self) -> None:
        """Display the empty state card."""
        self.loading_state.pack_forget()
        self.results_view.pack_forget()
        self.empty_state.pack(fill=tk.BOTH, expand=True)

    def _show_loading_state(self, message: str) -> None:
        """Display the loading state card."""
        self.empty_state.pack_forget()
        self.results_view.pack_forget()
        self.loading_detail_lbl.config(text=message)
        self.loading_state.pack(fill=tk.BOTH, expand=True)

    def _show_results_view(self, result: AnalysisResult) -> None:
        """Display results view and populate with findings."""
        self.empty_state.pack_forget()
        self.loading_state.pack_forget()
        self.results_view.pack(fill=tk.BOTH, expand=True)
        self.results_view.display_results(result)

    def load_external_result(self, result: AnalysisResult) -> None:
        """Externally load a completed result (e.g. from scan history)."""
        fname = getattr(result.application, "filename", "app.apk")
        self.selected_apk_path = Path(fname)
        self.drop_zone.show_selected_file(fname)
        self.progress_frame.pack(fill=tk.X, padx=20, pady=(0, 8), before=self.results_container)
        self.progress_bar.config(value=100)
        self.percent_label.config(text="100%")
        self.stage_label.config(text="Historical Scan Loaded")
        ts = getattr(result, "timestamp", "")
        if not ts and hasattr(result, "metrics") and result.metrics:
            ts = result.metrics.completed_at
        self.status_message.config(text=f"Loaded scan from {ts}")
        self._show_results_view(result)
