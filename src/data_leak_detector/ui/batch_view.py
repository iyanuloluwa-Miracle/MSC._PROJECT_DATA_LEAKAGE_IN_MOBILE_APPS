"""Batch Analysis View: Multi-APK queue management, execution, and CSV reporting."""

from __future__ import annotations

import logging
import queue
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable, Sequence

from data_leak_detector.analysis.batch_processor import (
    BatchItem,
    BatchItemStatus,
    BatchProcessor,
)
from data_leak_detector.core.config import AppConfig
from data_leak_detector.core.models import AnalysisResult
from data_leak_detector.storage.database import DatabaseManager
from data_leak_detector.ui.widgets import (
    COLOR_ACCENT,
    COLOR_BG,
    COLOR_BORDER_LIGHT,
    COLOR_CARD_BG,
    COLOR_DANGER,
    COLOR_SUCCESS,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    FONT_BODY_BOLD,
    FONT_SUBTITLE,
    FONT_TITLE,
    EmptyState,
)

logger = logging.getLogger(__name__)


class BatchView(ttk.Frame):
    """View managing multi-APK queued static analyses with sequential execution."""

    def __init__(
        self,
        master: tk.Misc,
        config: AppConfig | None = None,
        on_inspect_result: Callable[[AnalysisResult], None] | None = None,
        *args,
        **kwargs,
    ) -> None:
        super().__init__(master, *args, **kwargs)
        self.app_config = config or AppConfig()
        self.on_inspect_result = on_inspect_result
        self.processor = BatchProcessor(config=self.app_config, max_concurrent=1)
        self._event_queue: queue.Queue[tuple[str, Any]] = queue.Queue()

        self._init_layout()
        self._update_queue_display()
        self._poll_event_queue()

    def _init_layout(self) -> None:
        """Construct top header, action toolbar, status summary bar, treeview, and footer."""
        # Top Header
        header_frame = tk.Frame(self, bg=COLOR_BG, padx=20, pady=16)
        header_frame.pack(fill=tk.X)

        tk.Label(
            header_frame,
            text="Batch Analysis Queue",
            font=FONT_TITLE,
            bg=COLOR_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill=tk.X)

        tk.Label(
            header_frame,
            text="Queue and execute static vulnerability scans across multiple APKs sequentially to protect system resources.",
            font=FONT_SUBTITLE,
            bg=COLOR_BG,
            fg=COLOR_TEXT_MUTED,
            anchor="w",
        ).pack(fill=tk.X, pady=(2, 0))

        # Control Toolbar
        toolbar = tk.Frame(
            self,
            bg=COLOR_CARD_BG,
            padx=16,
            pady=10,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
        )
        toolbar.pack(fill=tk.X, padx=20, pady=(0, 10))

        self.btn_select_files = ttk.Button(
            toolbar,
            text="➕ Select APK Files...",
            style="Primary.TButton",
            command=self._select_apk_files,
        )
        self.btn_select_files.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_start = ttk.Button(
            toolbar,
            text="▶ Start Batch",
            style="Primary.TButton",
            command=self.start_batch,
        )
        self.btn_start.pack(side=tk.LEFT, padx=4)

        self.btn_cancel_all = ttk.Button(
            toolbar,
            text="⏹ Cancel All",
            style="Danger.TButton",
            command=self.cancel_all,
            state="disabled",
        )
        self.btn_cancel_all.pack(side=tk.LEFT, padx=4)

        self.btn_export_csv = ttk.Button(
            toolbar,
            text="📄 Export Batch CSV",
            style="Secondary.TButton",
            command=self.export_csv,
        )
        self.btn_export_csv.pack(side=tk.LEFT, padx=4)

        self.btn_clear = ttk.Button(
            toolbar,
            text="🗑 Clear Queue",
            style="Secondary.TButton",
            command=self.clear_queue,
        )
        self.btn_clear.pack(side=tk.RIGHT)

        # Status Summary Bar
        self.summary_bar = tk.Frame(self, bg=COLOR_BG, padx=20, pady=4)
        self.summary_bar.pack(fill=tk.X)

        self.lbl_queue_stats = tk.Label(
            self.summary_bar,
            text="Total: 0  |  Waiting: 0  |  Analyzing: 0  |  Complete: 0  |  Failed: 0  |  Cancelled: 0",
            font=FONT_BODY_BOLD,
            bg=COLOR_BG,
            fg=COLOR_TEXT_MUTED,
            anchor="w",
        )
        self.lbl_queue_stats.pack(fill=tk.X)

        # Main Table Container
        self.table_container = tk.Frame(self, bg=COLOR_BG)
        self.table_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=(4, 8))

        # Table Frame
        self.table_frame = tk.Frame(self.table_container, bg=COLOR_CARD_BG)

        columns = ("filename", "status", "progress", "risk_score", "package")
        self.tree = ttk.Treeview(
            self.table_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )
        self.tree.heading("filename", text="APK Filename")
        self.tree.heading("status", text="Status")
        self.tree.heading("progress", text="Progress")
        self.tree.heading("risk_score", text="Risk Score")
        self.tree.heading("package", text="Package Name")

        self.tree.column("filename", width=260, anchor="w")
        self.tree.column("status", width=110, anchor="center")
        self.tree.column("progress", width=160, anchor="center")
        self.tree.column("risk_score", width=130, anchor="center")
        self.tree.column("package", width=220, anchor="w")

        # Color-coded tags for item status
        self.tree.tag_configure("Waiting", foreground=COLOR_TEXT_MUTED)
        self.tree.tag_configure("Analyzing", foreground=COLOR_ACCENT)
        self.tree.tag_configure("Complete", foreground=COLOR_SUCCESS)
        self.tree.tag_configure("Failed", foreground=COLOR_DANGER)
        self.tree.tag_configure("Cancelled", foreground="#ea580c")

        tree_scroll = ttk.Scrollbar(self.table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<Double-1>", lambda e: self.inspect_selected_result())

        # Empty State
        self.empty_state = EmptyState(
            self.table_container,
            title="Batch Queue is Empty",
            message="Select multiple APK files to queue and audit them sequentially in a resource-protected manner.",
            icon="📦",
            action_text="Select APK Files...",
            action_command=self._select_apk_files,
        )

        # Bottom Action Bar
        bottom_bar = tk.Frame(self, bg=COLOR_BG, padx=20, pady=8)
        bottom_bar.pack(fill=tk.X)

        self.btn_inspect = ttk.Button(
            bottom_bar,
            text="🔍 Inspect Selected Result",
            style="Primary.TButton",
            command=self.inspect_selected_result,
        )
        self.btn_inspect.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_remove_item = ttk.Button(
            bottom_bar,
            text="Remove Selected Item",
            style="Secondary.TButton",
            command=self._remove_selected_item,
        )
        self.btn_remove_item.pack(side=tk.LEFT)

    # -------------------------------------------------------------------------
    # USER INTERACTIONS: ADD, REMOVE, CLEAR
    # -------------------------------------------------------------------------
    def _select_apk_files(self) -> None:
        """Open multi-select file dialog for APK files."""
        chosen_paths = filedialog.askopenfilenames(
            title="Select Multiple Android Packages (APK)",
            filetypes=[("Android Packages (*.apk)", "*.apk"), ("All Files (*.*)", "*.*")],
        )
        if chosen_paths:
            self.add_files(chosen_paths)

    def add_files(self, paths: Sequence[str | Path]) -> None:
        """Add files to the batch queue and update the UI."""
        self.processor.add_apks(paths)
        self._update_queue_display()

    def _remove_selected_item(self) -> None:
        """Remove selected item from queue."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Select Item", "Please select an APK record from the queue.")
            return
        item_id = selected[0]
        self.processor.remove_item(item_id)
        self._update_queue_display()

    def clear_queue(self) -> None:
        """Clear all items from batch queue with confirmation if running."""
        if self.processor.is_running:
            confirm = messagebox.askyesno(
                "Confirm Stop",
                "Batch analysis is currently running. Stopping will cancel pending scans. Continue?",
            )
            if not confirm:
                return
        self.processor.clear()
        self._update_queue_display()

    # -------------------------------------------------------------------------
    # EXECUTION CONTROLS
    # -------------------------------------------------------------------------
    def start_batch(self) -> None:
        """Start sequential batch processing in a background worker thread."""
        if not self.processor.items:
            messagebox.showinfo("Empty Queue", "Please select at least one APK file first.")
            return

        if self.processor.is_running:
            return

        self.btn_start.configure(state="disabled")
        self.btn_select_files.configure(state="disabled")
        self.btn_cancel_all.configure(state="normal")

        def _on_item_updated(item: BatchItem) -> None:
            # Post to main thread event queue
            self._event_queue.put(("item_updated", item))

        def _on_batch_complete() -> None:
            self._event_queue.put(("batch_complete", None))

        self.processor.start(
            on_item_updated=_on_item_updated,
            on_complete=_on_batch_complete,
        )

    def cancel_all(self) -> None:
        """Cancel all queued and currently running batch items."""
        self.processor.cancel_all()
        self._update_queue_display()

    # -------------------------------------------------------------------------
    # THREAD-SAFE EVENT DISPATCHER
    # -------------------------------------------------------------------------
    def _poll_event_queue(self) -> None:
        """Safely handle background worker events on Tkinter main thread."""
        try:
            while True:
                event_type, payload = self._event_queue.get_nowait()
                if event_type == "item_updated":
                    item: BatchItem = payload
                    self._update_single_tree_item(item)
                    self._update_stats_label()
                    # Also persist completed result into SQLite history
                    if item.status == BatchItemStatus.COMPLETE and item.result:
                        try:
                            db = DatabaseManager(self.app_config.database_path)
                            db.save_result(item.result)
                        except Exception as exc:
                            logger.warning("Could not persist batch result to database: %s", exc)

                elif event_type == "batch_complete":
                    self.btn_start.configure(state="normal")
                    self.btn_select_files.configure(state="normal")
                    self.btn_cancel_all.configure(state="disabled")
                    self._update_queue_display()

        except queue.Empty:
            pass

        self.after(100, self._poll_event_queue)

    # -------------------------------------------------------------------------
    # DISPLAY UPDATES
    # -------------------------------------------------------------------------
    def _update_queue_display(self) -> None:
        """Re-render entire treeview and empty state."""
        items = self.processor.items

        for child in self.tree.get_children():
            self.tree.delete(child)

        if not items:
            self.table_frame.pack_forget()
            self.empty_state.pack(fill=tk.BOTH, expand=True)
            self._update_stats_label()
            return

        self.empty_state.pack_forget()
        self.table_frame.pack(fill=tk.BOTH, expand=True)

        for itm in items:
            self._insert_tree_item(itm)

        self._update_stats_label()

    def _insert_tree_item(self, item: BatchItem) -> None:
        """Insert or refresh a single row in the treeview."""
        status_str = item.status.value
        score_str = f"{item.risk_score:.0f}/100 ({item.risk_rating})" if item.risk_score is not None else "-"
        prog_str = f"{int(item.progress * 100)}% ({item.current_stage})" if item.status == BatchItemStatus.ANALYZING else status_str
        pkg_str = item.package_name or "-"

        self.tree.insert(
            "",
            tk.END,
            iid=item.id,
            values=(item.filename, status_str, prog_str, score_str, pkg_str),
            tags=(status_str,),
        )

    def _update_single_tree_item(self, item: BatchItem) -> None:
        """Update existing item row in the treeview."""
        if self.tree.exists(item.id):
            status_str = item.status.value
            score_str = f"{item.risk_score:.0f}/100 ({item.risk_rating})" if item.risk_score is not None else "-"
            if item.status == BatchItemStatus.ANALYZING:
                prog_str = f"{int(item.progress * 100)}% ({item.current_stage})"
            else:
                prog_str = status_str
            pkg_str = item.package_name or "-"

            self.tree.item(
                item.id,
                values=(item.filename, status_str, prog_str, score_str, pkg_str),
                tags=(status_str,),
            )
        else:
            self._insert_tree_item(item)

    def _update_stats_label(self) -> None:
        """Update summary stats counter bar."""
        items = self.processor.items
        total = len(items)
        waiting = sum(1 for i in items if i.status == BatchItemStatus.WAITING)
        analyzing = sum(1 for i in items if i.status == BatchItemStatus.ANALYZING)
        complete = sum(1 for i in items if i.status == BatchItemStatus.COMPLETE)
        failed = sum(1 for i in items if i.status == BatchItemStatus.FAILED)
        cancelled = sum(1 for i in items if i.status == BatchItemStatus.CANCELLED)

        self.lbl_queue_stats.config(
            text=f"Total: {total}  |  Waiting: {waiting}  |  Analyzing: {analyzing}  |  Complete: {complete}  |  Failed: {failed}  |  Cancelled: {cancelled}"
        )

    # -------------------------------------------------------------------------
    # ACTIONS: INSPECT & CSV EXPORT
    # -------------------------------------------------------------------------
    def inspect_selected_result(self) -> None:
        """Load selected complete analysis into the main ResultsView."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Select Scan", "Please select a completed scan record from the table.")
            return

        item_id = selected[0]
        matching = [i for i in self.processor.items if i.id == item_id]
        if not matching:
            return

        item = matching[0]
        if item.status != BatchItemStatus.COMPLETE or not item.result:
            messagebox.showinfo("Not Ready", f"APK '{item.filename}' has status '{item.status.value}'. Only completed scans can be inspected.")
            return

        if self.on_inspect_result:
            self.on_inspect_result(item.result)
        else:
            messagebox.showinfo(
                "Scan Summary",
                f"Package: {item.package_name}\nScore: {item.risk_score:.0f}/100 ({item.risk_rating})\nDuration: {item.duration_seconds:.1f}s",
            )

    def export_csv(self) -> None:
        """Export current batch execution summary to CSV."""
        items = self.processor.items
        if not items:
            messagebox.showinfo("Empty Queue", "There are no APK items in the queue to export.")
            return

        save_path = filedialog.asksaveasfilename(
            title="Export Batch Summary as CSV",
            initialfile="BatchAnalysisSummary.csv",
            filetypes=[("CSV Document (*.csv)", "*.csv"), ("All Files (*.*)", "*.*")],
            defaultextension=".csv",
        )
        if not save_path:
            return

        try:
            out_file = self.processor.export_csv(save_path)
            messagebox.showinfo("Export Successful", f"Batch summary saved to:\n{out_file}")
        except Exception as exc:
            logger.error("Failed exporting batch CSV: %s", exc)
            messagebox.showerror("Export Failed", f"Could not export CSV:\n{exc}")
