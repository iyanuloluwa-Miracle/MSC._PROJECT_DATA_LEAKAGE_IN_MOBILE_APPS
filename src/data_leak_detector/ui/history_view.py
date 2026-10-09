"""History View: Table of past static analysis scans stored in local SQLite."""

from __future__ import annotations

import logging
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable

from data_leak_detector.core.config import AppConfig
from data_leak_detector.core.models import AnalysisResult
from data_leak_detector.reporting.report_generator import ReportGenerator
from data_leak_detector.storage.database import DatabaseManager
from data_leak_detector.ui.widgets import (
    COLOR_BG,
    COLOR_BORDER_LIGHT,
    COLOR_CARD_BG,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    FONT_BODY_BOLD,
    FONT_SUBTITLE,
    FONT_TITLE,
    EmptyState,
)

logger = logging.getLogger(__name__)


class HistoryView(ttk.Frame):
    """View rendering past scan history with search, inspect, sort, and delete capabilities."""

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
        self._history_items: list[dict[str, Any]] = []

        self._init_layout()
        self.refresh_history()

    def _init_layout(self) -> None:
        """Create header, filter and sort toolbar, treeview table, and action bar."""
        # Top Header
        header_frame = tk.Frame(self, bg=COLOR_BG, padx=20, pady=16)
        header_frame.pack(fill=tk.X)

        tk.Label(
            header_frame,
            text="Analysis History",
            font=FONT_TITLE,
            bg=COLOR_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill=tk.X)

        tk.Label(
            header_frame,
            text="Review, inspect findings, and open past static audits saved in local SQLite.",
            font=FONT_SUBTITLE,
            bg=COLOR_BG,
            fg=COLOR_TEXT_MUTED,
            anchor="w",
        ).pack(fill=tk.X, pady=(2, 0))

        # Filter, Sort & Action Bar
        toolbar = tk.Frame(
            self,
            bg=COLOR_CARD_BG,
            padx=16,
            pady=10,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
        )
        toolbar.pack(fill=tk.X, padx=20, pady=(0, 10))

        # Search by application name or package name
        tk.Label(
            toolbar,
            text="Search:",
            font=FONT_BODY_BOLD,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(toolbar, textvariable=self.search_var, width=28)
        self.search_entry.pack(side=tk.LEFT, padx=(0, 14))
        self.search_entry.bind("<KeyRelease>", lambda e: self._apply_search_filter())

        # Sort Order: Newest First / Oldest First
        tk.Label(
            toolbar,
            text="Sort:",
            font=FONT_BODY_BOLD,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.sort_var = tk.StringVar(value="Newest First")
        self.sort_combo = ttk.Combobox(
            toolbar,
            textvariable=self.sort_var,
            values=["Newest First", "Oldest First", "Highest Risk", "Lowest Risk"],
            state="readonly",
            width=14,
        )
        self.sort_combo.pack(side=tk.LEFT, padx=(0, 14))
        self.sort_combo.bind("<<ComboboxSelected>>", lambda e: self._apply_search_filter())

        self.btn_refresh = ttk.Button(
            toolbar,
            text="🔄 Refresh",
            style="Secondary.TButton",
            command=self.refresh_history,
        )
        self.btn_refresh.pack(side=tk.LEFT, padx=4)

        self.btn_clear_all = ttk.Button(
            toolbar,
            text="🗑 Clear History",
            style="Danger.TButton",
            command=self.clear_history,
        )
        self.btn_clear_all.pack(side=tk.RIGHT, padx=4)

        # Central Container: Paned Table vs Empty State
        self.table_container = tk.Frame(self, bg=COLOR_BG)
        self.table_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 8))

        # Table Frame
        self.table_frame = tk.Frame(self.table_container, bg=COLOR_CARD_BG)

        # Explicit columns: application name, package name, version, analysis date, risk score, risk rating
        columns = ("app_name", "package_name", "version", "created_at", "risk_score", "risk_rating")
        self.tree = ttk.Treeview(
            self.table_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )
        self.tree.heading("app_name", text="Application Name", command=lambda: self._sort_by_column("app_name"))
        self.tree.heading("package_name", text="Package Name", command=lambda: self._sort_by_column("package_name"))
        self.tree.heading("version", text="Version", command=lambda: self._sort_by_column("version"))
        self.tree.heading("created_at", text="Analysis Date", command=lambda: self._sort_by_column("created_at"))
        self.tree.heading("risk_score", text="Risk Score", command=lambda: self._sort_by_column("risk_score"))
        self.tree.heading("risk_rating", text="Risk Rating", command=lambda: self._sort_by_column("risk_rating"))

        self.tree.column("app_name", width=200, anchor="w")
        self.tree.column("package_name", width=250, anchor="w")
        self.tree.column("version", width=90, anchor="center")
        self.tree.column("created_at", width=150, anchor="center")
        self.tree.column("risk_score", width=95, anchor="center")
        self.tree.column("risk_rating", width=110, anchor="center")

        # Color-coded tags for risk rating
        self.tree.tag_configure("CRITICAL", foreground="#dc2626")
        self.tree.tag_configure("HIGH", foreground="#ea580c")
        self.tree.tag_configure("MEDIUM", foreground="#d97706")
        self.tree.tag_configure("LOW", foreground="#2563eb")
        self.tree.tag_configure("MINIMAL", foreground="#16a34a")

        tree_scroll = ttk.Scrollbar(self.table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<Double-1>", lambda e: self.open_previous_result())

        # Empty State
        self.empty_state = EmptyState(
            self.table_container,
            title="No Scans in Local History",
            message="Completed static audits are automatically recorded here for auditing and re-exporting.",
            icon="📜",
            action_text="Analyze New APK",
        )

        # Bottom Action Bar
        bottom_bar = tk.Frame(self, bg=COLOR_BG, padx=20, pady=8)
        bottom_bar.pack(fill=tk.X)

        self.btn_open = ttk.Button(
            bottom_bar,
            text="📂 Open Previous Result",
            style="Primary.TButton",
            command=self.open_previous_result,
        )
        self.btn_open.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_export_pdf = ttk.Button(
            bottom_bar,
            text="📄 Export PDF",
            style="Secondary.TButton",
            command=lambda: self._export_selected("pdf"),
        )
        self.btn_export_pdf.pack(side=tk.LEFT, padx=4)

        self.btn_export_html = ttk.Button(
            bottom_bar,
            text="🌐 Export HTML",
            style="Secondary.TButton",
            command=lambda: self._export_selected("html"),
        )
        self.btn_export_html.pack(side=tk.LEFT, padx=4)

        self.btn_delete = ttk.Button(
            bottom_bar,
            text="🗑 Delete Result",
            style="Danger.TButton",
            command=self.delete_result,
        )
        self.btn_delete.pack(side=tk.RIGHT)

    # -------------------------------------------------------------------------
    # DATA RETRIEVAL & FILTERING & SORTING
    # -------------------------------------------------------------------------
    def refresh_history(self) -> None:
        """Fetch historical records from SQLite and render in table."""
        try:
            db = DatabaseManager(self.app_config.database_path)
            self._history_items = db.list_history(limit=200)
            self._apply_search_filter()
        except Exception as exc:
            logger.error("Failed to query scan history: %s", exc)

    def _apply_search_filter(self) -> None:
        """Filter table items by search query (app/package name) and sort order."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        query = self.search_var.get().strip().lower()

        # 1. Filter by application name or package name
        filtered: list[dict[str, Any]] = []
        for row in self._history_items:
            app_name = str(row.get("app_name") or row.get("filename") or "").lower()
            package_name = str(row.get("package_name") or "").lower()
            haystack = f"{app_name} {package_name}"
            if not query or query in haystack:
                filtered.append(row)

        if not filtered and not self._history_items:
            # Entirely empty DB
            self.table_frame.pack_forget()
            self.empty_state.pack(fill=tk.BOTH, expand=True)
            return

        # Show table
        self.empty_state.pack_forget()
        self.table_frame.pack(fill=tk.BOTH, expand=True)

        # 2. Sort results
        sort_order = self.sort_var.get()
        if sort_order == "Newest First":
            filtered.sort(key=lambda r: str(r.get("created_at") or ""), reverse=True)
        elif sort_order == "Oldest First":
            filtered.sort(key=lambda r: str(r.get("created_at") or ""), reverse=False)
        elif sort_order == "Highest Risk":
            filtered.sort(key=lambda r: float(r.get("risk_score") or 0), reverse=True)
        elif sort_order == "Lowest Risk":
            filtered.sort(key=lambda r: float(r.get("risk_score") or 0), reverse=False)

        # 3. Populate rows
        for row in filtered:
            score = f"{float(row.get('risk_score', 0)):.0f}/100"
            rating = str(row.get("risk_rating", "N/A")).upper()
            app_display = row.get("app_name") or row.get("filename") or "Unknown"
            pkg_display = row.get("package_name") or "Unknown"
            ver_display = str(row.get("version") or "N/A")
            date_display = row.get("created_at", "")[:19].replace("T", " ")

            self.tree.insert(
                "",
                tk.END,
                iid=str(row["id"]),
                values=(
                    app_display,
                    pkg_display,
                    ver_display,
                    date_display,
                    score,
                    rating,
                ),
                tags=(rating,),
            )

        children = self.tree.get_children()
        if children:
            self.tree.selection_set(children[0])

    def _sort_by_column(self, col: str) -> None:
        """Sort by column header click."""
        if col == "created_at":
            if self.sort_var.get() == "Newest First":
                self.sort_var.set("Oldest First")
            else:
                self.sort_var.set("Newest First")
        elif col == "risk_score":
            if self.sort_var.get() == "Highest Risk":
                self.sort_var.set("Lowest Risk")
            else:
                self.sort_var.set("Highest Risk")
        self._apply_search_filter()

    def _get_selected_id(self) -> str | None:
        """Retrieve ID of selected item in history tree."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Select Scan", "Please select a scan record from the table first.")
            return None
        return selected[0]

    # -------------------------------------------------------------------------
    # ACTIONS: OPEN PREVIOUS RESULT, DELETE RESULT, CLEAR HISTORY, EXPORT
    # -------------------------------------------------------------------------
    def open_previous_result(self) -> None:
        """Load selected scan from SQLite and open in inspector / analyze view."""
        res_id = self._get_selected_id()
        if not res_id:
            return

        try:
            db = DatabaseManager(self.app_config.database_path)
            result = db.get_result(res_id)
            if not result:
                messagebox.showerror("Not Found", f"Could not find scan record '{res_id}'.")
                return

            if self.on_inspect_result:
                self.on_inspect_result(result)
            else:
                messagebox.showinfo(
                    "Scan Summary",
                    f"Scan ID: {result.analysis_id}\n"
                    f"Package: {result.application.package_name}\n"
                    f"Risk Score: {result.overall_risk_score:.0f}/100 ({result.risk_rating.value})\n"
                    f"Total Findings: {len(result.findings)}",
                )
        except Exception as exc:
            logger.error("Failed loading scan '%s': %s", res_id, exc)
            messagebox.showerror("Load Error", f"Failed retrieving scan:\n{exc}")

    def _inspect_selected_result(self) -> None:
        """Alias for open_previous_result."""
        self.open_previous_result()

    def delete_result(self) -> None:
        """Delete selected scan record from SQLite database with confirmation."""
        res_id = self._get_selected_id()
        if not res_id:
            return

        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to permanently delete scan '{res_id}'?",
        )
        if not confirm:
            return

        try:
            db = DatabaseManager(self.app_config.database_path)
            deleted = db.delete_result(res_id)
            if deleted:
                self.refresh_history()
                messagebox.showinfo("Deleted", "Scan record removed successfully.")
            else:
                messagebox.showwarning("Warning", "Record was not found or already deleted.")
        except Exception as exc:
            logger.error("Failed to delete scan '%s': %s", res_id, exc)
            messagebox.showerror("Delete Error", f"Failed deleting record:\n{exc}")

    def _delete_selected_record(self) -> None:
        """Alias for delete_result."""
        self.delete_result()

    def clear_history(self) -> None:
        """Clear all historical scans after user confirmation."""
        confirm = messagebox.askyesno(
            "Clear Entire History",
            "Are you sure you want to delete ALL historical scan records?\nThis operation cannot be undone.",
        )
        if not confirm:
            return

        try:
            db = DatabaseManager(self.app_config.database_path)
            db.clear_history()
            self.refresh_history()
            messagebox.showinfo("History Cleared", "All scan records have been cleared from local database.")
        except Exception as exc:
            logger.error("Failed clearing history: %s", exc)
            messagebox.showerror("Error", f"Failed to clear history:\n{exc}")

    def _clear_all_history(self) -> None:
        """Alias for clear_history."""
        self.clear_history()

    def _export_selected(self, fmt: str) -> None:
        """Export selected historical scan directly to PDF or HTML."""
        res_id = self._get_selected_id()
        if not res_id:
            return

        try:
            db = DatabaseManager(self.app_config.database_path)
            result = db.get_result(res_id)
            if not result:
                messagebox.showerror("Error", "Selected scan could not be retrieved.")
                return

            pkg = result.application.package_name or "app"
            default_name = f"DataLeakReport_{pkg}_{fmt.lower()}"
            file_types = {
                "pdf": [("PDF Document", "*.pdf")],
                "html": [("HTML Document", "*.html")],
            }

            save_path = filedialog.asksaveasfilename(
                title=f"Export Historical Report as {fmt.upper()}",
                initialfile=default_name,
                filetypes=file_types.get(fmt, [("All Files", "*.*")]),
                defaultextension=f".{fmt}",
            )

            if not save_path:
                return

            gen = ReportGenerator()
            gen.generate(result=result, format=fmt, output_path=Path(save_path))
            messagebox.showinfo("Export Successful", f"Report saved to:\n{save_path}")

        except Exception as exc:
            logger.error("Export failed: %s", exc)
            messagebox.showerror("Export Failed", f"Could not export report:\n{exc}")
