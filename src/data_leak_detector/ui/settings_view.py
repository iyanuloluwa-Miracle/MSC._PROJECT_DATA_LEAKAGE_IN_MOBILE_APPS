"""Settings View: Subprocess timeouts, tool detection status, and configuration management."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from data_leak_detector.analysis.tool_adapters import ApktoolAdapter, JadxAdapter
from data_leak_detector.core.config import AppConfig
from data_leak_detector.ui.widgets import (
    COLOR_ACCENT,
    COLOR_BG,
    COLOR_BORDER_LIGHT,
    COLOR_CARD_BG,
    COLOR_SUCCESS,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    FONT_BODY,
    FONT_BODY_BOLD,
    FONT_CODE,
    FONT_HEADING,
    FONT_SMALL,
    FONT_SUBTITLE,
    FONT_TITLE,
)

logger = logging.getLogger(__name__)


class SettingsView(ttk.Frame):
    """View managing tool diagnostics, subprocess timeouts, and environment preferences."""

    def __init__(self, master: tk.Misc, config: AppConfig | None = None, *args, **kwargs) -> None:
        super().__init__(master, *args, **kwargs)
        self.config = config or AppConfig()

        self._init_layout()
        self._refresh_diagnostics()

    def _init_layout(self) -> None:
        """Create header, diagnostic status cards, and settings form."""
        header_frame = tk.Frame(self, bg=COLOR_BG, padx=20, pady=16)
        header_frame.pack(fill=tk.X)

        tk.Label(
            header_frame,
            text="Settings & Environment Diagnostics",
            font=FONT_TITLE,
            bg=COLOR_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill=tk.X)

        tk.Label(
            header_frame,
            text="Verify external decompiler adapters, database storage path, and static analysis timeouts.",
            font=FONT_SUBTITLE,
            bg=COLOR_BG,
            fg=COLOR_TEXT_MUTED,
            anchor="w",
        ).pack(fill=tk.X, pady=(2, 0))

        content_frame = tk.Frame(self, bg=COLOR_BG, padx=20, pady=8)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # Section 1: Tool Diagnostics Card
        diag_card = tk.Frame(
            content_frame,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=16,
            pady=14,
        )
        diag_card.pack(fill=tk.X, pady=(0, 14))

        tk.Label(
            diag_card,
            text="External Tool & Dependency Status",
            font=FONT_HEADING,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 8))

        self.diag_grid = tk.Frame(diag_card, bg=COLOR_CARD_BG)
        self.diag_grid.pack(fill=tk.X)

        # JADX status
        self.jadx_status_lbl = self._create_diag_row(
            self.diag_grid,
            row=0,
            title="JADX Decompiler:",
            desc="Produces decompiled Java sources from DEX bytecode for deep secret & storage inspection.",
        )

        # Apktool status
        self.apktool_status_lbl = self._create_diag_row(
            self.diag_grid,
            row=1,
            title="Apktool Resource Extractor:",
            desc="Decodes XML resources and raw assets for static manifest auditing.",
        )

        # ReportLab status
        self.reportlab_status_lbl = self._create_diag_row(
            self.diag_grid,
            row=2,
            title="ReportLab PDF Engine:",
            desc="Academic-grade publication PDF report generator with Platypus layout engine.",
        )

        # Local SQLite status
        self.db_status_lbl = self._create_diag_row(
            self.diag_grid,
            row=3,
            title="Local SQLite Database:",
            desc="Zero external network dependency; persistent scan history stored locally.",
        )

        # Section 2: Engine Configuration Form
        config_card = tk.Frame(
            content_frame,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=16,
            pady=14,
        )
        config_card.pack(fill=tk.X, pady=(0, 14))

        tk.Label(
            config_card,
            text="Engine Preferences & Timeouts",
            font=FONT_HEADING,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 10))

        # Timeout field
        form_row1 = tk.Frame(config_card, bg=COLOR_CARD_BG)
        form_row1.pack(fill=tk.X, pady=4)

        tk.Label(
            form_row1,
            text="External Process Timeout (seconds):",
            font=FONT_BODY_BOLD,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            width=32,
            anchor="w",
        ).pack(side=tk.LEFT)

        self.timeout_var = tk.StringVar(value=str(self.config.subprocess_timeout_seconds))
        self.timeout_spin = ttk.Spinbox(
            form_row1,
            from_=15,
            to=600,
            textvariable=self.timeout_var,
            width=8,
        )
        self.timeout_spin.pack(side=tk.LEFT)

        tk.Label(
            form_row1,
            text="(Default: 120s. Enforces subprocess kill if external decompiler hangs)",
            font=FONT_SMALL,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_MUTED,
        ).pack(side=tk.LEFT, padx=(10, 0))

        # Storage Path field
        form_row2 = tk.Frame(config_card, bg=COLOR_CARD_BG)
        form_row2.pack(fill=tk.X, pady=(10, 4))

        tk.Label(
            form_row2,
            text="Local Database Path:",
            font=FONT_BODY_BOLD,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            width=32,
            anchor="w",
        ).pack(side=tk.LEFT)

        self.db_path_entry = ttk.Entry(
            form_row2,
            width=50,
            font=FONT_CODE,
        )
        self.db_path_entry.insert(0, str(self.config.database_path))
        self.db_path_entry.config(state="readonly")
        self.db_path_entry.pack(side=tk.LEFT, padx=(0, 8))

        btn_open_folder = ttk.Button(
            form_row2,
            text="Open Folder",
            style="Secondary.TButton",
            command=self._open_db_folder,
        )
        btn_open_folder.pack(side=tk.LEFT)

        # Action Buttons
        btn_row = tk.Frame(content_frame, bg=COLOR_BG)
        btn_row.pack(fill=tk.X, pady=8)

        btn_save = ttk.Button(
            btn_row,
            text="Save Settings",
            style="Primary.TButton",
            command=self._save_settings,
        )
        btn_save.pack(side=tk.LEFT, padx=(0, 8))

        btn_reset = ttk.Button(
            btn_row,
            text="Reset to Defaults",
            style="Secondary.TButton",
            command=self._reset_defaults,
        )
        btn_reset.pack(side=tk.LEFT)

    def _create_diag_row(self, master: tk.Misc, row: int, title: str, desc: str) -> tk.Label:
        """Create a standardized diagnostic row in the diagnostics table."""
        lbl_title = tk.Label(
            master,
            text=title,
            font=FONT_BODY_BOLD,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        )
        lbl_title.grid(row=row * 2, column=0, sticky="w", pady=(4, 0))

        status_lbl = tk.Label(
            master,
            text="Checking...",
            font=FONT_BODY_BOLD,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_MUTED,
            anchor="w",
        )
        status_lbl.grid(row=row * 2, column=1, sticky="w", padx=12, pady=(4, 0))

        lbl_desc = tk.Label(
            master,
            text=desc,
            font=FONT_SMALL,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_MUTED,
            anchor="w",
        )
        lbl_desc.grid(row=row * 2 + 1, column=0, columnspan=2, sticky="w", pady=(0, 8))

        return status_lbl

    def _refresh_diagnostics(self) -> None:
        """Inspect environment for external tools and update status labels."""
        # Check JADX
        jadx_adapter = JadxAdapter()
        if jadx_adapter.is_available():
            self.jadx_status_lbl.config(
                text=f"✔ Available ({jadx_adapter.tool_path})",
                fg=COLOR_SUCCESS,
            )
        else:
            self.jadx_status_lbl.config(
                text="⚠ Not found in PATH (Falling back to DEX string pool & manifest inspection)",
                fg="#d97706",
            )

        # Check Apktool
        apktool_adapter = ApktoolAdapter()
        if apktool_adapter.is_available():
            self.apktool_status_lbl.config(
                text=f"✔ Available ({apktool_adapter.tool_path})",
                fg=COLOR_SUCCESS,
            )
        else:
            self.apktool_status_lbl.config(
                text="⚠ Not found in PATH (Falling back to zip extraction)",
                fg="#d97706",
            )

        # Check ReportLab
        try:
            import reportlab
            self.reportlab_status_lbl.config(
                text=f"✔ Installed (v{reportlab.__version__})",
                fg=COLOR_SUCCESS,
            )
        except ImportError:
            self.reportlab_status_lbl.config(
                text="❌ Not installed (PDF generation will be disabled)",
                fg="#dc2626",
            )

        # Check SQLite Database
        db_path = self.config.database_path
        if db_path.exists():
            sz_kb = db_path.stat().st_size / 1024
            self.db_status_lbl.config(
                text=f"✔ Connected ({sz_kb:.1f} KB at {db_path.name})",
                fg=COLOR_SUCCESS,
            )
        else:
            self.db_status_lbl.config(
                text=f"✔ Ready (Auto-initialized at {db_path.name})",
                fg=COLOR_ACCENT,
            )

    def _open_db_folder(self) -> None:
        """Open the directory containing the local SQLite database in OS file explorer."""
        folder = self.config.database_path.parent
        folder.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform == "win32":
                os.startfile(folder)
            elif sys.platform == "darwin":
                subprocess.run(["open", str(folder)], check=False)
            else:
                subprocess.run(["xdg-open", str(folder)], check=False)
        except Exception as exc:
            messagebox.showinfo("Folder Path", f"Database folder:\n{folder}")

    def _save_settings(self) -> None:
        """Save updated settings to runtime AppConfig."""
        try:
            val = int(self.timeout_var.get())
            if val < 5:
                val = 5
            self.config.subprocess_timeout_seconds = val
            messagebox.showinfo("Settings Saved", "Runtime configuration updated successfully.")
        except ValueError:
            messagebox.showerror("Invalid Input", "Timeout must be an integer number of seconds.")

    def _reset_defaults(self) -> None:
        """Reset settings to default values."""
        self.config.subprocess_timeout_seconds = 120
        self.timeout_var.set("120")
        messagebox.showinfo("Defaults Restored", "Configuration settings restored to default values.")
