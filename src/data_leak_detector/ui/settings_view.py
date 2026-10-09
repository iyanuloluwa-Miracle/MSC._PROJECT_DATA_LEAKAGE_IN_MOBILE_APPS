"""Settings View: Tool paths, diagnostics, report preferences, accessibility, and rule controls."""

from __future__ import annotations

import logging
import shutil
import subprocess
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from data_leak_detector.analysis.tool_adapters import ApktoolAdapter, JadxAdapter
from data_leak_detector.core.config import AppConfig
from data_leak_detector.ui.widgets import (
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
    ScrollableFrame,
)

logger = logging.getLogger(__name__)


class SettingsView(ttk.Frame):
    """View managing external tool diagnostics, paths, report preferences, and rule toggles."""

    def __init__(self, master: tk.Misc, config: AppConfig | None = None, *args, **kwargs) -> None:
        super().__init__(master, *args, **kwargs)
        self.app_config = config or AppConfig()

        self._init_layout()
        self._load_values_into_form()
        self.check_tools()

    def _init_layout(self) -> None:
        """Construct the settings layout within a scrollable frame."""
        # Top Header
        header_frame = tk.Frame(self, bg=COLOR_BG, padx=20, pady=16)
        header_frame.pack(fill=tk.X)

        tk.Label(
            header_frame,
            text="Settings & Tool Diagnostics",
            font=FONT_TITLE,
            bg=COLOR_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill=tk.X)

        tk.Label(
            header_frame,
            text="Configure external decompilers, report generation preferences, accessibility, and analysis rules.",
            font=FONT_SUBTITLE,
            bg=COLOR_BG,
            fg=COLOR_TEXT_MUTED,
            anchor="w",
        ).pack(fill=tk.X, pady=(2, 0))

        # Main Scrollable Content
        scroll = ScrollableFrame(self, bg=COLOR_BG)
        scroll.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 10))
        self.content = scroll.scrollable_content

        # =====================================================================
        # SECTION 1: TOOL DIAGNOSTICS & "CHECK TOOLS"
        # =====================================================================
        diag_card = tk.Frame(
            self.content,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=16,
            pady=14,
        )
        diag_card.pack(fill=tk.X, pady=(0, 12))

        diag_top = tk.Frame(diag_card, bg=COLOR_CARD_BG)
        diag_top.pack(fill=tk.X, pady=(0, 10))

        tk.Label(
            diag_top,
            text="External Tool & Runtime Diagnostics",
            font=FONT_HEADING,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(side=tk.LEFT)

        # "Check Tools" Button
        self.btn_check_tools = ttk.Button(
            diag_top,
            text="🔍 Check Tools",
            style="Primary.TButton",
            command=self.check_tools,
        )
        self.btn_check_tools.pack(side=tk.RIGHT)

        self.diag_grid = tk.Frame(diag_card, bg=COLOR_CARD_BG)
        self.diag_grid.pack(fill=tk.X)

        # AndroGuard status
        self.androguard_status_lbl = self._create_diag_row(
            self.diag_grid,
            row=0,
            title="AndroGuard Static Parser:",
            desc="Extracts AndroidManifest XML, string pools, and DEX bytecode for fast static analysis.",
        )

        # apktool status
        self.apktool_status_lbl = self._create_diag_row(
            self.diag_grid,
            row=1,
            title="apktool Resource Extractor:",
            desc="Decodes compiled binary XML resources and application assets into textual representations.",
        )

        # jadx status
        self.jadx_status_lbl = self._create_diag_row(
            self.diag_grid,
            row=2,
            title="jadx Java Decompiler:",
            desc="Decompiles DEX bytecode into Java source files for deep source-level auditing.",
        )

        # Java status
        self.java_status_lbl = self._create_diag_row(
            self.diag_grid,
            row=3,
            title="Java Runtime Environment (JRE):",
            desc="Required runtime for launching external decompilers (apktool and jadx JARs).",
        )

        # =====================================================================
        # SECTION 2: TOOL PATHS & OUTPUT DIRECTORY
        # =====================================================================
        paths_card = tk.Frame(
            self.content,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=16,
            pady=14,
        )
        paths_card.pack(fill=tk.X, pady=(0, 12))

        tk.Label(
            paths_card,
            text="Tool Executable Paths & Output Location",
            font=FONT_HEADING,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 10))

        # JADX Path field
        self.jadx_path_var = tk.StringVar()
        self._create_path_row(
            paths_card,
            label_text="JADX Executable Path:",
            text_var=self.jadx_path_var,
            on_browse=self._browse_jadx,
            placeholder="Auto-detected in system PATH (or specify custom path)",
        )

        # Apktool Path field
        self.apktool_path_var = tk.StringVar()
        self._create_path_row(
            paths_card,
            label_text="Apktool Executable Path:",
            text_var=self.apktool_path_var,
            on_browse=self._browse_apktool,
            placeholder="Auto-detected in system PATH (or specify custom path)",
        )

        # Output Directory field
        self.output_dir_var = tk.StringVar()
        self._create_path_row(
            paths_card,
            label_text="Report Output Directory:",
            text_var=self.output_dir_var,
            on_browse=self._browse_output_dir,
            placeholder="Folder where exported PDF, HTML, and TXT reports will be saved",
        )

        # Timeout setting
        timeout_row = tk.Frame(paths_card, bg=COLOR_CARD_BG)
        timeout_row.pack(fill=tk.X, pady=(8, 2))

        tk.Label(
            timeout_row,
            text="Process Timeout (seconds):",
            font=FONT_BODY_BOLD,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            width=24,
            anchor="w",
        ).pack(side=tk.LEFT)

        self.timeout_var = tk.StringVar(value=str(self.app_config.subprocess_timeout_seconds))
        self.timeout_spin = ttk.Spinbox(
            timeout_row,
            from_=15,
            to=600,
            textvariable=self.timeout_var,
            width=8,
        )
        self.timeout_spin.pack(side=tk.LEFT)

        tk.Label(
            timeout_row,
            text="(Terminates subprocess if decompiler hangs. Default: 120s)",
            font=FONT_SMALL,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_MUTED,
        ).pack(side=tk.LEFT, padx=(10, 0))

        # =====================================================================
        # SECTION 3: REPORT PREFERENCES
        # =====================================================================
        report_card = tk.Frame(
            self.content,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=16,
            pady=14,
        )
        report_card.pack(fill=tk.X, pady=(0, 12))

        tk.Label(
            report_card,
            text="Report Preferences",
            font=FONT_HEADING,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 8))

        # Default Format
        fmt_row = tk.Frame(report_card, bg=COLOR_CARD_BG)
        fmt_row.pack(fill=tk.X, pady=4)

        tk.Label(
            fmt_row,
            text="Default Export Format:",
            font=FONT_BODY_BOLD,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            width=24,
            anchor="w",
        ).pack(side=tk.LEFT)

        self.report_fmt_var = tk.StringVar(value=self.app_config.report_default_format)
        fmt_combo = ttk.Combobox(
            fmt_row,
            textvariable=self.report_fmt_var,
            values=["PDF", "HTML", "TXT"],
            state="readonly",
            width=10,
        )
        fmt_combo.pack(side=tk.LEFT)

        # Checkboxes for report contents
        self.rep_disclaimer_var = tk.BooleanVar(value=self.app_config.report_include_disclaimer)
        self.rep_owasp_var = tk.BooleanVar(value=self.app_config.report_include_owasp)
        self.rep_perms_var = tk.BooleanVar(value=self.app_config.report_include_permissions)

        ttk.Checkbutton(
            report_card,
            text="Include academic methodology & static analysis disclaimer in reports",
            variable=self.rep_disclaimer_var,
        ).pack(anchor="w", pady=(6, 2))

        ttk.Checkbutton(
            report_card,
            text="Include OWASP MASVS and CWE vulnerability mappings in reports",
            variable=self.rep_owasp_var,
        ).pack(anchor="w", pady=2)

        ttk.Checkbutton(
            report_card,
            text="Include detailed permission auditing breakdown in reports",
            variable=self.rep_perms_var,
        ).pack(anchor="w", pady=2)

        # =====================================================================
        # SECTION 4: ACCESSIBILITY & HIGH-CONTRAST
        # =====================================================================
        access_card = tk.Frame(
            self.content,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=16,
            pady=14,
        )
        access_card.pack(fill=tk.X, pady=(0, 12))

        tk.Label(
            access_card,
            text="Accessibility & Display",
            font=FONT_HEADING,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 6))

        self.high_contrast_var = tk.BooleanVar(value=self.app_config.high_contrast_mode)
        ttk.Checkbutton(
            access_card,
            text="Enable High-Contrast Mode (Increases visual border definitions and badge contrast)",
            variable=self.high_contrast_var,
        ).pack(anchor="w", pady=2)

        # =====================================================================
        # SECTION 5: OPTIONAL ANALYSIS RULES CONTROLS
        # =====================================================================
        rules_card = tk.Frame(
            self.content,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=16,
            pady=14,
        )
        rules_card.pack(fill=tk.X, pady=(0, 12))

        tk.Label(
            rules_card,
            text="Analysis Rule Engine Controls",
            font=FONT_HEADING,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 4))

        tk.Label(
            rules_card,
            text="Enable or disable specific static vulnerability inspection rule categories:",
            font=FONT_BODY,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_MUTED,
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 8))

        self.rule_manifest_var = tk.BooleanVar(value=self.app_config.enable_manifest_rules)
        self.rule_secrets_var = tk.BooleanVar(value=self.app_config.enable_secret_rules)
        self.rule_network_var = tk.BooleanVar(value=self.app_config.enable_network_rules)
        self.rule_storage_var = tk.BooleanVar(value=self.app_config.enable_storage_rules)
        self.rule_crypto_var = tk.BooleanVar(value=self.app_config.enable_crypto_rules)
        self.rule_sdks_var = tk.BooleanVar(value=self.app_config.enable_sdk_rules)

        rules_grid = tk.Frame(rules_card, bg=COLOR_CARD_BG)
        rules_grid.pack(fill=tk.X)

        ttk.Checkbutton(
            rules_grid,
            text="Manifest Security Rules (exported components, debuggable, allowBackup)",
            variable=self.rule_manifest_var,
        ).grid(row=0, column=0, sticky="w", pady=3)

        ttk.Checkbutton(
            rules_grid,
            text="Secret & Credential Scanner (hardcoded API tokens, private keys)",
            variable=self.rule_secrets_var,
        ).grid(row=1, column=0, sticky="w", pady=3)

        ttk.Checkbutton(
            rules_grid,
            text="Network Communication Rules (cleartext HTTP, SSL validation bypasses)",
            variable=self.rule_network_var,
        ).grid(row=2, column=0, sticky="w", pady=3)

        ttk.Checkbutton(
            rules_grid,
            text="Insecure Storage Rules (world-readable modes, plaintext SharedPreferences)",
            variable=self.rule_storage_var,
        ).grid(row=0, column=1, sticky="w", padx=(20, 0), pady=3)

        ttk.Checkbutton(
            rules_grid,
            text="Cryptography Flaw Rules (DES/3DES/RC4, ECB mode, static IVs)",
            variable=self.rule_crypto_var,
        ).grid(row=1, column=1, sticky="w", padx=(20, 0), pady=3)

        ttk.Checkbutton(
            rules_grid,
            text="Third-Party SDK & Telemetry Rules (tracking SDKs, permission exposure)",
            variable=self.rule_sdks_var,
        ).grid(row=2, column=1, sticky="w", padx=(20, 0), pady=3)

        # =====================================================================
        # SECTION 6: ACTION BUTTONS (SAVE & RESET)
        # =====================================================================
        action_bar = tk.Frame(self.content, bg=COLOR_BG)
        action_bar.pack(fill=tk.X, pady=(6, 20))

        btn_save = ttk.Button(
            action_bar,
            text="💾 Save Settings",
            style="Primary.TButton",
            command=self.save_settings,
        )
        btn_save.pack(side=tk.LEFT, padx=(0, 10))

        btn_reset = ttk.Button(
            action_bar,
            text="🔄 Reset Settings to Default",
            style="Danger.TButton",
            command=self.reset_settings,
        )
        btn_reset.pack(side=tk.LEFT)

    # -------------------------------------------------------------------------
    # ROW BUILDERS
    # -------------------------------------------------------------------------
    def _create_diag_row(self, master: tk.Misc, row: int, title: str, desc: str) -> tk.Label:
        """Create a standardized diagnostic label row."""
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

    def _create_path_row(
        self,
        master: tk.Misc,
        label_text: str,
        text_var: tk.StringVar,
        on_browse: Callable[[], None],
        placeholder: str,
    ) -> None:
        """Create an executable or directory path input row with Browse button."""
        frame = tk.Frame(master, bg=COLOR_CARD_BG)
        frame.pack(fill=tk.X, pady=4)

        tk.Label(
            frame,
            text=label_text,
            font=FONT_BODY_BOLD,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            width=24,
            anchor="w",
        ).pack(side=tk.LEFT)

        entry = ttk.Entry(frame, textvariable=text_var, width=50, font=FONT_CODE)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        btn = ttk.Button(frame, text="Browse...", style="Secondary.TButton", command=on_browse)
        btn.pack(side=tk.RIGHT)

    # -------------------------------------------------------------------------
    # TOOL DIAGNOSTICS ("CHECK TOOLS")
    # -------------------------------------------------------------------------
    def check_tools(self) -> None:
        """Inspect and verify AndroGuard, apktool, jadx, and Java status."""
        logger.info("Running tool diagnostics check...")

        # 1. AndroGuard status
        try:
            import androguard
            ver = getattr(androguard, "__version__", "installed")
            self.androguard_status_lbl.config(
                text=f"✔ Available (v{ver} AST/DEX parser active)",
                fg=COLOR_SUCCESS,
            )
        except ImportError:
            self.androguard_status_lbl.config(
                text="✔ Available (Built-in static fallback parser active)",
                fg=COLOR_SUCCESS,
            )

        # 2. apktool status
        apktool_custom = self.apktool_path_var.get().strip() if hasattr(self, "apktool_path_var") else ""
        apktool_adapter = ApktoolAdapter(custom_path=Path(apktool_custom) if apktool_custom else None)
        if apktool_adapter.is_available():
            self.apktool_status_lbl.config(
                text="✔ Available (Binary XML and resource extraction ready)",
                fg=COLOR_SUCCESS,
            )
        else:
            self.apktool_status_lbl.config(
                text="⚠ Not Detected in PATH (Manifest extraction fallback active)",
                fg="#d97706",
            )

        # 3. jadx status
        jadx_custom = self.jadx_path_var.get().strip() if hasattr(self, "jadx_path_var") else ""
        jadx_adapter = JadxAdapter(custom_path=Path(jadx_custom) if jadx_custom else None)
        if jadx_adapter.is_available():
            self.jadx_status_lbl.config(
                text="✔ Available (Java decompilation ready)",
                fg=COLOR_SUCCESS,
            )
        else:
            self.jadx_status_lbl.config(
                text="⚠ Not Detected in PATH (DEX bytecode pool inspection active)",
                fg="#d97706",
            )

        # 4. Java status
        java_exe = shutil.which("java")
        if java_exe:
            try:
                res = subprocess.run(
                    [java_exe, "-version"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                )
                output = res.stderr or res.stdout
                first_line = output.splitlines()[0] if output else "Java runtime detected"
                # Keep it concise, do not expose internal paths
                self.java_status_lbl.config(
                    text=f"✔ Available ({first_line[:40]})",
                    fg=COLOR_SUCCESS,
                )
            except Exception:
                self.java_status_lbl.config(
                    text="✔ Available (Java runtime detected)",
                    fg=COLOR_SUCCESS,
                )
        else:
            self.java_status_lbl.config(
                text="⚠ Not Detected in PATH (Required for external decompiler JARs)",
                fg="#d97706",
            )

    # -------------------------------------------------------------------------
    # FILE / DIRECTORY BROWSERS
    # -------------------------------------------------------------------------
    def _browse_jadx(self) -> None:
        """Browse file dialog for jadx executable."""
        chosen = filedialog.askopenfilename(
            title="Select jadx Executable",
            filetypes=[("Executables", "*.bat;*.exe;jadx;*"), ("All Files", "*.*")],
        )
        if chosen:
            self.jadx_path_var.set(chosen)
            self.check_tools()

    def _browse_apktool(self) -> None:
        """Browse file dialog for apktool executable or JAR."""
        chosen = filedialog.askopenfilename(
            title="Select apktool Executable or JAR",
            filetypes=[("Executables / JARs", "*.bat;*.jar;apktool;*"), ("All Files", "*.*")],
        )
        if chosen:
            self.apktool_path_var.set(chosen)
            self.check_tools()

    def _browse_output_dir(self) -> None:
        """Browse directory dialog for report output destination."""
        chosen = filedialog.askdirectory(title="Select Report Output Directory")
        if chosen:
            self.output_dir_var.set(chosen)

    # -------------------------------------------------------------------------
    # FORM VALUE PERSISTENCE & RESET
    # -------------------------------------------------------------------------
    def _load_values_into_form(self) -> None:
        """Populate form variables from runtime AppConfig."""
        # Try loading persisted settings from disk if available
        self.app_config.load_from_disk()

        self.jadx_path_var.set(str(self.app_config.jadx_path or ""))
        self.apktool_path_var.set(str(self.app_config.apktool_path or ""))
        self.output_dir_var.set(str(self.app_config.output_dir or ""))
        self.timeout_var.set(str(self.app_config.subprocess_timeout_seconds))
        self.report_fmt_var.set(self.app_config.report_default_format)
        self.rep_disclaimer_var.set(self.app_config.report_include_disclaimer)
        self.rep_owasp_var.set(self.app_config.report_include_owasp)
        self.rep_perms_var.set(self.app_config.report_include_permissions)
        self.high_contrast_var.set(self.app_config.high_contrast_mode)
        self.rule_manifest_var.set(self.app_config.enable_manifest_rules)
        self.rule_secrets_var.set(self.app_config.enable_secret_rules)
        self.rule_network_var.set(self.app_config.enable_network_rules)
        self.rule_storage_var.set(self.app_config.enable_storage_rules)
        self.rule_crypto_var.set(self.app_config.enable_crypto_rules)
        self.rule_sdks_var.set(self.app_config.enable_sdk_rules)

    def save_settings(self) -> None:
        """Save form values into AppConfig and persist to user configuration directory."""
        try:
            val = int(self.timeout_var.get())
            if val < 5:
                val = 5
            self.app_config.subprocess_timeout_seconds = val
        except ValueError:
            messagebox.showerror("Invalid Timeout", "Timeout must be a positive integer number of seconds.")
            return

        self.app_config.jadx_path = self.jadx_path_var.get().strip()
        self.app_config.apktool_path = self.apktool_path_var.get().strip()
        self.app_config.output_dir = self.output_dir_var.get().strip()
        self.app_config.report_default_format = self.report_fmt_var.get().strip()
        self.app_config.report_include_disclaimer = self.rep_disclaimer_var.get()
        self.app_config.report_include_owasp = self.rep_owasp_var.get()
        self.app_config.report_include_permissions = self.rep_perms_var.get()
        self.app_config.high_contrast_mode = self.high_contrast_var.get()
        self.app_config.enable_manifest_rules = self.rule_manifest_var.get()
        self.app_config.enable_secret_rules = self.rule_secrets_var.get()
        self.app_config.enable_network_rules = self.rule_network_var.get()
        self.app_config.enable_storage_rules = self.rule_storage_var.get()
        self.app_config.enable_crypto_rules = self.rule_crypto_var.get()
        self.app_config.enable_sdk_rules = self.rule_sdks_var.get()

        # Persist to disk in user configuration directory
        saved_file = self.app_config.save_to_disk()
        messagebox.showinfo("Settings Saved", f"Configuration settings successfully saved to:\n{saved_file.name}")

    def reset_settings(self) -> None:
        """Reset all configuration settings to default and persist to disk."""
        confirm = messagebox.askyesno(
            "Confirm Reset",
            "Are you sure you want to restore all settings to their default values?",
        )
        if not confirm:
            return

        self.app_config.reset_to_defaults()
        self._load_values_into_form()
        self.check_tools()
        messagebox.showinfo("Settings Restored", "All configuration settings have been restored to defaults.")

    # -------------------------------------------------------------------------
    # BACKWARD COMPATIBILITY
    # -------------------------------------------------------------------------
    def _save_settings(self) -> None:
        """Backward compatibility alias for tests."""
        self.save_settings()

    def _reset_defaults(self) -> None:
        """Backward compatibility alias for tests."""
        self.reset_settings()
