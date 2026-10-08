"""Reusable custom Tkinter/ttk UI widgets and theme styling."""

from __future__ import annotations

import logging
import os
import sys
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Callable

logger = logging.getLogger(__name__)

# Typography definitions
FONT_FAMILY = "Segoe UI" if sys.platform == "win32" else "Helvetica"
FONT_TITLE = (FONT_FAMILY, 16, "bold")
FONT_SUBTITLE = (FONT_FAMILY, 10)
FONT_HEADING = (FONT_FAMILY, 12, "bold")
FONT_SUBHEADING = (FONT_FAMILY, 10, "bold")
FONT_BODY = (FONT_FAMILY, 9)
FONT_BODY_BOLD = (FONT_FAMILY, 9, "bold")
FONT_SMALL = (FONT_FAMILY, 8)
FONT_CODE = ("Consolas" if sys.platform == "win32" else "Courier", 9)

# Theme Palette (Professional Academic / Slate & Blue)
COLOR_BG = "#f8fafc"            # Slate-50
COLOR_CARD_BG = "#ffffff"       # Pure white
COLOR_SIDEBAR_BG = "#0f172a"    # Slate-900
COLOR_SIDEBAR_HOVER = "#1e293b" # Slate-800
COLOR_SIDEBAR_ACTIVE = "#2563eb"# Blue-600
COLOR_SIDEBAR_TEXT = "#f8fafc"  # Slate-50
COLOR_SIDEBAR_MUTED = "#94a3b8" # Slate-400
COLOR_TEXT_PRIMARY = "#0f172a"  # Slate-900
COLOR_TEXT_SECONDARY = "#334155"# Slate-700
COLOR_TEXT_MUTED = "#64748b"    # Slate-500
COLOR_BORDER = "#cbd5e1"        # Slate-300
COLOR_BORDER_LIGHT = "#e2e8f0"  # Slate-200
COLOR_ACCENT = "#2563eb"        # Blue-600
COLOR_ACCENT_HOVER = "#1d4ed8"  # Blue-700
COLOR_SUCCESS = "#16a34a"       # Green-600

# Severity Color Tokens (High contrast, accessible)
SEVERITY_COLORS: dict[str, dict[str, str]] = {
    "CRITICAL": {
        "bg": "#fef2f2",
        "fg": "#991b1b",
        "badge_bg": "#dc2626",
        "badge_fg": "#ffffff",
        "border": "#f87171",
    },
    "HIGH": {
        "bg": "#fff7ed",
        "fg": "#9a3412",
        "badge_bg": "#ea580c",
        "badge_fg": "#ffffff",
        "border": "#fb923c",
    },
    "MEDIUM": {
        "bg": "#fefce8",
        "fg": "#854d0e",
        "badge_bg": "#d97706",
        "badge_fg": "#ffffff",
        "border": "#facc15",
    },
    "LOW": {
        "bg": "#eff6ff",
        "fg": "#1e40af",
        "badge_bg": "#2563eb",
        "badge_fg": "#ffffff",
        "border": "#60a5fa",
    },
    "INFO": {
        "bg": "#f8fafc",
        "fg": "#334155",
        "badge_bg": "#64748b",
        "badge_fg": "#ffffff",
        "border": "#94a3b8",
    },
}


def apply_custom_styles(style: ttk.Style | None = None) -> ttk.Style:
    """Configure modern ttk styles with readable typography and clean spacing."""
    if style is None:
        style = ttk.Style()

    # Use 'clam' or 'alt' as baseline for consistent cross-platform theming
    try:
        available_themes = style.theme_names()
        if "clam" in available_themes:
            style.theme_use("clam")
        elif "vista" in available_themes and sys.platform == "win32":
            style.theme_use("vista")
    except Exception as exc:
        logger.debug("Failed to set ttk theme: %s", exc)

    # General Frame styles
    style.configure("TFrame", background=COLOR_BG)
    style.configure("Card.TFrame", background=COLOR_CARD_BG, relief="solid", borderwidth=1)
    style.configure("Sidebar.TFrame", background=COLOR_SIDEBAR_BG)

    # Label styles
    style.configure(
        "TLabel",
        background=COLOR_BG,
        foreground=COLOR_TEXT_PRIMARY,
        font=FONT_BODY,
    )
    style.configure(
        "Card.TLabel",
        background=COLOR_CARD_BG,
        foreground=COLOR_TEXT_PRIMARY,
        font=FONT_BODY,
    )
    style.configure(
        "Muted.TLabel",
        background=COLOR_BG,
        foreground=COLOR_TEXT_MUTED,
        font=FONT_SMALL,
    )
    style.configure(
        "CardMuted.TLabel",
        background=COLOR_CARD_BG,
        foreground=COLOR_TEXT_MUTED,
        font=FONT_SMALL,
    )
    style.configure(
        "Title.TLabel",
        background=COLOR_BG,
        foreground=COLOR_TEXT_PRIMARY,
        font=FONT_TITLE,
    )
    style.configure(
        "Subtitle.TLabel",
        background=COLOR_BG,
        foreground=COLOR_TEXT_MUTED,
        font=FONT_SUBTITLE,
    )
    style.configure(
        "Heading.TLabel",
        background=COLOR_BG,
        foreground=COLOR_TEXT_PRIMARY,
        font=FONT_HEADING,
    )
    style.configure(
        "CardHeading.TLabel",
        background=COLOR_CARD_BG,
        foreground=COLOR_TEXT_PRIMARY,
        font=FONT_SUBHEADING,
    )

    # Primary Action Button
    style.configure(
        "Primary.TButton",
        background=COLOR_ACCENT,
        foreground="#ffffff",
        font=FONT_BODY_BOLD,
        borderwidth=0,
        focuscolor="none",
        padding=(14, 8),
    )
    style.map(
        "Primary.TButton",
        background=[("active", COLOR_ACCENT_HOVER), ("disabled", "#94a3b8")],
        foreground=[("disabled", "#f1f5f9")],
    )

    # Secondary Action Button
    style.configure(
        "Secondary.TButton",
        background="#e2e8f0",
        foreground=COLOR_TEXT_PRIMARY,
        font=FONT_BODY,
        borderwidth=1,
        padding=(10, 6),
    )
    style.map(
        "Secondary.TButton",
        background=[("active", "#cbd5e1"), ("disabled", "#f1f5f9")],
        foreground=[("disabled", "#94a3b8")],
    )

    # Danger Button (e.g., Cancel / Delete)
    style.configure(
        "Danger.TButton",
        background="#dc2626",
        foreground="#ffffff",
        font=FONT_BODY,
        borderwidth=0,
        padding=(10, 6),
    )
    style.map(
        "Danger.TButton",
        background=[("active", "#b91c1c"), ("disabled", "#fca5a5")],
    )

    # Sidebar Navigation Buttons
    style.configure(
        "Sidebar.TButton",
        background=COLOR_SIDEBAR_BG,
        foreground=COLOR_SIDEBAR_TEXT,
        font=FONT_BODY,
        anchor="w",
        borderwidth=0,
        padding=(16, 10),
    )
    style.map(
        "Sidebar.TButton",
        background=[("active", COLOR_SIDEBAR_HOVER), ("selected", COLOR_SIDEBAR_ACTIVE)],
        foreground=[("active", "#ffffff"), ("selected", "#ffffff")],
    )

    # Notebook Tabs
    style.configure(
        "TNotebook",
        background=COLOR_BG,
        borderwidth=0,
    )
    style.configure(
        "TNotebook.Tab",
        background="#e2e8f0",
        foreground=COLOR_TEXT_PRIMARY,
        font=FONT_BODY_BOLD,
        padding=(16, 8),
        borderwidth=0,
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", COLOR_CARD_BG), ("active", "#cbd5e1")],
        foreground=[("selected", COLOR_ACCENT)],
    )

    # Treeview Styles
    style.configure(
        "Treeview",
        background=COLOR_CARD_BG,
        foreground=COLOR_TEXT_PRIMARY,
        rowheight=26,
        fieldbackground=COLOR_CARD_BG,
        font=FONT_BODY,
        borderwidth=1,
    )
    style.configure(
        "Treeview.Heading",
        background="#e2e8f0",
        foreground=COLOR_TEXT_PRIMARY,
        font=FONT_BODY_BOLD,
        padding=(6, 4),
    )
    style.map(
        "Treeview.Heading",
        background=[("active", "#cbd5e1")],
    )

    # Progressbar
    style.configure(
        "TProgressbar",
        troughcolor="#e2e8f0",
        background=COLOR_ACCENT,
        thickness=10,
    )

    return style


class SeverityBadge(tk.Frame):
    """Visual colored pill/badge for severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)."""

    def __init__(
        self,
        master: tk.Misc,
        severity: str,
        *args,
        **kwargs,
    ) -> None:
        norm_sev = str(severity).upper().strip()
        color_info = SEVERITY_COLORS.get(norm_sev, SEVERITY_COLORS["INFO"])

        super().__init__(
            master,
            bg=color_info["badge_bg"],
            padx=8,
            pady=2,
            relief="flat",
            *args,
            **kwargs,
        )

        self._label = tk.Label(
            self,
            text=norm_sev,
            bg=color_info["badge_bg"],
            fg=color_info["badge_fg"],
            font=FONT_SMALL,
            anchor="center",
        )
        self._label.pack(fill=tk.BOTH, expand=True)

    def set_severity(self, severity: str) -> None:
        """Update badge severity and color scheme."""
        norm_sev = str(severity).upper().strip()
        color_info = SEVERITY_COLORS.get(norm_sev, SEVERITY_COLORS["INFO"])
        self.configure(bg=color_info["badge_bg"])
        self._label.configure(
            text=norm_sev,
            bg=color_info["badge_bg"],
            fg=color_info["badge_fg"],
        )


class MetricCard(tk.Frame):
    """Clean stat card displaying count, title, and colored accent bar."""

    def __init__(
        self,
        master: tk.Misc,
        title: str,
        value: str | int = "0",
        subtitle: str = "",
        accent_color: str = COLOR_ACCENT,
        bg_color: str = COLOR_CARD_BG,
        *args,
        **kwargs,
    ) -> None:
        super().__init__(
            master,
            bg=bg_color,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightcolor=accent_color,
            highlightthickness=1,
            bd=0,
            padx=12,
            pady=10,
            *args,
            **kwargs,
        )
        self.accent_color = accent_color
        self.bg_color = bg_color

        # Accent top indicator stripe
        self.stripe = tk.Frame(self, bg=accent_color, height=4)
        self.stripe.pack(fill=tk.X, side=tk.TOP, pady=(0, 6))

        # Title Label
        self.title_label = tk.Label(
            self,
            text=title.upper(),
            bg=bg_color,
            fg=COLOR_TEXT_MUTED,
            font=FONT_SMALL,
            anchor="w",
        )
        self.title_label.pack(fill=tk.X)

        # Large Value Label
        self.value_label = tk.Label(
            self,
            text=str(value),
            bg=bg_color,
            fg=COLOR_TEXT_PRIMARY,
            font=(FONT_FAMILY, 20, "bold"),
            anchor="w",
        )
        self.value_label.pack(fill=tk.X, pady=(2, 2))

        # Subtitle / Details Label
        self.subtitle_label = tk.Label(
            self,
            text=subtitle,
            bg=bg_color,
            fg=COLOR_TEXT_MUTED,
            font=FONT_SMALL,
            anchor="w",
        )
        if subtitle:
            self.subtitle_label.pack(fill=tk.X)

    def set_value(self, value: str | int, subtitle: str | None = None) -> None:
        """Update metric value and optional subtitle."""
        self.value_label.config(text=str(value))
        if subtitle is not None:
            self.subtitle_label.config(text=subtitle)
            if subtitle and not self.subtitle_label.winfo_ismapped():
                self.subtitle_label.pack(fill=tk.X)


class EmptyState(tk.Frame):
    """Informative empty-state view with icon, title, and descriptive text."""

    def __init__(
        self,
        master: tk.Misc,
        title: str = "No Analysis Performed",
        message: str = "Select an Android APK file to begin static inspection.",
        icon: str = "📋",
        action_text: str = "",
        action_command: Callable[[], None] | None = None,
        *args,
        **kwargs,
    ) -> None:
        super().__init__(master, bg=COLOR_BG, *args, **kwargs)

        container = tk.Frame(self, bg=COLOR_BG, padx=20, pady=40)
        container.pack(expand=True)

        # Icon Glyph
        icon_label = tk.Label(
            container,
            text=icon,
            font=(FONT_FAMILY, 36),
            bg=COLOR_BG,
            fg=COLOR_TEXT_MUTED,
        )
        icon_label.pack(pady=(0, 10))

        # Title
        title_label = tk.Label(
            container,
            text=title,
            font=FONT_HEADING,
            bg=COLOR_BG,
            fg=COLOR_TEXT_PRIMARY,
        )
        title_label.pack(pady=(0, 6))

        # Message
        msg_label = tk.Label(
            container,
            text=message,
            font=FONT_BODY,
            bg=COLOR_BG,
            fg=COLOR_TEXT_MUTED,
            wraplength=480,
            justify="center",
        )
        msg_label.pack(pady=(0, 16))

        # Optional Action Button
        if action_text and action_command:
            btn = ttk.Button(
                container,
                text=action_text,
                style="Primary.TButton",
                command=action_command,
            )
            btn.pack()


class DropZone(tk.Frame):
    """APK selection frame with visual drop zone and Browse button."""

    def __init__(
        self,
        master: tk.Misc,
        on_browse: Callable[[], None],
        on_file_dropped: Callable[[str], None] | None = None,
        *args,
        **kwargs,
    ) -> None:
        super().__init__(
            master,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER,
            highlightcolor=COLOR_ACCENT,
            highlightthickness=2,
            bd=0,
            padx=20,
            pady=18,
            *args,
            **kwargs,
        )
        self.on_browse = on_browse
        self.on_file_dropped = on_file_dropped

        # Drop Zone Icon & Prompt
        top_frame = tk.Frame(self, bg=COLOR_CARD_BG)
        top_frame.pack(fill=tk.X)

        icon_label = tk.Label(
            top_frame,
            text="📦",
            font=(FONT_FAMILY, 28),
            bg=COLOR_CARD_BG,
            fg=COLOR_ACCENT,
        )
        icon_label.pack(side=tk.LEFT, padx=(0, 14))

        text_box = tk.Frame(top_frame, bg=COLOR_CARD_BG)
        text_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        prompt_title = tk.Label(
            text_box,
            text="Select Target Android Package (APK)",
            font=FONT_HEADING,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        )
        prompt_title.pack(fill=tk.X)

        prompt_sub = tk.Label(
            text_box,
            text="Choose an .apk file for static bytecode, manifest, secret, and cryptographic auditing.",
            font=FONT_BODY,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_MUTED,
            anchor="w",
        )
        prompt_sub.pack(fill=tk.X, pady=(2, 0))

        # Browse Button (Always available and prominent)
        self.browse_btn = ttk.Button(
            top_frame,
            text="Browse File...",
            style="Primary.TButton",
            command=self.on_browse,
        )
        self.browse_btn.pack(side=tk.RIGHT, padx=(10, 0))

        # Selected File Details Frame (Initially hidden)
        self.details_frame = tk.Frame(
            self,
            bg="#f1f5f9",
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=12,
            pady=8,
        )
        self.file_name_label = tk.Label(
            self.details_frame,
            text="",
            font=FONT_BODY_BOLD,
            bg="#f1f5f9",
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        )
        self.file_name_label.pack(fill=tk.X)

        self.file_meta_label = tk.Label(
            self.details_frame,
            text="",
            font=FONT_SMALL,
            bg="#f1f5f9",
            fg=COLOR_TEXT_MUTED,
            anchor="w",
        )
        self.file_meta_label.pack(fill=tk.X, pady=(2, 0))

        # Hook drag and drop if tkinterdnd2 is supported
        self._register_dnd_if_available()

    def _register_dnd_if_available(self) -> None:
        """Attempt to register tkinterdnd2 drop target if available."""
        try:
            # Check if root has drop_target_register method
            if hasattr(self, "drop_target_register"):
                self.drop_target_register("DND_Files")
                self.dnd_bind("<<Drop>>", self._on_drop_event)
        except Exception as exc:
            logger.debug("tkinterdnd2 not available on this widget: %s", exc)

    def _on_drop_event(self, event: Any) -> None:
        """Handle tkinterdnd2 drop event."""
        if self.on_file_dropped and hasattr(event, "data"):
            raw_path = str(event.data).strip("{}'\"")
            if raw_path.lower().endswith(".apk"):
                self.on_file_dropped(raw_path)

    def show_selected_file(self, file_path: str) -> None:
        """Display information for the selected APK file."""
        p = Path(file_path)
        size_str = "Unknown size"
        if p.exists():
            try:
                sz = p.stat().st_size
                if sz > 1024 * 1024:
                    size_str = f"{sz / (1024 * 1024):.1f} MB"
                else:
                    size_str = f"{sz / 1024:.1f} KB"
            except Exception:
                pass

        self.file_name_label.config(text=f"Selected APK: {p.name}")
        self.file_meta_label.config(text=f"Size: {size_str}  •  Path: {str(p)}")
        self.details_frame.pack(fill=tk.X, pady=(12, 0))

    def clear(self) -> None:
        """Reset selected file display."""
        self.file_name_label.config(text="")
        self.file_meta_label.config(text="")
        self.details_frame.pack_forget()


class DisclaimerBanner(tk.Frame):
    """Academic static analysis methodology and limitation notice."""

    def __init__(self, master: tk.Misc, *args, **kwargs) -> None:
        super().__init__(
            master,
            bg="#f8fafc",
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=12,
            pady=10,
            *args,
            **kwargs,
        )

        title_lbl = tk.Label(
            self,
            text="ℹ Academic Methodology & Research Prototype Notice",
            font=FONT_SUBHEADING,
            bg="#f8fafc",
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        )
        title_lbl.pack(fill=tk.X)

        text = (
            "Static analysis only: The application bytecode, manifest, and resources were evaluated "
            "without running the app in an emulator or on a physical device. Findings indicate potential "
            "vulnerabilities and architectural weaknesses. The risk score is an explainable heuristic "
            "prioritisation metric and does not constitute CVSS or conclusive proof of active runtime exploitation."
        )
        body_lbl = tk.Label(
            self,
            text=text,
            font=FONT_SMALL,
            bg="#f8fafc",
            fg=COLOR_TEXT_MUTED,
            wraplength=640,
            justify="left",
            anchor="w",
        )
        body_lbl.pack(fill=tk.X, pady=(4, 0))
