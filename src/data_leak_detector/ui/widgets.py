"""Reusable custom Tkinter/ttk UI widgets and theme styling."""

from __future__ import annotations

import logging
import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Any, Callable

from data_leak_detector.core.redactor import redact_text_secrets

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
COLOR_DANGER = "#dc2626"        # Red-600
COLOR_WARNING = "#d97706"       # Amber-600

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

# Confidence Color Tokens
CONFIDENCE_COLORS: dict[str, dict[str, str]] = {
    "HIGH": {"bg": "#f0fdf4", "fg": "#15803d", "border": "#86efac"},    # Green
    "MEDIUM": {"bg": "#fffbeb", "fg": "#b45309", "border": "#fde68a"},  # Amber
    "LOW": {"bg": "#f1f5f9", "fg": "#475569", "border": "#cbd5e1"},     # Slate
}

# Category Color Mapping
CATEGORY_COLORS: dict[str, dict[str, str]] = {
    "SECRETS": {"bg": "#fdf2f8", "fg": "#be185d", "border": "#f472b6"},
    "NETWORK": {"bg": "#f0f9ff", "fg": "#0369a1", "border": "#7dd3fc"},
    "STORAGE": {"bg": "#fefce8", "fg": "#a16207", "border": "#fde047"},
    "CRYPTOGRAPHY": {"bg": "#faf5ff", "fg": "#7e22ce", "border": "#d8b4fe"},
    "SDKS": {"bg": "#f0fdfa", "fg": "#0f766e", "border": "#5eead4"},
    "PERMISSIONS": {"bg": "#f8fafc", "fg": "#334155", "border": "#cbd5e1"},
    "MANIFEST": {"bg": "#f5f3ff", "fg": "#6d28d9", "border": "#c4b5fd"},
    "OTHER": {"bg": "#f8fafc", "fg": "#475569", "border": "#cbd5e1"},
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


class ConfidenceBadge(tk.Frame):
    """Visual pill badge displaying confidence ratings (HIGH, MEDIUM, LOW)."""

    def __init__(self, master: tk.Misc, confidence: str, *args, **kwargs) -> None:
        norm_conf = str(confidence).upper().strip()
        color_info = CONFIDENCE_COLORS.get(norm_conf, CONFIDENCE_COLORS["LOW"])

        super().__init__(
            master,
            bg=color_info["bg"],
            highlightbackground=color_info["border"],
            highlightthickness=1,
            padx=6,
            pady=2,
            bd=0,
            *args,
            **kwargs,
        )

        self._label = tk.Label(
            self,
            text=f"CONF: {norm_conf}",
            bg=color_info["bg"],
            fg=color_info["fg"],
            font=FONT_SMALL,
            anchor="center",
        )
        self._label.pack(fill=tk.BOTH, expand=True)


class CategoryBadge(tk.Frame):
    """Visual pill badge displaying finding category."""

    def __init__(self, master: tk.Misc, category: str, *args, **kwargs) -> None:
        cat_key = str(category).upper().replace(" ", "_")
        # Normalize category keys
        if "SECRET" in cat_key:
            norm_key = "SECRETS"
        elif "NET" in cat_key:
            norm_key = "NETWORK"
        elif "STOR" in cat_key:
            norm_key = "STORAGE"
        elif "CRYPTO" in cat_key:
            norm_key = "CRYPTOGRAPHY"
        elif "SDK" in cat_key:
            norm_key = "SDKS"
        elif "PERM" in cat_key:
            norm_key = "PERMISSIONS"
        elif "MANIFEST" in cat_key:
            norm_key = "MANIFEST"
        else:
            norm_key = "OTHER"

        color_info = CATEGORY_COLORS.get(norm_key, CATEGORY_COLORS["OTHER"])

        super().__init__(
            master,
            bg=color_info["bg"],
            highlightbackground=color_info["border"],
            highlightthickness=1,
            padx=6,
            pady=2,
            bd=0,
            *args,
            **kwargs,
        )

        self._label = tk.Label(
            self,
            text=str(category).upper(),
            bg=color_info["bg"],
            fg=color_info["fg"],
            font=FONT_SMALL,
            anchor="center",
        )
        self._label.pack(fill=tk.BOTH, expand=True)


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


class ScrollableFrame(tk.Frame):
    """Vertical scrollable frame using Canvas with responsive width resizing and mousewheel support."""

    def __init__(self, master: tk.Misc, bg: str = COLOR_BG, *args, **kwargs) -> None:
        super().__init__(master, bg=bg, *args, **kwargs)
        self.canvas = tk.Canvas(self, bg=bg, bd=0, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.canvas.yview)
        self.scrollable_content = tk.Frame(self.canvas, bg=bg)

        self.scrollable_content.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")),
        )

        self.canvas_window = self.canvas.create_window(
            (0, 0), window=self.scrollable_content, anchor="nw"
        )

        self.canvas.bind(
            "<Configure>",
            lambda e: self.canvas.itemconfig(self.canvas_window, width=e.width),
        )

        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._bind_mousewheel(self.canvas)
        self._bind_mousewheel(self.scrollable_content)

    def _bind_mousewheel(self, widget: tk.Widget) -> None:
        """Bind mousewheel scrolling to canvas on hover."""
        widget.bind("<Enter>", lambda e: self.canvas.bind_all("<MouseWheel>", self._on_mousewheel))
        widget.bind("<Leave>", lambda e: self.canvas.unbind_all("<MouseWheel>"))

    def _on_mousewheel(self, event: Any) -> None:
        """Handle mousewheel scroll event across platforms."""
        if sys.platform == "win32":
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        elif sys.platform == "darwin":
            self.canvas.yview_scroll(int(-1 * event.delta), "units")
        else:
            if event.num == 4:
                self.canvas.yview_scroll(-1, "units")
            elif event.num == 5:
                self.canvas.yview_scroll(1, "units")


class ExpandableFindingCard(tk.Frame):
    """Reusable expandable card displaying a security finding.
    
    Collapsed state shows Severity, Title, Category, Confidence, and Plain-language explanation.
    Expanded state shows Evidence (guaranteed redacted), Location, Impact, Recommended Remediation,
    and OWASP mapping.
    """

    def __init__(
        self,
        master: tk.Misc,
        finding: Any,
        on_copy_evidence: Callable[[str], None] | None = None,
        initially_expanded: bool = False,
        *args,
        **kwargs,
    ) -> None:
        super().__init__(
            master,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightcolor=COLOR_ACCENT,
            highlightthickness=1,
            bd=0,
            padx=16,
            pady=12,
            *args,
            **kwargs,
        )
        self.finding = finding
        self.on_copy_evidence = on_copy_evidence
        self._expanded = False

        self._init_card()
        if initially_expanded:
            self.expand()

    def _init_card(self) -> None:
        """Construct the card layout with permanent header and expandable details."""
        f_sev = str(
            self.finding.severity.value if hasattr(self.finding.severity, "value") else self.finding.severity
        ).upper()
        f_conf = str(
            self.finding.confidence.value if hasattr(self.finding.confidence, "value") else self.finding.confidence
        ).upper()
        f_cat = str(
            self.finding.category.value if hasattr(self.finding.category, "value") else self.finding.category
        )

        # 1. Top Badges & Controls Header Bar
        header_bar = tk.Frame(self, bg=COLOR_CARD_BG)
        header_bar.pack(fill=tk.X, pady=(0, 6))

        # Severity Badge
        self.sev_badge = SeverityBadge(header_bar, severity=f_sev)
        self.sev_badge.pack(side=tk.LEFT, padx=(0, 6))

        # Category Badge
        self.cat_badge = CategoryBadge(header_bar, category=f_cat)
        self.cat_badge.pack(side=tk.LEFT, padx=(0, 6))

        # Confidence Badge
        self.conf_badge = ConfidenceBadge(header_bar, confidence=f_conf)
        self.conf_badge.pack(side=tk.LEFT, padx=(0, 8))

        # Rule ID tag
        rule_id_lbl = tk.Label(
            header_bar,
            text=f"[{self.finding.rule_id}]",
            font=FONT_SMALL,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_MUTED,
        )
        rule_id_lbl.pack(side=tk.LEFT)

        # Expand/Collapse Toggle Button
        self.btn_toggle = ttk.Button(
            header_bar,
            text="▼ Details",
            style="Secondary.TButton",
            command=self.toggle,
        )
        self.btn_toggle.pack(side=tk.RIGHT)

        # 2. Finding Title (Prominent)
        self.title_lbl = tk.Label(
            self,
            text=self.finding.title,
            font=FONT_HEADING,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
            cursor="hand2",
        )
        self.title_lbl.pack(fill=tk.X, pady=(0, 4))
        self.title_lbl.bind("<Button-1>", lambda e: self.toggle())

        # 3. Plain-language explanation (description)
        self.desc_lbl = tk.Label(
            self,
            text=self.finding.description,
            font=FONT_BODY,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_SECONDARY,
            wraplength=760,
            justify="left",
            anchor="w",
        )
        self.desc_lbl.pack(fill=tk.X, pady=(0, 4))

        # 4. Expandable Details Container (Initially hidden)
        self.details_container = tk.Frame(
            self,
            bg="#f8fafc",
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=14,
            pady=12,
        )

        self._build_expanded_details()

    def _build_expanded_details(self) -> None:
        """Construct the technical details inside the expandable pane."""
        # Location
        if self.finding.location:
            loc_row = tk.Frame(self.details_container, bg="#f8fafc")
            loc_row.pack(fill=tk.X, pady=(0, 6))

            tk.Label(
                loc_row,
                text="Location / Source Reference:",
                font=FONT_BODY_BOLD,
                bg="#f8fafc",
                fg=COLOR_TEXT_PRIMARY,
            ).pack(side=tk.LEFT, padx=(0, 6))

            tk.Label(
                loc_row,
                text=self.finding.location,
                font=FONT_CODE,
                bg="#f8fafc",
                fg=COLOR_ACCENT,
            ).pack(side=tk.LEFT)

        # Impact
        impact_row = tk.Frame(self.details_container, bg="#f8fafc")
        impact_row.pack(fill=tk.X, pady=(0, 6))

        tk.Label(
            impact_row,
            text="Potential Impact:",
            font=FONT_BODY_BOLD,
            bg="#f8fafc",
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill=tk.X)

        tk.Label(
            impact_row,
            text=self.finding.impact or "Potential data exposure or privacy leak.",
            font=FONT_BODY,
            bg="#f8fafc",
            fg=COLOR_TEXT_SECONDARY,
            wraplength=730,
            justify="left",
            anchor="w",
        ).pack(fill=tk.X, pady=(2, 0))

        # Recommended Remediation
        rem_row = tk.Frame(self.details_container, bg="#f8fafc")
        rem_row.pack(fill=tk.X, pady=(0, 6))

        tk.Label(
            rem_row,
            text="Recommended Remediation:",
            font=FONT_BODY_BOLD,
            bg="#f8fafc",
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill=tk.X)

        tk.Label(
            rem_row,
            text=self.finding.remediation or "Review code configuration following secure Android guidelines.",
            font=FONT_BODY,
            bg="#f8fafc",
            fg=COLOR_TEXT_SECONDARY,
            wraplength=730,
            justify="left",
            anchor="w",
        ).pack(fill=tk.X, pady=(2, 0))

        # Redacted Evidence Block
        ev_header = tk.Frame(self.details_container, bg="#f8fafc")
        ev_header.pack(fill=tk.X, pady=(6, 2))

        tk.Label(
            ev_header,
            text="Static Evidence (Strictly Redacted):",
            font=FONT_BODY_BOLD,
            bg="#f8fafc",
            fg=COLOR_TEXT_PRIMARY,
        ).pack(side=tk.LEFT)

        btn_copy = ttk.Button(
            ev_header,
            text="Copy Evidence",
            style="Secondary.TButton",
            command=self._copy_evidence,
        )
        btn_copy.pack(side=tk.RIGHT)

        # Guarantee strict redaction of raw secret material
        raw_evidence = self.finding.evidence or "No raw snippet available."
        self.sanitized_evidence = redact_text_secrets(raw_evidence)

        ev_text = tk.Text(
            self.details_container,
            font=FONT_CODE,
            bg="#ffffff",
            fg=COLOR_TEXT_PRIMARY,
            height=3,
            wrap=tk.WORD,
            padx=10,
            pady=8,
            bd=1,
            relief="solid",
        )
        ev_text.pack(fill=tk.X, pady=(2, 6))
        ev_text.insert(tk.END, self.sanitized_evidence)
        ev_text.config(state=tk.DISABLED)

        # OWASP / Standards Mapping
        ref_row = tk.Frame(self.details_container, bg="#f8fafc")
        ref_row.pack(fill=tk.X, pady=(4, 0))

        tk.Label(
            ref_row,
            text="Security Standards & OWASP Mapping:",
            font=FONT_BODY_BOLD,
            bg="#f8fafc",
            fg=COLOR_TEXT_PRIMARY,
        ).pack(side=tk.LEFT, padx=(0, 6))

        ref_val = self.finding.owasp_reference or "OWASP Mobile Application Security Verification Standard (MASVS)"
        tk.Label(
            ref_row,
            text=ref_val,
            font=FONT_SMALL,
            bg="#f8fafc",
            fg=COLOR_ACCENT,
        ).pack(side=tk.LEFT)

    def _copy_evidence(self) -> None:
        """Copy sanitized evidence text to system clipboard."""
        if self.on_copy_evidence:
            self.on_copy_evidence(self.sanitized_evidence)
        else:
            self.clipboard_clear()
            self.clipboard_append(self.sanitized_evidence)
            messagebox.showinfo("Copied", "Sanitized evidence copied to clipboard.")

    def toggle(self) -> None:
        """Toggle expand/collapse state."""
        if self._expanded:
            self.collapse()
        else:
            self.expand()

    def expand(self) -> None:
        """Expand details pane."""
        if not self._expanded:
            self._expanded = True
            self.btn_toggle.config(text="▲ Collapse")
            self.details_container.pack(fill=tk.X, pady=(8, 0))

    def collapse(self) -> None:
        """Collapse details pane."""
        if self._expanded:
            self._expanded = False
            self.btn_toggle.config(text="▼ Details")
            self.details_container.pack_forget()

    @property
    def is_expanded(self) -> bool:
        """Return True if details pane is currently visible."""
        return self._expanded


class FilterBar(tk.Frame):
    """Reusable toolbar with Severity filter, Category filter, Search entry, and Reset button."""

    def __init__(
        self,
        master: tk.Misc,
        on_filter_changed: Callable[[], None],
        on_expand_all: Callable[[], None] | None = None,
        on_collapse_all: Callable[[], None] | None = None,
        bg: str = COLOR_CARD_BG,
        *args,
        **kwargs,
    ) -> None:
        super().__init__(
            master,
            bg=bg,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=14,
            pady=10,
            *args,
            **kwargs,
        )
        self.on_filter_changed = on_filter_changed
        self.on_expand_all = on_expand_all
        self.on_collapse_all = on_collapse_all

        # 1. Severity Filter Combobox
        tk.Label(
            self,
            text="Severity:",
            font=FONT_BODY_BOLD,
            bg=bg,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.sev_var = tk.StringVar(value="All")
        self.sev_combo = ttk.Combobox(
            self,
            textvariable=self.sev_var,
            values=["All", "Critical", "High", "Medium", "Low", "Info"],
            state="readonly",
            width=10,
        )
        self.sev_combo.pack(side=tk.LEFT, padx=(0, 14))
        self.sev_combo.bind("<<ComboboxSelected>>", lambda e: self.on_filter_changed())

        # 2. Category Filter Combobox
        tk.Label(
            self,
            text="Category:",
            font=FONT_BODY_BOLD,
            bg=bg,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.cat_var = tk.StringVar(value="All")
        self.cat_combo = ttk.Combobox(
            self,
            textvariable=self.cat_var,
            values=[
                "All",
                "Permissions",
                "Network",
                "Storage",
                "Secrets",
                "Cryptography",
                "Third-Party SDK",
                "Manifest",
                "Other",
            ],
            state="readonly",
            width=16,
        )
        self.cat_combo.pack(side=tk.LEFT, padx=(0, 14))
        self.cat_combo.bind("<<ComboboxSelected>>", lambda e: self.on_filter_changed())

        # 3. Search Box
        tk.Label(
            self,
            text="Search:",
            font=FONT_BODY_BOLD,
            bg=bg,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(self, textvariable=self.search_var, width=24)
        self.search_entry.pack(side=tk.LEFT, padx=(0, 8))
        self.search_entry.bind("<KeyRelease>", lambda e: self.on_filter_changed())

        # Reset Filters Button
        btn_reset = ttk.Button(
            self,
            text="Reset",
            style="Secondary.TButton",
            command=self.reset_filters,
        )
        btn_reset.pack(side=tk.LEFT, padx=(0, 14))

        # Expand / Collapse All Buttons
        if self.on_expand_all and self.on_collapse_all:
            btn_exp = ttk.Button(
                self,
                text="Expand All",
                style="Secondary.TButton",
                command=self.on_expand_all,
            )
            btn_exp.pack(side=tk.LEFT, padx=2)

            btn_col = ttk.Button(
                self,
                text="Collapse All",
                style="Secondary.TButton",
                command=self.on_collapse_all,
            )
            btn_col.pack(side=tk.LEFT, padx=2)

        # Results Count Label
        self.count_label = tk.Label(
            self,
            text="0 findings shown",
            font=FONT_SMALL,
            bg=bg,
            fg=COLOR_TEXT_MUTED,
        )
        self.count_label.pack(side=tk.RIGHT)

    def reset_filters(self) -> None:
        """Reset all filter controls to their default state."""
        self.sev_var.set("All")
        self.cat_var.set("All")
        self.search_var.set("")
        self.on_filter_changed()

    def set_count(self, shown: int, total: int) -> None:
        """Update count label display."""
        if shown == total:
            self.count_label.config(text=f"{total} findings total")
        else:
            self.count_label.config(text=f"Showing {shown} of {total} findings")


class ExportToolbar(tk.Frame):
    """Reusable toolbar with Export PDF, Export HTML, and Export TXT buttons."""

    def __init__(
        self,
        master: tk.Misc,
        on_export_pdf: Callable[[], None],
        on_export_html: Callable[[], None],
        on_export_txt: Callable[[], None],
        bg: str = COLOR_CARD_BG,
        *args,
        **kwargs,
    ) -> None:
        super().__init__(master, bg=bg, *args, **kwargs)

        tk.Label(
            self,
            text="EXPORT AUDIT REPORT:",
            font=FONT_SMALL,
            bg=bg,
            fg=COLOR_TEXT_MUTED,
            anchor="e",
        ).pack(side=tk.LEFT, padx=(0, 8))

        self.btn_pdf = ttk.Button(
            self,
            text="📄 Export PDF",
            style="Secondary.TButton",
            command=on_export_pdf,
        )
        self.btn_pdf.pack(side=tk.LEFT, padx=3)

        self.btn_html = ttk.Button(
            self,
            text="🌐 Export HTML",
            style="Secondary.TButton",
            command=on_export_html,
        )
        self.btn_html.pack(side=tk.LEFT, padx=3)

        self.btn_txt = ttk.Button(
            self,
            text="📝 Export TXT",
            style="Secondary.TButton",
            command=on_export_txt,
        )
        self.btn_txt.pack(side=tk.LEFT, padx=3)


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
            if hasattr(self, "drop_target_register") and hasattr(self, "dnd_bind"):
                getattr(self, "drop_target_register")("DND_Files")
                getattr(self, "dnd_bind")("<<Drop>>", self._on_drop_event)
        except Exception as exc:
            logger.debug("tkinterdnd2 not available on this widget: %s", exc)

    def _on_drop_event(self, event: Any) -> None:
        """Handle tkinterdnd2 drop event."""
        if self.on_file_dropped and hasattr(event, "data"):
            raw_path = str(event.data).strip("{}'\"")
            if raw_path.lower().endswith(".apk"):
                self.on_file_dropped(raw_path)

    def show_selected_file(self, file_path: str) -> None:
        """Display basic metadata for the selected APK package."""
        p = Path(file_path)
        size_str = "Unknown size"
        hash_preview = ""
        if p.exists() and p.is_file():
            try:
                sz = p.stat().st_size
                if sz > 1024 * 1024:
                    size_str = f"{sz / (1024 * 1024):.2f} MB"
                else:
                    size_str = f"{sz / 1024:.1f} KB"

                import hashlib
                hasher = hashlib.sha256()
                with open(p, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        hasher.update(chunk)
                full_hash = hasher.hexdigest()
                hash_preview = f"SHA-256: {full_hash[:12]}...{full_hash[-6:]}"
            except Exception:
                pass

        meta_parts = [f"Size: {size_str}"]
        if hash_preview:
            meta_parts.append(hash_preview)
        meta_parts.append(f"Location: {str(p)}")

        self.file_name_label.config(text=f"Selected APK: {p.name}")
        self.file_meta_label.config(text="  •  ".join(meta_parts))
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
