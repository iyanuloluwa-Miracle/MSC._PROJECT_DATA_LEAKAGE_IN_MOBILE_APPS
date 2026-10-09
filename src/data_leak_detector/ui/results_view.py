"""Results View: Findings breakdown, expandable finding cards, filters, and report export buttons."""

from __future__ import annotations

import logging
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from data_leak_detector.core.models import AnalysisResult, SecurityFinding
from data_leak_detector.core.redactor import redact_text_secrets
from data_leak_detector.reporting.report_generator import ReportGenerator
from data_leak_detector.ui.widgets import (
    COLOR_ACCENT,
    COLOR_BG,
    COLOR_BORDER_LIGHT,
    COLOR_CARD_BG,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    FONT_BODY,
    FONT_BODY_BOLD,
    FONT_HEADING,
    FONT_SMALL,
    FONT_TITLE,
    DisclaimerBanner,
    EmptyState,
    ExpandableFindingCard,
    ExportToolbar,
    FilterBar,
    MetricCard,
    ScrollableFrame,
)

logger = logging.getLogger(__name__)


def _normalize_category(cat_val: Any) -> str:
    """Normalize raw finding category into one of the canonical UI categories."""
    raw = str(cat_val.value if hasattr(cat_val, "value") else cat_val).upper().replace(" ", "_")
    if "SECRET" in raw:
        return "Secrets"
    elif "NET" in raw:
        return "Network"
    elif "STOR" in raw:
        return "Storage"
    elif "CRYPTO" in raw:
        return "Cryptography"
    elif "SDK" in raw:
        return "Third-Party SDK"
    elif "PERM" in raw:
        return "Permissions"
    elif "MANIFEST" in raw:
        return "Manifest"
    else:
        return "Other"


class ResultsView(ttk.Frame):
    """View rendering detailed static findings, risk score, expandable cards, and export options."""

    def __init__(self, master: tk.Misc, *args, **kwargs) -> None:
        super().__init__(master, *args, **kwargs)
        self.current_result: AnalysisResult | None = None
        self._all_findings: list[SecurityFinding] = []
        self._filtered_findings: list[SecurityFinding] = []
        self._finding_card_widgets: list[ExpandableFindingCard] = []

        self._init_layout()

    def _init_layout(self) -> None:
        """Construct the results layout with summary dashboard, filters, and tabs."""
        # =====================================================================
        # TOP CONTAINER: SUMMARY DASHBOARD BANNER
        # =====================================================================
        self.summary_card = tk.Frame(
            self,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=16,
            pady=12,
        )
        self.summary_card.pack(fill=tk.X, padx=16, pady=(12, 10))

        # Risk Score + Rating banner (Left side of summary card)
        score_left = tk.Frame(self.summary_card, bg=COLOR_CARD_BG)
        score_left.pack(side=tk.LEFT, padx=(0, 20))

        tk.Label(
            score_left,
            text="OVERALL RISK SCORE",
            font=FONT_SMALL,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_MUTED,
            anchor="w",
        ).pack(fill=tk.X)

        score_row = tk.Frame(score_left, bg=COLOR_CARD_BG)
        score_row.pack(fill=tk.X, pady=(2, 2))

        self.score_val_lbl = tk.Label(
            score_row,
            text="--",
            font=(FONT_TITLE[0], 24, "bold"),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
        )
        self.score_val_lbl.pack(side=tk.LEFT)

        self.score_max_lbl = tk.Label(
            score_row,
            text=" / 100",
            font=FONT_HEADING,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_MUTED,
        )
        self.score_max_lbl.pack(side=tk.LEFT, pady=(4, 0))

        self.rating_badge_frame = tk.Frame(
            score_left,
            bg="#94a3b8",
            padx=10,
            pady=2,
        )
        self.rating_badge_frame.pack(anchor="w", pady=(2, 0))
        self.rating_lbl = tk.Label(
            self.rating_badge_frame,
            text="PENDING",
            font=FONT_SMALL,
            bg="#94a3b8",
            fg="#ffffff",
        )
        self.rating_lbl.pack()

        # Center: Severity Count Cards
        self.cards_row = tk.Frame(self.summary_card, bg=COLOR_CARD_BG)
        self.cards_row.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.card_crit = MetricCard(
            self.cards_row,
            title="Critical",
            value="0",
            accent_color="#dc2626",
        )
        self.card_crit.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3)

        self.card_high = MetricCard(
            self.cards_row,
            title="High",
            value="0",
            accent_color="#ea580c",
        )
        self.card_high.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3)

        self.card_med = MetricCard(
            self.cards_row,
            title="Medium",
            value="0",
            accent_color="#d97706",
        )
        self.card_med.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3)

        self.card_low = MetricCard(
            self.cards_row,
            title="Low",
            value="0",
            accent_color="#2563eb",
        )
        self.card_low.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3)

        # Right: Export Report Actions Toolbar (PDF, HTML, TXT)
        self.export_toolbar = ExportToolbar(
            self.summary_card,
            on_export_pdf=lambda: self._export_report("pdf"),
            on_export_html=lambda: self._export_report("html"),
            on_export_txt=lambda: self._export_report("text"),
        )
        self.export_toolbar.pack(side=tk.RIGHT, padx=(16, 0))

        # Backward compatibility references for buttons
        self.btn_export_pdf = self.export_toolbar.btn_pdf
        self.btn_export_html = self.export_toolbar.btn_html
        self.btn_export_txt = self.export_toolbar.btn_txt

        # =====================================================================
        # NOTEBOOK TABS
        # =====================================================================
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 12))

        # Create tab containers
        self.tab_overview = ttk.Frame(self.notebook)
        self.tab_vulnerabilities = ttk.Frame(self.notebook)
        self.tab_permissions = ttk.Frame(self.notebook)
        self.tab_app_details = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_overview, text="📊 Summary Dashboard")
        self.notebook.add(self.tab_vulnerabilities, text="🛡 Vulnerabilities & Findings")
        self.notebook.add(self.tab_permissions, text="🔑 Permission View")
        self.notebook.add(self.tab_app_details, text="ℹ Application Details")

        self._build_overview_tab()
        self._build_vulnerabilities_tab()
        self._build_permissions_tab()
        self._build_app_details_tab()

    # -------------------------------------------------------------------------
    # TAB: SUMMARY DASHBOARD
    # -------------------------------------------------------------------------
    def _build_overview_tab(self) -> None:
        """Construct the Summary Dashboard tab content."""
        scroll = ScrollableFrame(self.tab_overview, bg=COLOR_BG)
        scroll.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
        container = scroll.scrollable_content

        # Executive summary box
        exec_card = tk.Frame(
            container,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=16,
            pady=14,
        )
        exec_card.pack(fill=tk.X, pady=(0, 12))

        tk.Label(
            exec_card,
            text="Executive Summary",
            font=FONT_HEADING,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill=tk.X)

        self.exec_summary_text = tk.Label(
            exec_card,
            text="No analysis data loaded.",
            font=FONT_BODY,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            wraplength=780,
            justify="left",
            anchor="w",
        )
        self.exec_summary_text.pack(fill=tk.X, pady=(8, 0))

        # Category Breakdown Dashboard Card
        self.cat_card = tk.Frame(
            container,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=16,
            pady=14,
        )
        self.cat_card.pack(fill=tk.X, pady=(0, 12))

        tk.Label(
            self.cat_card,
            text="Findings by Security Category",
            font=FONT_HEADING,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 8))

        self.cat_grid = tk.Frame(self.cat_card, bg=COLOR_CARD_BG)
        self.cat_grid.pack(fill=tk.X)
        self.cat_count_labels: dict[str, tk.Label] = {}

        # Pre-build grid rows for 8 categories
        cats = [
            ("Permissions", "Declared and requested permissions analysis"),
            ("Network", "Cleartext HTTP, SSL/TLS validation, endpoints"),
            ("Storage", "Plaintext storage, SharedPreferences, SQLite"),
            ("Secrets", "API keys, tokens, hardcoded private credentials"),
            ("Cryptography", "Weak ciphers, ECB mode, static IVs, hashing"),
            ("Third-Party SDK", "Ad and analytics tracking telemetry exposure"),
            ("Manifest", "Exported components, debuggable, allowBackup"),
            ("Other", "Miscellaneous architectural hygiene findings"),
        ]
        for idx, (cat_name, cat_desc) in enumerate(cats):
            r = idx // 2
            c = (idx % 2) * 2

            lbl_title = tk.Label(
                self.cat_grid,
                text=f"{cat_name}:",
                font=FONT_BODY_BOLD,
                bg=COLOR_CARD_BG,
                fg=COLOR_TEXT_PRIMARY,
                width=16,
                anchor="w",
            )
            lbl_title.grid(row=r, column=c, sticky="w", padx=(10, 4), pady=4)

            lbl_cnt = tk.Label(
                self.cat_grid,
                text="0 findings",
                font=FONT_BODY,
                bg=COLOR_CARD_BG,
                fg=COLOR_ACCENT,
                width=12,
                anchor="w",
            )
            lbl_cnt.grid(row=r, column=c + 1, sticky="w", padx=(0, 20), pady=4)
            self.cat_count_labels[cat_name] = lbl_cnt

        # Key Findings Highlights Card
        key_card = tk.Frame(
            container,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=16,
            pady=14,
        )
        key_card.pack(fill=tk.X, pady=(0, 12))

        tk.Label(
            key_card,
            text="Top Risk Highlights",
            font=FONT_HEADING,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill=tk.X)

        self.highlights_box = tk.Text(
            key_card,
            font=FONT_BODY,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            bd=0,
            highlightthickness=0,
            height=6,
            wrap=tk.WORD,
        )
        self.highlights_box.pack(fill=tk.X, pady=(8, 0))
        self.highlights_box.insert(tk.END, "Run an analysis to review key security indicators.")
        self.highlights_box.config(state=tk.DISABLED)

        # Quick Action Export Section
        export_box = tk.Frame(
            container,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=16,
            pady=14,
        )
        export_box.pack(fill=tk.X, pady=(0, 12))

        tk.Label(
            export_box,
            text="Export Audit Reports",
            font=FONT_HEADING,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 4))

        tk.Label(
            export_box,
            text="Save formatted audit documentation for technical review, academic publication, or client reporting:",
            font=FONT_BODY,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_MUTED,
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 10))

        dash_export_row = tk.Frame(export_box, bg=COLOR_CARD_BG)
        dash_export_row.pack(fill=tk.X)

        ttk.Button(
            dash_export_row,
            text="📄 Export PDF Report",
            style="Primary.TButton",
            command=lambda: self._export_report("pdf"),
        ).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(
            dash_export_row,
            text="🌐 Export HTML Report",
            style="Secondary.TButton",
            command=lambda: self._export_report("html"),
        ).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(
            dash_export_row,
            text="📝 Export TXT / Markdown",
            style="Secondary.TButton",
            command=lambda: self._export_report("text"),
        ).pack(side=tk.LEFT)

        # Methodology Disclaimer
        disclaimer = DisclaimerBanner(container)
        disclaimer.pack(fill=tk.X)

    # -------------------------------------------------------------------------
    # TAB: VULNERABILITIES & FINDINGS (EXPANDABLE CARDS + FILTERS)
    # -------------------------------------------------------------------------
    def _build_vulnerabilities_tab(self) -> None:
        """Construct the findings tab with FilterBar and ExpandableFindingCards."""
        container = tk.Frame(self.tab_vulnerabilities, bg=COLOR_BG)
        container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        # Reusable FilterBar with Severity filter, Category filter, Search, and Expand/Collapse All
        self.filter_bar = FilterBar(
            container,
            on_filter_changed=self._apply_finding_filters,
            on_expand_all=self._expand_all_cards,
            on_collapse_all=self._collapse_all_cards,
        )
        self.filter_bar.pack(fill=tk.X, pady=(0, 10))

        # Backward compatibility bindings
        self.sev_filter_var = self.filter_bar.sev_var
        self.cat_filter_var = self.filter_bar.cat_var
        self.vuln_search_var = self.filter_bar.search_var
        self.vuln_count_lbl = self.filter_bar.count_label

        # Scrollable Cards Container
        self.cards_scroll = ScrollableFrame(container, bg=COLOR_BG)
        self.cards_scroll.pack(fill=tk.BOTH, expand=True)
        self.cards_parent = self.cards_scroll.scrollable_content

        # Empty state for zero filter matches
        self.filter_empty_state = EmptyState(
            self.cards_parent,
            title="No Matching Findings",
            message="No security findings match the selected severity, category, and search criteria.",
            icon="🔍",
        )

        # Hidden Treeview for programmatic compatibility with unit tests
        self._build_compatibility_treeview()

    def _build_compatibility_treeview(self) -> None:
        """Create compatibility Treeview so existing tests can verify findings."""
        self.vuln_tree = ttk.Treeview(
            self,
            columns=("severity", "id", "title", "confidence", "category"),
            show="headings",
        )
        # Dummy detail widgets for compatibility
        self.detail_title_lbl = tk.Label(self)
        self.evidence_text = tk.Text(self)

    def _apply_finding_filters(self) -> None:
        """Filter vulnerabilities by severity, category, and search query, then render cards."""
        sev_query = self.sev_filter_var.get().strip().upper()
        cat_query = self.cat_filter_var.get().strip()
        search_query = self.vuln_search_var.get().lower().strip()

        # Clear existing card widgets
        for card in self._finding_card_widgets:
            card.destroy()
        self._finding_card_widgets.clear()

        # Clear compatibility treeview
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)

        self._filtered_findings = []

        for finding in self._all_findings:
            f_sev = str(
                finding.severity.value if hasattr(finding.severity, "value") else finding.severity
            ).upper()
            f_cat_norm = _normalize_category(finding.category)

            # 1. Severity Filter check
            if sev_query != "ALL" and f_sev != sev_query:
                continue

            # 2. Category Filter check
            if cat_query not in ("All", "All Categories") and f_cat_norm != cat_query:
                continue

            # 3. Search query check
            if search_query:
                haystack = (
                    f"{finding.title} {finding.rule_id} {finding.description} "
                    f"{finding.evidence} {finding.location} {finding.impact} "
                    f"{finding.remediation} {f_cat_norm}"
                ).lower()
                if search_query not in haystack:
                    continue

            self._filtered_findings.append(finding)

        # Update FilterBar count indicator
        self.filter_bar.set_count(len(self._filtered_findings), len(self._all_findings))

        # Show empty state or render cards
        if not self._filtered_findings:
            self.filter_empty_state.pack(fill=tk.BOTH, expand=True, pady=40)
            return

        self.filter_empty_state.pack_forget()

        # Instantiate ExpandableFindingCard for each matching finding
        for finding in self._filtered_findings:
            card = ExpandableFindingCard(
                self.cards_parent,
                finding=finding,
                on_copy_evidence=self._on_copy_evidence,
            )
            card.pack(fill=tk.X, pady=(0, 8))
            self._finding_card_widgets.append(card)

            # Also update compatibility treeview
            f_sev = str(
                finding.severity.value if hasattr(finding.severity, "value") else finding.severity
            ).upper()
            self.vuln_tree.insert(
                "",
                tk.END,
                values=(
                    f_sev,
                    finding.rule_id,
                    finding.title,
                    str(finding.confidence.value if hasattr(finding.confidence, "value") else finding.confidence),
                    finding.category or "General",
                ),
            )

    def _expand_all_cards(self) -> None:
        """Expand all finding card widgets."""
        for card in self._finding_card_widgets:
            card.expand()

    def _collapse_all_cards(self) -> None:
        """Collapse all finding card widgets."""
        for card in self._finding_card_widgets:
            card.collapse()

    def _on_copy_evidence(self, sanitized_text: str) -> None:
        """Handle copy evidence action from any finding card."""
        self.clipboard_clear()
        self.clipboard_append(sanitized_text)
        messagebox.showinfo("Copied", "Sanitized evidence copied to clipboard.")

    def _on_vuln_selected(self, _event: Any) -> None:
        """Backward compatibility handler for test selection."""
        selected = self.vuln_tree.selection()
        if not selected:
            return
        idx = self.vuln_tree.index(selected[0])
        if idx < len(self._filtered_findings):
            f = self._filtered_findings[idx]
            self.detail_title_lbl.config(text=f"[{f.rule_id}] {f.title}")
            self.evidence_text.config(state=tk.NORMAL)
            self.evidence_text.delete("1.0", tk.END)
            self.evidence_text.insert(tk.END, redact_text_secrets(f.evidence or ""))
            self.evidence_text.config(state=tk.DISABLED)

    # -------------------------------------------------------------------------
    # TAB: PERMISSION VIEW
    # -------------------------------------------------------------------------
    def _build_permissions_tab(self) -> None:
        """Construct the Permission View showing Permission, Protection level, Risk classification, Description, and Reason for concern."""
        container = tk.Frame(self.tab_permissions, bg=COLOR_BG)
        container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        # Top Toolbar: Summary Bar & Search Filter
        top_bar = tk.Frame(container, bg=COLOR_CARD_BG, highlightbackground=COLOR_BORDER_LIGHT, highlightthickness=1, padx=12, pady=8)
        top_bar.pack(fill=tk.X, pady=(0, 8))

        self.perm_count_lbl = tk.Label(
            top_bar,
            text="Total Permissions: 0  |  Dangerous: 0",
            font=FONT_HEADING,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
        )
        self.perm_count_lbl.pack(side=tk.LEFT)

        # Perm Search Filter
        tk.Label(
            top_bar,
            text="Filter Permissions:",
            font=FONT_BODY_BOLD,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(side=tk.RIGHT, padx=(10, 6))

        self.perm_filter_var = tk.StringVar()
        perm_search_entry = ttk.Entry(top_bar, textvariable=self.perm_filter_var, width=24)
        perm_search_entry.pack(side=tk.RIGHT)
        perm_search_entry.bind("<KeyRelease>", lambda e: self._filter_permissions_tree())

        # PanedWindow splitting Table and Detail inspection
        paned = ttk.PanedWindow(container, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # 5-Column Permission Treeview
        tree_frame = tk.Frame(paned, bg=COLOR_CARD_BG)
        paned.add(tree_frame, weight=3)

        perm_cols = (
            "permission",
            "protection_level",
            "risk_level",
            "description",
            "reason",
        )
        self.perm_tree = ttk.Treeview(
            tree_frame,
            columns=perm_cols,
            show="headings",
            selectmode="browse",
        )
        self.perm_tree.heading("permission", text="Permission")
        self.perm_tree.heading("protection_level", text="Protection Level")
        self.perm_tree.heading("risk_level", text="Risk Classification")
        self.perm_tree.heading("description", text="Description")
        self.perm_tree.heading("reason", text="Reason for Concern")

        self.perm_tree.column("permission", width=250, anchor="w")
        self.perm_tree.column("protection_level", width=110, anchor="center")
        self.perm_tree.column("risk_level", width=120, anchor="center")
        self.perm_tree.column("description", width=280, anchor="w")
        self.perm_tree.column("reason", width=340, anchor="w")

        p_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.perm_tree.yview)
        self.perm_tree.configure(yscrollcommand=p_scroll.set)

        self.perm_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        p_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.perm_tree.bind("<<TreeviewSelect>>", self._on_perm_selected)

        # Bottom Inspector for selected permission
        self.perm_detail_card = tk.Frame(
            paned,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=16,
            pady=12,
        )
        paned.add(self.perm_detail_card, weight=2)

        self.perm_detail_title = tk.Label(
            self.perm_detail_card,
            text="Select a permission from the table above to inspect details and data leak exposure.",
            font=FONT_HEADING,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        )
        self.perm_detail_title.pack(fill=tk.X, pady=(0, 4))

        self.perm_detail_text = tk.Text(
            self.perm_detail_card,
            font=FONT_BODY,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            wrap=tk.WORD,
            bd=0,
            height=4,
        )
        self.perm_detail_text.pack(fill=tk.BOTH, expand=True)
        self.perm_detail_text.config(state=tk.DISABLED)

    def _filter_permissions_tree(self) -> None:
        """Filter permission treeview based on search query."""
        if not self.current_result:
            return

        query = self.perm_filter_var.get().strip().lower()
        all_perms = getattr(
            self.current_result, "permissions", getattr(self.current_result, "permission_findings", [])
        )

        for item in self.perm_tree.get_children():
            self.perm_tree.delete(item)

        for pf in all_perms:
            haystack = f"{pf.permission} {pf.protection_level} {pf.risk_level} {pf.description} {pf.reason}".lower()
            if query and query not in haystack:
                continue

            r_class = str(pf.risk_level.value if hasattr(pf.risk_level, "value") else pf.risk_level).upper()
            self.perm_tree.insert(
                "",
                tk.END,
                values=(
                    pf.permission,
                    pf.protection_level or "normal",
                    r_class,
                    pf.description or "Standard Android permission",
                    pf.reason,
                ),
            )

    def _on_perm_selected(self, _event: Any) -> None:
        """Display detailed explanation for selected permission."""
        selected = self.perm_tree.selection()
        if not selected:
            return

        values = self.perm_tree.item(selected[0], "values")
        if not values:
            return

        perm_name, prot_lvl, risk_cls, desc, reason = values

        self.perm_detail_title.config(text=f"Permission: {perm_name} [{risk_cls}]")

        self.perm_detail_text.config(state=tk.NORMAL)
        self.perm_detail_text.delete("1.0", tk.END)
        self.perm_detail_text.insert(
            tk.END,
            f"Protection Level: {prot_lvl}\n"
            f"Risk Classification: {risk_cls}\n\n"
            f"Description:\n{desc}\n\n"
            f"Reason for Concern:\n{reason}",
        )
        self.perm_detail_text.config(state=tk.DISABLED)

    # -------------------------------------------------------------------------
    # TAB: APPLICATION DETAILS
    # -------------------------------------------------------------------------
    def _build_app_details_tab(self) -> None:
        """Construct the Application Details metadata tab."""
        container = tk.Frame(self.tab_app_details, bg=COLOR_BG)
        container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        meta_card = tk.Frame(
            container,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=18,
            pady=16,
        )
        meta_card.pack(fill=tk.BOTH, expand=True)

        tk.Label(
            meta_card,
            text="Package & Audit Metadata",
            font=FONT_HEADING,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 10))

        self.details_tree = ttk.Treeview(
            meta_card,
            columns=("property", "value"),
            show="headings",
            selectmode="browse",
            height=12,
        )
        self.details_tree.heading("property", text="Attribute / Property")
        self.details_tree.heading("value", text="Value")

        self.details_tree.column("property", width=220, anchor="w")
        self.details_tree.column("value", width=540, anchor="w")

        self.details_tree.pack(fill=tk.BOTH, expand=True)

    # -------------------------------------------------------------------------
    # PUBLIC API: DISPLAY SCAN RESULTS
    # -------------------------------------------------------------------------
    def display_results(self, result: AnalysisResult) -> None:
        """Populate all summary badges, score cards, expandable cards, and tabs with scan results."""
        self.current_result = result

        # 1. Extract Risk Score safely
        raw_score = getattr(result, "overall_risk_score", None)
        if raw_score is None and hasattr(result, "risk_score"):
            raw_score = getattr(result.risk_score, "score", getattr(result.risk_score, "final_score", 0.0))
        score_val = int(round(raw_score or 0.0))
        self.score_val_lbl.config(text=str(score_val))

        # 2. Extract Rating badge safely
        raw_rating = getattr(result, "risk_rating", None)
        if raw_rating is None and hasattr(result, "risk_score"):
            raw_rating = getattr(result.risk_score, "rating", "MINIMAL")
        rating_str = str(raw_rating.value if hasattr(raw_rating, "value") else raw_rating).upper()
        self.rating_lbl.config(text=rating_str)

        # Style rating badge
        badge_color = (
            "#dc2626"
            if score_val >= 80
            else ("#ea580c" if score_val >= 60 else ("#d97706" if score_val >= 40 else "#16a34a"))
        )
        self.rating_badge_frame.config(bg=badge_color)
        self.rating_lbl.config(bg=badge_color)

        # 3. Retrieve findings and permissions collections
        all_findings = getattr(result, "findings", getattr(result, "security_findings", []))
        all_perms = getattr(result, "permissions", getattr(result, "permission_findings", []))

        # 4. Count findings by severity
        crit_count = sum(
            1
            for f in all_findings
            if str(f.severity.value if hasattr(f.severity, "value") else f.severity).upper() == "CRITICAL"
        )
        high_count = sum(
            1
            for f in all_findings
            if str(f.severity.value if hasattr(f.severity, "value") else f.severity).upper() == "HIGH"
        )
        med_count = sum(
            1
            for f in all_findings
            if str(f.severity.value if hasattr(f.severity, "value") else f.severity).upper() == "MEDIUM"
        )
        low_count = sum(
            1
            for f in all_findings
            if str(f.severity.value if hasattr(f.severity, "value") else f.severity).upper() == "LOW"
        )

        self.card_crit.set_value(crit_count, f"{crit_count} Critical risks")
        self.card_high.set_value(high_count, f"{high_count} High risks")
        self.card_med.set_value(med_count, f"{med_count} Medium risks")
        self.card_low.set_value(low_count, f"{low_count} Low risks")

        # 5. Executive Summary
        total_vulns = len(all_findings)
        summary_text = (
            f"Static security evaluation of package '{result.application.package_name}' resulted in an "
            f"overall risk score of {score_val}/100 ({rating_str}). The audit discovered {total_vulns} static "
            f"findings across {len(all_perms)} declared Android permissions. "
            f"{crit_count + high_count} critical/high priority weaknesses require review before deployment."
        )
        self.exec_summary_text.config(text=summary_text)

        # 6. Category Breakdown Dashboard counts
        cat_counts: dict[str, int] = {k: 0 for k in self.cat_count_labels}
        for f in all_findings:
            norm_c = _normalize_category(f.category)
            if norm_c in cat_counts:
                cat_counts[norm_c] += 1
            else:
                cat_counts["Other"] += 1

        for cat_name, cnt_lbl in self.cat_count_labels.items():
            cnt = cat_counts.get(cat_name, 0)
            cnt_lbl.config(text=f"{cnt} findings")

        # 7. Top Highlights
        self.highlights_box.config(state=tk.NORMAL)
        self.highlights_box.delete("1.0", tk.END)
        top_findings = sorted(
            all_findings,
            key=lambda f: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(
                str(f.severity.value if hasattr(f.severity, "value") else f.severity).upper(), 0
            ),
            reverse=True,
        )[:5]

        if top_findings:
            for tf in top_findings:
                sev = str(tf.severity.value if hasattr(tf.severity, "value") else tf.severity).upper()
                self.highlights_box.insert(tk.END, f"• [{sev}] {tf.title}\n  Impact: {tf.impact}\n\n")
        else:
            self.highlights_box.insert(tk.END, "No security vulnerabilities were identified in static analysis.")
        self.highlights_box.config(state=tk.DISABLED)

        # 8. Sort findings (Critical -> High -> Medium -> Low -> Info) and render expandable cards
        order_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self._all_findings = sorted(
            all_findings,
            key=lambda f: order_map.get(
                str(f.severity.value if hasattr(f.severity, "value") else f.severity).upper(), 5
            ),
        )
        self._apply_finding_filters()

        # 9. Populate Permissions Tab
        self._filter_permissions_tree()
        dang_count = sum(
            1 for pf in all_perms if str(getattr(pf, "risk_level", "")).lower() in ("dangerous", "high")
        )
        self.perm_count_lbl.config(
            text=f"Total Permissions: {len(all_perms)}  |  Dangerous: {dang_count}"
        )

        # 10. Populate Application Details Tab
        for item in self.details_tree.get_children():
            self.details_tree.delete(item)

        app = result.application
        duration_sec = 0.0
        if hasattr(result, "metrics") and result.metrics:
            duration_sec = result.metrics.duration_seconds
        elif hasattr(result, "analysis_duration_seconds"):
            duration_sec = getattr(result, "analysis_duration_seconds", 0.0)

        ts_str = str(getattr(result, "timestamp", ""))
        if not ts_str and hasattr(result, "metrics") and result.metrics:
            ts_str = str(result.metrics.completed_at)

        sha256_str = getattr(app, "sha256", getattr(app, "file_hash", "N/A"))

        metrics_items = [
            ("Application Name", app.app_name or app.package_name),
            ("Package Name", app.package_name),
            ("Version Name", app.version_name or "N/A"),
            ("Version Code", str(app.version_code or "N/A")),
            ("Min SDK", str(app.min_sdk or "N/A")),
            ("Target SDK", str(app.target_sdk or "N/A")),
            ("SHA-256 Checksum", sha256_str or "N/A"),
            ("Analysis Timestamp", ts_str or "N/A"),
            ("Analysis Duration", f"{duration_sec:.2f} seconds"),
            ("Static Analyzer Version", result.analyzer_version),
        ]

        for prop, val in metrics_items:
            self.details_tree.insert("", tk.END, values=(prop, val))

        # Default to Summary Dashboard tab
        self.notebook.select(self.tab_overview)

    # -------------------------------------------------------------------------
    # REPORT EXPORTING (PDF, HTML, TXT)
    # -------------------------------------------------------------------------
    def _export_report(self, fmt: str) -> None:
        """Export current results to PDF, HTML, or Plain Text."""
        if not self.current_result:
            messagebox.showwarning("No Results", "Please run or load an analysis scan first.")
            return

        pkg = self.current_result.application.package_name or "app"
        default_name = f"DataLeakReport_{pkg}_{fmt.lower()}"

        file_types = {
            "pdf": [("PDF Document (*.pdf)", "*.pdf")],
            "html": [("HTML Web Page (*.html)", "*.html")],
            "text": [("Text / Markdown Document (*.txt;*.md)", "*.txt;*.md")],
        }

        ext = ".pdf" if fmt == "pdf" else (".html" if fmt == "html" else ".txt")
        save_path = filedialog.asksaveasfilename(
            title=f"Export Static Audit Report as {fmt.upper()}",
            initialfile=default_name,
            filetypes=file_types.get(fmt, [("All Files", "*.*")]),
            defaultextension=ext,
        )

        if not save_path:
            return

        try:
            generator = ReportGenerator()
            generator.generate(
                result=self.current_result,
                format=fmt,
                output_path=Path(save_path),
            )
            messagebox.showinfo(
                "Export Complete",
                f"Report successfully generated and saved to:\n{save_path}",
            )
        except Exception as exc:
            logger.error("Failed to export report: %s", exc, exc_info=True)
            messagebox.showerror(
                "Export Error",
                f"Failed to generate {fmt.upper()} report:\n{exc}",
            )
