"""Results View: Findings breakdown, risk score gauges, and report export buttons."""

from __future__ import annotations

import logging
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from data_leak_detector.core.models import AnalysisResult, SecurityFinding, Severity
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
    FONT_CODE,
    FONT_HEADING,
    FONT_SMALL,
    FONT_SUBHEADING,
    FONT_TITLE,
    SEVERITY_COLORS,
    DisclaimerBanner,
    EmptyState,
    MetricCard,
    SeverityBadge,
)

logger = logging.getLogger(__name__)


class ResultsView(ttk.Frame):
    """View rendering detailed static findings, risk score, and export options."""

    def __init__(self, master: tk.Misc, *args, **kwargs) -> None:
        super().__init__(master, *args, **kwargs)
        self.current_result: AnalysisResult | None = None
        self._all_findings: list[SecurityFinding] = []
        self._filtered_findings: list[SecurityFinding] = []

        self._init_layout()

    def _init_layout(self) -> None:
        """Construct the results layout with summary cards and tabs."""
        # Top Container: RESULTS SUMMARY
        self.summary_card = tk.Frame(
            self,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=16,
            pady=14,
        )
        self.summary_card.pack(fill=tk.X, padx=16, pady=(12, 10))

        # Risk Score + Rating banner (Left side of summary card)
        score_left = tk.Frame(self.summary_card, bg=COLOR_CARD_BG)
        score_left.pack(side=tk.LEFT, padx=(0, 24))

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
            font=(FONT_TITLE[0], 26, "bold"),
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
        self.score_max_lbl.pack(side=tk.LEFT, pady=(6, 0))

        self.rating_badge_frame = tk.Frame(
            score_left,
            bg="#94a3b8",
            padx=10,
            pady=3,
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
        self.card_crit.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)

        self.card_high = MetricCard(
            self.cards_row,
            title="High",
            value="0",
            accent_color="#ea580c",
        )
        self.card_high.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)

        self.card_med = MetricCard(
            self.cards_row,
            title="Medium",
            value="0",
            accent_color="#d97706",
        )
        self.card_med.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)

        self.card_low = MetricCard(
            self.cards_row,
            title="Low",
            value="0",
            accent_color="#2563eb",
        )
        self.card_low.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)

        # Right: Export Report Actions
        export_col = tk.Frame(self.summary_card, bg=COLOR_CARD_BG)
        export_col.pack(side=tk.RIGHT, padx=(16, 0))

        tk.Label(
            export_col,
            text="EXPORT REPORT",
            font=FONT_SMALL,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_MUTED,
            anchor="e",
        ).pack(fill=tk.X, pady=(0, 4))

        btn_row = tk.Frame(export_col, bg=COLOR_CARD_BG)
        btn_row.pack()

        self.btn_export_pdf = ttk.Button(
            btn_row,
            text="📄 PDF",
            style="Secondary.TButton",
            command=lambda: self._export_report("pdf"),
        )
        self.btn_export_pdf.pack(side=tk.LEFT, padx=2)

        self.btn_export_html = ttk.Button(
            btn_row,
            text="🌐 HTML",
            style="Secondary.TButton",
            command=lambda: self._export_report("html"),
        )
        self.btn_export_html.pack(side=tk.LEFT, padx=2)

        self.btn_export_txt = ttk.Button(
            btn_row,
            text="📝 Text",
            style="Secondary.TButton",
            command=lambda: self._export_report("text"),
        )
        self.btn_export_txt.pack(side=tk.LEFT, padx=2)

        # Notebook tabs: Overview, Permissions, Vulnerabilities, Application Details
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 12))

        # Create tab containers
        self.tab_overview = ttk.Frame(self.notebook)
        self.tab_permissions = ttk.Frame(self.notebook)
        self.tab_vulnerabilities = ttk.Frame(self.notebook)
        self.tab_app_details = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_overview, text="📊 Overview")
        self.notebook.add(self.tab_vulnerabilities, text="🛡 Vulnerabilities")
        self.notebook.add(self.tab_permissions, text="🔑 Permissions")
        self.notebook.add(self.tab_app_details, text="ℹ Application Details")

        self._build_overview_tab()
        self._build_vulnerabilities_tab()
        self._build_permissions_tab()
        self._build_app_details_tab()

    # -------------------------------------------------------------------------
    # TAB: OVERVIEW
    # -------------------------------------------------------------------------
    def _build_overview_tab(self) -> None:
        """Construct the Overview tab content."""
        scroll_container = tk.Frame(self.tab_overview, bg=COLOR_BG)
        scroll_container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        # Executive summary box
        exec_card = tk.Frame(
            scroll_container,
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

        # Key Findings Card
        key_card = tk.Frame(
            scroll_container,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=16,
            pady=14,
        )
        key_card.pack(fill=tk.BOTH, expand=True, pady=(0, 12))

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
            height=8,
            wrap=tk.WORD,
        )
        self.highlights_box.pack(fill=tk.BOTH, expand=True, pady=(8, 0))
        self.highlights_box.insert(tk.END, "Run an analysis to review key security indicators.")
        self.highlights_box.config(state=tk.DISABLED)

        # Methodology Disclaimer
        disclaimer = DisclaimerBanner(scroll_container)
        disclaimer.pack(fill=tk.X)

    # -------------------------------------------------------------------------
    # TAB: VULNERABILITIES (MASTER-DETAIL)
    # -------------------------------------------------------------------------
    def _build_vulnerabilities_tab(self) -> None:
        """Construct the master-detail vulnerabilities tab."""
        container = tk.Frame(self.tab_vulnerabilities, bg=COLOR_BG)
        container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        # Filter bar
        filter_bar = tk.Frame(container, bg=COLOR_BG)
        filter_bar.pack(fill=tk.X, pady=(0, 8))

        tk.Label(
            filter_bar,
            text="Filter by Severity:",
            font=FONT_BODY_BOLD,
            bg=COLOR_BG,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.sev_filter_var = tk.StringVar(value="ALL")
        self.sev_filter_combo = ttk.Combobox(
            filter_bar,
            textvariable=self.sev_filter_var,
            values=["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            state="readonly",
            width=12,
        )
        self.sev_filter_combo.pack(side=tk.LEFT, padx=(0, 14))
        self.sev_filter_combo.bind("<<ComboboxSelected>>", lambda e: self._apply_finding_filters())

        tk.Label(
            filter_bar,
            text="Search:",
            font=FONT_BODY_BOLD,
            bg=COLOR_BG,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.vuln_search_var = tk.StringVar()
        self.vuln_search_entry = ttk.Entry(filter_bar, textvariable=self.vuln_search_var, width=28)
        self.vuln_search_entry.pack(side=tk.LEFT)
        self.vuln_search_entry.bind("<KeyRelease>", lambda e: self._apply_finding_filters())

        self.vuln_count_lbl = tk.Label(
            filter_bar,
            text="0 findings",
            font=FONT_SMALL,
            bg=COLOR_BG,
            fg=COLOR_TEXT_MUTED,
        )
        self.vuln_count_lbl.pack(side=tk.RIGHT)

        # PanedWindow splitting Treeview (Master) and Detail View
        paned = ttk.PanedWindow(container, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Master Table (Treeview)
        tree_frame = tk.Frame(paned, bg=COLOR_CARD_BG)
        paned.add(tree_frame, weight=3)

        columns = ("severity", "id", "title", "confidence", "category")
        self.vuln_tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )
        self.vuln_tree.heading("severity", text="Severity")
        self.vuln_tree.heading("id", text="Rule ID")
        self.vuln_tree.heading("title", text="Finding Title")
        self.vuln_tree.heading("confidence", text="Confidence")
        self.vuln_tree.heading("category", text="Category")

        self.vuln_tree.column("severity", width=90, anchor="center")
        self.vuln_tree.column("id", width=120, anchor="w")
        self.vuln_tree.column("title", width=380, anchor="w")
        self.vuln_tree.column("confidence", width=90, anchor="center")
        self.vuln_tree.column("category", width=110, anchor="center")

        tree_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=tree_scroll.set)

        self.vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.vuln_tree.bind("<<TreeviewSelect>>", self._on_vuln_selected)

        # Detail Pane
        self.detail_frame = tk.Frame(
            paned,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER_LIGHT,
            highlightthickness=1,
            padx=16,
            pady=12,
        )
        paned.add(self.detail_frame, weight=4)

        # Detail Header
        detail_header = tk.Frame(self.detail_frame, bg=COLOR_CARD_BG)
        detail_header.pack(fill=tk.X, pady=(0, 6))

        self.detail_title_lbl = tk.Label(
            detail_header,
            text="Select a finding to inspect static evidence and remediation.",
            font=FONT_HEADING,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor="w",
        )
        self.detail_title_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.detail_badge = SeverityBadge(detail_header, severity="INFO")
        self.detail_badge.pack(side=tk.RIGHT)

        # Notebook inside detail pane for organized inspection
        self.detail_notebook = ttk.Notebook(self.detail_frame)
        self.detail_notebook.pack(fill=tk.BOTH, expand=True)

        # Sub-tab: Description & Impact
        self.tab_desc = ttk.Frame(self.detail_notebook)
        self.detail_notebook.add(self.tab_desc, text="Description & Impact")

        self.desc_text = tk.Text(
            self.tab_desc,
            font=FONT_BODY,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            wrap=tk.WORD,
            bd=0,
            padx=8,
            pady=8,
        )
        self.desc_text.pack(fill=tk.BOTH, expand=True)

        # Sub-tab: Redacted Evidence
        self.tab_evidence = ttk.Frame(self.detail_notebook)
        self.detail_notebook.add(self.tab_evidence, text="Redacted Evidence")

        ev_toolbar = tk.Frame(self.tab_evidence, bg=COLOR_CARD_BG)
        ev_toolbar.pack(fill=tk.X, padx=8, pady=(4, 2))

        tk.Label(
            ev_toolbar,
            text="Static Evidence (Sensitive tokens strictly redacted):",
            font=FONT_SMALL,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_MUTED,
        ).pack(side=tk.LEFT)

        btn_copy_ev = ttk.Button(
            ev_toolbar,
            text="Copy Evidence",
            style="Secondary.TButton",
            command=self._copy_evidence_to_clipboard,
        )
        btn_copy_ev.pack(side=tk.RIGHT)

        self.evidence_text = tk.Text(
            self.tab_evidence,
            font=FONT_CODE,
            bg="#f8fafc",
            fg=COLOR_TEXT_PRIMARY,
            wrap=tk.WORD,
            padx=10,
            pady=8,
            bd=1,
            relief="solid",
        )
        self.evidence_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        # Sub-tab: Remediation & Standards
        self.tab_remediation = ttk.Frame(self.detail_notebook)
        self.detail_notebook.add(self.tab_remediation, text="Remediation Guidance")

        self.remediation_text = tk.Text(
            self.tab_remediation,
            font=FONT_BODY,
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            wrap=tk.WORD,
            bd=0,
            padx=8,
            pady=8,
        )
        self.remediation_text.pack(fill=tk.BOTH, expand=True)

    def _apply_finding_filters(self) -> None:
        """Filter vulnerabilities treeview by selected severity and search query."""
        sev_query = self.sev_filter_var.get().upper()
        search_query = self.vuln_search_var.get().lower().strip()

        # Clear tree
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)

        self._filtered_findings = []
        for finding in self._all_findings:
            f_sev = str(finding.severity.value if hasattr(finding.severity, "value") else finding.severity).upper()
            if sev_query != "ALL" and f_sev != sev_query:
                continue

            if search_query:
                haystack = f"{finding.title} {finding.rule_id} {finding.description} {finding.category}".lower()
                if search_query not in haystack:
                    continue

            self._filtered_findings.append(finding)

            # Insert row
            item_id = self.vuln_tree.insert(
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

        self.vuln_count_lbl.config(text=f"{len(self._filtered_findings)} findings shown")

        # Select first item if available
        children = self.vuln_tree.get_children()
        if children:
            self.vuln_tree.selection_set(children[0])
            self.vuln_tree.focus(children[0])
            self._on_vuln_selected(None)

    def _on_vuln_selected(self, _event: Any) -> None:
        """Handle selection of finding in Master Treeview."""
        selected = self.vuln_tree.selection()
        if not selected:
            return

        idx = self.vuln_tree.index(selected[0])
        if idx >= len(self._filtered_findings):
            return

        finding = self._filtered_findings[idx]
        f_sev = str(finding.severity.value if hasattr(finding.severity, "value") else finding.severity).upper()

        self.detail_title_lbl.config(text=f"[{finding.rule_id}] {finding.title}")
        self.detail_badge.set_severity(f_sev)

        # Update description text
        self.desc_text.config(state=tk.NORMAL)
        self.desc_text.delete("1.0", tk.END)
        self.desc_text.insert(
            tk.END,
            f"Vulnerability Description:\n{finding.description}\n\n"
            f"Potential Impact:\n{finding.impact or 'Potential data exposure or privacy violation.'}\n\n"
            f"Location / Source Reference:\n{finding.location or 'Global application resources'}",
        )
        self.desc_text.config(state=tk.DISABLED)

        # Update evidence text
        self.evidence_text.config(state=tk.NORMAL)
        self.evidence_text.delete("1.0", tk.END)
        evidence_content = finding.evidence or "No raw snippet captured."
        self.evidence_text.insert(tk.END, evidence_content)
        self.evidence_text.config(state=tk.DISABLED)

        # Update remediation text
        self.remediation_text.config(state=tk.NORMAL)
        self.remediation_text.delete("1.0", tk.END)
        rem = finding.remediation or "Review and sanitize the detected configuration according to secure mobile coding guidelines."
        refs = f"• {finding.owasp_reference}" if finding.owasp_reference else "• OWASP Mobile Application Security Verification Standard (MASVS)"
        self.remediation_text.insert(
            tk.END,
            f"Remediation Guidance:\n{rem}\n\n"
            f"Security Standards & References:\n{refs}",
        )
        self.remediation_text.config(state=tk.DISABLED)

    def _copy_evidence_to_clipboard(self) -> None:
        """Copy redacted evidence text to system clipboard."""
        text = self.evidence_text.get("1.0", tk.END).strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            messagebox.showinfo("Copied", "Redacted evidence copied to clipboard.")

    # -------------------------------------------------------------------------
    # TAB: PERMISSIONS
    # -------------------------------------------------------------------------
    def _build_permissions_tab(self) -> None:
        """Construct the Permissions audit tab."""
        container = tk.Frame(self.tab_permissions, bg=COLOR_BG)
        container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        # Summary Bar
        top_bar = tk.Frame(container, bg=COLOR_BG)
        top_bar.pack(fill=tk.X, pady=(0, 8))

        self.perm_count_lbl = tk.Label(
            top_bar,
            text="Total Permissions: 0  |  Dangerous: 0",
            font=FONT_HEADING,
            bg=COLOR_BG,
            fg=COLOR_TEXT_PRIMARY,
        )
        self.perm_count_lbl.pack(side=tk.LEFT)

        # Treeview
        tree_frame = tk.Frame(container, bg=COLOR_CARD_BG)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        perm_cols = ("permission", "risk_level", "protection_level", "reason")
        self.perm_tree = ttk.Treeview(
            tree_frame,
            columns=perm_cols,
            show="headings",
            selectmode="browse",
        )
        self.perm_tree.heading("permission", text="Permission Name")
        self.perm_tree.heading("risk_level", text="Risk Level")
        self.perm_tree.heading("protection_level", text="Protection Level")
        self.perm_tree.heading("reason", text="Description / Risk Assessment")

        self.perm_tree.column("permission", width=280, anchor="w")
        self.perm_tree.column("risk_level", width=100, anchor="center")
        self.perm_tree.column("protection_level", width=120, anchor="center")
        self.perm_tree.column("reason", width=380, anchor="w")

        p_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.perm_tree.yview)
        self.perm_tree.configure(yscrollcommand=p_scroll.set)

        self.perm_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        p_scroll.pack(side=tk.RIGHT, fill=tk.Y)

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
        """Populate all summary badges, score cards, and tabs with scan results."""
        self.current_result = result

        # Extract Risk Score safely
        raw_score = getattr(result, "overall_risk_score", None)
        if raw_score is None and hasattr(result, "risk_score"):
            raw_score = getattr(result.risk_score, "score", getattr(result.risk_score, "final_score", 0.0))
        score_val = int(round(raw_score or 0.0))
        self.score_val_lbl.config(text=str(score_val))

        # Extract Rating badge safely
        raw_rating = getattr(result, "risk_rating", None)
        if raw_rating is None and hasattr(result, "risk_score"):
            raw_rating = getattr(result.risk_score, "rating", "MINIMAL")
        rating_str = str(raw_rating.value if hasattr(raw_rating, "value") else raw_rating).upper()
        self.rating_lbl.config(text=rating_str)

        # Style rating badge
        badge_color = "#dc2626" if score_val >= 80 else ("#ea580c" if score_val >= 60 else ("#d97706" if score_val >= 40 else "#16a34a"))
        self.rating_badge_frame.config(bg=badge_color)
        self.rating_lbl.config(bg=badge_color)

        # Retrieve findings and permissions collections
        all_findings = getattr(result, "findings", getattr(result, "security_findings", []))
        all_perms = getattr(result, "permissions", getattr(result, "permission_findings", []))

        # Count findings by severity
        crit_count = sum(1 for f in all_findings if str(f.severity.value if hasattr(f.severity, "value") else f.severity).upper() == "CRITICAL")
        high_count = sum(1 for f in all_findings if str(f.severity.value if hasattr(f.severity, "value") else f.severity).upper() == "HIGH")
        med_count = sum(1 for f in all_findings if str(f.severity.value if hasattr(f.severity, "value") else f.severity).upper() == "MEDIUM")
        low_count = sum(1 for f in all_findings if str(f.severity.value if hasattr(f.severity, "value") else f.severity).upper() == "LOW")

        self.card_crit.set_value(crit_count, f"{crit_count} Critical risks")
        self.card_high.set_value(high_count, f"{high_count} High risks")
        self.card_med.set_value(med_count, f"{med_count} Medium risks")
        self.card_low.set_value(low_count, f"{low_count} Low risks")

        # Executive Summary
        total_vulns = len(all_findings)
        summary_text = (
            f"Static security evaluation of package '{result.application.package_name}' resulted in an "
            f"overall risk score of {score_val}/100 ({rating_str}). The audit discovered {total_vulns} static "
            f"findings across {len(all_perms)} declared Android permissions. "
            f"{crit_count + high_count} critical/high priority weaknesses require review before deployment."
        )
        self.exec_summary_text.config(text=summary_text)

        # Top Highlights
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

        # Vulnerabilities List (Ordered Critical -> High -> Medium -> Low -> Info)
        order_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self._all_findings = sorted(
            all_findings,
            key=lambda f: order_map.get(
                str(f.severity.value if hasattr(f.severity, "value") else f.severity).upper(), 5
            ),
        )
        self._apply_finding_filters()

        # Populate Permissions Tab
        for item in self.perm_tree.get_children():
            self.perm_tree.delete(item)

        dang_count = 0
        for pf in all_perms:
            if pf.risk_level.lower() == "dangerous":
                dang_count += 1
            self.perm_tree.insert(
                "",
                tk.END,
                values=(
                    pf.permission,
                    pf.risk_level.upper(),
                    pf.protection_level or "normal",
                    pf.reason,
                ),
            )
        self.perm_count_lbl.config(
            text=f"Total Permissions: {len(all_perms)}  |  Dangerous: {dang_count}"
        )

        # Populate Application Details Tab
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

        # Default to overview or vulnerabilities tab
        self.notebook.select(self.tab_overview)

    # -------------------------------------------------------------------------
    # REPORT EXPORTING
    # -------------------------------------------------------------------------
    def _export_report(self, fmt: str) -> None:
        """Export current results to PDF, HTML, or Plain Text."""
        if not self.current_result:
            messagebox.showwarning("No Results", "Please run or load an analysis scan first.")
            return

        pkg = self.current_result.application.package_name or "app"
        default_name = f"DataLeakReport_{pkg}_{fmt.lower()}"

        file_types = {
            "pdf": [("PDF Document", "*.pdf")],
            "html": [("HTML Web Page", "*.html")],
            "text": [("Markdown / Text Document", "*.txt;*.md")],
        }

        save_path = filedialog.asksaveasfilename(
            title=f"Export Static Audit Report as {fmt.upper()}",
            initialfile=default_name,
            filetypes=file_types.get(fmt, [("All Files", "*.*")]),
            defaultextension=f".{fmt}",
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
