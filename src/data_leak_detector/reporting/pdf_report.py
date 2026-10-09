"""PDF report generator for static Android vulnerability audits using ReportLab."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from data_leak_detector.core.exceptions import ReportGenerationError
from data_leak_detector.core.logging_config import SensitiveDataFilter
from data_leak_detector.core.models import AnalysisResult
from data_leak_detector.reporting.text_report import (
    STATIC_ANALYSIS_DISCLAIMER,
    sort_findings_by_severity,
)


logger = logging.getLogger(__name__)


def _sanitize_xml(text: object) -> str:
    """Escape text for safe ReportLab XML/HTML Paragraph parsing."""
    if text is None:
        return ""
    s = str(text)
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    s = s.replace('"', "&quot;").replace("'", "&#39;")
    return s


class PDFReportFormatter:
    """Renders scan findings into an academic audit PDF via ReportLab Platypus."""

    def __init__(self, result: AnalysisResult) -> None:
        self.result = result

    def render(self, output_path: Path | str) -> Path:
        """Build and save PDF document using ReportLab Platypus elements.
        
        Guarantees:
        - Structured layout with title, executive summary, findings, and disclaimer.
        - Strict redaction of embedded secrets and sensitive credentials.
        - Ordered vulnerability findings from Critical down to Info.
        - Non-technical, executive-friendly formatting with visual score cards.
        """
        target_path = Path(output_path)
        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)

            doc = SimpleDocTemplate(
                str(target_path),
                pagesize=letter,
                leftMargin=40,
                rightMargin=40,
                topMargin=40,
                bottomMargin=45,
            )

            story: list[Any] = []
            styles = getSampleStyleSheet()

            # Custom typography styles
            title_style = ParagraphStyle(
                "DocTitle",
                parent=styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=20,
                leading=24,
                textColor=colors.HexColor("#0f172a"),
            )
            subtitle_style = ParagraphStyle(
                "DocSubtitle",
                parent=styles["Normal"],
                fontName="Helvetica",
                fontSize=10,
                leading=14,
                textColor=colors.HexColor("#64748b"),
            )
            h1_style = ParagraphStyle(
                "SectionHeading",
                parent=styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=13,
                leading=17,
                textColor=colors.HexColor("#1e293b"),
                spaceBefore=12,
                spaceAfter=6,
            )
            body_style = ParagraphStyle(
                "BodyTextCustom",
                parent=styles["Normal"],
                fontName="Helvetica",
                fontSize=9,
                leading=13,
                textColor=colors.HexColor("#1e293b"),
            )
            body_bold = ParagraphStyle(
                "BodyBoldCustom",
                parent=body_style,
                fontName="Helvetica-Bold",
            )
            code_style = ParagraphStyle(
                "EvidenceBox",
                parent=styles["Normal"],
                fontName="Courier",
                fontSize=8,
                leading=10,
                textColor=colors.HexColor("#0f172a"),
            )
            disclaimer_style = ParagraphStyle(
                "DisclaimerText",
                parent=styles["Normal"],
                fontName="Helvetica",
                fontSize=7.5,
                leading=10.5,
                textColor=colors.HexColor("#78350f"),
            )

            app = self.result.application
            metrics = self.result.metrics
            ordered_findings = sort_findings_by_severity(self.result.findings)

            # Severity counts
            counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for f in ordered_findings:
                sev_key = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                counts[sev_key] = counts.get(sev_key, 0) + 1

            # Permission stats
            dangerous_perms = sum(1 for p in self.result.permissions if "dangerous" in p.protection_level.lower())
            sensitive_data_perms = sum(1 for p in self.result.permissions if p.is_sensitive_user_data)

            # Rating colors
            rating_colors = {
                "CRITICAL": colors.HexColor("#dc2626"),
                "HIGH": colors.HexColor("#ea580c"),
                "MEDIUM": colors.HexColor("#d97706"),
                "LOW": colors.HexColor("#2563eb"),
                "MINIMAL": colors.HexColor("#16a34a"),
            }
            rating_col = rating_colors.get(self.result.risk_rating.value, colors.HexColor("#64748b"))

            # -------------------------------------------------------------
            # 1. Document Title & Header Banner
            # -------------------------------------------------------------
            story.append(Paragraph("Mobile Application Static Security & Privacy Audit", title_style))
            story.append(Spacer(1, 4))
            story.append(
                Paragraph(
                    f"Target Package: <b>{_sanitize_xml(app.package_name)}</b> &nbsp;|&nbsp; "
                    f"Date: <b>{_sanitize_xml(metrics.completed_at.strftime('%Y-%m-%d %H:%M UTC'))}</b> &nbsp;|&nbsp; "
                    f"Analysis ID: <code>{_sanitize_xml(self.result.analysis_id)}</code>",
                    subtitle_style,
                )
            )
            story.append(Spacer(1, 10))
            story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#cbd5e1"), spaceAfter=12))

            # -------------------------------------------------------------
            # 2. Risk Score & Executive Summary Card
            # -------------------------------------------------------------
            score_text = f"<b><font size='16'>{self.result.overall_risk_score:.1f}</font> / 100</b><br/><font size='10'>{self.result.risk_rating.value} RISK</font>"
            score_para = Paragraph(score_text, ParagraphStyle("ScoreText", parent=body_style, alignment=1, textColor=colors.white))

            exec_summary_text = (
                f"<b>Executive Summary:</b> Automated static inspection was conducted on <b>{_sanitize_xml(app.filename)}</b> in {metrics.duration_seconds:.2f}s. "
                f"The analysis identified <b>{len(ordered_findings)} security/privacy findings</b> across decompiled bytecodes and resources, "
                f"and evaluated <b>{len(self.result.permissions)} requested permissions</b> ({dangerous_perms} dangerous, {sensitive_data_perms} accessing sensitive user data). "
                f"<br/><br/>"
                f"{'<b>Action Required:</b> High-severity findings or credential exposures were flagged. Remediation is strongly recommended prior to release.' if counts['CRITICAL'] + counts['HIGH'] > 0 else '<b>Posture:</b> No critical indicators detected. Review medium/low findings for security hardening.'}"
            )
            exec_summary_para = Paragraph(exec_summary_text, body_style)

            score_table_data = [[
                score_para,
                exec_summary_para,
            ]]
            score_table = Table(score_table_data, colWidths=[100, 432])
            score_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, 0), rating_col),
                ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ]))
            story.append(score_table)
            story.append(Spacer(1, 14))

            # -------------------------------------------------------------
            # 3. Application Metadata Table
            # -------------------------------------------------------------
            story.append(Paragraph("Application Profile & Environment", h1_style))
            meta_data = [
                [Paragraph("<b>Package Name:</b>", body_style), Paragraph(_sanitize_xml(app.package_name), body_style)],
                [Paragraph("<b>App Name:</b>", body_style), Paragraph(_sanitize_xml(app.app_name or 'N/A'), body_style)],
                [Paragraph("<b>Version:</b>", body_style), Paragraph(_sanitize_xml(app.version_name or app.version_code or 'Unknown'), body_style)],
                [Paragraph("<b>Target / Min SDK:</b>", body_style), Paragraph(f"{_sanitize_xml(app.target_sdk or 'N/A')} / {_sanitize_xml(app.min_sdk or 'N/A')}", body_style)],
                [Paragraph("<b>File Size / Name:</b>", body_style), Paragraph(f"{app.file_size:,} bytes ({_sanitize_xml(app.filename)})", body_style)],
                [Paragraph("<b>SHA-256 Hash:</b>", body_style), Paragraph(f"<code>{_sanitize_xml(app.sha256)}</code>", code_style)],
            ]
            meta_table = Table(meta_data, colWidths=[130, 402])
            meta_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]))
            story.append(meta_table)
            story.append(Spacer(1, 14))

            # -------------------------------------------------------------
            # 4. Severity Breakdown Table
            # -------------------------------------------------------------
            story.append(Paragraph("Findings Severity Breakdown", h1_style))
            breakdown_data = [
                [
                    Paragraph("<b>CRITICAL</b>", body_style),
                    Paragraph("<b>HIGH</b>", body_style),
                    Paragraph("<b>MEDIUM</b>", body_style),
                    Paragraph("<b>LOW</b>", body_style),
                    Paragraph("<b>INFO</b>", body_style),
                ],
                [
                    Paragraph(f"<font color='#dc2626' size='12'><b>{counts['CRITICAL']}</b></font>", body_style),
                    Paragraph(f"<font color='#ea580c' size='12'><b>{counts['HIGH']}</b></font>", body_style),
                    Paragraph(f"<font color='#d97706' size='12'><b>{counts['MEDIUM']}</b></font>", body_style),
                    Paragraph(f"<font color='#2563eb' size='12'><b>{counts['LOW']}</b></font>", body_style),
                    Paragraph(f"<font color='#64748b' size='12'><b>{counts['INFO']}</b></font>", body_style),
                ],
            ]
            breakdown_table = Table(breakdown_data, colWidths=[106.4] * 5)
            breakdown_table.setStyle(TableStyle([
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(breakdown_table)
            story.append(Spacer(1, 16))

            # -------------------------------------------------------------
            # 5. Security & Privacy Findings (Ordered Critical to Info)
            # -------------------------------------------------------------
            story.append(Paragraph(f"Security & Privacy Findings ({len(ordered_findings)})", h1_style))

            if not ordered_findings:
                story.append(Paragraph("<i>No security or privacy vulnerabilities were detected in static resources.</i>", body_style))
                story.append(Spacer(1, 12))
            else:
                sev_badge_colors = {
                    "CRITICAL": colors.HexColor("#dc2626"),
                    "HIGH": colors.HexColor("#ea580c"),
                    "MEDIUM": colors.HexColor("#d97706"),
                    "LOW": colors.HexColor("#2563eb"),
                    "INFO": colors.HexColor("#64748b"),
                }

                for idx, finding in enumerate(ordered_findings, start=1):
                    sev_str = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
                    clean_evidence = SensitiveDataFilter.redact(finding.evidence or "N/A")
                    badge_color = sev_badge_colors.get(sev_str, colors.HexColor("#64748b"))

                    finding_rows = [
                        [
                            Paragraph(f"<b>#{idx}. {_sanitize_xml(finding.title)}</b>", body_bold),
                            Paragraph(f"<b><font color='{badge_color.hexval()}'>[{sev_str}]</font></b>", body_style),
                        ],
                        [
                            Paragraph(
                                f"<b>Rule ID:</b> <code>{_sanitize_xml(finding.rule_id)}</code> &nbsp;|&nbsp; "
                                f"<b>Confidence:</b> {_sanitize_xml(finding.confidence.value if hasattr(finding.confidence, 'value') else finding.confidence)}"
                                f"{f' &nbsp;|&nbsp; <b>OWASP:</b> {_sanitize_xml(finding.owasp_reference)}' if finding.owasp_reference else ''}",
                                body_style,
                            ),
                            Paragraph("", body_style),
                        ],
                    ]
                    if finding.location:
                        finding_rows.append([
                            Paragraph(f"<b>Location:</b> <code>{_sanitize_xml(finding.location)}</code>", body_style),
                            Paragraph("", body_style),
                        ])
                    finding_rows.append([
                        Paragraph(f"<b>Description:</b> {_sanitize_xml(finding.description)}", body_style),
                        Paragraph("", body_style),
                    ])
                    finding_rows.append([
                        Paragraph(f"<b>Evidence (Redacted):</b><br/><code>{_sanitize_xml(clean_evidence)}</code>", code_style),
                        Paragraph("", body_style),
                    ])
                    if finding.impact:
                        finding_rows.append([
                            Paragraph(f"<b>Potential Impact:</b> {_sanitize_xml(finding.impact)}", body_style),
                            Paragraph("", body_style),
                        ])
                    if finding.remediation:
                        finding_rows.append([
                            Paragraph(f"<b>Recommended Remediation:</b> <font color='#0369a1'>{_sanitize_xml(finding.remediation)}</font>", body_style),
                            Paragraph("", body_style),
                        ])

                    f_table = Table(finding_rows, colWidths=[452, 80])
                    f_table.setStyle(TableStyle([
                        ("SPAN", (0, 1), (1, 1)),
                        ("SPAN", (0, 2), (1, 2)),
                        ("SPAN", (0, 3), (1, 3)),
                        ("SPAN", (0, 4), (1, 4)),
                        ("SPAN", (0, 5), (1, 5)) if len(finding_rows) > 5 else ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("SPAN", (0, 6), (1, 6)) if len(finding_rows) > 6 else ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                        ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#cbd5e1")),
                        ("LINEBELOW", (0, 0), (-1, 0), 1, colors.HexColor("#cbd5e1")),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
                    ]))

                    story.append(KeepTogether(f_table))
                    story.append(Spacer(1, 8))

            story.append(Spacer(1, 10))

            # -------------------------------------------------------------
            # 6. Declared Permissions Audit Table
            # -------------------------------------------------------------
            story.append(
                Paragraph(
                    f"Declared Permissions Audit ({len(self.result.permissions)} requested, {dangerous_perms} dangerous)",
                    h1_style,
                )
            )

            perm_table_rows = [
                [
                    Paragraph("<b>Permission</b>", body_style),
                    Paragraph("<b>Protection</b>", body_style),
                    Paragraph("<b>Risk Level</b>", body_style),
                    Paragraph("<b>Family / Description</b>", body_style),
                ]
            ]
            if not self.result.permissions:
                perm_table_rows.append([
                    Paragraph("<i>No permissions declared in manifest.</i>", body_style),
                    Paragraph("", body_style),
                    Paragraph("", body_style),
                    Paragraph("", body_style),
                ])
            else:
                for p in self.result.permissions:
                    risk_val = p.risk_level.value if hasattr(p.risk_level, "value") else str(p.risk_level)
                    family_desc = f"<b>{_sanitize_xml(p.family)}</b>: {_sanitize_xml(p.description)}" if p.family else _sanitize_xml(p.description)
                    perm_table_rows.append([
                        Paragraph(f"<code>{_sanitize_xml(p.permission)}</code>", code_style),
                        Paragraph(_sanitize_xml(p.protection_level), body_style),
                        Paragraph(f"<b>{_sanitize_xml(risk_val)}</b>", body_style),
                        Paragraph(family_desc, body_style),
                    ])

            perm_table = Table(perm_table_rows, colWidths=[170, 70, 60, 232])
            perm_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(perm_table)
            story.append(Spacer(1, 14))

            # -------------------------------------------------------------
            # 7. Methodology & Limitations Disclaimer Box
            # -------------------------------------------------------------
            story.append(Paragraph("Tool Limitations & Methodology Disclaimer", h1_style))
            disclaimer_formatted = "<br/>".join(_sanitize_xml(line) for line in STATIC_ANALYSIS_DISCLAIMER.splitlines())
            disc_table = Table([[Paragraph(disclaimer_formatted, disclaimer_style)]], colWidths=[532])
            disc_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fffbeb")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#fde68a")),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]))
            story.append(disc_table)

            # Footer callback with page numbers
            def add_footer(canvas: Any, doc_obj: Any) -> None:
                canvas.saveState()
                canvas.setFont("Helvetica", 8)
                canvas.setFillColor(colors.HexColor("#64748b"))
                canvas.drawString(40, 25, "Mobile Application Static Security Audit Report — Research Prototype")
                canvas.drawRightString(doc_obj.pagesize[0] - 40, 25, f"Page {canvas.getPageNumber()}")
                canvas.restoreState()

            doc.build(story, onFirstPage=add_footer, onLaterPages=add_footer)
            logger.info(f"Successfully generated PDF report at: {target_path}")
            return target_path

        except Exception as e:
            raise ReportGenerationError(f"Failed to generate PDF report: {e}") from e
