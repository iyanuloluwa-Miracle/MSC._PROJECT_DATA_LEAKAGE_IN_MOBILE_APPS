"""HTML report formatter for static Android vulnerability and privacy analysis results."""

from __future__ import annotations

import html
import logging
from pathlib import Path
from typing import Sequence

from data_leak_detector.core.exceptions import ReportGenerationError
from data_leak_detector.core.logging_config import SensitiveDataFilter
from data_leak_detector.core.models import (
    AnalysisResult,
    PermissionFinding,
    SecurityFinding,
    Severity,
)
from data_leak_detector.reporting.text_report import (
    STATIC_ANALYSIS_DISCLAIMER,
    sort_findings_by_severity,
)


logger = logging.getLogger(__name__)


def _escape(text: object) -> str:
    """Safe HTML escaping helper."""
    if text is None:
        return ""
    return html.escape(str(text))


class HTMLReportFormatter:
    """Renders scan findings into an academic audit report formatted as standalone HTML."""

    def __init__(self, result: AnalysisResult) -> None:
        self.result = result

    def render_html(self) -> str:
        """Generate complete HTML report with embedded styles."""
        app = self.result.application
        metrics = self.result.metrics
        ordered_findings = sort_findings_by_severity(self.result.findings)

        # Count findings per severity
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in ordered_findings:
            sev_key = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            counts[sev_key] = counts.get(sev_key, 0) + 1

        # Calculate permission statistics
        dangerous_perms = sum(1 for p in self.result.permissions if "dangerous" in p.protection_level.lower())
        sensitive_data_perms = sum(1 for p in self.result.permissions if p.is_sensitive_user_data)
        sensitive_families = sorted(
            {p.family for p in self.result.permissions if p.family}
        )

        rating_color_map = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#d97706",
            "LOW": "#2563eb",
            "MINIMAL": "#16a34a",
        }
        rating_color = rating_color_map.get(self.result.risk_rating.value, "#64748b")

        html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report: {_escape(app.package_name)}</title>
    <style>
        :root {{
            --bg-primary: #f8fafc;
            --bg-card: #ffffff;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border-color: #e2e8f0;
            --critical-color: #dc2626;
            --high-color: #ea580c;
            --medium-color: #d97706;
            --low-color: #2563eb;
            --info-color: #64748b;
            --success-color: #16a34a;
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-main);
            line-height: 1.5;
            padding: 24px;
        }}
        .container {{
            max-width: 1040px;
            margin: 0 auto;
        }}
        .header {{
            background: #1e293b;
            color: #ffffff;
            padding: 32px;
            border-radius: 12px;
            margin-bottom: 24px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}
        .header h1 {{
            font-size: 26px;
            font-weight: 700;
            margin-bottom: 8px;
        }}
        .header-meta {{
            color: #94a3b8;
            font-size: 14px;
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
        }}
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .card-title {{
            font-size: 18px;
            font-weight: 600;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 12px;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .score-banner {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: #ffffff;
            border-left: 6px solid {rating_color};
            padding: 20px 24px;
            border-radius: 8px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .score-info h2 {{
            font-size: 20px;
            font-weight: 700;
        }}
        .score-info p {{
            color: var(--text-muted);
            font-size: 14px;
            margin-top: 4px;
        }}
        .score-badge {{
            background: {rating_color};
            color: white;
            padding: 10px 20px;
            border-radius: 8px;
            font-size: 22px;
            font-weight: 800;
            text-align: center;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
        }}
        .meta-item {{
            font-size: 14px;
        }}
        .meta-label {{
            color: var(--text-muted);
            font-size: 12px;
            text-transform: uppercase;
            font-weight: 600;
        }}
        .meta-val {{
            font-weight: 500;
            margin-top: 2px;
            word-break: break-all;
        }}
        .breakdown-row {{
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin-top: 12px;
        }}
        .pill {{
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }}
        .pill-critical {{ background: #fee2e2; color: #991b1b; }}
        .pill-high {{ background: #ffedd5; color: #c2410c; }}
        .pill-medium {{ background: #fef3c7; color: #b45309; }}
        .pill-low {{ background: #dbeafe; color: #1d4ed8; }}
        .pill-info {{ background: #f1f5f9; color: #475569; }}

        .finding-card {{
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 18px;
            margin-bottom: 16px;
            background: #ffffff;
            transition: box-shadow 0.2s;
        }}
        .finding-card:hover {{
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.07);
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 12px;
            flex-wrap: wrap;
            gap: 8px;
        }}
        .finding-title {{
            font-size: 16px;
            font-weight: 600;
        }}
        .finding-meta {{
            font-size: 13px;
            color: var(--text-muted);
            margin-bottom: 10px;
        }}
        .finding-section {{
            margin-top: 10px;
            font-size: 14px;
        }}
        .section-label {{
            font-weight: 600;
            color: var(--text-main);
            font-size: 13px;
            margin-bottom: 2px;
        }}
        .evidence-box {{
            background: #f1f5f9;
            color: #0f172a;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 12px;
            padding: 10px 14px;
            border-radius: 6px;
            overflow-x: auto;
            border-left: 3px solid #94a3b8;
            margin: 6px 0;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        table.perm-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin-top: 8px;
        }}
        table.perm-table th, table.perm-table td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        table.perm-table th {{
            background: #f8fafc;
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 11px;
        }}
        .disclaimer-box {{
            background: #fffbeb;
            border: 1px solid #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 16px;
            border-radius: 6px;
            font-size: 13px;
            color: #78350f;
            line-height: 1.6;
            white-space: pre-line;
        }}
        @media print {{
            body {{ padding: 0; background: #fff; }}
            .container {{ max-width: 100%; }}
            .card {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="header">
            <h1>Mobile Application Static Security & Privacy Audit Report</h1>
            <div class="header-meta">
                <span>App: <strong>{_escape(app.app_name or app.package_name)}</strong></span>
                <span>Package: <strong>{_escape(app.package_name)}</strong></span>
                <span>Analysis ID: <strong>{_escape(self.result.analysis_id)}</strong></span>
                <span>Date: <strong>{_escape(metrics.completed_at.strftime('%Y-%m-%d %H:%M UTC'))}</strong></span>
            </div>
        </header>

        <!-- Executive Summary & Score Banner -->
        <div class="score-banner">
            <div class="score-info">
                <h2>Risk Rating: {_escape(self.result.risk_rating.value)}</h2>
                <p>Heuristic prototype risk score: <strong>{self.result.overall_risk_score:.1f} / 100</strong>. Evaluated across static bytecode, manifest, and resources in {metrics.duration_seconds:.2f}s.</p>
            </div>
            <div class="score-badge">
                {self.result.overall_risk_score:.1f}
            </div>
        </div>

        <div class="card">
            <div class="card-title">Executive Summary</div>
            <p style="font-size: 14px; color: var(--text-main); margin-bottom: 14px;">
                An automated static vulnerability analysis was conducted on <strong>{_escape(app.filename)}</strong>.
                The scan identified <strong>{len(ordered_findings)} security/privacy findings</strong>
                and evaluated <strong>{len(self.result.permissions)} declared permissions</strong> ({dangerous_perms} dangerous, {sensitive_data_perms} accessing sensitive user data).
            </p>
            <div class="breakdown-row">
                <span class="pill pill-critical">Critical: {counts['CRITICAL']}</span>
                <span class="pill pill-high">High: {counts['HIGH']}</span>
                <span class="pill pill-medium">Medium: {counts['MEDIUM']}</span>
                <span class="pill pill-low">Low: {counts['LOW']}</span>
                <span class="pill pill-info">Info: {counts['INFO']}</span>
            </div>
        </div>

        <!-- Metadata Card -->
        <div class="card">
            <div class="card-title">Application Profile & Environment</div>
            <div class="meta-grid">
                <div class="meta-item">
                    <div class="meta-label">Package Name</div>
                    <div class="meta-val">{_escape(app.package_name)}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Version</div>
                    <div class="meta-val">{_escape(app.version_name or app.version_code or 'Unknown')}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Target / Min SDK</div>
                    <div class="meta-val">{_escape(app.target_sdk or 'N/A')} / {_escape(app.min_sdk or 'N/A')}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">File Size</div>
                    <div class="meta-val">{app.file_size:,} bytes</div>
                </div>
                <div class="meta-item" style="grid-column: 1 / -1;">
                    <div class="meta-label">SHA-256 Hash</div>
                    <div class="meta-val" style="font-family: monospace; font-size: 12px;">{_escape(app.sha256)}</div>
                </div>
            </div>
        </div>

        <!-- Vulnerability Findings Section -->
        <div class="card">
            <div class="card-title">
                <span>Security & Privacy Findings ({len(ordered_findings)})</span>
                <span style="font-size: 12px; font-weight: normal; color: var(--text-muted);">Ordered by Severity</span>
            </div>
"""

        if not ordered_findings:
            html_out += """
            <p style="font-size: 14px; color: var(--text-muted); padding: 12px 0;">
                No security or privacy vulnerabilities were detected in static resources.
            </p>
"""
        else:
            for idx, f in enumerate(ordered_findings, start=1):
                sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                pill_class = f"pill-{sev_str.lower()}"
                clean_evidence = SensitiveDataFilter.redact(f.evidence or "N/A")

                html_out += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <div>
                        <span class="pill {pill_class}">{_escape(sev_str)}</span>
                        <strong class="finding-title" style="margin-left: 8px;">#{idx}. {_escape(f.title)}</strong>
                    </div>
                    <div style="font-size: 12px; color: var(--text-muted);">
                        Rule: <code>{_escape(f.rule_id)}</code>
                        {f' | OWASP: <strong>{_escape(f.owasp_reference)}</strong>' if f.owasp_reference else ''}
                    </div>
                </div>

                <div class="finding-meta">
                    Category: <strong>{_escape(f.category.value if hasattr(f.category, 'value') else f.category)}</strong> | 
                    Confidence: <strong>{_escape(f.confidence.value if hasattr(f.confidence, 'value') else f.confidence)}</strong>
                    {f' | Location: <code>{_escape(f.location)}</code>' if f.location else ''}
                </div>

                <div class="finding-section">
                    <div class="section-label">Description:</div>
                    <p>{_escape(f.description)}</p>
                </div>

                <div class="finding-section">
                    <div class="section-label">Evidence (Redacted):</div>
                    <pre class="evidence-box"><code>{_escape(clean_evidence)}</code></pre>
                </div>

                {f'''<div class="finding-section">
                    <div class="section-label">Potential Impact:</div>
                    <p style="color: #475569;">{_escape(f.impact)}</p>
                </div>''' if f.impact else ''}

                {f'''<div class="finding-section">
                    <div class="section-label" style="color: #0369a1;">Recommended Remediation:</div>
                    <p style="color: #0c4a6e;">{_escape(f.remediation)}</p>
                </div>''' if f.remediation else ''}
            </div>
"""

        html_out += f"""
        </div>

        <!-- Permissions Section -->
        <div class="card">
            <div class="card-title">
                <span>Declared Permissions ({len(self.result.permissions)})</span>
                <span style="font-size: 12px; font-weight: normal; color: var(--text-muted);">
                    {dangerous_perms} Dangerous | {sensitive_data_perms} Sensitive Data Access
                </span>
            </div>
            <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;">
                Sensitive Families Detected: <strong>{_escape(', '.join(sensitive_families) if sensitive_families else 'None')}</strong>
            </p>
            <table class="perm-table">
                <thead>
                    <tr>
                        <th>Permission</th>
                        <th>Protection Level</th>
                        <th>Risk Level</th>
                        <th>Sensitive Family</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
"""

        if not self.result.permissions:
            html_out += """
                    <tr>
                        <td colspan="5" style="text-align: center; color: var(--text-muted);">No permissions declared in manifest.</td>
                    </tr>
"""
        else:
            for p in self.result.permissions:
                risk_val = p.risk_level.value if hasattr(p.risk_level, "value") else str(p.risk_level)
                html_out += f"""
                    <tr>
                        <td><code>{_escape(p.permission)}</code></td>
                        <td>{_escape(p.protection_level)}</td>
                        <td><strong>{_escape(risk_val)}</strong></td>
                        <td>{_escape(p.family or '-')}</td>
                        <td>{_escape(p.description or '-')}</td>
                    </tr>
"""

        html_out += f"""
                </tbody>
            </table>
        </div>

        <!-- Disclaimer Card -->
        <div class="card">
            <div class="card-title">Methodology & Limitations Disclaimer</div>
            <div class="disclaimer-box">
{_escape(STATIC_ANALYSIS_DISCLAIMER)}
            </div>
        </div>
    </div>
</body>
</html>
"""
        return html_out

    def render(self, output_path: Path | str) -> Path:
        """Render HTML audit report to disk."""
        target_path = Path(output_path)
        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            content = self.render_html()
            target_path.write_text(content, encoding="utf-8")
            logger.info(f"Generated HTML report at: {target_path}")
            return target_path
        except Exception as e:
            raise ReportGenerationError(f"Failed to generate HTML report: {e}") from e
