"""Plaintext and Markdown report formatter for static analysis results."""

from __future__ import annotations

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


logger = logging.getLogger(__name__)

SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

STATIC_ANALYSIS_DISCLAIMER: str = (
    "STATIC ANALYSIS METHODOLOGY & LIMITATIONS DISCLAIMER:\n"
    "1. Non-Execution Guarantee: The target APK was evaluated purely statically. The application was\n"
    "   not executed, installed, or run within an Android runtime or emulator environment.\n"
    "2. Potential Indicators: Flagged findings represent potential security and privacy weaknesses,\n"
    "   architectural risks, and insecure implementation patterns derived from bytecode, manifests,\n"
    "   and embedded static resources.\n"
    "3. Absence Does Not Prove Security: The absence of identified vulnerabilities does not prove that\n"
    "   the application is completely secure or free from vulnerabilities.\n"
    "4. No Runtime Transmission Confirmation: Static inspection cannot confirm whether sensitive user\n"
    "   information was actively exfiltrated or transmitted over the network at runtime.\n"
    "5. Research Prototype Notice: This report was produced by an academic static analysis research\n"
    "   prototype. Risk scores are heuristic metrics and do not represent formal CVSS ratings."
)


def sort_findings_by_severity(findings: Sequence[SecurityFinding]) -> list[SecurityFinding]:
    """Sort findings by severity rank: CRITICAL > HIGH > MEDIUM > LOW > INFO."""
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(
                f.severity if isinstance(f.severity, Severity) else Severity(f.severity), 5
            ),
            f.rule_id,
        ),
    )


class TextReportFormatter:
    """Renders scan findings into human-readable plaintext and markdown summaries."""

    def __init__(self, result: AnalysisResult) -> None:
        self.result = result

    def render_text(self) -> str:
        """Render complete audit report as formatted plain text string."""
        app = self.result.application
        metrics = self.result.metrics
        ordered_findings = sort_findings_by_severity(self.result.findings)

        # Count findings per severity
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in ordered_findings:
            sev_key = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            counts[sev_key] = counts.get(sev_key, 0) + 1

        # Count permission statistics
        dangerous_perms = sum(1 for p in self.result.permissions if "dangerous" in p.protection_level.lower())
        sensitive_data_perms = sum(1 for p in self.result.permissions if p.is_sensitive_user_data)
        sensitive_families = sorted(
            {p.family for p in self.result.permissions if p.family}
        )

        lines: list[str] = []
        divider = "=" * 80
        section_div = "-" * 80

        lines.append(divider)
        lines.append("MOBILE APPLICATION STATIC SECURITY & PRIVACY AUDIT REPORT")
        lines.append(divider)
        lines.append("")

        # 1. Executive Summary
        lines.append("EXECUTIVE SUMMARY")
        lines.append(section_div)
        lines.append(
            f"An automated static security audit was performed on '{app.filename}' "
            f"(package: {app.package_name})."
        )
        lines.append(
            f"Overall Risk Score: {self.result.overall_risk_score:.1f} / 100  |  "
            f"Risk Rating: {self.result.risk_rating.value}"
        )
        lines.append(
            f"The audit identified {len(ordered_findings)} security findings across static resources "
            f"({counts['CRITICAL']} Critical, {counts['HIGH']} High, {counts['MEDIUM']} Medium, "
            f"{counts['LOW']} Low, {counts['INFO']} Informational)."
        )
        lines.append(
            f"The application requests {len(self.result.permissions)} Android permissions "
            f"({dangerous_perms} dangerous, {sensitive_data_perms} accessing sensitive user data)."
        )
        if counts["CRITICAL"] > 0 or counts["HIGH"] > 0:
            lines.append(
                "ACTION REQUIRED: High-priority vulnerabilities or hardcoded secrets were detected. "
                "Immediate remediation is recommended prior to production deployment."
            )
        else:
            lines.append(
                "SUMMARY: No critical-severity vulnerabilities were identified. Review medium and low "
                "findings to improve defense-in-depth posture."
            )
        lines.append("")

        # 2. Application & Analysis Profile
        lines.append("1. AUDIT PROFILE & APPLICATION METADATA")
        lines.append(section_div)
        lines.append(f"Analysis ID:         {self.result.analysis_id}")
        lines.append(f"Analysis Timestamp:  {metrics.completed_at.isoformat()}")
        lines.append(f"Analysis Duration:   {metrics.duration_seconds:.2f} seconds")
        lines.append(f"Analyzer Version:    {self.result.analyzer_version}")
        lines.append(f"Application Name:    {app.app_name or 'N/A'}")
        lines.append(f"Package Name:        {app.package_name}")
        lines.append(f"Version:             {app.version_name or app.version_code or 'N/A'}")
        lines.append(f"File Name:           {app.filename}")
        lines.append(f"SHA-256 Hash:        {app.sha256}")
        lines.append(f"File Size:           {app.file_size:,} bytes")
        lines.append(f"Target SDK:          {app.target_sdk or 'N/A'}")
        lines.append(f"Min SDK:             {app.min_sdk or 'N/A'}")
        lines.append("")

        # 3. Risk Assessment & Severity Breakdown
        lines.append("2. RISK ASSESSMENT & SEVERITY BREAKDOWN")
        lines.append(section_div)
        lines.append(f"Risk Rating:         {self.result.risk_rating.value}")
        lines.append(f"Overall Risk Score:  {self.result.overall_risk_score:.1f} / 100")
        lines.append("Severity Breakdown:")
        lines.append(f"  - CRITICAL:        {counts['CRITICAL']}")
        lines.append(f"  - HIGH:            {counts['HIGH']}")
        lines.append(f"  - MEDIUM:          {counts['MEDIUM']}")
        lines.append(f"  - LOW:             {counts['LOW']}")
        lines.append(f"  - INFO:            {counts['INFO']}")
        lines.append(f"  Total Findings:    {len(ordered_findings)}")
        lines.append("")

        # 4. Security Findings
        lines.append("3. VULNERABILITY & PRIVACY FINDINGS (ORDERED BY SEVERITY)")
        lines.append(section_div)
        if not ordered_findings:
            lines.append("No security or privacy findings were detected during static evaluation.")
        else:
            for idx, finding in enumerate(ordered_findings, start=1):
                sev_val = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
                lines.append(f"[{sev_val}] Finding #{idx}: {finding.title}")
                lines.append(f"  Rule ID:           {finding.rule_id}")
                if finding.owasp_reference:
                    lines.append(f"  OWASP Reference:   {finding.owasp_reference}")
                lines.append(f"  Category:          {finding.category.value if hasattr(finding.category, 'value') else finding.category}")
                lines.append(f"  Confidence:        {finding.confidence.value if hasattr(finding.confidence, 'value') else finding.confidence}")
                if finding.location:
                    lines.append(f"  Location:          {finding.location}")
                lines.append(f"  Description:       {finding.description}")
                # Ensure evidence is strictly redacted
                clean_evidence = SensitiveDataFilter.redact(finding.evidence or "N/A")
                lines.append(f"  Evidence:          {clean_evidence}")
                if finding.impact:
                    lines.append(f"  Potential Impact:  {finding.impact}")
                if finding.remediation:
                    lines.append(f"  Remediation:       {finding.remediation}")
                lines.append("")

        # 5. Permission Summary and Details
        lines.append("4. PERMISSION AUDIT")
        lines.append(section_div)
        lines.append(f"Total Permissions:             {len(self.result.permissions)}")
        lines.append(f"Dangerous Permissions:         {dangerous_perms}")
        lines.append(f"Sensitive User Data Access:    {sensitive_data_perms}")
        lines.append(
            f"Sensitive Families Detected:   {', '.join(sensitive_families) if sensitive_families else 'None'}"
        )
        lines.append("")
        lines.append("Permission Details:")
        if not self.result.permissions:
            lines.append("  No permissions requested by this application.")
        else:
            for perm in self.result.permissions:
                risk_val = perm.risk_level.value if hasattr(perm.risk_level, "value") else str(perm.risk_level)
                family_str = f" [Family: {perm.family}]" if perm.family else ""
                sensitive_str = " [Accesses Sensitive User Data]" if perm.is_sensitive_user_data else ""
                lines.append(f"  * {perm.permission} ({perm.protection_level}, Risk: {risk_val}){family_str}{sensitive_str}")
                if perm.description:
                    lines.append(f"    Description: {perm.description}")
        lines.append("")

        # 6. Tool Limitations & Methodology Disclaimer
        lines.append("5. TOOL LIMITATIONS & METHODOLOGY DISCLAIMER")
        lines.append(section_div)
        lines.append(STATIC_ANALYSIS_DISCLAIMER)
        lines.append(divider)

        return "\n".join(lines)

    def render(self, output_path: Path | str) -> Path:
        """Render plaintext report and write to file."""
        target_path = Path(output_path)
        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            content = self.render_text()
            target_path.write_text(content, encoding="utf-8")
            logger.info(f"Generated text report at: {target_path}")
            return target_path
        except Exception as e:
            raise ReportGenerationError(f"Failed to generate text report: {e}") from e
