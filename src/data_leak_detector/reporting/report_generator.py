"""Orchestrator for exporting static scan reports to various formats."""

from __future__ import annotations

import logging
from pathlib import Path

from data_leak_detector.core.models import AnalysisResult
from data_leak_detector.core.path_safety import validate_output_path
from data_leak_detector.reporting.html_report import HTMLReportFormatter
from data_leak_detector.reporting.pdf_report import PDFReportFormatter
from data_leak_detector.reporting.text_report import TextReportFormatter


logger = logging.getLogger(__name__)


class ReportGenerator:
    """Dispatches report generation to PDF, HTML, or plain text formatters."""

    def __init__(self, result: AnalysisResult | None = None) -> None:
        self.result = result

    def generate(
        self,
        output_path: Path | str,
        format: str = "pdf",
        result: AnalysisResult | None = None,
    ) -> Path:
        """Export report to the specified format (pdf, html, or text)."""
        target = result or self.result
        if target is None:
            raise ValueError("An AnalysisResult must be provided to generate a report.")
        fmt = format.lower().strip(".")
        if fmt == "pdf":
            return PDFReportFormatter(target).render(validate_output_path(output_path))
        elif fmt == "html":
            return HTMLReportFormatter(target).render(validate_output_path(output_path))
        elif fmt in ("txt", "text"):
            return TextReportFormatter(target).render(validate_output_path(output_path))
        else:
            raise ValueError(f"Unsupported report format: {format}")

    def generate_pdf(self, output_path: Path | str) -> Path:
        """Generate PDF audit report using ReportLab."""
        if self.result is None:
            raise ValueError("No AnalysisResult configured on ReportGenerator.")
        safe_path = validate_output_path(output_path)
        formatter = PDFReportFormatter(self.result)
        return formatter.render(safe_path)

    def generate_html(self, output_path: Path | str) -> Path:
        """Generate HTML static audit report."""
        if self.result is None:
            raise ValueError("No AnalysisResult configured on ReportGenerator.")
        safe_path = validate_output_path(output_path)
        formatter = HTMLReportFormatter(self.result)
        return formatter.render(safe_path)

    def generate_text(self, output_path: Path | str) -> Path:
        """Generate plain text / markdown audit summary."""
        if self.result is None:
            raise ValueError("No AnalysisResult configured on ReportGenerator.")
        safe_path = validate_output_path(output_path)
        formatter = TextReportFormatter(self.result)
        return formatter.render(safe_path)

    def generate_all(
        self,
        output_dir: Path | str,
        base_filename: str | None = None,
    ) -> dict[str, Path]:
        """Generate audit reports across all supported formats simultaneously.
        
        Args:
            output_dir: Directory where report artifacts will be saved.
            base_filename: Optional base name (without extension) for the reports.
            
        Returns:
            Dictionary mapping format keys ("html", "pdf", "txt") to their created paths.
        """
        if self.result is None:
            raise ValueError("No AnalysisResult configured on ReportGenerator.")
        safe_dir = validate_output_path(output_dir)
        safe_dir.mkdir(parents=True, exist_ok=True)
        name = base_filename or f"scan_report_{self.result.analysis_id[:8]}"

        return {
            "html": self.generate_html(safe_dir / f"{name}.html"),
            "pdf": self.generate_pdf(safe_dir / f"{name}.pdf"),
            "txt": self.generate_text(safe_dir / f"{name}.txt"),
        }
