"""Orchestrator for exporting static scan reports to various formats."""

from __future__ import annotations

import logging
from pathlib import Path

from data_leak_detector.core.models import AnalysisResult
from data_leak_detector.reporting.html_report import HTMLReportFormatter
from data_leak_detector.reporting.pdf_report import PDFReportFormatter
from data_leak_detector.reporting.text_report import TextReportFormatter


logger = logging.getLogger(__name__)


class ReportGenerator:
    """Dispatches report generation to PDF, HTML, or plain text formatters."""

    def __init__(self, result: AnalysisResult) -> None:
        self.result = result

    def generate_pdf(self, output_path: Path | str) -> Path:
        """Generate PDF audit report using ReportLab."""
        formatter = PDFReportFormatter(self.result)
        return formatter.render(Path(output_path))

    def generate_html(self, output_path: Path | str) -> Path:
        """Generate HTML static audit report."""
        formatter = HTMLReportFormatter(self.result)
        return formatter.render(Path(output_path))

    def generate_text(self, output_path: Path | str) -> Path:
        """Generate plain text / markdown audit summary."""
        formatter = TextReportFormatter(self.result)
        return formatter.render(Path(output_path))

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
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        name = base_filename or f"scan_report_{self.result.analysis_id[:8]}"

        return {
            "html": self.generate_html(out_dir / f"{name}.html"),
            "pdf": self.generate_pdf(out_dir / f"{name}.pdf"),
            "txt": self.generate_text(out_dir / f"{name}.txt"),
        }
