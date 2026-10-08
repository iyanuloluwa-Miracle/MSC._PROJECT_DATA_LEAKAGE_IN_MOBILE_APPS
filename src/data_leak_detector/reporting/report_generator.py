"""Orchestrator for exporting static scan reports to various formats."""

from __future__ import annotations

import logging
from pathlib import Path

from data_leak_detector.core.models import AnalysisResult


logger = logging.getLogger(__name__)


class ReportGenerator:
    """Dispatches report generation to PDF, HTML, or plain text formatters."""

    def __init__(self, result: AnalysisResult) -> None:
        self.result = result

    def generate_pdf(self, output_path: Path) -> Path:
        """Generate PDF report using ReportLab."""
        raise NotImplementedError("PDF report generator will be implemented in subsequent phases.")

    def generate_html(self, output_path: Path) -> Path:
        """Generate HTML static audit report."""
        raise NotImplementedError("HTML report generator will be implemented in subsequent phases.")

    def generate_text(self, output_path: Path) -> Path:
        """Generate plain text / markdown audit summary."""
        raise NotImplementedError("Text report generator will be implemented in subsequent phases.")
