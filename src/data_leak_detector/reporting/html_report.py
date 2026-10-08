"""HTML report formatter for static analysis results."""

from __future__ import annotations

from pathlib import Path

from data_leak_detector.core.models import AnalysisResult


class HTMLReportFormatter:
    """Renders scan findings into a standalone styled HTML report."""

    def __init__(self, result: AnalysisResult) -> None:
        self.result = result

    def render(self, output_path: Path) -> Path:
        """Render and save HTML report."""
        raise NotImplementedError("HTMLReportFormatter not yet implemented.")
