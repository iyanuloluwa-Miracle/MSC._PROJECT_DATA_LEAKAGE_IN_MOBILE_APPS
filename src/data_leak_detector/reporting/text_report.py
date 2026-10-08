"""Plaintext and Markdown report formatter."""

from __future__ import annotations

from pathlib import Path

from data_leak_detector.core.models import AnalysisResult


class TextReportFormatter:
    """Renders scan findings into human-readable plaintext and markdown summaries."""

    def __init__(self, result: AnalysisResult) -> None:
        self.result = result

    def render(self, output_path: Path) -> Path:
        """Render plaintext summary to disk."""
        raise NotImplementedError("TextReportFormatter not yet implemented.")
