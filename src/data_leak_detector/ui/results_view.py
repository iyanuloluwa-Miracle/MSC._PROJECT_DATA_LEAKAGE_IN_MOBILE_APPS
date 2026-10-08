"""Results View: Findings breakdown, risk score gauges, and report export buttons."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from data_leak_detector.core.models import AnalysisResult


class ResultsView(ttk.Frame):
    """View rendering detailed static findings, risk score, and export options."""

    def __init__(self, master: tk.Misc, *args, **kwargs) -> None:
        super().__init__(master, *args, **kwargs)
        # Results rendering stub

    def display_results(self, result: AnalysisResult) -> None:
        """Populate treeview and score gauges with scan results."""
        pass
