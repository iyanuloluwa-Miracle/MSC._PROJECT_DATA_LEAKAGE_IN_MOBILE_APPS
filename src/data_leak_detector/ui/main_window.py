"""Main Application Window with ttk Notebook tabs for navigation."""

from __future__ import annotations

import logging
import tkinter as tk
from tkinter import ttk

from data_leak_detector.core.config import AppConfig


logger = logging.getLogger(__name__)


class MainWindow(tk.Tk):
    """Primary application window hosting tabbed navigation."""

    def __init__(self, config: AppConfig | None = None) -> None:
        super().__init__()
        self.config = config or AppConfig()
        self.title("Mobile Data Leak Detector")
        self.geometry("1024x720")
        self.minsize(800, 600)
        self._init_ui()

    def _init_ui(self) -> None:
        """Initialize tabs and main layout."""
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        # Tab initialization stub
