"""History View: Table of past static analysis scans stored in local SQLite."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class HistoryView(ttk.Frame):
    """View rendering past scan history with search and re-open capabilities."""

    def __init__(self, master: tk.Misc, *args, **kwargs) -> None:
        super().__init__(master, *args, **kwargs)
        # Scan history table stub
