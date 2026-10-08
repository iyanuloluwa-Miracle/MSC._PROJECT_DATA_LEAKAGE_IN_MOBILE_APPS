"""Reusable custom Tkinter/ttk UI widgets."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class SeverityBadge(ttk.Frame):
    """Visual colored badge for Severity labels (INFO, LOW, MEDIUM, HIGH, CRITICAL)."""

    def __init__(self, master: tk.Misc, severity: str, *args, **kwargs) -> None:
        super().__init__(master, *args, **kwargs)
        # Widget implementation stub
