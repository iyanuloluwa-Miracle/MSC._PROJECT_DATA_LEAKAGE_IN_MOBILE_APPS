"""Analyze View: File selector, drag-and-drop / browse target APK, and scan initiation."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class AnalyzeView(ttk.Frame):
    """View allowing the user to select an APK file and launch static analysis."""

    def __init__(self, master: tk.Misc, *args, **kwargs) -> None:
        super().__init__(master, *args, **kwargs)
        # Layout and controls stub
