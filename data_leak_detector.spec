# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller specification file for Mobile Data Leak Detector.

Builds a standalone one-directory (onedir) distribution package.
Includes all bundled rule patterns and permission metadata resources.
Produces a windowed GUI executable without a console window in production.
"""

import sys
from pathlib import Path

# Base directory of the repository
ROOT_DIR = Path(SPECPATH).resolve()
SRC_DIR = ROOT_DIR / "src"

# Data files bundled into the distribution directory under 'resources/'
datas = [
    (str(ROOT_DIR / "resources" / "permission_metadata.json"), "resources"),
    (str(ROOT_DIR / "resources" / "sdk_patterns.json"), "resources"),
    (str(ROOT_DIR / "resources" / "tracking_patterns.json"), "resources"),
]

# Hidden imports for reflection, dynamic packaging, and C-extensions
hiddenimports = [
    "sqlite3",
    "tkinter",
    "tkinter.ttk",
    "tkinter.filedialog",
    "tkinter.messagebox",
    "reportlab",
    "reportlab.lib",
    "reportlab.platypus",
    "reportlab.pdfgen",
    "androguard",
    "androguard.core",
    "androguard.core.apk",
    "androguard.core.analysis",
    "androguard.core.analysis.analysis",
    "data_leak_detector",
    "data_leak_detector.analysis",
    "data_leak_detector.core",
    "data_leak_detector.reporting",
    "data_leak_detector.rules",
    "data_leak_detector.storage",
    "data_leak_detector.ui",
]

a = Analysis(
    [str(ROOT_DIR / "run_app.py")],
    pathex=[str(ROOT_DIR), str(SRC_DIR)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "pytest",
        "unittest",
        "flake8",
        "coverage",
        "IPython",
        "jupyter",
        "notebook",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="data_leak_detector",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="data_leak_detector",
)
