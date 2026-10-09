"""Mobile Data Leak Detector application launcher."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure 'src' is available in sys.path when running from source checkout
CURRENT_DIR = Path(__file__).resolve().parent
SRC_DIR = CURRENT_DIR / "src"
if SRC_DIR.exists() and str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from data_leak_detector.app import main  # noqa: E402


if __name__ == "__main__":
    sys.exit(main())
