"""Desktop Application entry point."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from data_leak_detector.core.config import AppConfig
from data_leak_detector.core.logging_config import setup_logging
from data_leak_detector.ui.main_window import MainWindow

logger = logging.getLogger(__name__)


def main() -> int:
    """Launch the Mobile Data Leak Detector desktop application."""
    # Set Windows DPI awareness for crisp font rendering if available
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

    # Initialize logging
    setup_logging()
    logger.info("Starting Mobile Data Leak Detector desktop application...")

    try:
        config = AppConfig()
        app = MainWindow(config=config)
        app.mainloop()
        return 0
    except Exception as exc:
        logger.critical("Fatal error encountered in desktop application: %s", exc, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
