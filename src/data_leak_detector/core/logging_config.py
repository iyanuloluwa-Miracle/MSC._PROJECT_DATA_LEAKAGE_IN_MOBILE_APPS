"""Logging configuration with sensitive data redaction and log injection neutralization."""

from __future__ import annotations

import logging
import re

from data_leak_detector.core.path_safety import sanitize_for_logging


class SensitiveDataFilter(logging.Filter):
    """Filter that masks potential secrets and neutralizes CRLF log injection attacks (CWE-117)."""

    PATTERNS = [
        re.compile(r"(AIza[0-9A-Za-z\-_]{30,45})"),
        re.compile(r"(AKIA[0-9A-Z]{16})"),
        re.compile(r"(gh[pousr]_[A-Za-z0-9_]{36,120})"),
        re.compile(r"(xox[baprs]-[0-9a-zA-Z-]{24,80})"),
        re.compile(r"(?i)(password|secret|token|api_key|apikey)\s*[=:]\s*([^\s,;]+)"),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.redact_and_sanitize(record.msg)
        if record.args:
            if isinstance(record.args, tuple):
                record.args = tuple(
                    self.redact_and_sanitize(str(a)) if isinstance(a, str) else a
                    for a in record.args
                )
            elif isinstance(record.args, dict):
                record.args = {
                    k: (self.redact_and_sanitize(str(v)) if isinstance(v, str) else v)
                    for k, v in record.args.items()
                }
        return True

    @classmethod
    def redact(cls, text: str) -> str:
        """Redact known secret patterns and credentials from a string."""
        if not text:
            return ""
        for pattern in cls.PATTERNS:
            text = pattern.sub("[REDACTED_SECRET]", text)
        return text

    @classmethod
    def redact_and_sanitize(cls, text: str) -> str:
        """Mask credentials and neutralize log-injection control characters (CRLF)."""
        redacted = cls.redact(text)
        return sanitize_for_logging(redacted)


def setup_logging(level: int = logging.INFO) -> None:
    """Configure root logger with privacy-preserving redacting filter."""
    import sys

    logger = logging.getLogger("data_leak_detector")
    logger.setLevel(level)

    if not logger.handlers:
        # Check if sys.stderr is available (can be None in windowed PyInstaller mode)
        stream = sys.stderr if sys.stderr is not None else sys.stdout
        if stream is not None:
            handler = logging.StreamHandler(stream)
            formatter = logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            )
            handler.setFormatter(formatter)
            handler.addFilter(SensitiveDataFilter())
            logger.addHandler(handler)

        # Persistent user log file in application data directory
        try:
            from data_leak_detector.core.config import get_default_config_dir

            log_dir = get_default_config_dir() / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            log_file = log_dir / "app.log"
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_formatter = logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            )
            file_handler.setFormatter(file_formatter)
            file_handler.addFilter(SensitiveDataFilter())
            logger.addHandler(file_handler)
        except Exception:
            pass
