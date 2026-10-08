"""Logging configuration with sensitive data redaction."""

from __future__ import annotations

import logging
import re
from typing import Any


class SensitiveDataFilter(logging.Filter):
    """Filter that masks potential secrets and tokens from logging streams."""

    PATTERNS = [
        re.compile(r"(AIza[0-9A-Za-z\-_]{30,40})"),
        re.compile(r"(AKIA[0-9A-Z]{16})"),
        re.compile(r"(?i)(password|secret|token|api_key|apikey)\s*[=:]\s*([^\s,]+)"),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.redact(record.msg)
        return True

    @classmethod
    def redact(cls, text: str) -> str:
        for pattern in cls.PATTERNS:
            text = pattern.sub("[REDACTED_SECRET]", text)
        return text


def setup_logging(level: int = logging.INFO) -> None:
    """Configure root logger with privacy-preserving redacting filter."""
    logger = logging.getLogger("data_leak_detector")
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )
        handler.setFormatter(formatter)
        handler.addFilter(SensitiveDataFilter())
        logger.addHandler(handler)
