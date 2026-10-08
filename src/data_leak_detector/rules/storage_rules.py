"""Rules identifying insecure local storage patterns."""

from __future__ import annotations

from typing import Any

from data_leak_detector.core.models import Finding, FindingCategory, Severity
from data_leak_detector.rules.base import BaseRule


class InsecureStorageRule(BaseRule):
    """Detects usage of world-readable/writable files or external storage for sensitive data."""

    rule_id = "STO-001"
    category = FindingCategory.STORAGE_INSECURITY
    severity = Severity.HIGH
    title = "Insecure Local Storage Usage"
    description = (
        "Static detection of world-readable shared preferences or unencrypted external storage access."
    )

    def evaluate(self, context: dict[str, Any]) -> list[Finding]:
        raise NotImplementedError()
