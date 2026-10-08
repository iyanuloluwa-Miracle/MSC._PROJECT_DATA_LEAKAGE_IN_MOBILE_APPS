"""Rules identifying static network communication indicators and unencrypted endpoints."""

from __future__ import annotations

from typing import Any

from data_leak_detector.core.models import Finding, FindingCategory, Severity
from data_leak_detector.rules.base import BaseRule


class CleartextTrafficRule(BaseRule):
    """Detects cleartext HTTP URLs and cleartext traffic permission settings."""

    rule_id = "NET-001"
    category = FindingCategory.NETWORK_INDICATOR
    severity = Severity.HIGH
    title = "Cleartext HTTP Transmission Indicator"
    description = (
        "Static string analysis identified unencrypted HTTP endpoint(s). "
        "Represents potential eavesdropping risk if used to transmit user data."
    )

    def evaluate(self, context: dict[str, Any]) -> list[Finding]:
        raise NotImplementedError()
