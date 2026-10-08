"""Rules identifying embedded third-party ad, tracking, and analytics SDKs."""

from __future__ import annotations

from typing import Any

from data_leak_detector.core.models import Finding, FindingCategory, Severity
from data_leak_detector.rules.base import BaseRule


class ThirdPartyTrackerRule(BaseRule):
    """Detects known embedded commercial tracking and advertising SDK packages."""

    rule_id = "SDK-001"
    category = FindingCategory.TRACKING_SDK
    severity = Severity.MEDIUM
    title = "Third-Party Analytics or Tracking SDK Detected"
    description = (
        "Static class analysis detected presence of third-party telemetry, "
        "advertising, or attribution SDKs capable of harvesting device metrics."
    )

    def evaluate(self, context: dict[str, Any]) -> list[Finding]:
        raise NotImplementedError()
