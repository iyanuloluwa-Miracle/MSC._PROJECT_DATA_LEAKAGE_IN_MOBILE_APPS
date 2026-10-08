"""Risk scoring algorithm mapping findings and permissions to a normalized score."""

from __future__ import annotations

from data_leak_detector.core.models import Finding, PermissionDetail, RiskScore, Severity


class RiskScorer:
    """Calculates weighted risk score from static findings and permission audits."""

    WEIGHTS = {
        Severity.INFO: 0.0,
        Severity.LOW: 5.0,
        Severity.MEDIUM: 15.0,
        Severity.HIGH: 30.0,
        Severity.CRITICAL: 50.0,
    }

    @classmethod
    def calculate_score(
        cls, permissions: list[PermissionDetail], findings: list[Finding]
    ) -> RiskScore:
        """Calculate aggregate risk score bounded between 0.0 and 100.0."""
        raise NotImplementedError("RiskScorer not yet implemented.")
