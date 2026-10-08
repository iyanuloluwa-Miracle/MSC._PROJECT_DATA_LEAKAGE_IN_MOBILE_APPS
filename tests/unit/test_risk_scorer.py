"""Unit tests for the transparent prototype RiskScorer.

Tests:
- No findings -> Score 0.0, Minimal rating
- One critical finding -> Score 25.0, Low rating
- Multiple findings -> Correct aggregation and rating
- Confidence differences -> Confidence scaling (High 1.0, Medium 0.75, Low 0.5)
- Score capped at 100.0 -> Upper boundary containment
- Duplicate findings and repetition mitigation -> Deduplication and low-severity cap
- Rating boundary values -> 0-19 Minimal, 20-39 Low, 40-59 Medium, 60-79 High, 80-100 Critical
- Explicit prototype disclaimer verification
"""

from __future__ import annotations

import unittest

from data_leak_detector.analysis.risk_scorer import PROTOTYPE_DISCLAIMER, RiskScorer
from data_leak_detector.core.models import (
    Confidence,
    FindingCategory,
    RiskRating,
    SecurityFinding,
    Severity,
)


class TestRiskScorer(unittest.TestCase):
    def _create_finding(
        self,
        rule_id: str = "SEC-001",
        title: str = "Test Security Finding",
        severity: Severity = Severity.HIGH,
        confidence: Confidence = Confidence.HIGH,
        category: FindingCategory = FindingCategory.HARDCODED_SECRET,
        evidence: str = "test_evidence",
        location: str = "Class.java:10",
    ) -> SecurityFinding:
        return SecurityFinding(
            rule_id=rule_id,
            title=title,
            category=category,
            severity=severity,
            confidence=confidence,
            description="Test description.",
            evidence=evidence,
            location=location,
        )

    # -----------------------------------------------------------------------
    # Test 1: No Findings
    # -----------------------------------------------------------------------
    def test_no_findings(self) -> None:
        result = RiskScorer.calculate_score([])
        self.assertEqual(result.score, 0.0)
        self.assertEqual(result.rating, RiskRating.MINIMAL)
        self.assertEqual(result.findings_evaluated, 0)
        self.assertIn(PROTOTYPE_DISCLAIMER, result.disclaimer)
        self.assertIn(PROTOTYPE_DISCLAIMER, result.explanations[0])

    # -----------------------------------------------------------------------
    # Test 2: One Critical Finding
    # -----------------------------------------------------------------------
    def test_one_critical_finding(self) -> None:
        # Critical base = 25.0, High confidence = 1.0 -> 25.0
        # 25.0 falls in 20-39 band -> Low risk rating
        f = self._create_finding(
            rule_id="SEC-CRIT-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
        )
        result = RiskScorer.calculate_score([f])
        self.assertEqual(result.score, 25.0)
        self.assertEqual(result.rating, RiskRating.LOW)
        self.assertEqual(result.findings_evaluated, 1)
        self.assertEqual(result.findings_deduplicated, 0)
        self.assertIn("SEC-CRIT-001", result.rule_contributions)
        self.assertEqual(result.rule_contributions["SEC-CRIT-001"], 25.0)

    # -----------------------------------------------------------------------
    # Test 3: Multiple Findings
    # -----------------------------------------------------------------------
    def test_multiple_findings(self) -> None:
        # 1 Critical (25.0) in HARDCODED_SECRET
        # 1 High (15.0) in NETWORK_INDICATOR
        # 1 Medium (8.0) in STORAGE_INSECURITY
        # Sum = 25 + 15 + 8 = 48.0 -> Medium band (40-59)
        f1 = self._create_finding(
            rule_id="SEC-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=FindingCategory.HARDCODED_SECRET,
        )
        f2 = self._create_finding(
            rule_id="NET-001",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=FindingCategory.NETWORK_INDICATOR,
        )
        f3 = self._create_finding(
            rule_id="STO-001",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category=FindingCategory.STORAGE_INSECURITY,
        )

        result = RiskScorer.calculate_score([f1, f2, f3])
        self.assertEqual(result.score, 48.0)
        self.assertEqual(result.rating, RiskRating.MEDIUM)
        self.assertEqual(result.findings_evaluated, 3)
        self.assertEqual(len(result.category_scores), 3)

    # -----------------------------------------------------------------------
    # Test 4: Confidence Differences
    # -----------------------------------------------------------------------
    def test_confidence_differences(self) -> None:
        # Critical base = 25.0
        # High confidence = 1.0 -> 25.0
        # Medium confidence = 0.75 -> 18.75 (rounds to 18.8)
        # Low confidence = 0.5 -> 12.5
        f_high = self._create_finding(severity=Severity.CRITICAL, confidence=Confidence.HIGH)
        f_med = self._create_finding(severity=Severity.CRITICAL, confidence=Confidence.MEDIUM)
        f_low = self._create_finding(severity=Severity.CRITICAL, confidence=Confidence.LOW)

        res_high = RiskScorer.calculate_score([f_high])
        res_med = RiskScorer.calculate_score([f_med])
        res_low = RiskScorer.calculate_score([f_low])

        self.assertEqual(res_high.score, 25.0)
        self.assertEqual(res_med.score, 18.8)
        self.assertEqual(res_low.score, 12.5)

        self.assertGreater(res_high.score, res_med.score)
        self.assertGreater(res_med.score, res_low.score)

    # -----------------------------------------------------------------------
    # Test 5: Score Capped at 100.0
    # -----------------------------------------------------------------------
    def test_score_capped_at_100(self) -> None:
        # Generate multiple critical findings across different categories
        findings = [
            self._create_finding(
                rule_id=f"RULE-{i}",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category=FindingCategory(list(FindingCategory)[i % len(FindingCategory)]),
                evidence=f"evidence_{i}",
                location=f"loc_{i}",
            )
            for i in range(10)
        ]
        # 10 critical findings across categories would sum to >> 100
        result = RiskScorer.calculate_score(findings)
        self.assertEqual(result.score, 100.0)
        self.assertEqual(result.rating, RiskRating.CRITICAL)

    # -----------------------------------------------------------------------
    # Test 6: Duplicate Findings and Low-Severity Repetition Mitigation
    # -----------------------------------------------------------------------
    def test_exact_duplicate_findings_deduplicated(self) -> None:
        f = self._create_finding(rule_id="DUP-001", evidence="same_evidence", location="same_location")
        # Provide 5 exact copies of the same finding
        result = RiskScorer.calculate_score([f, f, f, f, f])
        self.assertEqual(result.findings_evaluated, 5)
        self.assertEqual(result.findings_deduplicated, 4)
        # Score must equal exactly 1 instance (High = 15.0)
        self.assertEqual(result.score, 15.0)

    def test_repetitive_low_severity_findings_capped(self) -> None:
        """Dozens of low findings must not unrealistically inflate score beyond minimal cap."""
        low_findings = [
            self._create_finding(
                rule_id=f"LOW-RULE-{i}",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                category=FindingCategory.NETWORK_INDICATOR,
                evidence=f"http://api-{i}.com",
                location=f"File{i}.java",
            )
            for i in range(30)
        ]
        result = RiskScorer.calculate_score(low_findings)
        # Without cap: 30 * 3.0 = 90.0 (Critical)
        # With cap: capped at LOW_SEVERITY_TOTAL_CAP = 15.0
        self.assertLessEqual(result.score, RiskScorer.LOW_SEVERITY_TOTAL_CAP)
        self.assertEqual(result.rating, RiskRating.MINIMAL)

    # -----------------------------------------------------------------------
    # Test 7: Rating Boundaries
    # -----------------------------------------------------------------------
    def test_rating_boundaries(self) -> None:
        scorer = RiskScorer()

        # 0 - 19: Minimal
        self.assertEqual(scorer.get_rating_band(0.0), RiskRating.MINIMAL)
        self.assertEqual(scorer.get_rating_band(10.5), RiskRating.MINIMAL)
        self.assertEqual(scorer.get_rating_band(19.0), RiskRating.MINIMAL)
        self.assertEqual(scorer.get_rating_band(19.9), RiskRating.MINIMAL)

        # 20 - 39: Low
        self.assertEqual(scorer.get_rating_band(20.0), RiskRating.LOW)
        self.assertEqual(scorer.get_rating_band(30.0), RiskRating.LOW)
        self.assertEqual(scorer.get_rating_band(39.0), RiskRating.LOW)
        self.assertEqual(scorer.get_rating_band(39.9), RiskRating.LOW)

        # 40 - 59: Medium
        self.assertEqual(scorer.get_rating_band(40.0), RiskRating.MEDIUM)
        self.assertEqual(scorer.get_rating_band(50.0), RiskRating.MEDIUM)
        self.assertEqual(scorer.get_rating_band(59.0), RiskRating.MEDIUM)
        self.assertEqual(scorer.get_rating_band(59.9), RiskRating.MEDIUM)

        # 60 - 79: High
        self.assertEqual(scorer.get_rating_band(60.0), RiskRating.HIGH)
        self.assertEqual(scorer.get_rating_band(70.0), RiskRating.HIGH)
        self.assertEqual(scorer.get_rating_band(79.0), RiskRating.HIGH)
        self.assertEqual(scorer.get_rating_band(79.9), RiskRating.HIGH)

        # 80 - 100: Critical
        self.assertEqual(scorer.get_rating_band(80.0), RiskRating.CRITICAL)
        self.assertEqual(scorer.get_rating_band(90.0), RiskRating.CRITICAL)
        self.assertEqual(scorer.get_rating_band(100.0), RiskRating.CRITICAL)

    # -----------------------------------------------------------------------
    # Test 8: Explicit Disclaimer & Explainability
    # -----------------------------------------------------------------------
    def test_disclaimer_and_explainability_audit_trail(self) -> None:
        f = self._create_finding(rule_id="AUDIT-001", severity=Severity.MEDIUM, confidence=Confidence.HIGH)
        result = RiskScorer.calculate_score([f])

        # Mandatory disclaimer exact match
        expected_disclaimer = (
            "This risk score is a heuristic prioritisation metric developed for this research prototype "
            "and should not be interpreted as CVSS or proof of exploitation."
        )
        self.assertEqual(result.disclaimer, expected_disclaimer)
        self.assertIn(expected_disclaimer, result.summary)

        # Itemized breakdown explainability
        self.assertEqual(len(result.breakdown["findings"]), 1)
        item = result.breakdown["findings"][0]
        self.assertEqual(item["rule_id"], "AUDIT-001")
        self.assertEqual(item["base_weight"], 8.0)
        self.assertEqual(item["confidence_multiplier"], 1.0)
        self.assertEqual(item["raw_calculated"], 8.0)
        self.assertEqual(item["adjusted_score"], 8.0)


if __name__ == "__main__":
    unittest.main()
