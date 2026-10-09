"""Unit tests for static analysis Rule Engine and RuleRegistry."""

from __future__ import annotations

import unittest
from typing import Any

from data_leak_detector.analysis.vulnerability_detector import VulnerabilityDetector
from data_leak_detector.core.models import (
    Confidence,
    FindingCategory,
    SecurityFinding,
    Severity,
)
from data_leak_detector.rules.base import BaseRule
from data_leak_detector.rules.registry import RuleRegistry


class DummyCleanRule(BaseRule):
    rule_id = "CLEAN-001"
    title = "Clean Rule"
    category = FindingCategory.MANIFEST_MISCONFIG
    default_severity = Severity.LOW
    description = "Checks that always pass cleanly"
    owasp_reference = "OWASP-M1"

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        return []


class DummyFindingRule(BaseRule):
    rule_id = "FIND-001"
    title = "Detected Leakage Indicator"
    category = FindingCategory.NETWORK_INDICATOR
    default_severity = Severity.HIGH
    description = "Static indicator finding test"
    owasp_reference = "OWASP-M3: Insecure Communication"

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        finding_1 = self.create_finding(
            description="Cleartext HTTP endpoint found",
            evidence="http://insecure.endpoint.org/api",
            location="com/example/NetworkService.smali:12",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            impact="Network eavesdropping may expose user metadata.",
            remediation="Enforce HTTPS via Network Security Config.",
        )
        finding_2 = self.create_finding(
            description="Cleartext telemetry beacon",
            evidence="http://telemetry.tracker.io",
            location="com/example/Tracker.smali:98",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            impact="Telemetry leakage.",
            remediation="Use TLS for all analytics telemetry.",
        )
        return [finding_1, finding_2]


class DummyCrashingRule(BaseRule):
    rule_id = "CRASH-001"
    title = "Broken Rule"
    category = FindingCategory.CRYPTO_FLAW
    default_severity = Severity.CRITICAL
    description = "Rule that intentionally raises an unhandled exception"

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        raise RuntimeError("Fatal internal parser error in Smali AST walker")


class DummySecretLeakingRule(BaseRule):
    rule_id = "SECRET-CRASH-001"
    title = "Rule With Secret In Exception"
    category = FindingCategory.HARDCODED_SECRET
    default_severity = Severity.CRITICAL
    description = "Rule whose error message contains a sensitive secret"

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        raise ValueError("Failed on raw key AIzaSyD3x9ExampleKey1234567890abcdef in string pool")


class TestRuleEngine(unittest.TestCase):
    def test_rules_register_and_list(self) -> None:
        registry = RuleRegistry()
        rule1 = DummyCleanRule()
        rule2 = DummyFindingRule()

        registry.register(rule1)
        registry.register(rule2)

        self.assertEqual(len(registry.list_rules()), 2)
        self.assertIs(registry.get_rule("CLEAN-001"), rule1)
        self.assertIs(registry.get_rule("FIND-001"), rule2)

        # Unregister
        self.assertTrue(registry.unregister("CLEAN-001"))
        self.assertIsNone(registry.get_rule("CLEAN-001"))
        self.assertEqual(len(registry.list_rules()), 1)

    def test_register_invalid_type_raises_error(self) -> None:
        registry = RuleRegistry()
        with self.assertRaises(TypeError):
            registry.register("not a BaseRule")  # type: ignore

    def test_rules_execute_and_findings_aggregate(self) -> None:
        registry = RuleRegistry()
        registry.register(DummyCleanRule())
        registry.register(DummyFindingRule())

        report = registry.execute_all(context={"dummy": True})

        self.assertEqual(report.rules_executed, 2)
        self.assertEqual(report.rules_skipped, 0)
        self.assertEqual(report.rule_errors, 0)
        self.assertEqual(len(report.findings), 2)

        # Verify finding fields
        f1, f2 = report.findings[0], report.findings[1]
        self.assertEqual(f1.rule_id, "FIND-001")
        self.assertEqual(f2.rule_id, "FIND-001")
        self.assertEqual(f1.title, "Detected Leakage Indicator")
        self.assertEqual(f1.severity, Severity.HIGH)
        self.assertEqual(f1.confidence, Confidence.HIGH)
        self.assertEqual(f1.evidence, "http://insecure.endpoint.org/api")
        self.assertEqual(f1.location, "com/example/NetworkService.smali:12")
        self.assertIn("OWASP-M3", str(f1.owasp_reference))
        self.assertTrue(f1.impact)
        self.assertTrue(f1.remediation)

    def test_rule_exceptions_are_contained(self) -> None:
        registry = RuleRegistry()
        registry.register(DummyFindingRule())
        registry.register(DummyCrashingRule())

        # Execution must NOT raise an exception
        report = registry.execute_all(context={})

        self.assertEqual(report.rules_executed, 1)
        self.assertEqual(report.rule_errors, 1)
        self.assertEqual(report.rules_skipped, 0)

        # Findings from the non-crashing rule are preserved
        self.assertEqual(len(report.findings), 2)
        self.assertEqual(len(report.errors), 1)
        self.assertEqual(report.errors[0]["rule_id"], "CRASH-001")
        self.assertIn("Fatal internal parser error", report.errors[0]["error"])

    def test_disabled_rules_are_skipped(self) -> None:
        registry = RuleRegistry()
        registry.register(DummyCleanRule())
        registry.register(DummyFindingRule())

        # Disable finding rule
        self.assertTrue(registry.disable_rule("FIND-001"))

        report = registry.execute_all(context={})

        self.assertEqual(report.rules_executed, 1)
        self.assertEqual(report.rules_skipped, 1)
        self.assertEqual(report.rule_errors, 0)
        self.assertEqual(len(report.findings), 0)

        # Re-enable rule
        self.assertTrue(registry.enable_rule("FIND-001"))
        report2 = registry.execute_all(context={})
        self.assertEqual(report2.rules_executed, 2)
        self.assertEqual(report2.rules_skipped, 0)
        self.assertEqual(len(report2.findings), 2)

    def test_never_expose_secrets_in_rule_failure_logs(self) -> None:
        registry = RuleRegistry()
        registry.register(DummySecretLeakingRule())

        report = registry.execute_all(context={})

        self.assertEqual(report.rule_errors, 1)
        error_msg = report.errors[0]["error"]
        self.assertNotIn("AIzaSyD3x9ExampleKey1234567890abcdef", error_msg)
        self.assertIn("[REDACTED_SECRET]", error_msg)

    def test_vulnerability_detector_integration(self) -> None:
        registry = RuleRegistry()
        registry.register(DummyFindingRule())
        detector = VulnerabilityDetector(registry=registry)

        findings = detector.evaluate_all(apk_context={})
        self.assertEqual(len(findings), 2)

        report = detector.run_report(apk_context={})
        self.assertEqual(report.rules_executed, 1)
        self.assertEqual(len(report.findings), 2)


if __name__ == "__main__":
    unittest.main()
